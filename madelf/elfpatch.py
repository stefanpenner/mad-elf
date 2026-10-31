"""ELF64 helpers: read and replace PT_INTERP, read a .madelf section."""

from __future__ import annotations

import os
import shutil
import struct
import subprocess
import tempfile

ELF_MAGIC = b"\x7fELF"
PT_INTERP = 3
SHT_STRTAB = 3


class ElfError(Exception):
    pass


def _u16(buf: bytes, off: int) -> int:
    return struct.unpack_from("<H", buf, off)[0]


def _u32(buf: bytes, off: int) -> int:
    return struct.unpack_from("<I", buf, off)[0]


def _u64(buf: bytes, off: int) -> int:
    return struct.unpack_from("<Q", buf, off)[0]


def _need(buf: bytes, off: int, n: int, what: str) -> None:
    if off < 0 or n < 0 or off + n > len(buf):
        raise ElfError(f"{what} is outside the file")


def _elf64_header(buf: bytes) -> dict:
    if len(buf) < 64 or buf[:4] != ELF_MAGIC:
        raise ElfError("not an ELF file")
    if buf[4] != 2 or buf[5] != 1:
        raise ElfError("only ELF64 little-endian is supported")
    return {
        "phoff": _u64(buf, 32),
        "shoff": _u64(buf, 40),
        "phentsize": _u16(buf, 54),
        "phnum": _u16(buf, 56),
        "shentsize": _u16(buf, 58),
        "shnum": _u16(buf, 60),
        "shstrndx": _u16(buf, 62),
    }


def read_interpreter(path: str) -> str | None:
    """Return the PT_INTERP path, or None when the ELF has no interpreter.

    None means a static binary (or another ELF with no PT_INTERP). Non-ELF
    input raises ElfError.
    """
    with open(path, "rb") as f:
        head = f.read(64)
        hdr = _elf64_header(head)
        if hdr["phentsize"] < 56 or hdr["phnum"] > 512:
            raise ElfError("unreasonable program header table")
        f.seek(hdr["phoff"])
        phdrs = f.read(hdr["phentsize"] * hdr["phnum"])
    if len(phdrs) < hdr["phentsize"] * hdr["phnum"]:
        raise ElfError("truncated program header table")
    found = None
    for i in range(hdr["phnum"]):
        off = i * hdr["phentsize"]
        p_type = _u32(phdrs, off)
        if p_type != PT_INTERP:
            continue
        if found is not None:
            raise ElfError("multiple PT_INTERP headers")
        p_offset = _u64(phdrs, off + 8)
        p_filesz = _u64(phdrs, off + 32)
        if p_filesz == 0 or p_filesz > 4096:
            raise ElfError("PT_INTERP size is unreasonable")
        with open(path, "rb") as f:
            f.seek(p_offset)
            raw = f.read(p_filesz)
        if len(raw) != p_filesz:
            raise ElfError("truncated PT_INTERP")
        found = raw.split(b"\x00", 1)[0].decode("utf-8", "surrogateescape")
    return found


def set_interpreter(path: str, interp: str) -> None:
    """Point PT_INTERP at interp.

    If the new path fits in the existing segment it is written in place.
    Otherwise the path is appended and the program header is retargeted.
    The kernel reads PT_INTERP from the file; it does not need to stay inside
    the original string's virtual address.
    """
    if not interp.startswith("/"):
        raise ElfError(f"interpreter path must be absolute: {interp}")
    raw = interp.encode("utf-8") + b"\x00"
    if len(raw) > 4096:
        raise ElfError("interpreter path is too long")
    with open(path, "r+b") as f:
        head = f.read(64)
        hdr = _elf64_header(head)
        if hdr["phentsize"] < 56 or hdr["phnum"] > 512:
            raise ElfError("unreasonable program header table")
        f.seek(hdr["phoff"])
        phdrs = bytearray(f.read(hdr["phentsize"] * hdr["phnum"]))
        if len(phdrs) < hdr["phentsize"] * hdr["phnum"]:
            raise ElfError("truncated program header table")
        slot = None
        for i in range(hdr["phnum"]):
            off = i * hdr["phentsize"]
            if _u32(phdrs, off) == PT_INTERP:
                if slot is not None:
                    raise ElfError("multiple PT_INTERP headers")
                slot = off
        if slot is None:
            raise ElfError("no PT_INTERP; this is a static binary and cannot be patched")
        p_offset = _u64(phdrs, slot + 8)
        p_filesz = _u64(phdrs, slot + 32)
        if len(raw) <= p_filesz:
            f.seek(p_offset)
            f.write(raw + b"\x00" * (p_filesz - len(raw)))
            struct.pack_into("<Q", phdrs, slot + 32, len(raw))
            struct.pack_into("<Q", phdrs, slot + 40, len(raw))
            f.seek(hdr["phoff"])
            f.write(phdrs)
            return
        f.seek(0, os.SEEK_END)
        new_off = f.tell()
        f.write(raw)
        struct.pack_into("<Q", phdrs, slot + 8, new_off)
        struct.pack_into("<Q", phdrs, slot + 32, len(raw))
        struct.pack_into("<Q", phdrs, slot + 40, len(raw))
        f.seek(hdr["phoff"])
        f.write(phdrs)


def read_section(path: str, name: str) -> bytes | None:
    with open(path, "rb") as f:
        blob = f.read()
    try:
        hdr = _elf64_header(blob)
    except ElfError:
        return None
    if not hdr["shoff"] or not hdr["shnum"] or hdr["shentsize"] < 64:
        return None
    if hdr["shstrndx"] >= hdr["shnum"]:
        return None
    shoff = hdr["shoff"]
    entsize = hdr["shentsize"]
    _need(blob, shoff, entsize * hdr["shnum"], "section header table")
    str_hdr = shoff + hdr["shstrndx"] * entsize
    str_off = _u64(blob, str_hdr + 24)
    str_size = _u64(blob, str_hdr + 32)
    _need(blob, str_off, str_size, "section name table")
    names = blob[str_off : str_off + str_size]
    target = name.encode("utf-8")
    for i in range(hdr["shnum"]):
        sh = shoff + i * entsize
        name_off = _u32(blob, sh)
        if name_off >= len(names):
            continue
        end = names.find(b"\x00", name_off)
        if end < 0:
            continue
        if names[name_off:end] != target:
            continue
        off = _u64(blob, sh + 24)
        size = _u64(blob, sh + 32)
        _need(blob, off, size, f"section {name}")
        return blob[off : off + size]
    return None


def read_config_text(path: str) -> str | None:
    sidecar = path + ".madelf"
    if os.path.isfile(sidecar):
        with open(sidecar, "r", encoding="utf-8") as f:
            return f.read()
    blob = read_section(path, ".madelf")
    if blob is None:
        return None
    return blob.decode("utf-8", "replace")


def embed_config_section(path: str, text: str) -> None:
    objcopy = shutil.which("objcopy")
    if not objcopy:
        raise ElfError("objcopy is required to embed a .madelf section")
    with tempfile.TemporaryDirectory() as tmp:
        blob = os.path.join(tmp, "madelf.cfg")
        with open(blob, "w", encoding="utf-8") as f:
            f.write(text)
        rm = subprocess.run(
            [objcopy, "--remove-section", ".madelf", path],
            capture_output=True,
            text=True,
        )
        if rm.returncode != 0 and "can't" not in (rm.stderr or "").lower():
            # objcopy returns non-zero when the section is absent on some versions.
            if "no such section" not in (rm.stderr or "").lower() and rm.stderr.strip():
                pass
        add = subprocess.run(
            [
                objcopy,
                "--add-section",
                f".madelf={blob}",
                "--set-section-flags",
                ".madelf=noload,readonly,contents",
                path,
            ],
            capture_output=True,
            text=True,
        )
        if add.returncode != 0:
            raise ElfError(f"objcopy failed: {add.stderr.strip() or add.stdout.strip()}")


def first_loader(text: str) -> str | None:
    for line in text.splitlines():
        s = line.strip()
        if s.startswith("loader=") and not s.startswith("loader=#"):
            return s[len("loader=") :]
    return None
