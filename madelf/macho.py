"""Insert an absolute LC_LOAD_DYLIB into a 64-bit Mach-O (thin or fat)."""

from __future__ import annotations

import struct

MH_MAGIC_64 = 0xFEEDFACF
FAT_MAGIC_BYTES = b"\xca\xfe\xba\xbe"
LC_SEGMENT_64 = 0x19
LC_SYMTAB = 0x2
LC_DYSYMTAB = 0xB
LC_LOAD_DYLIB = 0xC
LC_CODE_SIGNATURE = 0x1D
LC_DATA_IN_CODE = 0x29
LC_FUNCTION_STARTS = 0x26
S_ZEROFILL = 1

# Linkedit-style commands whose payload is (dataoff, datasize) at +8.
_DATAOFF_CMDS = {
    LC_CODE_SIGNATURE,
    LC_DATA_IN_CODE,
    LC_FUNCTION_STARTS,
    0x2A,  # LC_DYLIB_CODE_SIGN_DRS
    0x2B,  # LC_LINKER_OPTIMIZATION_HINT
    0x2C,  # LC_DYLD_EXPORTS_TRIE
    0x2D,  # LC_DYLD_CHAINED_FIXUPS
    0x33,  # LC_SEGMENT_SPLIT_INFO is 0x1E; keep the well-known dataoff ones above
}


class MachOError(Exception):
    pass


def validate_dylib_path(path: str) -> None:
    if not path.startswith("/"):
        raise MachOError(
            "LC_LOAD_DYLIB path must be absolute "
            f"(got {path!r}). @executable_path, @loader_path, and @rpath are rejected "
            "so every launch resolves the same file."
        )
    for token in ("@executable_path", "@loader_path", "@rpath"):
        if token in path:
            raise MachOError(f"LC_LOAD_DYLIB path must not contain {token}: {path}")
    if not path.endswith("/libmadelf.dylib"):
        raise MachOError(
            "the injected library path must end with /libmadelf.dylib "
            f"so detection can recognize it (got {path})"
        )


def _dylib_command(path: str) -> bytes:
    raw = path.encode("utf-8") + b"\x00"
    size = (24 + len(raw) + 7) & ~7
    buf = bytearray(size)
    struct.pack_into("<II", buf, 0, LC_LOAD_DYLIB, size)
    struct.pack_into("<I", buf, 8, 24)  # name offset from the start of this command
    struct.pack_into("<III", buf, 12, 0, 0x00010000, 0x00010000)
    buf[24 : 24 + len(raw)] = raw
    return bytes(buf)


def _is_fat(data: bytes) -> bool:
    return len(data) >= 8 and data[:4] == FAT_MAGIC_BYTES


def _slices(data: bytes) -> list[tuple[int, int]]:
    if _is_fat(data):
        nfat = struct.unpack_from(">I", data, 4)[0]
        if nfat == 0 or nfat > 8:
            raise MachOError(f"unreasonable fat arch count {nfat}")
        need = 8 + nfat * 20
        if len(data) < need:
            raise MachOError("truncated fat header")
        out = []
        for i in range(nfat):
            _cputype, _subtype, offset, size, _align = struct.unpack_from(">IIIII", data, 8 + i * 20)
            if offset + size > len(data):
                raise MachOError("fat slice extends past the file")
            out.append((offset, size))
        return out
    magic = struct.unpack_from("<I", data, 0)[0] if len(data) >= 4 else 0
    if magic != MH_MAGIC_64:
        raise MachOError("not a 64-bit little-endian Mach-O (or fat) file")
    return [(0, len(data))]


def _walk_commands(data: bytes, base: int, size: int):
    if size < 32:
        raise MachOError("Mach-O slice is too small")
    magic = struct.unpack_from("<I", data, base)[0]
    if magic != MH_MAGIC_64:
        raise MachOError("only 64-bit little-endian Mach-O slices are supported")
    ncmds, sizeofcmds = struct.unpack_from("<II", data, base + 16)
    if sizeofcmds > size - 32 or ncmds > 4096:
        raise MachOError("unreasonable Mach-O load commands")
    pos = base + 32
    end = pos + sizeofcmds
    cmds = []
    for _ in range(ncmds):
        if pos + 8 > end:
            raise MachOError("load command overruns sizeofcmds")
        cmd, cmdsize = struct.unpack_from("<II", data, pos)
        if cmdsize < 8 or pos + cmdsize > end:
            raise MachOError("invalid load command size")
        cmds.append((pos, cmd, cmdsize))
        pos += cmdsize
    return ncmds, sizeofcmds, cmds


def _content_offsets(data: bytes, base: int, cmds) -> list[int]:
    """File offsets, relative to the slice, where real content begins."""
    found = []
    for pos, cmd, cmdsize in cmds:
        if cmd == LC_SEGMENT_64 and cmdsize >= 72:
            fileoff = struct.unpack_from("<Q", data, pos + 40)[0]
            nsects = struct.unpack_from("<I", data, pos + 64)[0]
            if fileoff > 0:
                found.append(fileoff)
            sec = pos + 72
            for _ in range(nsects):
                if sec + 80 > pos + cmdsize:
                    break
                offset = struct.unpack_from("<I", data, sec + 48)[0]
                flags = struct.unpack_from("<I", data, sec + 64)[0]
                if offset > 0 and (flags & 0xFF) != S_ZEROFILL:
                    found.append(offset)
                sec += 80
        elif cmd == LC_SYMTAB and cmdsize >= 24:
            symoff, _nsyms, stroff, _strsize = struct.unpack_from("<IIII", data, pos + 8)
            if symoff > 0:
                found.append(symoff)
            if stroff > 0:
                found.append(stroff)
        elif cmd == LC_DYSYMTAB and cmdsize >= 80:
            for rel in (32, 40, 48, 56, 64, 72):  # toc, modtab, extref, indirect, extrel, locrel
                off = struct.unpack_from("<I", data, pos + rel)[0]
                if off > 0:
                    found.append(off)
        elif cmd in _DATAOFF_CMDS and cmdsize >= 16:
            dataoff = struct.unpack_from("<I", data, pos + 8)[0]
            if dataoff > 0:
                found.append(dataoff)
    return found


def _dylib_paths_in_slice(data: bytes, base: int, size: int) -> list[str]:
    _ncmds, _sizeofcmds, cmds = _walk_commands(data, base, size)
    paths = []
    for pos, cmd, cmdsize in cmds:
        if cmd != LC_LOAD_DYLIB and cmd != (0x18 | 0x80000000):
            continue
        if cmdsize < 24:
            continue
        name_off = struct.unpack_from("<I", data, pos + 8)[0]
        if name_off >= cmdsize:
            continue
        raw = bytes(data[pos + name_off : pos + cmdsize])
        raw = raw.split(b"\x00", 1)[0]
        paths.append(raw.decode("utf-8", "surrogateescape"))
    return paths


def load_dylibs(path: str) -> list[str]:
    with open(path, "rb") as f:
        data = f.read()
    out = []
    for base, size in _slices(data):
        out.extend(_dylib_paths_in_slice(data, base, size))
    return out


def inject_load_dylib(path: str, dylib: str) -> None:
    """Bake an absolute LC_LOAD_DYLIB into every slice, using existing header slack.

    The path is stored verbatim. Moving the dylib later requires running this
    again. There is no @rpath and no environment variable.
    """
    validate_dylib_path(dylib)
    with open(path, "r+b") as f:
        data = bytearray(f.read())
    cmd = _dylib_command(dylib)
    slices = _slices(data)
    plans = []
    for base, size in slices:
        existing = _dylib_paths_in_slice(data, base, size)
        mad = [p for p in existing if p.endswith("/libmadelf.dylib")]
        if dylib in mad:
            plans.append(None)
            continue
        if mad:
            raise MachOError(
                f"binary already loads a different mad-elf dylib ({mad[0]}); "
                "start from an unmodified copy"
            )
        ncmds, sizeofcmds, cmds = _walk_commands(data, base, size)
        offsets = _content_offsets(data, base, cmds)
        header_end = 32 + sizeofcmds
        if not offsets:
            raise MachOError("Mach-O slice has no section past the load commands; no header slack")
        first = min(offsets)
        if first < header_end:
            raise MachOError("Mach-O load commands overlap file content")
        slack = first - header_end
        if slack < len(cmd):
            raise MachOError(
                f"not enough Mach-O header slack ({slack} bytes, need {len(cmd)}). "
                "Relink with -Wl,-headerpad_max_install_names or use a binary that has header padding."
            )
        plans.append((base, ncmds, sizeofcmds, header_end))
    if all(p is None for p in plans):
        return
    for plan in plans:
        if plan is None:
            continue
        base, ncmds, sizeofcmds, header_end = plan
        data[base + header_end : base + header_end + len(cmd)] = cmd
        struct.pack_into("<I", data, base + 16, ncmds + 1)
        struct.pack_into("<I", data, base + 20, sizeofcmds + len(cmd))
    with open(path, "wb") as f:
        f.write(data)


def is_madelf_macho(path: str) -> bool:
    try:
        paths = load_dylibs(path)
    except (OSError, MachOError):
        return False
    return any(p.startswith("/") and p.endswith("/libmadelf.dylib") for p in paths)
