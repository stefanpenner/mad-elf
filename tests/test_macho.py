#!/usr/bin/env python3
"""Mach-O LC_LOAD_DYLIB injection. Runs without macOS."""

from __future__ import annotations

import struct
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from madelf.macho import MachOError, inject_load_dylib, is_madelf_macho, load_dylibs  # noqa: E402

MH_MAGIC_64 = 0xFEEDFACF
LC_SEGMENT_64 = 0x19
LC_MAIN = 0x80000028
CPU_X86_64 = 0x01000007
CPU_ARM64 = 0x0100000C
DYLIB = "/usr/local/lib/mad-elf/libmadelf.dylib"


def _section(segname: bytes, sectname: bytes, addr: int, offset: int, size: int) -> bytes:
    buf = bytearray(80)
    buf[0:16] = sectname.ljust(16, b"\x00")
    buf[16:32] = segname.ljust(16, b"\x00")
    struct.pack_into("<Q", buf, 32, addr)
    struct.pack_into("<Q", buf, 40, size)
    struct.pack_into("<I", buf, 48, offset)
    struct.pack_into("<I", buf, 52, 2)  # align
    return bytes(buf)


def build_macho(cputype: int = CPU_X86_64, section_off: int = 0x400) -> bytes:
    section = _section(b"__TEXT", b"__text", section_off, section_off, 4)
    # segment command (72) + one section (80) + LC_MAIN (24)
    seg_size = 72 + 80
    sizeofcmds = seg_size + 24
    header = bytearray(32)
    struct.pack_into("<IIIIIIII", header, 0, MH_MAGIC_64, cputype, 3, 2, 2, sizeofcmds, 1, 0)
    seg = bytearray(72)
    struct.pack_into("<II", seg, 0, LC_SEGMENT_64, seg_size)
    seg[8:24] = b"__TEXT".ljust(16, b"\x00")
    struct.pack_into("<QQQQ", seg, 24, 0, 0x1000, 0, max(section_off + 4, 0x100))
    struct.pack_into("<II", seg, 56, 7, 5)
    struct.pack_into("<II", seg, 64, 1, 0)
    main = bytearray(24)
    struct.pack_into("<IIQQ", main, 0, LC_MAIN, 24, section_off, 0)
    blob = bytes(header) + bytes(seg) + section + bytes(main)
    if section_off < len(blob):
        raise RuntimeError("section overlaps the header; slack test should set section_off exactly")
    body = blob + b"\x00" * (section_off - len(blob)) + b"\xc3\x00\x00\x00"
    return body


def build_fat(slice_a: bytes, slice_b: bytes) -> bytes:
    # fat_arch align is a power of two; place slices on 8-byte boundaries
    off1 = 8 + 40
    off1 = (off1 + 7) & ~7
    off2 = (off1 + len(slice_a) + 7) & ~7
    total = off2 + len(slice_b)
    buf = bytearray(total)
    struct.pack_into(">II", buf, 0, 0xCAFEBABE, 2)
    struct.pack_into(">IIIII", buf, 8, CPU_X86_64, 3, off1, len(slice_a), 3)
    struct.pack_into(">IIIII", buf, 28, CPU_ARM64, 0, off2, len(slice_b), 3)
    buf[off1 : off1 + len(slice_a)] = slice_a
    buf[off2 : off2 + len(slice_b)] = slice_b
    return bytes(buf)


class MachOInjectTests(unittest.TestCase):
    def test_absolute_path_is_baked_into_a_thin_binary(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "host"
            path.write_bytes(build_macho())
            inject_load_dylib(str(path), DYLIB)
            libs = load_dylibs(str(path))
            self.assertIn(DYLIB, libs)
            self.assertTrue(DYLIB.startswith("/"))
            self.assertTrue(is_madelf_macho(str(path)))
            # idempotent
            inject_load_dylib(str(path), DYLIB)
            self.assertEqual(load_dylibs(str(path)).count(DYLIB), 1)

    def test_fat_binary_both_slices(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "host"
            arm = bytearray(build_macho(CPU_ARM64))
            struct.pack_into("<I", arm, 4, CPU_ARM64)
            path.write_bytes(build_fat(build_macho(CPU_X86_64), bytes(arm)))
            inject_load_dylib(str(path), DYLIB)
            libs = load_dylibs(str(path))
            self.assertEqual(libs.count(DYLIB), 2)
            self.assertTrue(all(p.startswith("/") for p in libs if p.endswith("/libmadelf.dylib")))

    def test_rejects_relative_and_special_paths(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "host"
            path.write_bytes(build_macho())
            for bad in (
                "libmadelf.dylib",
                "rel/libmadelf.dylib",
                "@executable_path/libmadelf.dylib",
                "@loader_path/libmadelf.dylib",
                "@rpath/libmadelf.dylib",
                "/tmp/libother.dylib",
            ):
                with self.assertRaises(MachOError):
                    inject_load_dylib(str(path), bad)
            self.assertEqual(load_dylibs(str(path)), [])

    def test_no_header_slack_fails(self):
        # Place the first section immediately after the load commands.
        # header 32 + segment 152 + LC_MAIN 24 = 208.
        section_off = 208
        blob = build_macho(section_off=section_off)
        self.assertEqual(len(blob), section_off + 4)
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "host"
            path.write_bytes(blob)
            with self.assertRaises(MachOError) as ctx:
                inject_load_dylib(str(path), DYLIB)
            self.assertIn("slack", str(ctx.exception).lower())


if __name__ == "__main__":
    unittest.main(verbosity=2)
