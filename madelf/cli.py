"""mad-elf install / detect / inspect."""

from __future__ import annotations

import argparse
import os
import shutil
import stat
import subprocess
import sys

from madelf.elfpatch import (
    ElfError,
    embed_config_section,
    first_loader,
    read_config_text,
    read_interpreter,
    set_interpreter,
)
from madelf.macho import MachOError, inject_load_dylib, is_madelf_macho, load_dylibs


def repo_shim() -> str:
    env = os.environ.get("MADELF_SHIM")
    if env:
        return os.path.abspath(env)
    here = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "build", "mad-elf-shim"))
    return here


def render_config(loader: str | None, directives: list[str]) -> str:
    lines = []
    if loader:
        lines.append(f"loader={loader}")
    lines.extend(directives)
    lines.append("")
    return "\n".join(lines)


def _file_kind(path: str) -> str:
    with open(path, "rb") as f:
        magic = f.read(4)
    if magic == b"\x7fELF":
        return "elf"
    if magic == b"\xcf\xfa\xed\xfe":
        return "macho"
    if magic == b"\xca\xfe\xba\xbe":
        return "macho"
    return "other"


def install_elf(src: str, dst: str, shim: str, directives: list[str], embed: bool, embed_only: bool) -> None:
    loader = read_interpreter(src)
    if loader is None:
        raise ElfError(
            f"{src} has no PT_INTERP. Static binaries do not use an interpreter, "
            "so mad-elf cannot run ahead of them."
        )
    shim = os.path.abspath(shim)
    if not os.path.isfile(shim):
        raise ElfError(f"shim not found: {shim}")
    if os.path.exists(dst) and os.path.samefile(src, dst):
        raise ElfError("refusing to patch a binary in place; install onto a copy")
    os.makedirs(os.path.dirname(os.path.abspath(dst)) or ".", exist_ok=True)
    shutil.copy2(src, dst)
    mode = os.stat(dst).st_mode
    os.chmod(dst, mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    text = render_config(loader, directives)
    if embed or embed_only:
        embed_config_section(dst, text)
    sidecar = dst + ".madelf"
    if embed_only:
        if os.path.exists(sidecar):
            os.remove(sidecar)
    else:
        with open(sidecar, "w", encoding="utf-8") as f:
            f.write(text)
    set_interpreter(dst, shim)


def _codesign(path: str) -> None:
    if sys.platform != "darwin" or not shutil.which("codesign"):
        return
    subprocess.run(["codesign", "--remove-signature", path], check=False, capture_output=True)
    subprocess.run(["codesign", "-f", "-s", "-", path], check=True)


def install_macho(src: str, dst: str, dylib: str, directives: list[str]) -> None:
    dylib = os.path.abspath(dylib)
    if os.path.exists(dst) and os.path.samefile(src, dst):
        raise MachOError("refusing to patch a binary in place; install onto a copy")
    os.makedirs(os.path.dirname(os.path.abspath(dst)) or ".", exist_ok=True)
    shutil.copy2(src, dst)
    mode = os.stat(dst).st_mode
    os.chmod(dst, mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    inject_load_dylib(dst, dylib)
    text = render_config(None, directives)
    with open(dst + ".madelf", "w", encoding="utf-8") as f:
        f.write(text)
    if os.path.isfile(dylib):
        _codesign(dylib)
    _codesign(dst)


def is_madelf_elf(path: str) -> bool:
    try:
        interp = read_interpreter(path)
    except (OSError, ElfError):
        return False
    if not interp:
        return False
    if os.path.basename(interp) == "mad-elf-shim":
        return True
    text = read_config_text(path)
    if not text:
        return False
    loader = first_loader(text)
    if loader and interp != loader:
        return True
    return False


def executable_for_pid(pid: int) -> str:
    if sys.platform == "linux":
        return os.path.realpath(f"/proc/{pid}/exe")
    if sys.platform == "darwin":
        import ctypes

        lib = ctypes.CDLL("/usr/lib/libproc.dylib")
        buf = ctypes.create_string_buffer(4096)
        n = lib.proc_pidpath(pid, buf, 4096)
        if n <= 0:
            raise OSError(f"proc_pidpath failed for {pid}")
        return buf.value.decode("utf-8", "surrogateescape")
    raise OSError(f"detect is not implemented on {sys.platform}")


def marker_in_environ(pid: int) -> bool:
    if sys.platform == "linux":
        try:
            with open(f"/proc/{pid}/environ", "rb") as f:
                data = f.read()
        except OSError:
            return False
        return b"MADELF_SHIM=1" in data.split(b"\x00")
    if sys.platform == "darwin":
        try:
            out = subprocess.check_output(
                ["ps", "eww", "-p", str(pid), "-o", "command="],
                text=True,
                stderr=subprocess.DEVNULL,
            )
        except (OSError, subprocess.CalledProcessError):
            return False
        return "MADELF_SHIM=1" in out
    return False


def _linux_handoff_target(pid: int) -> str | None:
    """Binary the shim asked ld.so to run, if this process is that handoff.

    After the shim execs the real loader, /proc/<pid>/exe is ld.so and the
    kernel cmdline is: loader --argv0 <argv0> <binary> <args...>.
    """
    try:
        with open(f"/proc/{pid}/cmdline", "rb") as f:
            raw = f.read().split(b"\x00")
    except OSError:
        return None
    args = [part.decode("utf-8", "surrogateescape") for part in raw if part]
    if len(args) < 4 or args[1] != "--argv0":
        return None
    candidate = args[3]
    if not candidate.startswith("/") or not os.path.isfile(candidate):
        return None
    if is_madelf_elf(candidate):
        return candidate
    return None


def detect(pid: int) -> int:
    try:
        exe = executable_for_pid(pid)
    except OSError as exc:
        print(f"mad-elf: cannot inspect pid {pid}: {exc}", file=sys.stderr)
        return 2
    kind = _file_kind(exe) if os.path.exists(exe) else "other"
    patched = None
    if kind == "elf" and is_madelf_elf(exe):
        patched = exe
    elif kind == "macho" and is_madelf_macho(exe):
        patched = exe
    elif sys.platform == "linux":
        patched = _linux_handoff_target(pid)
    marker = marker_in_environ(pid)
    if patched and marker:
        print(f"mad-elf: yes  pid {pid} is running patched binary {patched}")
        print("mad-elf: MADELF_SHIM=1 is set in the process environment")
        return 0
    if patched:
        print(
            f"mad-elf: yes  pid {pid} executable {patched} is a mad-elf binary; "
            "MADELF_SHIM is not currently in its environment",
        )
        return 0
    if marker:
        print(
            f"mad-elf: no   pid {pid} has MADELF_SHIM set, but {exe} is not a mad-elf binary "
            "(the variable was inherited)",
            file=sys.stderr,
        )
        return 1
    print(f"mad-elf: no   pid {pid} ({exe}) was not launched through mad-elf", file=sys.stderr)
    return 1


def inspect(path: str) -> int:
    kind = _file_kind(path)
    print(f"file: {path}")
    print(f"kind: {kind}")
    if kind == "elf":
        try:
            interp = read_interpreter(path)
        except ElfError as exc:
            print(f"elf: {exc}")
            return 1
        print(f"interpreter: {interp or '(none — static)'}")
        text = read_config_text(path)
        print(f"config: {path + '.madelf' if os.path.isfile(path + '.madelf') else '(no sidecar)'}")
        if text:
            loader = first_loader(text)
            print(f"recorded-loader: {loader or '(none)'}")
            print("--- config ---")
            print(text, end="" if text.endswith("\n") else "\n")
        print(f"mad-elf: {'yes' if is_madelf_elf(path) else 'no'}")
        return 0
    if kind == "macho":
        try:
            libs = load_dylibs(path)
        except MachOError as exc:
            print(f"macho: {exc}")
            return 1
        print("load-dylibs:")
        for lib in libs:
            mark = ""
            if lib.startswith("/") and lib.endswith("/libmadelf.dylib"):
                mark = "  [mad-elf]"
            print(f"  {lib}{mark}")
        text = read_config_text(path) if os.path.isfile(path + ".madelf") else None
        if text:
            print("--- config ---")
            print(text, end="" if text.endswith("\n") else "\n")
        print(f"mad-elf: {'yes' if is_madelf_macho(path) else 'no'}")
        return 0
    print("not an ELF or Mach-O file")
    return 1


def _directives(args: argparse.Namespace) -> list[str]:
    lines: list[str] = []
    for flag in args.flag or []:
        if not flag:
            raise SystemExit("empty --flag")
        lines.append(f"flag={flag}")
    for item in args.setenv or []:
        if "=" not in item:
            raise SystemExit(f"--setenv needs KEY=VALUE, got {item!r}")
        lines.append(f"setenv={item}")
    for item in args.forceenv or []:
        if "=" not in item:
            raise SystemExit(f"--forceenv needs KEY=VALUE, got {item!r}")
        lines.append(f"forceenv={item}")
    for item in args.mergeenv or []:
        if "=" not in item:
            raise SystemExit(f"--mergeenv needs KEY=VALUE, got {item!r}")
        lines.append(f"mergeenv={item}")
    if args.marker_file:
        lines.append(f"markerfile={args.marker_file}")
    if args.config:
        with open(args.config, "r", encoding="utf-8") as f:
            for line in f:
                s = line.strip()
                if not s or s.startswith("#"):
                    continue
                if s.startswith("loader="):
                    continue
                lines.append(s)
    return lines


def cmd_install(args: argparse.Namespace) -> int:
    src = os.path.abspath(args.src)
    dst = os.path.abspath(args.dst)
    if not os.path.isfile(src):
        print(f"mad-elf: not a file: {src}", file=sys.stderr)
        return 1
    directives = _directives(args)
    kind = _file_kind(src)
    try:
        if kind == "elf":
            shim = args.shim or repo_shim()
            install_elf(src, dst, shim, directives, embed=args.embed, embed_only=args.embed_only)
            print(f"installed {dst}")
            print(f"interpreter -> {os.path.abspath(shim)}")
            if not args.embed_only:
                print(f"config {dst}.madelf")
            return 0
        if kind == "macho":
            if not args.dylib:
                print("mad-elf: Mach-O install needs --dylib /absolute/path/libmadelf.dylib", file=sys.stderr)
                return 1
            install_macho(src, dst, args.dylib, directives)
            print(f"installed {dst}")
            print(f"LC_LOAD_DYLIB -> {os.path.abspath(args.dylib)}")
            print(f"config {dst}.madelf")
            return 0
    except (ElfError, MachOError, OSError) as exc:
        print(f"mad-elf: {exc}", file=sys.stderr)
        return 1
    print(f"mad-elf: {src} is not an ELF or Mach-O executable", file=sys.stderr)
    return 1


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="mad-elf", description="Launch a binary with enforced flags and environment.")
    sub = p.add_subparsers(dest="cmd", required=True)

    inst = sub.add_parser("install", help="copy a binary and attach the shim")
    inst.add_argument("src")
    inst.add_argument("dst")
    inst.add_argument("--shim", help="absolute path to the Linux mad-elf-shim (default: ./build/mad-elf-shim)")
    inst.add_argument("--dylib", help="absolute path ending in /libmadelf.dylib (macOS)")
    inst.add_argument("--flag", action="append", help="argv flag to insert if missing (repeatable)")
    inst.add_argument("--setenv", action="append", metavar="KEY=VALUE", help="set if the variable is absent")
    inst.add_argument("--forceenv", action="append", metavar="KEY=VALUE", help="set even if the variable is present")
    inst.add_argument("--mergeenv", action="append", metavar="KEY=VALUE", help="append missing whitespace-separated tokens")
    inst.add_argument("--marker-file", help="constructor/shim proof file (macOS ctor writes ctor\\n)")
    inst.add_argument("--config", help="extra config lines (loader= is ignored; install records the real loader)")
    inst.add_argument("--embed", action="store_true", help="also embed the config in a .madelf ELF section")
    inst.add_argument("--embed-only", action="store_true", help="embed the config and do not write a sidecar file")
    inst.set_defaults(func=cmd_install)

    det = sub.add_parser("detect", help="report whether a pid is running a mad-elf binary")
    det.add_argument("pid", type=int)
    det.set_defaults(func=lambda a: detect(a.pid))

    ins = sub.add_parser("inspect", help="show interpreter / load commands / config")
    ins.add_argument("path")
    ins.set_defaults(func=lambda a: inspect(a.path))
    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
