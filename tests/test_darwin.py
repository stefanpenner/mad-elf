#!/usr/bin/env python3
"""macOS LC_LOAD_DYLIB runtime test. Skips cleanly off Darwin.

Proves the constructor runs before main with a clean environment: no
DYLD_INSERT_LIBRARIES, absolute dylib path only.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import textwrap
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from madelf.cli import install_macho  # noqa: E402
from madelf.macho import load_dylibs  # noqa: E402


def skip(msg: str) -> int:
    print(f"SKIP: {msg}")
    return 0


def run(cmd, **kw):
    return subprocess.run(cmd, check=False, text=True, capture_output=True, **kw)


def main() -> int:
    if sys.platform != "darwin":
        return skip("LC_LOAD_DYLIB runtime test requires macOS")
    if not shutil.which("clang"):
        return skip("clang is not installed")

    with tempfile.TemporaryDirectory(prefix="madelf-darwin-") as tmp:
        work = Path(tmp)
        dylib = work / "lib" / "libmadelf.dylib"
        dylib.parent.mkdir()
        host_src = ROOT / "tests" / "fixtures" / "darwin_host.c"
        host = work / "host"
        built = run(
            [
                "clang",
                "-dynamiclib",
                "-o",
                str(dylib),
                str(ROOT / "src" / "shim_darwin.c"),
                str(ROOT / "src" / "logic.c"),
                "-Wl,-install_name," + str(dylib),
            ]
        )
        if built.returncode != 0:
            print(built.stderr)
            return 1
        built = run(["clang", "-Wl,-headerpad,0x400", "-o", str(host), str(host_src)])
        if built.returncode != 0:
            print(built.stderr)
            return 1

        marker = work / "order.txt"
        install_macho(
            str(host),
            str(work / "host-patched"),
            str(dylib),
            [
                "flag=--madelf-flag",
                "setenv=MADELF_PROFILE=from-shim",
                "markerfile=" + str(marker),
            ],
        )
        patched = work / "host-patched"
        libs = load_dylibs(str(patched))
        if str(dylib) not in libs:
            print(f"FAIL: absolute dylib path not in load commands: {libs}")
            return 1
        if any(p.startswith("@") for p in libs):
            print(f"FAIL: special dyld path leaked into load commands: {libs}")
            return 1

        # Clean environment. The caller sets nothing, including DYLD_INSERT_LIBRARIES.
        proc = subprocess.run(
            ["env", "-i", str(patched), "user-arg"],
            check=False,
            text=True,
            capture_output=True,
            timeout=20,
        )
        if proc.returncode != 0:
            print(proc.stdout)
            print(proc.stderr)
            print(f"FAIL: patched host exited {proc.returncode}")
            return 1
        out = proc.stdout
        if "SHIM=1\n" not in out:
            print(out)
            print("FAIL: MADELF_SHIM was not visible to main")
            return 1
        if "PROFILE=from-shim\n" not in out:
            print(out)
            print("FAIL: configured environment did not reach main")
            return 1
        if "DYLD=\n" not in out:
            print(out)
            print("FAIL: DYLD_INSERT_LIBRARIES was set; the supported path does not use it")
            return 1
        if "arg=--madelf-flag\n" not in out or "arg=user-arg\n" not in out:
            print(out)
            print("FAIL: configured argv flag was not inserted")
            return 1
        if out.index("arg=--madelf-flag") > out.index("arg=user-arg"):
            print(out)
            print("FAIL: flag was not inserted before the original argument")
            return 1
        order = marker.read_text() if marker.exists() else ""
        if order != "ctor\nmain\n":
            print(repr(order))
            print("FAIL: constructor did not run exactly once before main")
            return 1

        # Flag already on argv: still one constructor, no duplicate flag, no loop.
        marker.unlink()
        proc = subprocess.run(
            ["env", "-i", str(patched), "--madelf-flag", "user-arg"],
            check=False,
            text=True,
            capture_output=True,
            timeout=20,
        )
        if proc.returncode != 0:
            print(proc.stderr)
            return 1
        if proc.stdout.count("arg=--madelf-flag") != 1:
            print(proc.stdout)
            print("FAIL: flag duplicated")
            return 1
        if marker.read_text() != "ctor\nmain\n":
            print(repr(marker.read_text()))
            print("FAIL: unexpected constructor ordering when the flag was already present")
            return 1

        # Preset environment is not overwritten.
        marker.unlink()
        proc = subprocess.run(
            ["env", "-i", "MADELF_PROFILE=from-parent", str(patched), "user-arg"],
            check=False,
            text=True,
            capture_output=True,
            timeout=20,
        )
        if "PROFILE=from-parent\n" not in proc.stdout:
            print(proc.stdout)
            print(proc.stderr)
            print("FAIL: existing environment was overwritten")
            return 1

        node = shutil.which("node")
        if not node:
            print("SKIP: node is not installed; host LC_LOAD_DYLIB test passed")
            print("PASS: darwin LC_LOAD_DYLIB")
            return 0
        node_dst = work / "node-madelf"
        node_marker = work / "node-order.txt"
        try:
            install_macho(
                node,
                str(node_dst),
                str(dylib),
                ["flag=--no-warnings", "markerfile=" + str(node_marker)],
            )
        except Exception as exc:  # noqa: BLE001 — slack/SIP failures skip the node portion
            print(f"SKIP: could not patch node ({exc}); host LC_LOAD_DYLIB test passed")
            print("PASS: darwin LC_LOAD_DYLIB")
            return 0
        script = textwrap.dedent(
            """\
            const fs = require('fs');
            const marker = process.env.MADELF_MARKER_FILE;
            if (marker) fs.appendFileSync(marker, 'js\\n');
            const out = {
              shim: process.env.MADELF_SHIM || null,
              execArgv: process.execArgv,
              dyld: process.env.DYLD_INSERT_LIBRARIES || null,
            };
            fs.writeFileSync(process.argv[1], JSON.stringify(out));
            """
        )
        result_path = work / "node.json"
        proc = subprocess.run(
            ["env", "-i", "HOME=" + str(work), "TMPDIR=" + str(work), str(node_dst), "-e", script, str(result_path)],
            check=False,
            text=True,
            capture_output=True,
            timeout=30,
        )
        if proc.returncode != 0 or not result_path.exists():
            print(proc.stdout)
            print(proc.stderr)
            print("FAIL: patched node did not run under a clean environment")
            return 1
        data = json.loads(result_path.read_text())
        if data["shim"] != "1" or data["dyld"] is not None:
            print(data)
            print("FAIL: node did not observe the shim under a clean environment")
            return 1
        if "--no-warnings" not in data["execArgv"]:
            print(data)
            print("FAIL: node process.execArgv is missing the injected flag")
            return 1
        if node_marker.read_text() != "ctor\njs\n":
            print(repr(node_marker.read_text()))
            print("FAIL: dylib constructor did not run before Node started JS")
            return 1
        print("PASS: darwin LC_LOAD_DYLIB (host and node)")
        return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except subprocess.TimeoutExpired:
        print("FAIL: process timed out (possible re-exec loop)")
        raise SystemExit(1)
