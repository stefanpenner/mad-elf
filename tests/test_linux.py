#!/usr/bin/env python3
"""Integration tests against a real dynamic binary and a patched Node."""

from __future__ import annotations

import io
import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import textwrap
import time
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from madelf.cli import detect, install_elf  # noqa: E402
from madelf.elfpatch import ElfError, read_config_text, read_interpreter  # noqa: E402


SHIM = ROOT / "build" / "mad-elf-shim"


def run(cmd, **kw):
    return subprocess.run(cmd, check=False, text=True, capture_output=True, **kw)


class LinuxShimTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not SHIM.is_file():
            raise unittest.SkipTest("build/mad-elf-shim is missing; run make")
        cls.tmp = tempfile.TemporaryDirectory(prefix="madelf-")
        cls.work = Path(cls.tmp.name)
        src = ROOT / "tests" / "fixtures" / "printenv.c"
        cls.printer = cls.work / "printenv"
        gcc = subprocess.run(
            ["gcc", "-O2", "-o", str(cls.printer), str(src)],
            check=False,
            text=True,
            capture_output=True,
        )
        if gcc.returncode != 0:
            raise unittest.SkipTest(gcc.stderr)
        static_src = ROOT / "tests" / "fixtures" / "static_exit.S"
        cls.static = cls.work / "staticbin"
        subprocess.run(
            ["gcc", "-nostdlib", "-static", "-o", str(cls.static), str(static_src)],
            check=True,
        )
        cls.node = shutil.which("node")

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def install(self, src, dst, directives, embed=False, embed_only=False):
        install_elf(str(src), str(dst), str(SHIM), directives, embed=embed, embed_only=embed_only)

    def test_shim_direct_exec_is_not_a_program(self):
        proc = run([str(SHIM)])
        self.assertEqual(proc.returncode, 2, proc.stderr)
        self.assertIn("PT_INTERP", proc.stderr)

    def test_static_binary_is_refused(self):
        with self.assertRaises(ElfError) as ctx:
            self.install(self.static, self.work / "static-out", ["flag=--no-warnings"])
        self.assertIn("PT_INTERP", str(ctx.exception))

    def test_printer_gets_flag_env_and_argv0(self):
        dst = self.work / "printenv-patched"
        self.install(
            self.printer,
            dst,
            [
                "flag=--from-shim",
                "setenv=MADELF_PROFILE=from-shim",
                "mergeenv=NODE_OPTIONS=--zero-fill-buffers",
            ],
        )
        interp = read_interpreter(str(dst))
        self.assertEqual(os.path.realpath(interp), os.path.realpath(str(SHIM)))
        text = read_config_text(str(dst))
        self.assertIsNotNone(text)
        original = read_interpreter(str(self.printer))
        self.assertIn(f"loader={original}", text)

        env = os.environ.copy()
        env.pop("MADELF_SHIM", None)
        env.pop("MADELF_PROFILE", None)
        env.pop("NODE_OPTIONS", None)
        proc = run([str(dst), "user-arg"], env=env)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("SHIM=1\n", proc.stdout)
        self.assertIn("PROFILE=from-shim\n", proc.stdout)
        self.assertIn("NODE_OPTIONS=--zero-fill-buffers\n", proc.stdout)
        self.assertIn("arg=--from-shim\n", proc.stdout)
        self.assertIn("arg=user-arg\n", proc.stdout)
        # flag is inserted once, ahead of the original argument
        self.assertLess(proc.stdout.index("arg=--from-shim"), proc.stdout.index("arg=user-arg"))

        # flag already present: do not duplicate
        proc = run([str(dst), "--from-shim", "user-arg"], env=env)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(proc.stdout.count("arg=--from-shim"), 1)

        # env already set is kept; mergeenv appends a missing token
        env2 = env.copy()
        env2["MADELF_PROFILE"] = "from-parent"
        env2["NODE_OPTIONS"] = "--throw-deprecation"
        proc = run([str(dst)], env=env2)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("PROFILE=from-parent\n", proc.stdout)
        self.assertIn("NODE_OPTIONS=--throw-deprecation --zero-fill-buffers\n", proc.stdout)

        # argv0 is preserved across the ld.so handoff
        proc = run(["bash", "-c", f"exec -a my-name {dst} user-arg"], env=env)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("argv0=my-name\n", proc.stdout)

    def test_embedded_section_and_sidecar_precedence(self):
        if not shutil.which("objcopy"):
            self.skipTest("objcopy is not installed")
        embedded = self.work / "printenv-embedded"
        self.install(
            self.printer,
            embedded,
            ["setenv=MADELF_PROFILE=from-section"],
            embed_only=True,
        )
        self.assertFalse((str(embedded) + ".madelf") and Path(str(embedded) + ".madelf").exists())
        env = os.environ.copy()
        env.pop("MADELF_PROFILE", None)
        env.pop("MADELF_SHIM", None)
        proc = run([str(embedded)], env=env)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("PROFILE=from-section\n", proc.stdout)
        self.assertIn("SHIM=1\n", proc.stdout)

        # sidecar wins over the embedded section
        sidecar = Path(str(embedded) + ".madelf")
        original = read_interpreter(str(self.printer))
        sidecar.write_text(
            f"loader={original}\nsetenv=MADELF_PROFILE=from-sidecar\n",
            encoding="utf-8",
        )
        proc = run([str(embedded)], env=env)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("PROFILE=from-sidecar\n", proc.stdout)

    def test_node_execargv_env_and_detect(self):
        if not self.node:
            self.skipTest("node is not installed")
        dst = self.work / "node-madelf"
        self.install(
            self.node,
            dst,
            [
                "flag=--no-warnings",
                "setenv=MADELF_PROFILE=from-shim",
                "mergeenv=NODE_OPTIONS=--zero-fill-buffers",
            ],
        )
        script_path = self.work / "report.js"
        script_path.write_text(
            textwrap.dedent(
                """\
                const fs = require('fs');
                const out = {
                  shim: process.env.MADELF_SHIM || null,
                  profile: process.env.MADELF_PROFILE || null,
                  nodeOptions: process.env.NODE_OPTIONS || null,
                  execArgv: process.execArgv,
                  argv0: process.argv0,
                };
                fs.writeFileSync(process.env.OUT, JSON.stringify(out));
                """
            ),
            encoding="utf-8",
        )
        env = os.environ.copy()
        for key in ("MADELF_SHIM", "MADELF_PROFILE", "NODE_OPTIONS"):
            env.pop(key, None)
        out = self.work / "node-out.json"
        env["OUT"] = str(out)
        proc = run([str(dst), str(script_path)], env=env)
        self.assertEqual(proc.returncode, 0, proc.stderr + proc.stdout)
        data = json.loads(out.read_text())
        self.assertEqual(data["shim"], "1")
        self.assertEqual(data["profile"], "from-shim")
        self.assertIn("--zero-fill-buffers", data["nodeOptions"])
        self.assertIn("--no-warnings", data["execArgv"])
        self.assertEqual(data["execArgv"].count("--no-warnings"), 1)

        # already present on the command line
        proc = run([str(dst), "--no-warnings", str(script_path)], env=env)
        self.assertEqual(proc.returncode, 0, proc.stderr + proc.stdout)
        data = json.loads(out.read_text())
        self.assertEqual(data["execArgv"].count("--no-warnings"), 1)

        # preset env is kept; NODE_OPTIONS tokens are merged
        env2 = env.copy()
        env2["MADELF_PROFILE"] = "from-parent"
        env2["NODE_OPTIONS"] = "--throw-deprecation"
        proc = run([str(dst), str(script_path)], env=env2)
        self.assertEqual(proc.returncode, 0, proc.stderr + proc.stdout)
        data = json.loads(out.read_text())
        self.assertEqual(data["profile"], "from-parent")
        self.assertIn("--throw-deprecation", data["nodeOptions"])
        self.assertIn("--zero-fill-buffers", data["nodeOptions"])

        # argv0 survives the handoff to ld.so
        proc = run(["bash", "-c", f"exec -a my-node {dst} {script_path}"], env=env)
        self.assertEqual(proc.returncode, 0, proc.stderr + proc.stdout)
        data = json.loads(out.read_text())
        self.assertEqual(data["argv0"], "my-node")

        # live process: flag is on the kernel cmdline, detect accepts it,
        # and an unpatched child that merely inherited MADELF_SHIM does not match.
        child_script = textwrap.dedent(
            f"""\
            const {{spawn}} = require('child_process');
            const fs = require('fs');
            const c = spawn('/bin/sleep', ['60'], {{stdio: 'ignore'}});
            fs.writeFileSync({json.dumps(str(self.work / 'child.pid'))}, String(c.pid));
            setInterval(() => {{}}, 1000);
            """
        )
        proc = subprocess.Popen(
            [str(dst), "-e", child_script],
            env=env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        try:
            child_pid_path = self.work / "child.pid"
            for _ in range(50):
                if child_pid_path.exists() and proc.poll() is None:
                    break
                time.sleep(0.1)
            self.assertIsNone(proc.poll(), "patched node exited before detect")
            cmdline = Path(f"/proc/{proc.pid}/cmdline").read_bytes().split(b"\x00")
            self.assertIn(b"--no-warnings", cmdline)
            out = io.StringIO()
            err = io.StringIO()
            with redirect_stdout(out), redirect_stderr(err):
                self.assertEqual(detect(proc.pid), 0)
            self.assertIn("mad-elf: yes", out.getvalue())
            child = int(child_pid_path.read_text().strip())
            out = io.StringIO()
            err = io.StringIO()
            with redirect_stdout(out), redirect_stderr(err):
                self.assertEqual(detect(child), 1)
            self.assertIn("inherited", err.getvalue())
            inherited = Path(f"/proc/{child}/environ").read_bytes().split(b"\x00")
            self.assertIn(b"MADELF_SHIM=1", inherited)
        finally:
            proc.send_signal(signal.SIGTERM)
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()

        plain = subprocess.Popen(
            [self.node, "-e", "setInterval(() => {}, 1000)"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        try:
            time.sleep(0.3)
            err = io.StringIO()
            with redirect_stderr(err):
                self.assertEqual(detect(plain.pid), 1)
            self.assertIn("mad-elf: no", err.getvalue())
        finally:
            plain.send_signal(signal.SIGTERM)
            try:
                plain.wait(timeout=5)
            except subprocess.TimeoutExpired:
                plain.kill()

        slept = subprocess.Popen(
            ["/bin/sleep", "60"],
            env={**env, "MADELF_SHIM": "1"},
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        try:
            err = io.StringIO()
            with redirect_stderr(err):
                self.assertEqual(detect(slept.pid), 1)
            self.assertIn("inherited", err.getvalue())
        finally:
            slept.send_signal(signal.SIGTERM)
            slept.wait(timeout=5)


if __name__ == "__main__":
    unittest.main(verbosity=2)
