#!/usr/bin/env python3
"""Exercise the LFN guest ABI in a disposable hosted directory."""
import os
import pathlib
import shutil
import subprocess
import tempfile

ROOT = pathlib.Path(__file__).resolve().parent.parent


def run(*args):
    subprocess.run([str(arg) for arg in args], cwd=ROOT, check=True)


def main():
    engine = os.environ.get("ENGINE", "tcg")
    if engine not in ("tcg", "kvm"):
        raise SystemExit(f"Unknown ENGINE: {engine}")
    target = "retroos-host-kvm" if engine == "kvm" else "retroos-host"
    with tempfile.TemporaryDirectory(prefix="retroos-lfn-") as directory:
        root = pathlib.Path(directory)
        (root / "TESTS").mkdir()
        shutil.copyfile(ROOT / "bazel-bin/test/dos/lfnprobe/LFNPROBE.COM", root / "TESTS/LFNPROBE.COM")
        run("python3", "test/hosted_test.py", "--directory", root,
            "--host-bin", ROOT / "bazel-bin/kernel" / target, "--screenshot", root / "screen.txt",
            "--cmd", "TESTS/LFNPROBE.COM", "--expect-log", "LFN-ALL-OK",
            "--forbid-log", "LFN-FAIL", "--settle", "5", "--timeout", "25")


if __name__ == "__main__":
    main()
