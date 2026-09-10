#!/usr/bin/env python3
"""Exercise the LFN guest ABI on a disposable writable ext4 disk."""
import pathlib
import stat
import subprocess
import tempfile

ROOT = pathlib.Path(__file__).resolve().parent.parent


def run(*args):
    subprocess.run([str(arg) for arg in args], cwd=ROOT, check=True)


def main():
    run("bazelisk", "build", "//:image")
    run("bazelisk", "build", "--platforms=@platforms//host", "//kernel:retroos-host")
    with tempfile.TemporaryDirectory(prefix="retroos-lfn-") as directory:
        image = pathlib.Path(directory) / "disk.img"
        # Bazel artifacts are read-only. Never ask a mutation test to open
        # them directly (the hosted ATA device can fall back to read-only).
        run("cp", "--reflink=auto", "--sparse=always", ROOT / "bazel-bin/image.bin", image)
        image.chmod(image.stat().st_mode | stat.S_IWUSR)
        run("python3", "test/hosted_test.py", "--image", image,
            "--cmd", "TESTS/LFNPROBE.COM", "--expect-log", "LFN-ALL-OK",
            "--forbid-log", "LFN-FAIL", "--settle", "5", "--timeout", "25")


if __name__ == "__main__":
    main()
