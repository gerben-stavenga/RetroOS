#!/usr/bin/env python3
"""Exercise RM/PM exception routing without a disk or application assets."""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parent.parent


def main():
    engine = os.environ.get("ENGINE", "tcg")
    if engine not in ("tcg", "kvm"):
        raise SystemExit(f"Unknown ENGINE: {engine}")
    target = "retroos-host-kvm" if engine == "kvm" else "retroos-host"
    subprocess.run([
        "bazelisk", "build", "//test/dos/rmexception:rmexception_com",
        f"//kernel:{target}", "--platforms=@platforms//host",
    ], cwd=ROOT, check=True)
    with tempfile.TemporaryDirectory(prefix="retroos-rmexception-") as directory:
        shutil.copyfile(ROOT / "bazel-bin/test/dos/rmexception/RMEXCEPT.COM",
                        Path(directory) / "RMEXCEPT.COM")
        result = subprocess.run([
            str(ROOT / "bazel-bin/kernel" / target),
            "--host", directory, "--c-root", "/", "--cmd", "/RMEXCEPT.COM",
        ], cwd=ROOT, capture_output=True, text=True, timeout=30)
        log = result.stdout + result.stderr
        if (result.returncode != 0 or "RMEXCEPT PASS" not in log
                or any(marker in log for marker in
                       ("RMEXCEPT FAIL", "SEGV", "KERNEL PANIC", "panicked at"))):
            raise SystemExit(log)
    print(f"PASS: DPMI RM/PM exception handlers ({engine})")


if __name__ == "__main__":
    main()
