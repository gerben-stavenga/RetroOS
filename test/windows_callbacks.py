#!/usr/bin/env python3
"""Exercise guest-stack USER32 callbacks, including nesting and thread switches."""
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
        "bazelisk", "build", f"//kernel:{target}",
        "//test/windows/callbacks:callbacks", "//test/windows/callbacks:dynamic", "//test/windows/callbacks:lifecycle", "//test/windows/callbacks:messages",
        "//lib/windows/kernel32:kernel32_dll",
        "//lib/windows/user32:user32_dll", "--platforms=@platforms//host",
    ], cwd=ROOT, check=True)
    with tempfile.TemporaryDirectory(prefix="retroos-wincallbacks-") as directory:
        root = Path(directory)
        system = root / "RETROOS/WINDOWS/SYSTEM32"
        system.mkdir(parents=True)
        for name in ("kernel32", "user32"):
            shutil.copyfile(ROOT / f"bazel-bin/lib/windows/{name}/{name.upper()}.DLL", system / f"{name.upper()}.DLL")
        for program in ("callbacks", "dynamic", "lifecycle", "messages"):
            shutil.copyfile(ROOT / f"bazel-bin/test/windows/callbacks/{program}.exe", root / "CALLBACK.EXE")
            try:
                result = subprocess.run([
                    "python3", str(ROOT / "test/disk_fixture.py"), "--root", directory, "--",
                    str(ROOT / "bazel-bin/kernel" / target), "--c-root", "/", "--cmd", "/CALLBACK.EXE",
                ], cwd=ROOT, capture_output=True, text=True, timeout=30)
            except subprocess.TimeoutExpired as error:
                raise SystemExit(f"USER32 callback test timed out: {error.stdout!r} {error.stderr!r}")
            log = result.stdout + result.stderr
            if result.returncode or "WINCALLBACK PASS" not in log or any(
                marker in log for marker in ("PANIC", "SEGV", "WINCALLBACK FAIL")
            ):
                raise SystemExit(log)
        print(f"PASS: USER32 lifecycle, callbacks, thread queues, nested cross-thread sends and timers ({engine})")


if __name__ == "__main__":
    main()
