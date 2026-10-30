#!/usr/bin/env python3
"""Exercise guest-stack USER32 callbacks, including nesting and thread switches."""
import os
from pathlib import Path
from wine_runtime import install as install_windows_runtime
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
        "//test/windows/callbacks:callbacks", "//test/windows/callbacks:dynamic", "//test/windows/callbacks:lifecycle", "//test/windows/callbacks:messages", "//test/windows/callbacks:events", "//test/windows/callbacks:regions", "//test/windows/callbacks:bitmap_profile", "//test/windows/callbacks:frame", "//test/windows/callbacks:popup", "//test/windows/callbacks:multimedia", "//test/windows/callbacks:mmio", "//test/windows/callbacks:text", "//lib/wine:runtime",
        "--platforms=@platforms//host",
    ], cwd=ROOT, check=True)
    with tempfile.TemporaryDirectory(prefix="retroos-wincallbacks-") as directory:
        root = Path(directory)
        system = root / "RETROOS/WINDOWS/SYSTEM32"
        system.mkdir(parents=True)
        install_windows_runtime(root)
        for program in ("callbacks", "dynamic", "lifecycle", "messages", "events", "regions", "bitmap_profile", "frame", "popup", "multimedia", "mmio", "text"):
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
        print(f"PASS: USER32 lifecycle, callbacks, thread queues, nested cross-thread sends, timers, event waits, GDI regions/bitmaps, window frames/menus, multimedia timers, MMIO and INI profiles ({engine})")


if __name__ == "__main__":
    main()
