#!/usr/bin/env python3
"""Verify that GetDC drawing reaches scanout without any keyboard/mouse input."""
import os
from pathlib import Path
from wine_runtime import install as install_windows_runtime
import shutil
import subprocess
import tempfile

from rustdos_suite import Machine
from windows_callbacks import ROOT


def main():
    engine = os.environ.get("ENGINE", "kvm")
    if engine not in ("kvm", "tcg"):
        raise SystemExit(f"Unknown engine: {engine}")
    target = "retroos-host-kvm" if engine == "kvm" else "retroos-host"
    subprocess.run([
        "bazelisk", "build", f"//kernel:{target}",
        "//test/windows/callbacks:repaint",
        "//lib/wine:runtime", "--platforms=@platforms//host",
    ], cwd=ROOT, check=True)
    with tempfile.TemporaryDirectory(prefix="retroos-repaint-") as directory:
        work = Path(directory)
        root = work / "drive"
        system = root / "RETROOS/WINDOWS/SYSTEM32"
        system.mkdir(parents=True)
        install_windows_runtime(root)
        shutil.copyfile(ROOT / "bazel-bin/test/windows/callbacks/repaint.exe", root / "REPAINT.EXE")
        machine = Machine([
            "python3", str(ROOT / "test/disk_fixture.py"), "--root", str(root), "--",
            str(ROOT / "bazel-bin/kernel" / target), "--input-control",
            "--screenshot", str(work / "screen.txt"), "--c-root", "/", "--cmd", "/REPAINT.EXE",
        ], work, 45)
        try:
            for _ in range(80 if engine == "tcg" else 20):
                machine.run(250)
                if "WINREPAINT READY" in machine.log_path.read_text():
                    break
            else:
                raise AssertionError(machine.log_path.read_text())
            machine.run(250)
            machine.snapshot()
            magic, dimensions, maximum, pixels = (work / "screen.txt.ppm").read_bytes().split(b"\n", 3)
            assert magic == b"P6" and maximum == b"255"
            width, height = map(int, dimensions.split())
            assert (width, height) == (160, 80), (width, height)
            def pixel(x, y):
                at = (y * width + x) * 3
                return pixels[at:at + 3]
            assert pixel(70, 40) == b"\0\0\xff", "FillRect damage was not presented"
            assert pixel(100, 40) == b"\0\xff\0", "SetPixel damage was not presented"
            assert any(pixel(x, y) == b"\xff\xff\xff" for y in range(10, 26) for x in range(10, 50)), "TextOut damage was not presented"
        finally:
            machine.close()
    print(f"PASS: GetDC fill/text/pixel drawing is presented with no input ({engine})")


if __name__ == "__main__":
    main()
