#!/usr/bin/env python3
"""Exercise Wine font discovery and rasterization through the GDI32 API."""
import os
from pathlib import Path
import shutil
import signal
import subprocess
import tempfile
from wine_runtime import install

ROOT = Path(__file__).resolve().parent.parent


def main():
    engine = os.environ.get("ENGINE", "kvm")
    if engine not in ("kvm", "tcg"):
        raise SystemExit("ENGINE must be kvm or tcg")
    host = "retroos-host-kvm" if engine == "kvm" else "retroos-host"
    subprocess.run(["bazelisk", "build", f"//kernel:{host}", "//lib/wine:runtime",
        "//test/windows/ntdll:fonts", "--platforms=@platforms//host"],
        cwd=ROOT, check=True)
    with tempfile.TemporaryDirectory(prefix="retroos-wine-fonts-") as directory:
        root = Path(directory)
        install(root)
        probe_dir=root / "PROBE"
        probe_dir.mkdir()
        shutil.copyfile(ROOT / "bazel-bin/test/windows/ntdll/fonts.exe", probe_dir / "PROBE.EXE")
        process = subprocess.Popen(["python3", str(ROOT / "test/disk_fixture.py"), "--root", directory,
            "--", str(ROOT / f"bazel-bin/kernel/{host}"), "--c-root", "/", "--cmd", "/PROBE/PROBE.EXE"],
            cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, start_new_session=True)
        try:
            stdout, stderr = process.communicate(timeout=60)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            stdout, stderr = process.communicate()
            raise SystemExit("Wine font test timed out\n" + stdout + stderr)
        log = stdout + stderr
        if process.returncode or "FONTS PASS" not in log or any(x in log for x in ("PANIC", "SEGV", "FONTS FAIL", "not implemented")):
            raise SystemExit(log)
        print(f"PASS: Wine font selection, text metrics and FreeType glyph rasterization ({engine})")


if __name__ == "__main__":
    main()
