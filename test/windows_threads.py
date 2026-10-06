#!/usr/bin/env python3
"""Check Win32 execute permissions, threads, synchronization, TLS, FPU and DLL initialization."""
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
        "//test/windows/threads:threads", "//test/windows/threads:probe_dll",
        "//lib/windows/kernel32:kernel32_dll",
        "//lib/windows/compat:gdi32_dll", "//lib/windows/compat:advapi32_dll",
        "//lib/windows/user32:user32_dll", "--platforms=@platforms//host",
    ], cwd=ROOT, check=True)
    with tempfile.TemporaryDirectory(prefix="retroos-winthreads-") as directory:
        root = Path(directory)
        system = root / "RETROOS/WINDOWS/SYSTEM32"
        system.mkdir(parents=True)
        for source, destination in [
            ("lib/windows/kernel32/KERNEL32.DLL", system / "KERNEL32.DLL"),
            ("lib/windows/user32/USER32.DLL", system / "USER32.DLL"),
            ("lib/windows/compat/GDI32.DLL", system / "GDI32.DLL"),
            ("lib/windows/compat/ADVAPI32.DLL", system / "ADVAPI32.DLL"),
            ("test/windows/threads/threads.exe", root / "WINTHREAD.EXE"),
            ("test/windows/threads/PROBE.DLL", root / "PROBE.DLL"),
        ]:
            shutil.copyfile(ROOT / "bazel-bin" / source, destination)
        ndn_directory = os.environ.get("NDN_DIR")
        if ndn_directory:
            for name in ("SCRRES.DLL", "DESCSS.DLL", "NDNPASS.DLL", "TETRIS.DLL"):
                data = bytearray((Path(ndn_directory) / "PLUGINS" / name).read_bytes())
                # Virtual Pascal DLL startup expects NDN's shared heap callbacks.
                # This fixture checks imports and exports; NDN exercises DllMain.
                pe = int.from_bytes(data[0x3c:0x40], "little")
                data[pe + 40:pe + 44] = bytes(4)
                (root / name).write_bytes(data)
        try:
            result = subprocess.run([
                str(ROOT / "bazel-bin/kernel" / target), "--host", directory,
                "--c-root", "/", "--cmd", "/WINTHREAD.EXE",
            ], cwd=ROOT, capture_output=True, text=True, timeout=30)
        except subprocess.TimeoutExpired as error:
            raise SystemExit((error.stdout or b"").decode(errors="replace") +
                             (error.stderr or b"").decode(errors="replace") +
                             "\nWin32 thread test timed out")
        log = result.stdout + result.stderr
        if ndn_directory:
            for name in ("SCRRES.DLL", "DESCSS.DLL", "NDNPASS.DLL", "TETRIS.DLL"):
                if f"{name} LOAD PASS" not in log:
                    raise SystemExit(log)
            print("PASS: NDN plugin import resolution")
        if (result.returncode != 0 or "WINTHREAD PASS" not in log or
                any(marker in log for marker in ("SEGV", "PANIC", "Stack Overflow"))):
            raise SystemExit(log)
    print(f"PASS: Win32 protection, threads, events, TLS, FPU and LoadLibrary ({engine})")


if __name__ == "__main__":
    main()
