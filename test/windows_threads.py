#!/usr/bin/env python3
"""Check Win32 protection, threads, DLL initialization, MC CRT directories and cross-personality launches."""
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
    # Save the native shell before switching Bazel to the host platform.
    subprocess.run(["bazelisk", "build", "//tools/command:command_com"], cwd=ROOT, check=True)
    command_image = (ROOT / "bazel-bin/tools/command/COMMAND.COM").read_bytes()
    subprocess.run([
        "bazelisk", "build", f"//kernel:{target}",
        "//test/windows/threads:threads", "//test/windows/threads:probe_dll",
        "//test/windows/threads:spawn_child", "//test/os2/hello:hello_lx",
        "//lib/os2/doscalls:doscalls_dll",
        "//lib/wine:runtime",
        "--platforms=@platforms//host",
    ], cwd=ROOT, check=True)
    with tempfile.TemporaryDirectory(prefix="retroos-winthreads-") as directory:
        root = Path(directory)
        install_windows_runtime(root)
        system = root / "RETROOS/WINDOWS/SYSTEM32"
        system.mkdir(parents=True, exist_ok=True)
        (root / "APPS").mkdir()
        (root / "WORK").mkdir()
        os2_system = root / "RETROOS/OS2/DLL"
        os2_system.mkdir(parents=True, exist_ok=True)
        (root / "RETROOS/COMMAND.COM").write_bytes(command_image)
        for source, destination in [
            ("test/windows/threads/threads.exe", root / "WINTHREAD.EXE"),
            ("test/windows/threads/PROBE.DLL", root / "PROBE.DLL"),
            ("test/windows/threads/spawn_child.exe", root / "APPS/WINCHILD.EXE"),
            ("test/windows/threads/PROBE.DLL", root / "APPS/LOCAL.DLL"),
            ("test/os2/hello/hello_lx.exe", root / "APPS/OS2CHILD.EXE"),
            ("lib/os2/doscalls/DOSCALLS.DLL", os2_system / "DOSCALLS.DLL"),
        ]:
            shutil.copyfile(ROOT / "bazel-bin" / source, destination)
        # Exercise the actual CRT shipped with Win32 MC, including _chdir.
        shutil.copyfile(ROOT / "showcase-bundle/COMMANDER/MC/MSVCRT.DLL", root / "MSVCRT.DLL")
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
            result = subprocess.run(['python3', str(Path(__file__).resolve().parent / 'disk_fixture.py'), '--root', directory, '--', str(ROOT / "bazel-bin/kernel" / target), "--c-root", "/", "--cmd", "/WINTHREAD.EXE"], cwd=ROOT, capture_output=True, text=True, timeout=30)
        except subprocess.TimeoutExpired as error:
            raise SystemExit((error.stdout or b"").decode(errors="replace") +
                             (error.stderr or b"").decode(errors="replace") +
                             "\nWin32 thread test timed out")
        log = result.stdout + result.stderr
        if (root / "APPS/éЖ😀.txt").read_bytes() != bytes([0, 255, 130, 195, 40]):
            raise SystemExit("Win32 UTF-16 path or raw file contents did not cross the UTF-8 VFS boundary")
        if not (root / "APPS/café/x.txt").is_file():
            raise SystemExit("Win32 ANSI/OEM path did not reach the UTF-8 VFS")
        if ndn_directory:
            for name in ("SCRRES.DLL", "DESCSS.DLL", "NDNPASS.DLL", "TETRIS.DLL"):
                if f"{name} LOAD PASS" not in log:
                    raise SystemExit(log)
            print("PASS: NDN plugin import resolution")
        if (result.returncode != 0 or "WINTHREAD PASS" not in log or
                log.count("WINCHILD PASS") != 2 or
                log.count("Hello from Open Watcom C") != 2 or
                any(marker in log for marker in ("SEGV", "PANIC", "Stack Overflow"))):
            raise SystemExit(log)
    print(f"PASS: Win32 protection, threads, events, TLS, FPU, LoadLibrary, MC CRT chdir and Win32/OS2 child launches ({engine})")


if __name__ == "__main__":
    main()
