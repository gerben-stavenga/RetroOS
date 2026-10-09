#!/usr/bin/env python3
"""Exercise OS/2 DLL initialization, shared memory, files, 16-bit console calls, process launches, Unicode conversion and PM fallbacks."""
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
    modules = ("doscalls", "kbdcalls", "viocalls", "nls", "uconv", "moucalls", "msg", "pmwin", "pmshapi", "pmwp")
    # COMMAND.COM depends on the native boot image, which needs the default
    # target platform. Save it before changing Bazel's output configuration.
    subprocess.run(["bazelisk", "build", "//tools/command:command_com"], cwd=ROOT, check=True)
    command_image = (ROOT / "bazel-bin/tools/command/COMMAND.COM").read_bytes()
    subprocess.run([
        "bazelisk", "build", f"//kernel:{target}",
        "//test/os2/runtime:runtime", "//test/os2/runtime:probe_dll",
        "//test/os2/runtime:exec_child", "//test/os2/runtime:uconv",
        "//test/os2/hello:hello_lx", "//test/os2/watcom_io:watcom_io",
        *(f"//lib/os2/{name}:{name}_dll" for name in modules),
        "--platforms=@platforms//host",
    ], cwd=ROOT, check=True)
    with tempfile.TemporaryDirectory(prefix="retroos-os2-runtime-") as directory:
        host_root = Path(directory)
        for prefix in ("", "home/retroos/"):
            root = host_root / prefix
            system = root / "RETROOS/OS2/DLL"
            apps = root / "OS2/APPS"
            system.mkdir(parents=True)
            apps.mkdir(parents=True)
            (apps / "EXEC.COM").write_bytes(bytes([0xb8, 37, 0x4c, 0xcd, 0x21]))
            (root / "RETROOS/COMMAND.COM").write_bytes(command_image)
            for name in modules:
                shutil.copyfile(ROOT / f"bazel-bin/lib/os2/{name}/{name.upper()}.DLL", system / f"{name.upper()}.DLL")
            for source, name in (
                ("runtime/runtime.exe", "RUNTIME.EXE"),
                ("runtime/uconv.exe", "UCONV.EXE"),
                ("runtime/PROBE.DLL", "PROBE.DLL"),
                ("runtime/exec_child.exe", "EXECCHILD.EXE"),
                ("hello/hello_lx.exe", "HELLO.EXE"),
                ("watcom_io/watcom_io.exe", "WATCIO.EXE"),
            ):
                shutil.copyfile(ROOT / "bazel-bin/test/os2" / source, apps / name)
            for command, marker in (
                ("/OS2/APPS/RUNTIME.EXE", "OS2RUNTIME PASS"),
                ("/OS2/APPS/UCONV.EXE", "OS2UCONV PASS"),
                ("/OS2/APPS/HELLO.EXE", "Hello from Open Watcom C"),
                ("/OS2/APPS/WATCIO.EXE", "Open Watcom file I/O works"),
                (r"RETROOS/COMMAND.COM /C C:\OS2\APPS\RUNTIME.EXE", "OS2RUNTIME PASS"),
            ):
                launch = "/" + prefix + command[1:] if command.startswith("/") else prefix + command
                try:
                    result = subprocess.run([
                        str(ROOT / "bazel-bin/kernel" / target), "--host", directory,
                        "--c-root", prefix or "/", "--cwd", prefix + "OS2/APPS",
                        "--cmd", launch,
                    ], cwd=ROOT, capture_output=True, text=True, timeout=30)
                except subprocess.TimeoutExpired as error:
                    raise SystemExit((error.stdout or b"").decode(errors="replace") +
                                     (error.stderr or b"").decode(errors="replace") +
                                     f"\n{command} timed out")
                log = result.stdout + result.stderr
                if result.returncode != 0 or marker not in log or any(
                        bad in log for bad in ("SEGV", "PANIC", "FAIL", "unhandled event", "invalid API gate")):
                    raise SystemExit(log)
            if (apps / "café.dat").read_bytes() != bytes([0, 255, 130, 195, 40]):
                raise SystemExit("OS/2 OEM path or raw file contents did not cross the UTF-8 VFS boundary")
    print(f"PASS: OS/2 CRT, DLL initialization, shared memory, files, 16-bit VIO/KBD, DosExecPgm, Sleep, UCONV and PM fallbacks ({engine})")


if __name__ == "__main__":
    main()
