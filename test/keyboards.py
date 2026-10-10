#!/usr/bin/env python3
"""Exercise national keyboard input through all four guest console APIs.

The pure Rust tests anchor the physical positions and modifier behavior. This
fixture checks BIOS/KBD OEM bytes, Win32 UTF-16/UTF-8 events, Linux UTF-8 input,
and an explicit keyboard choice independent of the regional profile.
"""
from pathlib import Path
import shutil
import subprocess
import tempfile
import time

ROOT = Path(__file__).resolve().parent.parent


def main():
    targets = ["//kernel:retroos-host-kvm", "//test/dos/locale:keyboard",
               "//test/windows/locale:keyboard", "//test/os2/locale:keyboard",
               "//test/linux/runtime:keyboard", "//lib/windows/kernel32:kernel32_dll",
               "//lib/windows/user32:user32_dll", "//lib/os2/doscalls:doscalls_dll",
               "//lib/os2/kbdcalls:kbdcalls_dll", "//lib/os2/nls:nls_dll"]
    subprocess.run(["bazelisk", "build", *targets, "--platforms=@platforms//host"], cwd=ROOT, check=True)
    linux = subprocess.check_output(["bazelisk", "cquery", "//test/linux/runtime:keyboard",
                                    "--platforms=@platforms//host", "--output=files"], cwd=ROOT, text=True).strip()
    with tempfile.TemporaryDirectory(prefix="retroos-keyboard-") as directory:
        root = Path(directory)
        for folder in ["RETROOS/WINDOWS/SYSTEM32", "RETROOS/OS2/DLL"]:
            (root / folder).mkdir(parents=True)
        for source, destination in [
            ("test/dos/locale/KEYBOARD.COM", "DOS.COM"),
            ("test/windows/locale/keyboard.exe", "WIN.EXE"),
            ("test/os2/locale/keyboard.exe", "OS2.EXE"),
            ("lib/windows/kernel32/KERNEL32.DLL", "RETROOS/WINDOWS/SYSTEM32/KERNEL32.DLL"),
            ("lib/windows/user32/USER32.DLL", "RETROOS/WINDOWS/SYSTEM32/USER32.DLL"),
            ("lib/os2/doscalls/DOSCALLS.DLL", "RETROOS/OS2/DLL/DOSCALLS.DLL"),
            ("lib/os2/kbdcalls/KBDCALLS.DLL", "RETROOS/OS2/DLL/KBDCALLS.DLL"),
            ("lib/os2/nls/NLS.DLL", "RETROOS/OS2/DLL/NLS.DLL"),
        ]:
            shutil.copyfile(ROOT / "bazel-bin" / source, root / destination)
        shutil.copyfile(ROOT / linux, root / "LINUX.ELF")
        cases = [
            ("LOCALE=it-IT\n", "è@éàùì\\[]{}", 850, "it"),
            ("LOCALE=de-DE\n", "zyüäöß@[]{}\\^é", 850, "de"),
            ("LOCALE=pl-PL\n", "ąęłŁżźćńó", 852, "pl"),
            ("LOCALE=ru-RU\n", "фЖёЯxyz", 866, "ru"),
            ("LOCALE=nl-NL\n", "aA@[]{}\\^", 850, "us"),
            ("LOCALE=de-DE\nKEYBOARD=iT\nCODEPAGE=437\n", "è@é\\", 437, "it"),
            ("LOCALE=it-IT\nKEYBOARD=unknown\n", "è@é\\", 850, "it"),
        ]
        for config, text, cp, layout in cases:
            (root / "RETROOS/RETROOS.INI").write_text("[locale]\n" + config.replace("LOCALE=", "language=").replace("KEYBOARD=", "keyboard=").replace("CODEPAGE=", "codepage="))
            encoded = text.encode(f"cp{cp}", errors="replace") + b"\r"
            markers = {
                "/DOS.COM": "KEYBOARD DOS " + " ".join(f"{b:02X}" for b in encoded),
                "/OS2.EXE": "KEYBOARD OS2 " + " ".join(f"{b:02X}" for b in encoded),
                "/LINUX.ELF": "KEYBOARD LINUX " + " ".join(f"{b:02X}" for b in text.encode() + b"\n"),
                "/WIN.EXE": "KEYBOARD W " + " ".join(f"{ord(c):04X}" for c in text + "\r"),
            }
            for command, marker in markers.items():
                with (root / "out.log").open("wb") as out, (root / "err.log").open("wb") as err:
                    process = subprocess.Popen([str(ROOT / "bazel-bin/kernel/retroos-host-kvm"),
                                                "--host", directory, "--c-root", "/", "--cwd", "/", "--cmd", command],
                                               cwd=ROOT, stdin=subprocess.PIPE, stdout=out, stderr=err)
                    def output():
                        return (root / "out.log").read_text(errors="replace") + (root / "err.log").read_text(errors="replace")
                    def wait_for(needle):
                        deadline = time.monotonic() + 20
                        while time.monotonic() < deadline:
                            if needle in output():
                                return
                            if process.poll() is not None:
                                break
                            time.sleep(0.05)
                        raise AssertionError(f"{config!r} {command}, waiting for {needle}:\n{output()}")
                    try:
                        wait_for("KEYBOARD READY")
                        process.stdin.write((text + "\n").encode()); process.stdin.flush()
                        wait_for(marker)
                        if command == "/WIN.EXE":
                            wait_for("KEYBOARD UTF8 READY")
                            process.stdin.write((text + "\n").encode()); process.stdin.flush()
                            wait_for("KEYBOARD A " + " ".join(f"{b:02X}" for b in text.encode() + b"\r"))
                        process.wait(timeout=10)
                        assert process.returncode == 0 and f"Keyboard: {layout}" in output(), output()
                        assert not any(bad in output() for bad in ["SEGV", "PANIC", "FAIL", "panicked"]), output()
                    finally:
                        if process.poll() is None:
                            process.terminate(); process.wait(timeout=3)
            print(f"PASS: {config.strip()} keyboard across all four personalities", flush=True)


if __name__ == "__main__":
    main()
