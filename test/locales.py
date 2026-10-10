#!/usr/bin/env python3
"""Check RETROOS.INI locale policy through DOS, Win32, OS/2 and Linux guest APIs."""
from pathlib import Path
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parent.parent


def main():
    targets = [
        "//kernel:retroos-host-kvm", "//test/dos/locale:locale",
        "//test/windows/locale:locale", "//test/os2/locale:locale",
        "//test/linux/runtime:runtime", "//lib/windows/kernel32:kernel32_dll", "//lib/windows/user32:user32_dll",
        "//lib/os2/doscalls:doscalls_dll", "//lib/os2/nls:nls_dll",
        "//lib/os2/kbdcalls:kbdcalls_dll", "//lib/os2/viocalls:viocalls_dll",
    ]
    subprocess.run(["bazelisk", "build", *targets, "--platforms=@platforms//host"], cwd=ROOT, check=True)
    linux = subprocess.check_output([
        "bazelisk", "cquery", "//test/linux/runtime:runtime", "--platforms=@platforms//host", "--output=files",
    ], cwd=ROOT, text=True).strip()
    with tempfile.TemporaryDirectory(prefix="retroos-locale-") as directory:
        root = Path(directory)
        for folder in ["RETROOS/WINDOWS/SYSTEM32", "RETROOS/OS2/DLL"]:
            (root / folder).mkdir(parents=True)
        for source, dest in [
            ("test/dos/locale/LOCALE.COM", "DOS.COM"),
            ("test/windows/locale/locale.exe", "WIN.EXE"),
            ("test/os2/locale/locale.exe", "OS2.EXE"),
            ("lib/windows/kernel32/KERNEL32.DLL", "RETROOS/WINDOWS/SYSTEM32/KERNEL32.DLL"),
            ("lib/windows/user32/USER32.DLL", "RETROOS/WINDOWS/SYSTEM32/USER32.DLL"),
            ("lib/os2/doscalls/DOSCALLS.DLL", "RETROOS/OS2/DLL/DOSCALLS.DLL"),
            ("lib/os2/nls/NLS.DLL", "RETROOS/OS2/DLL/NLS.DLL"),
            ("lib/os2/kbdcalls/KBDCALLS.DLL", "RETROOS/OS2/DLL/KBDCALLS.DLL"),
            ("lib/os2/viocalls/VIOCALLS.DLL", "RETROOS/OS2/DLL/VIOCALLS.DLL"),
        ]:
            shutil.copyfile(ROOT / "bazel-bin" / source, root / dest)
        shutil.copyfile(ROOT / linux, root / "LINUX.ELF")
        (root / "TEST.COM").write_bytes(bytes.fromhex("803e80000d750c803e8100227505b8254ccd21b8014ccd21"))
        cases = [
            ("", "en_US.UTF-8", 1, 437, 0, 0x2e, 0),
            ("LOCALE=en-US\n", "en_US.UTF-8", 1, 437, 0, 0x2e, 0),
            ("LOCALE=ru-RU\n", "ru_RU.UTF-8", 7, 866, 1, 0x2c, 3),
            ("LOCALE=pl-PL\n", "pl_PL.UTF-8", 48, 852, 1, 0x2c, 3),
            ("LOCALE=de-DE\n", "de_DE.UTF-8", 49, 850, 1, 0x2c, 3),
            ("LOCALE=it-IT\n", "it_IT.UTF-8", 39, 850, 1, 0x2c, 2),
            ("LOCALE=nl-NL\n", "nl_NL.UTF-8", 31, 850, 1, 0x2c, 2),
            ("LOCALE=rU-rU\nCODEPAGE=850\n", "ru_RU.UTF-8", 7, 850, 1, 0x2c, 3),
            ("LOCALE=unknown\nCODEPAGE=9999\n", "en_US.UTF-8", 1, 437, 0, 0x2e, 0),
        ]
        for config, lang, country, page, order, decimal, currency in cases:
            (root / "RETROOS/RETROOS.INI").write_text("[locale]\n" + config.replace("LOCALE=", "language=").replace("KEYBOARD=", "keyboard=").replace("CODEPAGE=", "codepage="))
            profile = lang.split(".")[0].replace("_", "-")
            (root / "EXPECT.TXT").write_text(f"{profile} {page}\n")
            dos = (f"LOCALE DOS PASS country={country:04X} oem={page:04X} system={page:04X} "
                   f"date={order:04X} decimal={decimal:04X} currency={currency:04X}")
            for command, marker in [
                ("/DOS.COM", dos), ("/WIN.EXE", "LOCALE WINDOWS PASS"),
                ("/OS2.EXE", "LOCALE OS2 PASS"), (f"/LINUX.ELF {lang}", "LINUX RUNTIME PASS"),
            ]:
                try:
                    result = subprocess.run([
                    str(ROOT / "bazel-bin/kernel/retroos-host-kvm"), "--host", directory,
                    "--c-root", "/", "--cwd", "/", "--cmd", command,
                    ], cwd=ROOT, capture_output=True, text=True, timeout=30)
                except subprocess.TimeoutExpired as error:
                    raise SystemExit((error.stdout or b"").decode(errors="replace") + (error.stderr or b"").decode(errors="replace") + f"\n{command} timed out")
                output = result.stdout + result.stderr
                if result.returncode or marker not in output or any(bad in output for bad in ["FAIL", "SEGV", "PANIC", "panicked"]):
                    raise SystemExit(f"Locale case {config!r}, {command}:\n{output}")
            print(f"PASS: {config.strip() or 'defaults'} across all four personalities", flush=True)


if __name__ == "__main__":
    main()
