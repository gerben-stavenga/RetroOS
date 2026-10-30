#!/usr/bin/env python3
"""Run the new NT root without KERNEL32, USER32, or a Windows CRT."""
import os
from pathlib import Path
import shutil
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
                    "//test/windows/ntdll:probe", "//test/windows/ntdll:forwarders",
                    "//test/windows/ntdll:lazy", "//test/windows/ntdll:initdep", "//test/windows/ntdll:reject",
                    "--platforms=@platforms//host"], cwd=ROOT, check=True)
    with tempfile.TemporaryDirectory(prefix="retroos-ntdll-") as directory:
        root = Path(directory)
        install(root)
        shutil.copyfile(ROOT / "bazel-bin/test/windows/ntdll/probe.exe", root / "PROBE.EXE")
        for name in ("FORWARD.DLL", "RELAY.DLL", "LAZY.DLL", "INITDEP.DLL", "REJECT.DLL"):
            shutil.copyfile(ROOT / "bazel-bin/test/windows/ntdll" / name, root / name)
        result = subprocess.run(["python3", str(ROOT / "test/disk_fixture.py"), "--root", directory,
            "--", str(ROOT / f"bazel-bin/kernel/{host}"), "--c-root", "/", "--cmd", "/PROBE.EXE"],
            cwd=ROOT, capture_output=True, text=True, timeout=30)
        log = result.stdout + result.stderr
        if result.returncode or "NTDLL PASS" not in log or any(x in log for x in ("PANIC", "SEGV", "NTDLL FAIL")):
            raise SystemExit(log)
        print(f"PASS: native NTDLL strings, overlapping memory move, forwarded DLL calls, private I/O and process exit ({engine})")


if __name__ == "__main__":
    main()
