#!/usr/bin/env python3
"""Exercise upstream NTDLL RTL and its ordinary imports from RETROOS.DLL.

This does not replace windows_ntdll.py's full loader acceptance test.
"""
import os
from pathlib import Path
import re
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
        "//test/windows/ntdll:portable", "//test/windows/ntdll:forwarders", "--platforms=@platforms//host"],
        cwd=ROOT, check=True)
    dll = ROOT / "bazel-bin/lib/wine/ntdll/NTDLL.DLL"
    headers = subprocess.check_output(["objdump", "-p", str(dll)], text=True)
    assert re.findall(r"DLL Name: (\S+)", headers) == ["RETROOS.DLL"]
    assert "RetroNtTerminateProcess" in headers and "RetroDebugWrite" in headers
    assembly = subprocess.check_output(["objdump", "-d", str(dll)], text=True)
    assert not re.search(r"\b(?:sysenter|syscall)\b|\bint\s+\$0x(?:2e|80|83)\b", assembly)
    graphics = ROOT / "bazel-bin/lib/wine/ntdll/WIN32U.DLL"
    graphics_headers = subprocess.check_output(["objdump", "-p", str(graphics)], text=True)
    assert "RetroUserCallback" in graphics_headers
    graphics_code = subprocess.check_output(["objdump", "-d", str(graphics)], text=True)
    assert not re.search(r"\b(?:sysenter|syscall)\b|\bint\s+\$0x(?:2e|80|83)\b", graphics_code)
    with tempfile.TemporaryDirectory(prefix="retroos-wine-boundary-") as directory:
        root = Path(directory)
        install(root)
        probe_dir=root / "PROBE"
        probe_dir.mkdir()
        shutil.copyfile(ROOT / "bazel-bin/test/windows/ntdll/portable.exe", probe_dir / "PROBE.EXE")
        for name in ("FORWARD.DLL", "RELAY.DLL"):
            shutil.copyfile(ROOT / "bazel-bin/test/windows/ntdll" / name, probe_dir / name)
        process = subprocess.Popen(["python3", str(ROOT / "test/disk_fixture.py"), "--root", directory,
            "--", str(ROOT / f"bazel-bin/kernel/{host}"), "--c-root", "/", "--cmd", "/PROBE/PROBE.EXE"],
            cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, start_new_session=True)
        try:
            stdout, stderr = process.communicate(timeout=30)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            stdout, stderr = process.communicate()
            raise SystemExit("Wine boundary timed out\n" + stdout + stderr)
        log = stdout + stderr
        if process.returncode or "NTDLL PASS" not in log or any(x in log for x in ("PANIC", "SEGV", "NTDLL FAIL", "not implemented")):
            raise SystemExit(log)
        print(f"PASS: Wine NTDLL RTL/heap, page lifecycle, forwarded imports and RETROOS.DLL kernel boundary ({engine})")


if __name__ == "__main__":
    main()
