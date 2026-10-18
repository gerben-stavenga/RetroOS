#!/usr/bin/env python3
"""Check console echo/editing with the system shell and BusyBox's line editor."""
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import time

import pyte

ROOT = Path(__file__).resolve().parents[1]


def main():
    subprocess.run(["bazelisk", "build", "//kernel:retroos-host-kvm",
                    "--platforms=@platforms//host"], cwd=ROOT, check=True)
    for shell in ("/bin/dash", str(ROOT / "boot-bundle/bin/busybox")):
        with tempfile.TemporaryDirectory(prefix="retroos-shell-echo-") as directory:
            root = Path(directory)
            (root / "bin").mkdir()
            shutil.copyfile(shell, root / "bin/sh")
            shutil.copyfile(ROOT / "boot-bundle/bin/busybox", root / "bin/busybox")
            if shell == "/bin/dash":
                dependencies = subprocess.check_output(["ldd", shell], text=True)
                for name in re.findall(r"(/[^\s()]+)", dependencies):
                    source = Path(name)
                    if source.is_file():
                        target = root / name.lstrip("/")
                        target.parent.mkdir(parents=True, exist_ok=True)
                        shutil.copyfile(source, target)
            with (root / "terminal").open("wb") as terminal, (root / "klog").open("wb") as log:
                process = subprocess.Popen([str(ROOT / "bazel-bin/kernel/retroos-host-kvm"),
                    "--host", directory, "--cmd", "/bin/sh -i", "--cwd", "/"],
                    stdin=subprocess.PIPE, stdout=terminal, stderr=log)

                def screen():
                    grid = pyte.Screen(80, 25)
                    pyte.Stream(grid).feed((root / "terminal").read_text(errors="replace").replace("\n", "\r\n"))
                    return "\n".join(grid.display)

                def wait(predicate):
                    deadline = time.monotonic() + 20
                    while time.monotonic() < deadline:
                        if predicate():
                            return
                        if process.poll() is not None:
                            break
                        time.sleep(.05)
                    artifacts = ROOT / "build/ci" / ("shell-echo-dash" if shell == "/bin/dash" else "shell-echo-busybox")
                    artifacts.mkdir(parents=True, exist_ok=True)
                    for file in ("terminal", "klog"):
                        shutil.copyfile(root / file, artifacts / file)
                    raise AssertionError(f"{shell}: console check failed:\n{screen()}\n{(root / 'klog').read_text(errors='replace')[-2000:]}")

                def send(keys):
                    process.stdin.write(keys)
                    process.stdin.flush()
                    time.sleep(.3)

                try:
                    wait(lambda: "#" in screen())
                    send(b"echo TTY_ECHO_CHECX")
                    wait(lambda: "echo TTY_ECHO_CHECX" in screen())
                    assert screen().count("TTY_ECHO_CHECX") == 1, screen()
                    send(b"\x7fK")
                    wait(lambda: "echo TTY_ECHO_CHECK" in screen())
                    send(b"\r")
                    wait(lambda: screen().count("TTY_ECHO_CHECK") == 2)
                    if shell == "/bin/dash":
                        send(b"/bin/busybox stty -echo\r")
                        send(b"printf hidden > /hidden\r")
                        wait(lambda: (root / "hidden").exists())
                        assert "printf hidden" not in screen(), screen()
                        assert (root / "hidden").read_text() == "hidden"
                    send(b"/bin/busybox stty echo\r")
                    send(b"echo RESTORED")
                    wait(lambda: "echo RESTORED" in screen())
                    send(b"\r")
                    wait(lambda: screen().count("RESTORED") == 2)
                    send(b"\x04")
                    process.wait(timeout=10)
                    assert process.returncode == 0, (root / "klog").read_text(errors="replace")
                finally:
                    if process.poll() is None:
                        process.terminate()
                        process.wait(timeout=5)
        print(f"PASS: {shell}: input visible once, erase, settings across exec, EOF")


if __name__ == "__main__":
    main()
