#!/usr/bin/env python3
"""Drive the shipped upstream file manager/editor on the Linux KVM personality."""
from pathlib import Path
import shutil
import subprocess
import tempfile
import time

ROOT = Path(__file__).resolve().parent.parent


def main():
    subprocess.run(["bazelisk", "build", "//kernel:retroos-host-kvm", "--platforms=@platforms//host"], cwd=ROOT, check=True)
    with tempfile.TemporaryDirectory(prefix="retroos-rat-") as directory:
        root = Path(directory)
        (root / "bin").mkdir()
        shutil.copyfile(ROOT / "apps-boot/rc/RC.EXE", root / "bin/rc")
        shutil.copyfile(ROOT / "apps/busybox/busybox", root / "bin/busybox")
        (root / "bin/sh").symlink_to("busybox")
        (root / "TEST.COM").write_bytes(bytes.fromhex("ba0c01b409cd21b8004ccd21") + b"RC DOS CHILD PASS$")
        work = root / "work"
        (work / "child").mkdir(parents=True)
        (work / "note.txt").write_text("Original text\n")
        with (root / "guest.log").open("wb") as log:
            process = subprocess.Popen([str(ROOT / "bazel-bin/kernel/retroos-host-kvm"), "--host", directory, "--cmd", "/bin/rc", "--cwd", "/work"], stdin=subprocess.PIPE, stdout=log, stderr=log)
            def send(keys, delay=0.8):
                time.sleep(delay)
                if process.poll() is not None:
                    raise AssertionError("Rat Commander exited before input completed")
                process.stdin.write(keys)
                process.stdin.flush()
            try:
                # Enter a child and return through '..', then create a folder.
                send(b"\x1b[B\r", 3)
                send(b"\r")
                send(b"\x1b[18~")  # F7
                send(b"created\r")
                # Copy note.txt under a new name; the destination starts selected.
                send(b"\x1b[F\x1b[15~")  # End, F5
                send(b"/work/copied.txt\r")
                # Edit note.txt. Period and Enter must insert.
                send(b"\x1b[F\x1bOS", 2.5)  # End, F4 after transfer completion
                send(b"\x1b[H.x\r", 1.5)
                send(b"\x1bOQ")  # F2: save
                send(b"\r")  # Confirm save if configured.
                send(b"\x1b[21~")  # Close editor.
                send(b"/TEST.COM\r")  # Launch DOS through Rust -> shell -> exec.
                send(b" ", 2)  # Return from the foreground command to panels.
                send(b"\x1b[21~")  # Quit manager.
                send(b"\r")  # Confirm quit.
                process.wait(timeout=10)
            finally:
                if process.poll() is None:
                    process.terminate()
                    process.wait(timeout=3)
        output = (root / "guest.log").read_text(errors="replace")
        if process.returncode or any(s in output for s in ("SEGV", "PANIC", "panicked", "fatal Exception")):
            raise AssertionError(output[-6000:])
        assert "RC DOS CHILD PASS" in output, output[-6000:]
        assert "failed to run" not in output, output[-6000:]
        assert (work / "created").is_dir(), output[-6000:]
        assert (work / "copied.txt").read_text() == "Original text\n"
        contents = (work / "note.txt").read_text()
        assert contents.startswith(".x\n"), repr(contents)
    print("PASS: Rat Commander navigation, mkdir, copy, editor period/Enter/save, DOS child execution and clean quit (KVM)")


if __name__ == "__main__":
    main()
