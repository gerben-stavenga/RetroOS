#!/usr/bin/env python3
"""Drive the shipped upstream file manager/editor on the Linux KVM personality."""
from pathlib import Path
import shutil
import subprocess
import tempfile
import time

import pyte

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
        with (root / "guest.log").open("wb") as log, (root / "terminal.log").open("wb") as terminal:
            process = subprocess.Popen([str(ROOT / "bazel-bin/kernel/retroos-host-kvm"), "--host", directory, "--cmd", "/bin/rc", "--cwd", "/work"], stdin=subprocess.PIPE, stdout=terminal, stderr=log)
            def send(keys, delay=0.8):
                time.sleep(delay)
                if process.poll() is not None:
                    raise AssertionError("Rat Commander exited before input completed")
                process.stdin.write(keys)
                process.stdin.flush()
            def wait_for(description, predicate, timeout=20):
                deadline = time.monotonic() + timeout
                while time.monotonic() < deadline:
                    if predicate():
                        return
                    if process.poll() is not None:
                        break
                    time.sleep(0.05)
                output = (root / "guest.log").read_text(errors="replace")
                artifacts = ROOT / "build/ci"
                artifacts.mkdir(parents=True, exist_ok=True)
                (artifacts / "rat-commander.log").write_text(output)
                shutil.copyfile(root / "terminal.log", artifacts / "rat-commander-terminal.log")
                raise AssertionError(f"Timed out waiting for {description}:\n{terminal_text()[-6000:]}")

            def terminal_text():
                # The hosted runner sends the terminal to stdout and KLOG to
                # stderr. Feeding KLOG diagnostics into the VT model corrupts it.
                output = (root / "terminal.log").read_text(errors="replace")
                # Cursor-based redraws omit cells that are already correct.
                # Reconstruct the screen instead of stripping escape sequences.
                screen = pyte.Screen(80, 25)
                pyte.Stream(screen).feed(output)
                return "\n".join(screen.display)

            def left_directory():
                # RC normalizes the trailing slash after navigating upwards.
                title = terminal_text().splitlines()[1][:40].split()
                return title[1].rstrip("/") if len(title) > 1 else ""

            try:
                # Directory changes reload the panel asynchronously. Drive the
                # next key only after its target directory/selection is visible.
                wait_for("initial panels", lambda: left_directory() == "/work")
                send(b"\x1b[B")
                wait_for("child selection", lambda: "child" in terminal_text().splitlines()[21][:40])
                send(b"\r")
                wait_for("child directory", lambda: left_directory() == "/work/child"
                         and ".." in terminal_text().splitlines()[21][:40])
                send(b"\r")
                wait_for("parent directory", lambda: left_directory() == "/work")
                send(b"\x1b[18~")  # F7
                send(b"created\r")
                wait_for("created directory", lambda: (work / "created").is_dir())
                wait_for("created selection", lambda: "created" in terminal_text().splitlines()[21][:40])
                # Copy note.txt under a new name; the destination starts selected.
                send(b"\x1b[F")  # End
                wait_for("copy source selection", lambda: "note.txt" in terminal_text().splitlines()[21][:40])
                send(b"\x1b[15~")  # F5
                send(b"/work/copied.txt\r")
                wait_for("completed copy", lambda: (work / "copied.txt").exists() and (work / "copied.txt").read_text() == "Original text\n")
                # TaskDone reloads the panels and focuses the copied file after
                # the bytes are written. Wait for that visible refresh first.
                wait_for("copy panel refresh", lambda: "copied.txt" in terminal_text().splitlines()[21][:40])
                # Edit note.txt. Period and Enter must insert.
                send(b"\x1b[F")  # End: select note.txt after the copy refresh.
                wait_for("note.txt selection", lambda: "note.txt" in terminal_text().splitlines()[21][:40])
                send(b"\x1bOS")  # F4
                wait_for("editor contents", lambda: "Original text" in terminal_text())
                send(b"\x1b[H.x\r", 1.5)
                send(b"\x1bOQ")  # F2: save
                send(b"\r")  # Confirm save if configured.
                wait_for("saved editor contents", lambda: (work / "note.txt").read_text().startswith(".x\n"))
                send(b"\x1b[21~")  # Close editor.
                wait_for("manager after editor", lambda: "Name" in terminal_text().splitlines()[2][:40])
                send(b"/TEST.COM\r")  # Launch DOS through Rust -> shell -> exec.
                wait_for("DOS child output", lambda: "RC DOS CHILD PASS" in (root / "guest.log").read_text(errors="replace"))
                send(b" ", 2)  # Return from the foreground command to panels.
                send(b"\x1b[21~")  # Quit manager.
                send(b"\r")  # Confirm quit.
                process.wait(timeout=10)
            finally:
                if process.poll() is None:
                    process.terminate()
                    process.wait(timeout=3)
        output = (root / "guest.log").read_text(errors="replace") + (root / "terminal.log").read_text(errors="replace")
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
