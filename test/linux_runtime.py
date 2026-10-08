#!/usr/bin/env python3
"""Exercise 64-bit musl TLS, shared threads, futexes, epoll/eventfd and timed poll."""
from pathlib import Path
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parent.parent

def main():
    subprocess.run(["bazelisk", "build", "//kernel:retroos-host-kvm", "//test/linux/runtime:runtime", "--platforms=@platforms//host"], cwd=ROOT, check=True)
    with tempfile.TemporaryDirectory(prefix="retroos-linux-runtime-") as directory:
        root = Path(directory)
        artifact = subprocess.check_output(["bazelisk", "cquery", "//test/linux/runtime:runtime", "--platforms=@platforms//host", "--output=files"], cwd=ROOT, text=True).strip()
        shutil.copyfile(ROOT / artifact, root / "probe.elf")
        # Check the Linux argv -> DOS PSP command tail, then exit with 37.
        # cmp byte [0080h],13; jne fail; cmp byte [0081h],'"'; jne fail
        # mov ax,4c25h; int21h; fail: mov ax,4c01h; int21h
        (root / "TEST.COM").write_bytes(bytes.fromhex("803e80000d750c803e8100227505b8254ccd21b8014ccd21"))
        result = subprocess.run([str(ROOT / "bazel-bin/kernel/retroos-host-kvm"), "--host", directory, "--cmd", "/probe.elf", "--cwd", "/"], cwd=ROOT, capture_output=True, text=True, timeout=20)
        log = result.stdout + result.stderr
        if result.returncode or "LINUX RUNTIME PASS" not in log or any(s in log for s in ("SEGV", "PANIC", "panicked", "fatal Exception")):
            raise SystemExit(log)
    print("PASS: Linux x86_64 musl threads, TLS, synchronization, epoll/eventfd, poll timeout, file operations and DOS subprocess execution (KVM)")

if __name__ == "__main__":
    main()
