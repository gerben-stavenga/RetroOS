#!/usr/bin/env python3
"""Exercise run.sh's disk lifecycle and backend attachments with fake tools."""
import configparser
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parent.parent


def main():
    with tempfile.TemporaryDirectory(prefix="retroos-launcher-") as tmp:
        root = Path(tmp)
        shutil.copy(ROOT / "run.sh", root)
        shutil.copytree(ROOT / "tools/run", root / "tools/run")
        shutil.copy(ROOT / "tools/configure_shared_86box.py", root / "tools")
        (root / "bazel-bin").mkdir()
        mock = root / "bazel"
        mock.write_text('''#!/usr/bin/env python3
import json, os, pathlib, sys
root = pathlib.Path(os.environ["TEST_ROOT"])
with (root / "builds").open("a") as out: out.write(json.dumps(sys.argv[1:]) + "\\n")
if "//:data_disk" in sys.argv:
    if os.environ.get("FAIL_SEED"): sys.exit(1)
    (root / "bazel-bin/data_disk.bin").write_bytes(b"seed" + bytes(512 * 16 * 63 - 4))
if "//:boot_disk" in sys.argv:
    (root / "bazel-bin/boot_disk.bin").write_bytes(bytes(512 * 16 * 63))
''')
        mock.chmod(0o755)
        emulator = root / "emulator"
        emulator.write_text('''#!/usr/bin/env python3
import json, os, pathlib, sys
root = pathlib.Path(os.environ["TEST_ROOT"])
(root / "arguments").write_text(json.dumps(sys.argv[1:]))
if os.environ.get("HOLD_VM"):
    print("READY", flush=True)
    sys.stdin.readline()
''')
        emulator.chmod(0o755)
        env = dict(os.environ, TEST_ROOT=str(root), BAZEL=str(mock),
                   RETROOS_QEMU_BIN=str(emulator), BOX86=str(emulator),
                   BOCHS_BIN=str(emulator), BOCHS_BIOS=str(mock), BOCHS_VGA_ROM=str(mock))
        env.pop("RETROOS_DATA_IMAGE", None)
        env.pop("RETROOS_86BOX_KERNEL_LOG", None)
        command = [str(root / "run.sh"), "qemu", "--firmware", "bios", "--sound", "none"]
        def run(args=command, extra=None):
            result = subprocess.run(args, env=env | (extra or {}), capture_output=True, text=True, timeout=10)
            return result
        def good(result):
            assert result.returncode == 0, result.stdout + result.stderr
        good(run())
        data = root / "build/data.bin"
        assert data.read_bytes().startswith(b"seed")
        with data.open("r+b") as stream: stream.write(b"guest changes")
        good(run())
        assert data.read_bytes().startswith(b"guest changes")
        builds = [json.loads(line) for line in (root / "builds").read_text().splitlines()]
        assert sum("//:data_disk" in call for call in builds) == 1
        assert sum("//:boot_disk" in call for call in builds) == 2
        args = json.loads((root / "arguments").read_text())
        assert f"file={data},if=none,id=data,format=raw" in args
        assert "ide-hd,drive=data,bus=ide.0,unit=1" in args
        assert not any("snapshot=" in arg for arg in args)
        holder = subprocess.Popen(command, env=env | {"HOLD_VM": "1"}, stdin=subprocess.PIPE,
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            while holder.stdout.readline().strip() != "READY":
                assert holder.poll() is None
            blocked = run()
            assert blocked.returncode != 0 and "already in use" in blocked.stderr
        finally:
            holder.communicate("done\n", timeout=5)
        good(run())
        failed_image = root / "failed.bin"
        assert run(command + ["--data-image", str(failed_image)], {"FAIL_SEED": "1"}).returncode != 0
        assert not failed_image.exists()
        assert not list(root.glob(".data-seed.*"))
        for backend in ("bochs", "86box"):
            vm = root / (backend + " vm")
            good(run([str(root / "run.sh"), backend], {"VM_DIR": str(vm)}))
            if backend == "bochs":
                assert str(data) in (vm / "bochsrc.txt").read_text()
            else:
                config = configparser.ConfigParser()
                config.read(vm / "86box.cfg")
                assert config["Hard disks"]["hdd_02_fn"] == str(data)
                good(run([str(root / "run.sh"), backend, "--freedos"], {"VM_DIR": str(vm)}))
                # Read into a fresh parser so removed options do not linger.
                config = configparser.ConfigParser()
                config.read(vm / "86box.cfg")
                assert config["Hard disks"]["hdd_01_fn"] == str(data)
                assert "hdd_02_fn" not in config["Hard disks"]
        assert run(command + ["-i", "image"]).returncode != 0
        assert data.read_bytes().startswith(b"guest changes")
    print("PASS: seed once, rebuild boot, preserve writes, lock, failed seed, backend attachments")


if __name__ == "__main__":
    main()
