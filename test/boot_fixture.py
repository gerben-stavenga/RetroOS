"""Prepare an explicit INI profile in a private VM boot image."""
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
from vm_mount_config import configure, volumes


def prepare_boot(work, data, config=None):
    boot = Path(work) / "fixture-boot.img"
    shutil.copyfile(ROOT / "bazel-bin/boot_disk.bin", boot)
    boot.chmod(0o600)
    if config is None:
        with Path(data).open("rb") as stream:
            mbr = stream.read(512)
        start = struct.unpack_from("<I", mbr, 454)[0] if mbr[450] else 0
        result = subprocess.run(["mtype", "-i", f"{data}@@{start * 512}",
                                 "::RETROOS/RETROOS.INI"], capture_output=True)
        config = result.stdout.decode() if result.returncode == 0 else (ROOT / "etc/RETROOS.INI").read_text()
    generated = config if '[mount "data"]' in config else configure(config, volumes(data))
    with tempfile.TemporaryDirectory(prefix="retroos-fixture-ini-") as temp:
        ini = Path(temp) / "RETROOS.INI"
        ini.write_text(generated)
        subprocess.run(["mcopy", "-o", "-i", f"{boot}@@1048576", ini,
                        "::RETROOS/RETROOS.INI"], check=True)
    return boot
