#!/usr/bin/env python3
"""Update disk attachments while retaining the VM's hardware settings."""
import configparser
from pathlib import Path
import sys


def main():
    config_path, boot, data = map(Path, sys.argv[1:4])
    freedos, sound = sys.argv[4:6]
    # 86Box advertises LBA only at >=1024 cylinders (or >16 heads / >63
    # sectors). Below that, the TX97 BIOS's Auto translation cannot read our
    # boot volume reliably. The kernel itself supports both CHS and LBA.
    # Pad only the disposable boot copy; its partition and the data disk stay
    # the same size. truncate leaves the extra space sparse.
    if freedos != "1" and boot.stat().st_size < 1024 * 16 * 63 * 512:
        with boot.open("r+b") as stream:
            stream.truncate(1024 * 16 * 63 * 512)
    config = configparser.ConfigParser(interpolation=None, strict=False)
    config.read(config_path)
    for section in ("Hard disks", "Sound"):
        if not config.has_section(section):
            config.add_section(section)
    disks = config["Hard disks"]
    # Both slots belong to the launcher; switching to FreeDOS removes the boot slot.
    for key in list(disks):
        if key.startswith(("hdd_01_", "hdd_02_")):
            del disks[key]
    for index, image in enumerate([data] if freedos == "1" else [boot, data], 1):
        cylinders, remainder = divmod(image.stat().st_size, 512 * 16 * 63)
        if remainder:
            sys.exit(f"{image}: disk must contain whole 16-head, 63-sector cylinders")
        disks[f"hdd_{index:02}_fn"] = str(image)
        disks[f"hdd_{index:02}_parameters"] = f"63, 16, {cylinders}, 0, ide"
        disks[f"hdd_{index:02}_ide_channel"] = f"0:{index - 1}"
    config["Sound"]["sndcard"] = "none" if sound == "none" else "sb16"
    with config_path.open("w") as stream:
        config.write(stream)


if __name__ == "__main__":
    main()
