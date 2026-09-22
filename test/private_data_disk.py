#!/usr/bin/env python3
"""Make a disposable test disk; command injection never touches the user's disk."""
import argparse
from pathlib import Path
import struct
import subprocess
import tempfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("seed")
    parser.add_argument("output")
    parser.add_argument("--command")
    args = parser.parse_args()
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run(["cp", "--reflink=auto", args.seed, str(output)], check=True)
    output.chmod(0o600)
    if args.command is None:
        return
    with output.open("rb") as stream:
        mbr = stream.read(512)
    start = struct.unpack_from("<I", mbr, 446 + 8)[0]
    volume = f"{output}@@{start * 512}"
    config = subprocess.check_output(["mtype", "-i", volume, "::CONFIG/CONFIG.SYS"])
    lines = [line for line in config.splitlines() if not line.upper().startswith(b"TEST=")]
    lines.append(b"TEST=" + args.command.encode("ascii"))
    with tempfile.NamedTemporaryFile() as staged:
        staged.write(b"\r\n".join(lines) + b"\r\n")
        staged.flush()
        subprocess.run(["mcopy", "-o", "-i", volume, staged.name, "::CONFIG/CONFIG.SYS"], check=True)


if __name__ == "__main__":
    main()
