#!/usr/bin/env python3
"""Make a disposable test disk; command injection never touches the user's disk."""
import argparse
from pathlib import Path
import subprocess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("seed")
    parser.add_argument("output")
    args = parser.parse_args()
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run(["cp", "--reflink=auto", args.seed, str(output)], check=True)
    output.chmod(0o600)


if __name__ == "__main__":
    main()
