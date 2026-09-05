#!/usr/bin/env python3
"""Build the compact, pre-demangled symbol file consumed by stacktrace.rs."""

import re
import struct
import subprocess
import sys


def main() -> None:
    source, output = sys.argv[1:]
    raw = subprocess.run(
        ["nm", "-S", "--defined-only", "--format=posix", source],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.splitlines()

    symbols = []
    for line in raw:
        fields = line.rsplit(maxsplit=3)
        if len(fields) != 4 or fields[1] not in "tTwW":
            continue
        name, _, address, size = fields
        address = int(address, 16)
        size = int(size, 16)
        if address:
            symbols.append((address, size, name))

    symbols.sort(key=lambda symbol: (symbol[0], -symbol[1], symbol[2]))
    symbols = [
        symbol for index, symbol in enumerate(symbols)
        if index == 0 or symbol[0] != symbols[index - 1][0]
    ]
    symbols = [
        (address, size or (symbols[index + 1][0] - address if index + 1 < len(symbols) else 0), name)
        for index, (address, size, name) in enumerate(symbols)
    ]

    demangled = subprocess.run(
        ["c++filt", "-s", "rust"],
        input="\n".join(symbol[2] for symbol in symbols) + "\n",
        check=True,
        capture_output=True,
        text=True,
    ).stdout.splitlines()
    if len(demangled) != len(symbols):
        raise RuntimeError("c++filt returned the wrong number of names")

    # Crate disambiguators make linker symbols unique but add no useful context
    # to a backtrace. Removing them also saves about 40 KB in KERNEL.SYM.
    names = bytearray()
    entries = bytearray()
    for (address, size, _), name in zip(symbols, demangled):
        name = re.sub(r"\[[0-9a-f]{16}\]", "", name)
        name_offset = len(names)
        names.extend(name.encode("utf-8"))
        names.append(0)
        entries.extend(struct.pack("<III", address, size, name_offset))

    names_offset = 16 + len(entries)
    with open(output, "wb") as packed:
        packed.write(b"RSYM")
        packed.write(struct.pack("<III", 1, len(symbols), names_offset))
        packed.write(entries)
        packed.write(names)


if __name__ == "__main__":
    main()
