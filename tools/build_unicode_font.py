#!/usr/bin/env python3
"""Compile the vendored Uni-VGA BDF to sorted Unicode/bitmap records."""
from pathlib import Path
import struct

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "lib/fonts/uni-vga/u_vga16.bdf"
OUTPUT = ROOT / "lib/src/fonts/unicode_8x16.bin"


def build():
    glyphs = {}
    codepoint = None
    bitmap = None
    for line in SOURCE.read_text().splitlines():
        if line.startswith("ENCODING "):
            codepoint = int(line.split()[1])
        elif line.startswith("BBX "):
            assert line == "BBX 8 16 0 -4", line
        elif line == "BITMAP":
            bitmap = []
        elif line == "ENDCHAR":
            assert codepoint is not None and len(bitmap) == 16
            assert 0 <= codepoint <= 0x10FFFF and codepoint not in glyphs
            glyphs[codepoint] = bytes(bitmap)
            bitmap = None
        elif bitmap is not None:
            bitmap.append(int(line, 16))
    OUTPUT.write_bytes(b"".join(struct.pack("<I", cp) + glyphs[cp] for cp in sorted(glyphs)))
    print(f"{len(glyphs)} glyphs, {OUTPUT.stat().st_size} bytes: {OUTPUT}")


if __name__ == "__main__":
    build()
