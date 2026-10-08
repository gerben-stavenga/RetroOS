# Uni-VGA

Upstream: https://inp.nsk.su/~bolkhov/files/fonts/univga/

`u_vga16.bdf` and `uni-vga.lsm` are unmodified files from the upstream
`uni-vga.tgz` archive. BDF SHA-256:
`6a7420c7f49bb1888ebd318c6adede6c8458565232bcb7fcc9e1f27d8e40fdce`.

Copyright (c) 2000 Dmitry Bolkhovityanov, bolkhov@inp.nsk.su.
The upstream homepage states: “The UNI-VGA font can be distributed and
modified freely, according to the X license.” The included upstream LSM
also identifies the copying policy as “Freely Distributable”.
Basic Latin originates in DosEmu's vga.bdf; Hebrew comes from a public domain
console font; Arabic glyphs were donated by Behdad Esfahbod. See the upstream
homepage for acknowledgements.

Run `python3 tools/build_unicode_font.py` from the repository to regenerate
`lib/src/fonts/unicode_8x16.bin`. Each sorted record holds a little-endian
Unicode scalar (four bytes), then sixteen bitmap rows (MSB is the left pixel).
There are 2,899 records, taking 57,980 bytes. The kernel does not parse BDF.

The atlas covers a subset of Unicode, including Latin, Cyrillic, Greek and
box drawing. It does not include CJK or modern emoji. Unsupported scalars
render as `?`. Bitmap lookup does not implement combining marks, bidirectional
layout or Arabic shaping.

VGA 8×16 fonts are assembled from this atlas using the selected OEM page's
glyph mapping. Existing 8×8 and 8×14 fonts retain their original bitmaps.
