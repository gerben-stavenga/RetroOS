# Minesweeper Win32 compatibility fixture

`MINESWPR.EXE` is the unmodified 32-bit x86 release binary from
<https://github.com/wesmar/minesweeper/releases/tag/minesweeper>.

- Upstream: `wesmar/minesweeper`
- License: MIT, reproduced in `LICENSE.md`
- Downloaded asset: `minesweeper.zip`
- ZIP SHA-256: `4f4d19f5004d5f70d2f94c2063928595dcedd47f730d7f0dd2e949d89874e547`
- EXE SHA-256: `d97ab2cabe8e4eb9cfd95079fb743bdd9b762592e2774382bc0d032a22b2988e`

The executable is intentionally kept unchanged. It is the acceptance fixture
for RetroOS's native PE32 USER32/GDI32 window personality.
