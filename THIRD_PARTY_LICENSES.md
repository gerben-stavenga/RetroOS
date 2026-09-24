# Third-party components & credits

RetroOS's own source is under the WTFPL (see `LICENSE`), except for the
explicitly licensed adaptations below. Dependencies are fetched at build time
and some derived code is maintained in-tree. This file credits their authors
and records their licenses.

> **Redistribution note.** Some components are copyleft. In particular, a build
> that links **unicorn** (GPL-2.0) produces a **GPL-2.0**
> binary. RetroOS is distributed as *source* (you build it yourself), so no
> combined-work distribution obligation is triggered here — but if you
> redistribute a compiled binary, that binary is GPL-2.0. RetroOS's own source
> stays WTFPL regardless.

## Copyleft

| Component | Used for | License | Author / project |
|---|---|---|---|
| **unicorn** (`unicorn-engine`, `unicorn-engine-sys`, C core) | CPU emulation (hosted TCG backend) | GPL-2.0 | Unicorn Engine — https://www.unicorn-engine.org |
| **nuked-opl3** | OPL3 (YMF262) FM synthesis core | LGPL-2.1 | Nuke.YKT et al. — https://github.com/nukeykt/Nuked-OPL3 |

## Derived work in-tree

| Component | Used for | License | Author / project |
|---|---|---|---|
| **`//third_party/voodoo`** | 3dfx Voodoo Graphics (SST-1) emulation | BSD-3-Clause | Aaron Giles — MAME `voodoo.cpp` / `voodoo_render.cpp` |
| **`//ext4` read validation** | portable ext4 checksum and on-disk validation conventions | MIT OR Apache-2.0 | Nicholas Bishop / Google — `ext4-view` |

Unlike everything else here this is *our* source: a Rust transliteration
written against a different memory/ownership model, not a fetched dependency.
It is nonetheless a derived work of Aaron Giles' BSD-3-Clause Voodoo core in
MAME and is credited as such — see `third_party/voodoo/README.md`. None of the
GPL-carrying DOSBox glue (threading, SDL, `PIC_`/`RENDER_` calls) is present.

## Permissive (MIT / Apache-2.0 / zlib)

| Component | Used for | License |
|---|---|---|
| `spin` | spinlocks (no_std) | MIT |
| `bitflags` | bitflag types | MIT OR Apache-2.0 |
| `crc`, `crc_catalog` | CRC (image/MD5 verify) | MIT OR Apache-2.0 |
| `rustc-demangle` | symbol demangling (backtraces) | MIT OR Apache-2.0 |
| `compiler_builtins` | intrinsics (`mem*`, `__udivdi3`, …) | MIT OR Apache-2.0 |
| `libc` | host libc bindings (hosted) | MIT OR Apache-2.0 |
| `kvm-ioctls`, `kvm-bindings` | KVM execution engine (hosted `--kvm`) | Apache-2.0 |
| `sdl2` (Rust) + SDL2 | windowed host emulator (`retroos-play`) | MIT (crate) / zlib (SDL2) |

## Build tooling (not linked into the OS)

Bazel rulesets used only to build — `rules_rust`, `rules_cc`, `rules_nasm`,
`rules_pkg`, `rules_foreign_cc`, `platforms` — are Apache-2.0.

---

Licenses above are the projects' documented terms; consult each project's own
`LICENSE` for the authoritative text. Thanks to all of these authors — RetroOS
would be a great deal more work without them.

## NVIDIA video-BIOS workarounds

`kernel/src/kernel/drivers/nvidia_vga.rs` and the native BIOS wrapper contain
workarounds inspired by **EGAFIX 0.08**, by **Gael Cathelin** (the supplied
`EGAFIX08.zip` / `egafix.asm`), and adapted from **NEWAX**, by **Marco Pistella**
(https://github.com/Marco-Pistella/NEWAX). EGAFIX is credited for its legacy
mode substitutions and hardware register recipes; its TSR is not included.
NEWAX is credited for NVIDIA extended CRTC pitch/start-address programming
and compatibility detection. Its MIT notice follows:

```text
MIT License

Copyright (c) 2026 Marco Pistella

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

## dISAppointment LPC/ISA setup

`kernel/src/kernel/drivers/isa_lpc.rs` adapts the hardware setup from
[sapphisa.c by rasteri](https://github.com/rasteri/dISAppointment/blob/main/software/sapphisa.c),
part of dISAppointment. The upstream project and this adaptation are licensed
under [Creative Commons Attribution-ShareAlike 4.0 International](https://creativecommons.org/licenses/by-sa/4.0/).
The upstream license is at https://github.com/rasteri/dISAppointment/blob/main/LICENSE.
Provided as-is, without warranties; see the linked license for its disclaimer.

RetroOS changes: Rust implementation, explicit GRUB opt-in, Intel chipset and
Fintek identity checks, register readback with rollback, and standard ISA DMA
reset/cascade initialization that preserves the kernel's interrupt masks.
No endorsement by the original author is implied.
