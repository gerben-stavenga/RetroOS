# Third-party components & credits

RetroOS's own source is under the WTFPL (see `LICENSE`). It does **not** vendor
third-party code — the components below are fetched at build time (Bazel
`http_archive` / `crate.spec`) and linked into the build. This file credits
their authors and records their licenses.

> **Redistribution note.** Some components are copyleft. In particular, a build
> that links **lwext4** or **unicorn** (both GPL-2.0) produces a **GPL-2.0**
> binary. RetroOS is distributed as *source* (you build it yourself), so no
> combined-work distribution obligation is triggered here — but if you
> redistribute a compiled binary, that binary is GPL-2.0. RetroOS's own source
> stays WTFPL regardless.

## Copyleft

| Component | Used for | License | Author / project |
|---|---|---|---|
| **lwext4** | writable ext4 filesystem (metal + hosted) | GPL-2.0 [1] | Grzegorz Kostka — https://github.com/gkostka/lwext4 |
| **unicorn** (`unicorn-engine`, `unicorn-engine-sys`, C core) | CPU emulation (hosted TCG backend) | GPL-2.0 | Unicorn Engine — https://www.unicorn-engine.org |
| **nuked-opl3** | OPL3 (YMF262) FM synthesis core | LGPL-2.1 | Nuke.YKT et al. — https://github.com/nukeykt/Nuked-OPL3 |

[1] lwext4 is BSD-3-Clause except `ext4_extents.c` and `ext4_xattr.c`, which are
GPL-2.0; since extents are required for ext4, the effective license is GPL-2.0.

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
