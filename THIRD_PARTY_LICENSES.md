# Third-party components & credits

RetroOS's own source is under the WTFPL (see `LICENSE`), except for the
explicitly licensed adaptations below. Dependencies are fetched at build time
and some derived code is maintained in-tree. This file credits their authors
and records their licenses.

> **Redistribution note.** Some components are copyleft. Builds embedding the
> FreeDOS CPI fonts carry GPL-2.0-or-later terms; hosted builds linking
> **unicorn** also carry GPL-2.0 terms. RetroOS's own source stays WTFPL,
> while distribution of a compiled binary must honor the included components'
> licenses.

## Copyleft

| Component | Used for | License | Author / project |
|---|---|---|---|
| **unicorn** (`unicorn-engine`, `unicorn-engine-sys`, C core) | CPU emulation (hosted TCG backend) | GPL-2.0 | Unicorn Engine — https://www.unicorn-engine.org |
| **nuked-opl3** | OPL3 (YMF262) FM synthesis core | LGPL-2.1 | Nuke.YKT et al. — https://github.com/nukeykt/Nuked-OPL3 |
| **FreeDOS CPI fonts** (`lib/src/fonts`) | VGA 8×8, 8×14, and 8×16 glyphs for CP850, CP852, CP866 | GPL-2.0-or-later | Henrique Peron — https://github.com/FDOS/cpi |

## Derived work in-tree

The font bitmaps are extracted from FreeDOS CPI's `ega.cpx` and `ega3.cpx`.
The original CPX files, upstream readme, and GPL text are preserved in
`third_party/freedos_cpi/`. The Unicode byte mappings in
`lib/src/codepage_tables.rs` come from the [Unicode Consortium's Microsoft DOS
mapping files](https://www.unicode.org/Public/MAPPINGS/VENDORS/MICSFT/PC/).

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
| `smb2-core` (adapted vdavid/smb2) | SMB packet codecs and NTLMv2 authentication | MIT OR Apache-2.0 |
| `digest`, `hmac`, `md4`, `md-5`, `sha2`, `crypto-common`, `block-buffer`, `hybrid-array`, `typenum`, `cmov`, `ctutils`, `cpufeatures` | SMB authentication and signing | MIT OR Apache-2.0 |
| `aes`, `aes-kw`, `sha1`, `pbkdf2`, `zeroize` | Native WPA2-Personal authentication and key protection | MIT OR Apache-2.0 |
| `subtle` | Constant-time WPA2 MIC and key comparison | BSD-3-Clause |
| `num_enum`, `num_enum_derive`, `log` | SMB protocol enums and logging | MIT OR Apache-2.0 |
| `spin` | spinlocks (no_std) | MIT |
| `smoltcp`, `managed` | bare-metal IPv4, DHCP, TCP, UDP and buffer ownership | 0BSD |
| `heapless`, `hash32` | fixed-capacity network tables | MIT OR Apache-2.0 |
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

## Qualcomm native Wi-Fi bring-up

The PCI register sequencing in `kernel/src/kernel/drivers/wcn785x/{mod,reset}.rs`
is adapted from Linux v6.8 `ath12k/pci.c`, `pci.h`, and `mhi.h`, under
BSD-3-Clause-Clear. WLANFW message fields and startup sequencing in
`kernel/src/kernel/drivers/wcn785x/wlanfw.rs` follow ath12k `qmi.c`/`qmi.h`
(Linux v6.8 and current shared ath12k QMI/board-bundle definitions), under the
same license. The shared CE rings (`kernel/src/kernel/drivers/ce.rs`), HTC
framing (`kernel/src/kernel/htc.rs`), WMI startup (`kernel/src/kernel/wmi.rs`),
shared SRNG registers (`kernel/src/kernel/drivers/srng.rs`), packet-engine
bootstrap (`kernel/src/kernel/drivers/qca_dp.rs`), and WCN7850 hardware profile
also reference Linux v6.8 ath12k `dp.c`/`dp.h`, `hal.c`/`hal.h`,
`ce.c`/`ce.h`, `htc.c`/`htc.h`, `wmi.c`/`wmi.h`, and `hw.c`, under the same
license. The license is included in the WCN785x driver directory.
Common packet-engine rings and REO global configuration also reference Linux
v6.17 ath12k `dp.c`/`dp.h`, `hal.c`/`hal.h`, `hal_rx.c`, `hal_desc.h`,
and `hw.c`, under BSD-3-Clause-Clear.
The cookie-conversion tables in `kernel/src/kernel/drivers/qca_dp/cookie.rs`
reference Linux v6.17 ath12k `dp.c`/`dp.h`/`hal.h` and the `pci.c` window
encoding under that same license.
The shadow-v3 doorbell mapping, QMI TLV 0x17 encoding, and single-chip
firmware-topology HOST_CAP fields additionally reference
Linux v7.0 `ath12k/wifi7/hal.c`, `wifi7/hal.h`, and `qmi.c`/`qmi.h`, and were
checked against a local successful Linux WCN7850 startup capture. These Linux
definitions use the same BSD-3-Clause-Clear license as the ath12k sources above.
The independent SMBIOS reader in `tools/inspect_wifi_platform.py` consults the
Qualcomm type-248 metadata layout documented by Linux v7.0 ath12k
`core.c`/`core.h`, also distributed under BSD-3-Clause-Clear.
Extended regulatory event fields and capability negotiation in
`kernel/src/kernel/wmi/regulatory.rs` also reference Linux v6.17 ath12k
`wmi.c`/`wmi.h`, under BSD-3-Clause-Clear.
The passive-scan command layouts and management-event decoder in
`kernel/src/kernel/wmi/scan.rs` reference Linux v7.0 ath12k `wmi.c`/`wmi.h`;
station wake setup and regulatory channel-list units also reference its
`mac.c` and `reg.c`, under the same BSD-3-Clause-Clear license.
HTT negotiation, receive-ring registration, buffer descriptors, and RX filters
in `kernel/src/kernel/htt.rs` and `kernel/src/kernel/drivers/qca_dp/rx.rs`
reference Linux v7.0 ath12k `dp_htt.c`/`dp_htt.h`, `dp_rx.c`, `hal.c`/`hal.h`,
`wifi7/dp_rx.c`, `wifi7/hal_wcn7850.c` and `wifi7/hal_rx_desc.h`. Shared radio
configuration in `kernel/src/kernel/wmi/radio.rs` additionally references
its `mac.c` and `wmi.c`/`wmi.h`, under the same BSD-3-Clause-Clear license.
Station command/event layouts in `kernel/src/kernel/wmi/station.rs` and
packet descriptors in `kernel/src/kernel/drivers/qca_dp.rs` and
`kernel/src/kernel/drivers/wcn785x/packets.rs` additionally reference Linux
v7.0 ath12k `wmi.c`/`wmi.h`, `wifi7/dp_tx.c`, `wifi7/dp_rx.c`,
`wifi7/hal_tx.c`, `wifi7/hal_desc.h` and `wifi7/hal_rx_desc.h` under the same
BSD-3-Clause-Clear license. The independent shared WPA2 supplicant consults
IEEE RSN/EAPOL layouts and hostap's `src/rsn_supp/wpa.c` and
`src/common/wpa_common.c` as protocol references; it uses RustCrypto primitives.
The MHI/QRTR/QMI
transport (`kernel/src/kernel/drivers/mhi`, `kernel/src/kernel/qrtr.rs`, and
`kernel/src/kernel/qmi.rs`)
is implemented in Rust against their wire/register formats. The read-only
WLANFW ATHDIAG wire fields are documented in Linux ath10k
`qmi_wlfw_v01.c`/`qmi_wlfw_v01.h`; the Rust request/reply codec is independently
implemented. No
Linux kernel runtime is linked. Qualcomm firmware is installed separately
from the user's local firmware files, with its original `Notice.txt`, and
is not checked into this repository.

The WCN7850 hot-reset register address follows Linux correction
[`7588a893cde5`](https://kernel.googlesource.com/pub/scm/linux/kernel/git/torvalds/linux/+/7588a893cde5385ad308400ff167d29a29913b3a).

The Clear BSD License

Copyright (c) 2018-2021 The Linux Foundation. All rights reserved.
Copyright (c) 2021-2025 Qualcomm Innovation Center, Inc. All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted (subject to the limitations in the disclaimer
below) provided that the following conditions are met:

 * Redistributions of source code must retain the above copyright notice,
   this list of conditions and the following disclaimer.

 * Redistributions in binary form must reproduce the above copyright
   notice, this list of conditions and the following disclaimer in the
   documentation and/or other materials provided with the distribution.

 * Neither the name of [Owner Organization] nor the names of its
   contributors may be used to endorse or promote products derived from
   this software without specific prior written permission.

NO EXPRESS OR IMPLIED LICENSES TO ANY PARTY'S PATENT RIGHTS ARE GRANTED BY
THIS LICENSE. THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND
CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT
NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER
OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
