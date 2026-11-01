# Backend tests

Bazel owns test discovery, dependencies, execution, caching, and results.
CI and local development use the same targets:

```sh
bazelisk test //tests:unit
bazelisk test //tests:portable
bazelisk test //tests:windows_threads_kvm //tests:machine_fat
bazelisk test //tests:release
```

`unit` contains Rust and Python unit tests, plus workflow validation. On a
machine without KVM, add `--test_tag_filters=-requires-kvm`. `portable`
contains the public checks that do not require hardware virtualization or
locally installed Wi-Fi firmware. QEMU, Bochs, GRUB, and filesystem tools
still need to be installed for the corresponding integration tests.

`boot`, `dos`, `personalities`, and `devices` select explicit Bazel tags.
`public` combines all public checks; use `--test_tag_filters=-requires-qemu-kvm`
on hosted CI runners that support the hosted KVM engine but cannot boot
firmware guests with KVM. Select individual targets to run a smaller set.
Missing prerequisites fail a selected test; the harness does not silently
skip it. Guest tests carry Bazel’s `exclusive` tag: they run after builds and one
at a time within each shard, avoiding contention with compilers or other
emulators. Builds and unit tests remain parallel.

Each integration target declares its compiled inputs in `metal` and `host`.
The rule applies the appropriate platform transition and passes the outputs
to an isolated writable workspace. Harnesses consume those files; they do
not build or query Bazel, switch platform flags, or share the checkout's
`bazel-bin`. Python and the terminal packages are supplied by `rules_python`.

Add test targets to [tests/BUILD.bazel](../tests/BUILD.bazel), with a suite tag
and declared dependencies. Suite membership follows those tags. Bazel writes
`test.log` and JUnit `test.xml` under `bazel-testlogs/tests/<target>/`.
`test/run_all.sh` is only a compatibility launcher for `//tests:portable`.

Manual regressions, proprietary game checks, FreeDOS references, and desktop
emulator checks have `manual` targets. Select them explicitly after providing
their required fixtures. Pass harness options using `--test_arg=...`; tests
that exercise native Bazel/Rust builds require explicit `--install-base` and
`--toolchain` paths rather than querying the outer Bazel server.

| Backend | Coverage |
| --- | --- |
| Hosted interpreter | Unit/MMU tests, Navigator, games, video/sound probes, LFN, HX DPMI, XMS |
| Hosted KVM | Hardware execution, DOS/Windows/OS2/Linux APIs, input, threads, and differential tests |
| QEMU / metal | Disk and module boot, BIOS/UEFI, storage, USB, network, audio, and process execution |
| Bochs / metal | Public XMS, HX DPMI and VBE probes with a headless SDL driver |
| 86Box / DOSBox-X | Explicit manual reference targets requiring their emulator and display |

The KVM execution proofs include remapping a previously executed code page
without changing CR3. They assert that the next entry executes the new frame,
catching stale translations after host-side page-table edits (the cause of
Navigator hanging in its loader).

The EMS probe covers simultaneous aliases, saved page maps, cross-page
move/exchange, overlapping regions, rejected mappings, and handle resizing.
It exercises the services used by Aladdin without requiring the game assets.

`bazelisk test //tests:dos_cpu_pacing` uses KVM to compare an unthrottled DOS
busy loop with a per-program `cpu25` launch. It checks BIOS timer progress,
COMMAND.COM fork and LOADFIX launches, and a batch that returns to full speed
for its next program. It needs `nasm`, `mkfs.ext4`, `debugfs` and KVM access.

The host unit group includes formatting, heap, ext4 (including independently
generated filesystem images), and Voodoo tests in addition to kernel, CPU,
VGA, and sound coverage. Sustained audio records a minute of actual HDA PCM
and rejects missing/truncated output, prolonged silence, repeated underruns,
and crashes, after a ten-second loading/settling period. The old per-driver
HDA counters no longer exist; cursor and ring
accounting are tested in `lib:sound_test`. The PCM checker itself has negative
tests for silence, stalled playback and truncated recordings.

`bazelisk test //tests:xhci_smoke` boots with a USB keyboard and mouse on xHCI,
checks both HID endpoints initialize, and runs HELLO.COM. Host unit tests
(`//arch-metal:xhci_dma_test`) cover X99's 16 scratchpads, the full 1023-buffer
count, non-overlapping DMA regions, allocation failure, and BIOS ownership
handoff. `//arch-metal:phys_mm_test` covers the RAM bitmap, shared refcounts,
firmware holes, contiguous allocations, and bootstrap metadata.

`bazelisk test //tests:arch_tls` checks guest FS/GS restoration across syscalls and
timer interrupts under legacy paging, PAE, and a 64-bit guest with a GS base
above 4 GiB. Add `--kvm` to run the 32/64-bit cases on hardware.

`bazelisk test //tests:physical_memory` touches and releases 300 MiB twice under
legacy paging, PAE, and a 64-bit client. The latter two give QEMU only 128 MiB
below 4 GiB, so the probe must use high physical RAM.

`bazelisk test //tests:shared_disks` checks that the shared data disk is seeded once,
preserves guest changes across launches, rejects concurrent launchers, and checks
backend disk attachments. `test/private_data_disk.py` prepares disposable copies
for probes. Startup commands are set in the disposable boot INI with `--cmd`;
the data disk is never edited to inject commands.

`bazelisk test //tests:machine_layout` boots an ext4 laptop-style layout containing
`/boot/grub`, checks UUID selection with reordered disks, read-only runtime files,
persistent C: writes, rejection of a missing UUID, and a clean ext4 filesystem.
It exercises ATA bus-master DMA (asserting that startup selected DMA without
firmware setup), NVMe, and AHCI, and verifies the final bytes from the host.
Kernel unit tests cover shared transfer batching, partial sectors, bounds,
failure quarantine, IDE DMA descriptors/timings, and AHCI command encoding.

`bazelisk test //tests:dn_state` drives the shipped DN through QEMU: save configuration,
execute a command, exit and restart, then verify persistent history/config and
separate temporary files. The data disk's runtime directory stays empty.

`bazelisk test //tests:release` builds the release and checks checksums,
extracts the public bundles, exercises the packaged installer, and boots the
prebuilt VM launcher without invoking Bazel. Each ATA/AHCI/NVMe case writes
and closes a file, then checks its bytes in the disk image after shutdown.
BIOS covers both 386 and 686 CPU configurations; UEFI covers x64. CI publishes the bundles only after
all required checks pass. `dpmi_hdpmi_pvi` is a local reference test requiring
an installed FreeDOS disk; it is optional in CI.

Hosted tests that need writable fixture files use `test/disk_fixture.py`.
It creates a private ext4 disk with explicit BOOT.INI mounts and copies guest
changes back after exit. This requires `mkfs.ext4` and `debugfs`; it does not
mount a host directory inside the kernel. Live network-sharing tests use SMB.

`bazelisk test //tests:arch_smp` boots the small `//arch-metal:smp_example` kernel on
four CPUs in legacy and PAE modes. It checks the common BSP/AP Rust entry,
initialized/zeroed and isolated TLS, dynamically allocated stacks, private GDTs
and page roots, and reuse of the low-memory trampoline after acknowledgement.
AP stacks/TLS are allocated first from the final BSS pool, then ISA DMA
buffers use the remaining space. Actual CPU boot allocations leave 128 KiB
below physical 4 MiB; the reserved pool tail may extend beyond it. Ordinary
heap/physical allocations stay outside the whole pool.
Add `--kvm` to exercise xAPIC and x2APIC startup with hardware virtualization.

`bazelisk test //tests:kernel_smp` checks actual-kernel MADT discovery and parked APs,
then runs a guest syscall/IRQ/TLS workload on core 0. Cases cover one CPU, four
CPUs, pool-limited startup with eight CPUs, sparse APIC IDs, missing ACPI, and
legacy paging. Add `--kvm` for the hardware cases. `//arch-metal:acpi_test` checks
enabled/disabled entries, x2APIC IDs, duplicates and malformed MADT records.
