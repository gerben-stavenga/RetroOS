# Backend tests

Run the complete locally available suite with `bash test/run_all.sh`.
The summary distinguishes passes, failures, and missing prerequisites.
Set `RETRO_REQUIRE_KVM=1` to fail instead of skipping when `/dev/kvm` cannot
be opened; CI requires this.
CI also sets `RETRO_REQUIRE_PUBLIC=1`: missing prerequisites for public tests
fail the job instead of silently skipping coverage. Proprietary assets and
the desktop-only 86Box reference remain optional there.

| Backend | Coverage |
| --- | --- |
| Hosted TCG | Unit/MMU tests, Navigator, games, video/sound probes, LFN, HX DPMI, XMS |
| Hosted KVM | The same hosted integration suites, hardware execution proofs, Navigator screen comparison against TCG |
| QEMU / metal | FAT and Multiboot storage, guest program execution, HostFS recovery, root policy, serial logging; UEFI AC'97/HDA/silent device matrix and sustained HDA PCM under TCG and KVM; proprietary DPMI/game probes when assets exist |
| Bochs / metal | Public XMS, HX DPMI and VBE probes, with SDL's dummy video driver (requires `bochs-sdl`) |
| 86Box / metal | Native SB16 sustained interrupts, completion protocol and discovery; requires an installed emulator and display |

Select individual suites with a space-separated `RETRO_TEST_ONLY`, for example:

```sh
RETRO_REQUIRE_KVM=1 RETRO_TEST_ONLY='hosted_games_kvm hosted_diff unit_kvm' bash test/run_all.sh
ENGINE=kvm bash test/hosted_games.sh
ENGINE=kvm bash test/dpmi_hx.sh
ENGINE=kvm bash test/xms.sh
ENGINE=kvm python3 test/lfn.py
```

Directly requesting the KVM game suite without KVM access fails. The default
engine for a directly invoked hosted suite is TCG; the aggregator selects
each engine explicitly.

The KVM execution proofs include remapping a previously executed code page
without changing CR3. They assert that the next entry executes the new frame,
catching stale translations after host-side page-table edits (the cause of
Navigator hanging in its loader).

The host unit group includes formatting, heap, ext4 (including independently
generated filesystem images), and Voodoo tests in addition to kernel, CPU,
VGA, and sound coverage. Sustained audio records a minute of actual HDA PCM
and rejects missing/truncated output, prolonged silence, repeated underruns,
and crashes, after a ten-second loading/settling period. The old per-driver
HDA counters no longer exist; cursor and ring
accounting are tested in `lib:sound_test`. The PCM checker itself has negative
tests for silence, stalled playback and truncated recordings.

`python3 test/xhci_smoke.py` boots with a USB keyboard and mouse on xHCI,
checks both HID endpoints initialize, and runs HELLO.COM. Host unit tests
(`//arch-metal:xhci_dma_test`) cover X99's 16 scratchpads, the full 1023-buffer
count, non-overlapping DMA regions, and allocation failure.

`python3 test/shared_disks.py` checks that the shared data disk is seeded once,
preserves guest changes across launches, rejects concurrent launchers, and checks
backend disk attachments. `test/private_data_disk.py` prepares disposable copies
for probes that need a `CONFIG.SYS` command; normal launches never inject it.

`python3 test/machine_layout.py` boots an ext4 laptop-style layout containing
`/boot/grub`, checks UUID selection with reordered disks, read-only runtime files,
persistent C: writes, rejection of a missing UUID, and a clean ext4 filesystem.
It exercises ATA bus-master DMA (asserting that startup selected DMA without
firmware setup), NVMe, and AHCI, and verifies the final bytes from the host.
Kernel unit tests cover shared transfer batching, partial sectors, bounds,
failure quarantine, IDE DMA descriptors/timings, and AHCI command encoding.

`python3 test/dn_state.py` drives the shipped DN through QEMU: save configuration,
execute a command, exit and restart, then verify persistent history/config and
separate temporary files. The data disk's runtime directory stays empty.

After `bazelisk build //:release`, `python3 test/release.py` checks checksums,
extracts the public bundles, exercises the packaged installer, and boots the
prebuilt VM launcher without invoking Bazel. CI uploads the bundles only after
all required checks pass. `dpmi_hdpmi_pvi` is a local reference test requiring
an installed FreeDOS disk; it is optional in CI.
