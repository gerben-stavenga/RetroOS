# TODO

This file lists unfinished work only. Completed designs and investigations live
in Git history.

## Platform and kernel structure

- [ ] **Hosted real-time audio.** Feed the emulated audio sink to SDL (or an
  equivalent host device); the hosted backend currently only writes a WAV
  file.
- [ ] **Run background DOS threads.** Focus already owns input and display,
  but the event loop still executes only the focused thread. Keep runnable
  background threads advancing while preserving foreground responsiveness.
- [ ] **Finish the scheduler seam.** Consolidate yielding and scheduling so
  blocking, yielding, and focus changes all use one
  scheduler operation.
- [ ] **Clean up process lifecycle.** Move the old `handle_fork_exec` path onto
  `ExecutionContext` and make ownership transfer explicit.
- [ ] **Reduce DOS dispatch.** Split the large port-dispatch matches and the
  monolithic `kernel/src/kernel/dos/dos.rs` INT 21 implementation into
  cohesive devices/services.
- [ ] **Make the hostfs probe truthful.** `hostfs::init` currently treats the
  presence of a COM1 UART as proof that the host protocol is available; add a
  protocol handshake and timeout.
- [ ] **Exercise modern UEFI boot on real hardware.** Validate the existing
  GRUB path, GOP, and storage on the target laptop; add xHCI keyboard support
  if it has no usable i8042 controller.

## Interp backend

- [ ] **Idle efficiently.** An idle DOS Navigator session still divides time
  between the CPU worker and SDL thread instead of sleeping until useful work
  or an event arrives.
- [ ] **Implement COW fork.** Interp fork still copies the complete address
  space. Correctness is adequate, but the cost is unnecessarily high.
- [ ] **Remove the DPMI IOPL=3 escape hatch.** Find where protected-mode
  clients acquire IOPL 3, keep guest port access mediated by the personality,
  and ensure metal pins the same policy into the TSS I/O bitmap.

## Build and toolchain

- [ ] **Upstream the generated Unicorn bindings into the fork.** Remove the
  repository-local workaround once the fork contains the required bindings.
- [ ] **Watch the `rules_python` stale-repository failure.** Remove the current
  workaround when the `rules_foreign_cc` dependency no longer creates the
  obsolete repository.

## DOS compatibility

- [ ] **Complete remaining DOS filesystem edge cases.** Core create/delete,
  mkdir/rmdir/rename, commit, create-new/temp, attributes, timestamps,
  sharing and byte-range locking are implemented. Finish current-directory
  edge cases, exact wildcard/volume-label behavior, and DOS error reporting.
  Add standard character-device names and behavior (`NUL`, `CON`, `AUX`,
  `PRN`, and `COM`/`LPT` aliases) where programs can encounter them through
  file APIs.
- [ ] **Add the common DOS control and error paths.** Implement compatible
  Ctrl-C/Break checking, critical-error handling (`INT 24h`), and the process
  and file-state behavior applications expect around failed or interrupted
  calls.
- [ ] **Add raw disk compatibility where software requires it.** Implement the
  useful `INT 13h` disk services and DOS absolute-sector interfaces against
  mounted media. Keep access mediated by the DOS machine rather than exposing
  host block devices directly.
- [ ] **Mount FAT filesystems from floppy images.** The OSD floppy slot only
  supplies a sector image; DOS file APIs also need a filesystem layer over it.
  Implement BPB parsing and FAT12 first, including subdirectories, allocation,
  create/write/delete/rename, timestamps and attributes, media-change handling,
  and safe writeback on eject. Add FAT16 for larger floppy/superfloppy images
  and tolerate common nonstandard geometries when the BPB is self-consistent.
  Long filenames belong to the separate LFN work; short-name FAT access must
  work independently.
- [ ] **Add CD-ROM and MSCDEX compatibility over OSD media slots.** Keep
  persistent floppy and CD drive slots whose inserted media can change while
  the drive remains registered. Provide a synthetic MSCDEX interface, drive
  letter, ISO 9660 data access, media-change status, TOC queries, and audio
  play/pause/stop controls. A pure-audio disc has no filesystem but remains an
  MSCDEX CD device; a mixed-mode disc mounts its data track and sends audio
  tracks to the mixer.
- [ ] **Implement the initial CD image formats deliberately.** Start with
  ISO 9660 primary volume descriptors, directory extents, and `;1` version
  stripping. Support Mode 1/2048 directly and Mode 1/2352 by extracting user
  data. CUE/BIN track offsets and mixed-mode layout come next; XA, Joliet,
  Rock Ridge, multisession, and unusual sector modes can remain later
  extensions.
- [ ] **Add an LFN read/query subset, then mutation support.** DFS already
  retains long names and synthesizes short aliases, so implement the Windows
  `INT 21h AX=71xx` query/open/find surface first. Full LFN behavior also needs
  correct mkdir/rmdir/rename operations and independent concurrent search
  handles. Add code-page/NLS behavior separately where applications depend on
  it.
- [ ] **Finish LIM EMS 4.0 application services.** Correct allocation so
  application handles begin at 1 (handle 0 is reserved) and freed physical
  pages are reusable. Then implement save/restore page map (`47h`/`48h`),
  whole and partial page-map operations (`4Eh`/`4Fh`), handle attributes and
  names/directories (`52h`-`54h`), alter-map-and-transfer (`55h`/`56h`), and
  move/exchange memory (`57h`). The OS/environment functions `59h`-`5Dh` are
  lower priority.
- [ ] **Audit XMS conformance and edge cases.** Verify handle lifecycle,
  realloc/free behavior, move overlap and validation, A20 ownership, reported
  memory limits, UMB calls, and exact error returns against common HIMEM/XMS
  clients.
- [ ] **Add remaining common BIOS peripherals as demand appears.** Cover the
  useful serial, printer, and joystick BIOS services and tighten keyboard,
  mouse, timer, and video semantics exposed by real games.
- [ ] **Treat VCPI/pMAX as privileged-client compatibility, not more DPMI.**
  CWSDPMI consumes VCPI in order to provide DPMI; it does not provide VCPI to
  pMAX. Investigate the exact pMAX calls and implement the smallest constrained
  VCPI/privileged execution path required by Pinball Illusions. General VCPI
  gives its client ring-0-style ownership of paging, descriptors, interrupts,
  and I/O, so native backends cannot safely expose it as an ordinary DOS
  thread; the interpreter can virtualize it more naturally.
- [ ] **Debug The Incredible Machine's timer interrupt chain.** TIM has never
  worked and currently reaches `0000:00c4`, inside the IVT, after entering its
  `INT 08h` handler at `0027:0510`. Byte `62h` is then decoded as `BOUND` and
  raises exception 5 (`#BR`). Trace the first far call, `RETF`, or `IRET` that
  produces a zero CS to distinguish a bad saved/chained timer vector (including
  `INT 21h AH=25h/35h` semantics) from a malformed VM86 interrupt frame. This
  failure is unrelated to pMAX, VCPI, or DPMI.
- [ ] **Pace native DOS CPU execution independently of display work.** F22's
  startup calibrates a `DEC ECX` busy loop against a timer counter. On KVM with
  native VGA, even a nearly full 32-bit count completes below its 120-tick
  threshold, the count wraps, and calibration retries for minutes. QEMU/UEFI
  and the OSD mask this by spending time on software rendering; TCG masks it
  through interpreter overhead. Add an explicit DOS CPU-speed/throttling policy
  so timing never depends on the display backend. Do not special-case F22,
  joystick port `0x201`, or restore needless native-VGA presentation.
- [ ] **Ironman Off-Road Racing:** fix the timer ISR's polling of port `0x3DA`.
  It requires a runtime-derived number of consecutive samples and can grind
  to a halt when emulated retrace advances independently of guest polling.
- [ ] **Aladdin:** sound degrades and graphics eventually become corrupt.
- [ ] **Golden Axe:** missing keyboard keys prevent selection.
- [ ] **Comanche/F22:** no arrow key response.
- [ ] **Civilization:** introscreen crawls

## Emulator-specific reference issues

These also reproduce in ordinary QEMU/FreeDOS and are not necessarily RetroOS
bugs:

- QEMU 8.2 odd/even VGA addressing corrupts the Keen 4 sign-on screen and
  Jazz Jackrabbit's tweaked 256-color mode. The upstream fix should be present
  in QEMU 9 or newer.
- QEMU does not naturally provide the `0x3DA` hsync/vsync behavior expected by
  several DOS games; RetroOS supplies synthetic trace timing.
- QEMU SB16 emulation can stop Dune II digitized speech after its first sample.
