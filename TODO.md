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
- [ ] **Complete raw disk compatibility where software requires it.** Floppy
  `INT 13h` services are implemented. Add the useful hard-disk services and
  DOS absolute-sector interfaces against mounted media. Keep access mediated
  by the DOS machine rather than exposing host block devices directly.
- [ ] **Finish the MSCDEX device and CD-audio interfaces.** The persistent OSD
  slot, D: drive, ISO 9660 filesystem, media-change handling, and ISO/CUE/BIN
  Mode 1 data tracks are implemented. Add the MSCDEX device-request surface,
  TOC queries, and audio play/pause/stop controls. A pure-audio disc has no
  filesystem but must remain an MSCDEX CD device; mixed-mode audio tracks must
  feed the mixer. Add XA, Joliet, Rock Ridge, multisession, and unusual sector
  modes only as compatibility demands them.
- [ ] **Add DOS code-page and NLS filename semantics.** The Windows
  `INT 21h AX=71xx` LFN query, open, find, mutation, canonical-name, and
  independent search-handle surface is implemented. Replace ASCII-only case
  folding and raw-byte names with active OEM-code-page rules, and add the
  required OEM/ANSI/Unicode conversions, including the non-OEM forms of
  `AX=71A8h`.
- [ ] **Finish and correct the advertised LIM EMS 4.0 interface.** EMS now
  reserves handle 0 from application allocation and reuses released pages, but
  the protocol surface still needs conformance work. `43h` must reject a
  zero-page request with `89h` and distinguish total (`87h`) from currently
  free (`88h`) exhaustion. Model OS handle 0 as active in `4Bh`/`4Dh`; increase
  the 16-application-handle limit if compatibility requires it. Only advertise
  EMS when `scan_uma` actually reserves a 64 KiB page frame, and make unmapped
  windows inaccessible. Tighten `50h` so zero-count, AL, count, exact segment,
  and per-entry failure semantics do not desynchronize the shadow map; return
  exact `51h` exhaustion and `58h` subfunction errors. Implement the EMS 3.0
  save/restore calls (`47h`/`48h`), EMS 3.2 whole-map call (`4Eh`), and EMS 4.0
  partial maps (`4Fh`), attributes/names/directory (`52h`-`54h`), alter-map
  jump/call (`55h`/`56h`), and move/exchange (`57h`). The OS/environment calls
  `59h`-`5Dh` remain lower priority.
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

## Emulator-specific reference issues

These also reproduce in ordinary QEMU/FreeDOS and are not necessarily RetroOS
bugs:

- QEMU 8.2 odd/even VGA addressing corrupts the Keen 4 sign-on screen and
  Jazz Jackrabbit's tweaked 256-color mode. The upstream fix should be present
  in QEMU 9 or newer.
- QEMU does not naturally provide the `0x3DA` hsync/vsync behavior expected by
  several DOS games; RetroOS supplies synthetic trace timing.
- QEMU SB16 emulation can stop Dune II digitized speech after its first sample.
