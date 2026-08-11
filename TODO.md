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
- [ ] **Pinball Illusions:** add the required pMAX protected-mode support.
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
