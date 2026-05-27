# DOS Game Compatibility — Bug Sprint

## Kernel — virtual IF gets stuck at 0
- Freezes seen for
      * Dos Navigator
      * Sokoban
      * Zone66
      * TIM
- [ ] Intermittent across games: a program runs fine for a while then
      freezes. F12 dump shows EFLAGS.IF=0 — some interrupt sequence
      (INT reflect / IRET / exception dispatch / mode transition) is
      leaving the user's virtual IF cleared and never restoring it.
      vPIC IRQs queue up but never get delivered, so anything waiting
      on a timer/keyboard IRQ wedges. Related to the Hexen hang above
      (same symptom, also IF=0 + VIP=1), but here it's not game-specific
      so the IF=1→0-without-pairing path is somewhere on a common code
      path, not Hexen-specific.

## INT 10h teletype rendering
- [x] Fixed: word-sized passthrough for Bochs VBE ports 0x01CE/0x01CF/0x01D0
      in `handle_in_event`/`handle_out_event`. SeaBIOS's graphics-mode
      teletype reads/writes those to program the display; our byte-wise
      emulator returned zeros, so glyph-blit math computed a junk
      framebuffer offset and nothing rendered. Alley Cat, Digger and
      similar now show text in graphics modes.

## Prince of Persia
- [ ] Key events missed, resulting in stuck running (always running in one 
      direction) until you press arraw again and key release is seen.

## Offroad
- [ ] Doesn't work — failure mode TBD (capture trace)

## Borland C IDE
- [ ] **Mouse click crashes**. BC installs INT 33 AX=000C with a PM
      handler address (ES:DX = PM selector:offset, e.g. `030F:00F3`).
      Our `mouse_callback_invoke` does a VM86 `CALL FAR cb_seg:cb_off`,
      treating the PM selector value as a real-mode paragraph → wild
      jump → crash. **Fix sketch:** in `int_33h` AX=000C from PM,
      allocate an internal DPMI callback wrapping the client's PM
      handler. Reuse the existing `dpmi.callbacks[]` pool + a new
      `MouseEvent` kind tag in `callback_entry` so MS-Mouse register
      convention (`AX=cond, BX=buttons, CX=x, DX=y, SI=dx, DI=dy`) is
      used instead of DPMI 0303's `DS:SI/ES:DI` setup. Likely shared
      root cause with Settlers below.
- [ ] **Wolf3d project compile crashes**.

## Settlers
- [ ] **Mouse crashes.** Probably same root cause as Borland C IDE above
      (PM handler installed via INT 33 AX=000C, our mouse_callback_invoke
      treats PM selector as RM paragraph). Re-test after the BC mouse
      fix lands; if it still crashes, it's a different mouse-driver
      convention requiring separate handling.

## Monkey Island 1, 2 / Indiana Jones IV (Atlantis) — SCUMM
- [ ] Both hang at startup before the LucasArts logo paints. Stuck inside
      SeaBIOS `wait_irq` (`STI; HLT; CLI; CLD; RETD` at F000:B7C0). INT
      15h is not the trigger — needs fresh diagnosis.

## Indiana Jones and the last crusade
- [ ] Division by 0 error on startup

## Jazz Jackrabbit
- [ ] Get it working — its bundled DPMI host rejects us. Jazz ships with
      its own extender (Borland RTM), and that host.

## Epic Pinball
- [ ] Menu is way too fast, arrow keypresses often result in 2/3 steps

## One Must Fall 2097
- [ ] (sb-dma-virt) MOD music has deep comb-echo "reverb" + unstable
      tempo at "ultra high quality" mixing; "486" mixing sounds normal.
      Not a buffer/remap-coherency bug (a coherency fault would echo at
      any rate). It's a throughput ceiling: with host IRQ5 re-armed on
      the guest vPIC EOI (`0x20`) — the correct, existing trigger — the
      full per-IRQ round trip (QEMU sb16 → host trap → event-loop drain
      → relay → vPIC → mode-transition into guest ISR → passthrough port
      I/O traps → EOI → cross-mode restore) exceeds the ultra-quality
      segment period, so free-running auto-init drops segments. Prime
      suspect: `run_qemu.sh` runs QEMU under TCG (no `-enable-kvm` /
      `-accel`), inflating every trap. Rejected dead-ends: auto-init
      special-case + kernel-side 2xEh ack (reverted — both hacks); the
      0x22E-read re-arm idea (wrong; EOI 0x20 is the right trigger).
- [ ] Restart from launcher after quitting OMF hangs. **Diagnosis
      confirmed** via fresh trace: OMF2 enters a tight `INT 21 AH=2C`
      (GetTime) timeout loop that OMF1 never executes (526 calls vs 0)
      — different sound-init branch. EFLAGS in the loop: IF=0, VIP=1,
      vpic `pending=[08,0F,09]` (timer + SB IRQ + kbd queued, all
      blocked by IF=0). BIOS tick at `0:046C` therefore can't advance,
      AH=2C returns the same time forever, the timeout never fires.
      Root is *not* IF=0 itself (umbrella IF-stuck bug downstream) —
      it's persistent HW state (most likely SB DSP / real 8237 / host-
      IRQ5 mask) carried over from OMF1 sending OMF2 down a "wait for
      the card to settle" branch. Speculative fix: issue an SB DSP
      reset and mask the host SB channels in `release_dma_pool` so the
      next program sees a clean card.

## Pinball Fantasies
- [ ] Doesn't boot. INTRO.PRG loads, sets mode 13h, never paints the
      LucasArts/intro logo. Spends ~80 % of runtime in a tight VSYNC-
      counter loop at `3E93:1BC8` (`linesync` macro from INTRO.ASM line
      3342, followed by `INC BX; JNZ outer; CLI`). The outer loop wraps
      a full 0x10000 INC BX iterations.
- [ ] Loop progresses (BX values change between F12 dumps: 2871, 815E,
      E05C, 2FF8…) so the inner spin DOES exit, but the game stays in
      this routine — likely an outer animation/wait loop calling it
      many times waiting on something else.
- [ ] Source from historicalsource/pinballfantasies confirms the
      pattern; file containing the outer-loop call site isn't in the
      open-source drop (probably a sound/mod-player .OBJ linked in).
- [ ] Diagnosis: capture more of the surrounding code (extend prof
      F12 dump to a full instruction window) or single-step the outer
      loop after the inner exits to find what condition it's polling.

## Aladdin
- [ ] Sound is bad and game after a bit starts producing garbage on screen

## GoldenAxe
- [ ] Keyboard is missing keys preventing from actually selecting
      a player and starting the game. You need awkward keyboard bindings
      in its keyboard config menu

## Pinball illusions
- [ ] pMAX protected mode is incompatible

## Extreme pinball
- [ ] Kernel panic on keypress

## Strunts
- [ ] Does not start

# QEMU related problems

There are some known problems that also occur in regular QEMU+freedos 
emulation, which should match original hardware closest. These are
thus not related to RetroOS but due to inaccurate QEMU emulation.

## List

- Odd/even vga address mode problem
  * Keen4e signon screen is slightly garbled. QEMU EGA emulation is doing
    something wrong with odd/even addressing, causing the checkmarks to
    by located at wrong position and attribute bytes to garble part of
    screen.
- No hsync/vsync emulation in vga port 3da.
  * Wolf3d hangs
  * Epic pinball, supaplex and other games unplayable fast 
  RetroOS solves this explicitly by producing synthetic vtrace/htrace
- SB16 emulation problem
  * Dune2 stops digitized speech after first sample