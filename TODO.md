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

## Prince of Persia
- [x] Fixed (45b9bc5): the virtual 8042 surfaced a coalesced make+release in
      a single INT 9 (the event loop drains host IRQs in batches). PoP's INT 9
      handler applies only the first scancode and discards the rest, so it
      recorded "key down", threw the release away, and the prince kept running.
      Fix models the 8042 refill delay so each scancode arrives in its own
      IRQ1, the way real hardware delivers make and release.

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
- [ ] **Goal: successful WOLFSRC compile from the BC IDE** (`bc`, project
      `WOLF3D.PRJ`, sources served over hostfs at `C:\PROJECT\WOLFSRC`).
  - [x] Fixed: TASM printed its syntax screen instead of assembling. Root
        cause was unhandled INT 21h AH=37h (get switch char) — the Borland/MS
        C runtime then used `/` as the path separator, so the IDE handed TASM
        `OBJ/H_LDIV.OBJ`, whose `/H` parses as the `/h` help switch. Added an
        AH=37h handler returning `DL='/'` (DOS 5+ semantics). H_LDIV.ASM now
        assembles cleanly (`Error messages: None`). See
        `[[project_dos_switchar_pathsep]]`.
  - [ ] **Blocked: TASM hangs at exit.** After assembling H_LDIV.ASM and
        writing OBJ\H_LDIV.OBJ, TASM wedges while printing "Remaining memory"
        and never reaches `AH=4C`. Resume IP is pinned at `1B79:0DF9` (its
        decimal-print routine, confirmed by disasm) across hundreds of
        `RESUME_CONTINUATION_STUB` events with no intervening DOS calls/excs,
        yet SS:ESP wanders the whole 64K segment — the kernel keeps replaying
        the same saved frame. Suspect the continuation / `other_stack` LIFO
        bookkeeping after TASM's long run of reflected INT 21h calls through
        the bc.exe DPMI host, not a TASM bug. Next: arm `PM_STEP_BUDGET` /
        `pm_step_log` when the client first hits `1B79:0DF9` to confirm
        whether TASM advances at all, then inspect `resume_continuation_from_stub`.

## Settlers
- [ ] **Mouse crashes.** Probably same root cause as Borland C IDE above
      (PM handler installed via INT 33 AX=000C, our mouse_callback_invoke
      treats PM selector as RM paragraph). Re-test after the BC mouse
      fix lands; if it still crashes, it's a different mouse-driver
      convention requiring separate handling.

## Monkey Island 1, 2 — SCUMM
- [ ] Hits `run-time error R6003 - integer divide by 0` (#DE) just after
      entering mode 13h — the classic SCUMM fast-CPU timing calibration
      divide-by-zero (a measurement loop sees 0 timer-tick delta because the
      guest runs at full native host speed with no throttle). Same root
      cause as Indy 3's startup divide-by-0 below; fixing one should fix both.

## Indiana Jones IV: Fate of Atlantis (CD)
- [ ] **Mouse doesn't work** — no mouse clicks register; you have to drive
      menus/dialogue with Enter instead. The game now boots and runs (RTC
      wait + ext4 on-demand reads fixed the earlier hang/OOM). SCUMM runs in
      real mode (VM86), so unlike the BC IDE / Settlers cases this is *not*
      the PM-handler-as-RM-paragraph bug — likely the INT 33 button/callback
      path: either AX=0003 button state isn't reflecting presses, or the
      AX=000C event callback / AX=0005 press-count isn't delivered. Needs a
      trace of which INT 33 subfunctions SCUMM polls.

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