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
- [ ] **End-of-level door hangs, repeating.** When the prince reaches the exit
      door, the game wedges with the door animation/sound looping. Failure mode
      TBD — capture a trace at the level-exit transition (likely a wait loop on
      a timer/IRQ or sound-DMA completion that never fires).

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

## Borland RTM extender (Jazz Jackrabbit + Borland Pascal 7)
- [x] **FIXED** (branch `fix-rtm-loader`): both ship Borland's **RTM.EXE**
      ("Run-Time Manager" loader v1.1) as their DPMI loader. RTM hooks INT 31h
      and, for functions it doesn't handle itself, **tail-chains to the
      previously-installed (host) vector** — which we report via `AX=0204` as
      our per-vector default stub (`VECTOR_STUB_SEL:STUB_BASE+0x62`). The bug:
      `vector_stub_reflect` reflected that chained INT 31h to **real mode**
      (`F000:FF53`), silently dropping the DPMI call. RTM's loader chains
      `set-descriptor-base/limit` (AX=0007/0008) on its PSP-alias selector
      (`0177`) that way, so the selector stayed unset → RTM's loader rejected
      it with `Loader error (0010): internal error` after the raw PM→RM into
      its loader. Fix: `mode_transitions::vector_stub_reflect` now services
      vector 0x31 via `dpmi::dpmi_api` (popping the stub's own IRET frame so
      results return to the chain's original caller) instead of reflecting to
      RM. Verified headless: **BP loads to its IDE** (idles on INT 16 keyboard
      poll), **Jazz clears the loader and runs SETUP**, and the **BC IDE still
      loads** (DPMILOAD path — no regression). The earlier "Jazz fails earlier"
      note was wrong: BP and Jazz failed identically (same `EXCEPTION 11` #NP
      on sel ~0x16F, same `Loader error (0010)`); one fix unblocked both.
  - [x] **BP** IDE is interactive-ready (confirmed at the IDE).
  - [x] **Jazz** now reaches its **title/menu** (branch `fix-vme-pm-vector`).
        Getting there took three more fixes past the RTM loader:
        (1) the fast-CPU **RTE 200** (Borland Pascal `CRT.Delay` divide
        overflow) — patched out by running **TPPATCH** on `FILE0001.EXE`
        (TPPATCH now shipped at `C:\TPPATCH`); (2) a **VME ring-0 `#GP`**
        when a HW IRQ was delivered to the default PM stub — `pm_vectors`
        offset carried stale high bits (`63b576c`); (3) the **menu.000
        "not found"** — its INT 21h AH=3Dh open read an *empty* filename
        because PM `linear()` used the full 32-bit `EDX` and 16-bit clients
        leave the high half garbage, so the read went out of bounds. Fixed by
        zeroing the high 16 bits of GP regs across PMDOS INT 21h for 16-bit
        clients (`f020295`). Jazz now loads CONFIG/MENU/fonts/SOUNDCRD/music
        and runs its main loop. Under QEMU it **runs but the screen is garbled
        — old sprite/scroll positions aren't erased (Mode X trails)**; under
        Bochs the screen stays **black** (it's still loading — see below).
        Confirmed the garble is the **emulator's VGA, not us**:
        VGA ports (0x3C0-0x3DF) + 0xA0000 are passthrough, and there were ZERO
        `VgaState` saves during the whole gameplay run — RetroOS is never in the
        pixel path while Jazz runs. Jazz uses unchained **Mode X** (planar +
        latch blits + CRTC page-flips), which QEMU's std VGA renders imperfectly
        — same bucket as the "QEMU related problems" below. Root-confirmed via
        the OpenJazz HN thread (id=42831927): Jazz uses an undocumented
        **odd/even mode applied to 256-color** (tweaked Mode X — 128K, fast
        blit + double-buffer). QEMU's maintainer (bonzini) states in that thread
        he **fixed VRAM-wraparound + odd/even handling in QEMU** ("I had to fix
        in QEMU"), patch `lore.kernel.org/all/20231231093918.239549-4-pbonzini`
        dated 2023-12-31. That postdates the QEMU 8.2.0 branch (2023-12-20), so
        our 8.2.2 likely lacks it — but the exact release that carries the
        commit is UNVERIFIED. **Next:** confirm which QEMU tag has the fix (or
        just test QEMU ≥9.0) — expected to render correctly with no RetroOS
        change. **Bochs is NOT hung** — Jazz keeps loading (LDT selector idx
        climbs 22→194 over the run, 100+ #NP demand-loads), but Bochs's
        realtime-paced interpreter crawls through the heavy segment
        decompression, so the screen stays black for a long time and looks
        hung. Run `BOCHS_SYNC=none ./run_bochs.sh …` (flat-out, no realtime
        clock pacing) to let it finish loading. Then DMA/GUS for audio.
      (Dev aid discovered: `run_qemu.sh -r 'PATH/PROG.EXE'` auto-runs a DOS
       program headlessly via fw_cfg `opt/cmdline` then shuts down — ideal for
       capturing load-time DPMI traces without driving DN.)

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