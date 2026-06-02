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
- [ ] **End-of-level door hangs, repeating.** When the prince reaches the exit
      door, the game wedges with the door animation/sound looping. Failure mode
      TBD — capture a trace at the level-exit transition (likely a wait loop on
      a timer/IRQ or sound-DMA completion that never fires).

## Ironman Off-Road Racing (Offroad)
- [ ] **Freezes / grinds to a halt — timer ISR's 0x3DA vblank loop never
      completes.** Root-caused (not yet fixed). The game installs an INT 8
      (timer) ISR at `067D:0A44` that re-tunes the PIT *phase-locked to vblank*
      by splitting the divisor write across a vblank edge, then JMP-FARs to the
      old handler:
      ```
        OUT 43h,36h
        MOV AX,[06BA]          ; new PIT divisor
        OUT 40h,AL             ; low byte only
        wait 0x3DA bit0 == 0   ; (out of blank)
        MOV CX,[06B8]          ; <-- the "reads-per-vblank" calibration count
      .lp:
        IN  AL,0x3DA           ; individual reads
        TEST AL,1
        LOOPNE .lp             ; count CX *sustained* bit0=1 reads
        JZ  restart            ; CX exhausted w/o vblank → retry
        OUT 40h,AL             ; high byte, now phase-locked to vblank
        ADD [06C1],1
        JMP FAR [06BD]
      ```
- [ ] **Why it hangs (solid):** the loop needs `CX = [06B8]` *consecutive*
      `bit0=1` reads to accept a vblank. Our synthetic 0x3DA (`synth_status1`,
      raster off `hr_cycles`) sustains bit0=1 for only ~565 consecutive
      *individual* `IN` reads, but `[06B8]` is **48963**. 48963 ≫ 565 → `LOOPNE`
      never falls through → ISR never returns → `[06C1]` (the game's frame
      counter) freezes → grind to a halt.
- [ ] **`[06B8]` is runtime-derived, not a shipped constant.** A gdb watchpoint
      on `[06B8]` (lin `0x8288`) caught its first write `0 → 48963` from
      F-segment block-I/O (`REP INSD`). 48963 reads/vblank implies a ~200+ MHz
      `IN`/`TEST`/`LOOPNE` throughput — impossible for the game's 1990 target, so
      the game *calibrated this count against our (fast) emulated read rate* and
      stored it. (Exact calibration instruction not pinned down — gdb's
      real-mode watchpoint disassembly kept erroring; the magnitude alone proves
      runtime derivation.)
- [ ] **The fundamental tension.** The whole 0x3DA scheme assumes
      reads-per-second is a fixed constant (one CPU speed): the game calibrates
      the count in one path and consumes it in the ISR via individual `IN`.
      Under a *trapping* emulator the per-read cost isn't constant — in
      particular a block `REP INS` (a strong candidate for the calibration path)
      and individual `IN` (the ISR) don't cost the same — so the calibrated
      count is structurally unreachable by the ISR. A *time-based* 0x3DA can
      never satisfy a read-count detector unless reads occur at the calibrated
      rate.
- [ ] **Fix options (undecided):**
      1. *Cheap, uniform 0x3DA reads* (fast in-trap path, or don't trap 0x3DA
         for the common read pattern) so reads track a near-constant rate and
         calibration ≈ ISR. Principled but the biggest change.
      2. *Read-count-based raster* (bit0 set for K reads, clear for M): fixes the
         hang but makes game speed depend on emulated read throughput and drifts
         against the time-based PIT. Earlier hblank/read-counter experiments were
         this, and failed only because K didn't match the calibrated count.
      3. Document as a known trap-based-VGA limitation and move on.

## Borland C IDE
- [ ] **Goal: successful WOLFSRC compile from the BC IDE** (`bc`, project
      `WOLF3D.PRJ`, sources served over hostfs at `C:\PROJECT\WOLFSRC`).
  - [ ] **Blocked: 2nd TASM exec under bc crashes #UD.** Build order now: C0.ASM
        (TASM #1) assembles ✓, TASM2MSG ✓, then H_LDIV.ASM (TASM #2) → CPU
        exception 6 at `f4a4:0x206c` (vm86) — a wild far transfer into the
        F-segment BIOS region; the crash stack holds ASCII string data, not a
        return addr (misplaced/corrupted stack). NOT file-specific: H_LDIV.ASM
        assembles `Error messages: None` standalone via `-r`. Both TASM execs
        load **identically** (child_seg=02DF, cs:ip=1B79:1AEE, psp=0BD9), so the
        corruption is resident state carried across the bc DPMI-host's
        EXEC/reap cycles — same family as `[[project_bcc_regression_is_flaky_layout]]`
        (the 14e7301 MCB-keep fix), evidently not fully closed. Clean execs
        restore bc to its PM stack (`ss:sp=0597:F572 pm_env=restored`); the
        crashing one degrades to a real-mode frame (`0239:013A`). Next:
        run the full bc compile with PM single-step / DOS_TRACE_RT armed at the
        2nd TASM EXEC; dump the locked-stack/mode-save chain + MCB list at
        child entry and diff vs the 1st (working) TASM exec.

## Settlers (DOS/4GW 32-bit)
- [ ] **Mouse click → kernel #GP panic.** NOT the BC selector-as-paragraph bug
      (that fix is correctly bypassed here). Settlers runs under **DOS/4GW 1.92**
      as a 32-bit DPMI client and does its **own** PM↔RM mouse bridging:
      - DOS/4GW hooks PM INT 33h (`015f:0xcc`) and, via `AX=0204`, captures the
        prior PM vector = our `SLOT_PMDOS_INT33` host stub (`003f:06f4` =
        `SPECIAL_STUB_SEL : STUB_BASE+0xFA*2`). For ordinary functions
        (AX=000E/0002/…) it **chains to our handler** → serviced in PM, works.
        (Confirms the `pm_vectors[0x33]` routing is load-bearing — keep it.)
      - For **AX=000C** it intercepts and reflects to real mode via **DPMI
        AX=0302** (call RM proc), passing its own **tiled** trampoline
        `ES:DX = 0229:0000` (DOS/4GW uses 1:1 selector tiling: base = sel<<4,
        so `0229` ↔ linear `0x2290`). So `int_33h` correctly sees VM86 →
        `cb_is_pm=false`; DOS/4GW *wants* a real-mode callback.
      - Failure: our RM far-call reaches `0229:0000` (trampoline runs), which
        switches RM→PM and raises **`INT 60h`** (DOS/4GW's internal gateway) to
        call the app's 32-bit handler. The panic is a kernel `#GP err=0x200` while
        **delivering that PM `INT 60h`** — the IRET-to-user (`common_call+0x39`)
        loads an invalid selector `0x200` on client `SS:ESP=002f:0x2094`. Trace:
        `[MOUSE] CB enter -> 0229:0 → [DPMI] PM_INT vec=60 -> 015f:0x180 → PANIC`.
      - **Root is a nested cross-mode transition during a mouse callback**
        (PM client → our RM-callback excursion → DOS/4GW RM trampoline →
        RM→PM → `INT 60h`), likely corrupting the locked-stack/`other_stack`
        chain or leaking a garbage segment that the PM-INT-60 IRET then loads.
      - Underlying hardening gap: a `#GP` from a bad client segment on the
        IRET-to-user path should be re-attributed to the client (vector 0x0D →
        DOS/4GW's installed exception handler), not panic the kernel as
        "Unhandled exception in arch" (`traps.rs:873`).
      - **Next:** arm PM single-step at `[MOUSE] CB enter`, trace the `0229:0000`
        trampoline through its RM→PM→`INT 60h` sequence, find where `0x200`
        enters and dump the locked-stack/mode-save chain at the `INT 60h`
        delivery vs. a clean PM-INT delivery. Headless `-r` repro won't reach
        a click; needs interactive + `DOS_TRACE_RT` (AH=02) on.

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
  * Jazz Jackrabbit gameplay is garbled (old sprite/scroll positions not
    erased) on QEMU 8.2.2. Jazz uses an undocumented odd/even mode applied to
    256-color graphics (tweaked Mode X w/ double-buffer + VRAM wraparound).
    QEMU's maintainer fixed odd/even + VRAM-wraparound handling (patch
    2023-12-31, postdates the 8.2 branch) → expected fixed on QEMU ≥9.0.
    RetroOS is not in the pixel path (VGA passthrough); see the Jazz entry
    above. Bochs renders it but is too slow at realtime sync to finish loading.
- No hsync/vsync emulation in vga port 3da.
  * Wolf3d hangs
  * Epic pinball, supaplex and other games unplayable fast 
  RetroOS solves this explicitly by producing synthetic vtrace/htrace
- SB16 emulation problem
  * Dune2 stops digitized speech after first sample