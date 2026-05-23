# DOS Game Compatibility — Bug Sprint

## INT 10h teletype rendering
- [x] Fixed: word-sized passthrough for Bochs VBE ports 0x01CE/0x01CF/0x01D0
      in `handle_in_event`/`handle_out_event`. SeaBIOS's graphics-mode
      teletype reads/writes those to program the display; our byte-wise
      emulator returned zeros, so glyph-blit math computed a junk
      framebuffer offset and nothing rendered. Alley Cat, Digger and
      similar now show text in graphics modes.

## Offroad
- [ ] Doesn't work — failure mode TBD (capture trace)

## Test Drive 1
- [x] Works.

## Borland C IDE
- [ ] Still throws an exception — identify vector and trigger

## Dark Forces
- [x] AH=08 IP-rewind HACK on PM-via-VECSTUB path — fixed by `SLOT_RESUME`
      block-and-retry closure mechanism. Game now boots through intro and
      menu.
- [x] Mouse-click crash on "Begin Mission" — DPMI 0303 callback dispatch
      was missing the IRET return frame, planting `STUB_BASE` in the EIP,
      and DPMI 0.9 §6.1.1 DS:(E)SI semantics. Also fixed an unrelated
      `deliver_pm_irq` bug where `host_stack_write_iret` hardcoded
      `host_stack_base()` instead of resolving through `regs.frame.ss`
      (broke nested IRQ delivery on a non-host-stack handler stack).

## Hexen
- [x] Works.

## Monkey Island 1 / Indiana Jones IV (Atlantis) — SCUMM
- [ ] Both hang at startup before the LucasArts logo paints. Stuck inside
      SeaBIOS `wait_irq` (`STI; HLT; CLI; CLD; RETD` at F000:B7C0). INT
      15h is not the trigger — needs fresh diagnosis.

## Duke Nukem 3D — via DOS/4GW (no LOADFIX wrap)
- [ ] With DOS32A wrap (LOADFIX) it works; without, DOS/4GW triggers an
      infinite exception loop. PM #13 fires → DOS/4GW handler RETFs with
      ExcFrame32 modified to resume in VM86 at `0000:0x10B` (an IVT-area
      address) → #UD → DOS/4GW's #UD handler is a decode/skip emulator
      that advances EIP into more IVT garbage → loop, leaking ~60 stack
      bytes per iteration. DOS/4GW evidently expects its RM panic stub
      to be present at some low-memory address that we don't set up.
      Kernel panic on the *first* loop iteration was fixed by zeroing
      DS/ES/FS/GS in VM86-source dispatch (DPMI 0.9 §6.1.4); the loop
      itself is a DOS/4GW-internal issue.

## Duke Nukem 3D — palette fades super-slow
- [x] Fixed (commit `b9a7f41`): synthetic `0x3DA` bit 0 now toggles via
      a per-read counter (runs of 8) instead of a once-per-frame block,
      so Build's per-DAC-entry snow-avoidance wait finds a blanking
      window in ≤16 reads instead of stalling a full ~14 ms frame
      between writes. ~4096 DAC writes × ~14 ms ≈ 60 s collapsed back
      to <1 s. Bit 3 (vsync) still on the 70 Hz wallclock phase so
      Wolf3D's `VL_WaitVBL` and Epic Pinball's pacing are unaffected.

## Zone 66 (PMODE/W extender)
- [x] Original "PMODE doesn't work" hang fixed by two virtual-PC
      pieces. Root cause was NOT the extender — PMODE/W is a normal
      DPMI 0.9 client and INT 2F AX=1687 ENTER worked fine. The actual
      blocker was INTRO.EXE busy-polling port 0x61 for a DRAM
      refresh-bit edge (the classic ~15 µs sub-tick timer) which our
      `read_port61` never produced. Fix: XOR bit 4 on each read in
      `kernel/src/kernel/dos/machine.rs`. Also added a minimal PS/2
      keyboard command/ACK handler for `OUT 0x60` (was previously
      dropped silently) so the prior `OUT 0xED` set-LEDs path queues
      0xFA correctly — needed for full PS/2 detection paths (probably
      shared with Operation Wolf and others).
- [ ] Downstream crash: INTRO.EXE later issues `INT 31 AX=BA02`
      (DPMI 1.0 vendor / phys-mapping group, unhandled by us → returns
      AX=8001 CF=1) and shortly after SEGVs at RM `0269:003E`. Need to
      identify what BA02 should do for PMODE/W and either implement
      it or stub it more sympathetically.

## Jazz Jackrabbit
- [ ] Get it working — its bundled DPMI host rejects us. Jazz ships with
      its own extender (not CWSDPMI / DOS32A / DOS/4GW), and that host
      bails out before reaching the game. Capture the failing INT 2Fh
      AX=1687 / DPMI entry sequence and the host's first few PM
      requests to identify which service or expectation we miss
      (likely a 0.9 detail it probes for before installing).

## Operation Wolf
- [x] Mouse worked all along — runtime input choice was pinned in
      `OWconfig.dat`. Trace showed exactly one `INT 33h AX=0000`
      install check at startup (we correctly returned AX=FFFF) and
      no further mouse calls; the game just used whatever device the
      config named. Deleting `OWconfig.dat` forces the startup menu
      to re-prompt; selecting "Mouse" routes input through our INT
      33h driver normally. No code change needed; lesson: when a DOS
      game ignores an obviously-detected device, check for a saved-
      config file before chasing emulation bugs.

## Epic Pinball
- [x] "Runs unplayably fast" was the 0x3DA retrace-emulation bug
      (fixed in commit `efe5911`): we advanced the retrace phase
      per-read instead of per-host-millisecond, so `VL_WaitVBL`
      completed in microseconds instead of ~14 ms. With wallclock-
      derived phase the engine paces correctly at 70 Hz.

## One Must Fall 2097
- [x] Playable with the in-game "Game Speed" slider set to 1
      (minimum). OMF has no wallclock timer — diagnosed via trace
      + Vogons: doesn't reprogram the PIT, doesn't read `40:6C`,
      doesn't poll INT 1A, doesn't even use 0x3DA. Game loop just
      runs as fast as the CPU executes it; on a 486DX2/66 (target
      hw) this landed near 30–60 fps because file streaming + 8bpp
      blitting saturated the CPU. The shipped speed slider bounds
      work per frame and is enough on RetroOS.
- [ ] (Optional) Generic guest-CPU-throttle knob (à la DOSBox
      `cpu cycles fixed`) — gate event-loop iterations against
      `get_ticks()` so any DOS guest runs at a chosen effective
      MIPS. Would help Wing Commander, Pinball Fantasies' linesync
      loop, and the rest of the Vogons CPU-sensitive list without
      per-game in-engine knobs.
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

## Kernel — virtual IF gets stuck at 0
- [ ] Intermittent across games: a program runs fine for a while then
      freezes. F12 dump shows EFLAGS.IF=0 — some interrupt sequence
      (INT reflect / IRET / exception dispatch / mode transition) is
      leaving the user's virtual IF cleared and never restoring it.
      vPIC IRQs queue up but never get delivered, so anything waiting
      on a timer/keyboard IRQ wedges. Related to the Hexen hang above
      (same symptom, also IF=0 + VIP=1), but here it's not game-specific
      so the IF=1→0-without-pairing path is somewhere on a common code
      path, not Hexen-specific.
- [ ] Diagnosis: instrument every CLI/STI/POPF/IRET/PM-INT-deliver site
      with a "virtual IF state changed" trace, run a session, watch for
      a 1→0 transition with no matching 0→1 before the freeze.

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

## Dune II — single-cycle SB DMA (sb-dma-virt)
- [ ] Speech still broken. Dune2 uses single-cycle (not auto-init) SB
      DMA; under the virtual-8237 + host-IRQ5-relay path the speech
      pump doesn't advance. Single-cycle keeps the deferred-ack model
      (host IRQ5 masked until guest vPIC EOI `0x20` → `arch_rearm_irq(5)`),
      the card halts at terminal count and the guest owns the re-arm.
      Investigate terminal-count current-count readback (the ISR tests
      8237 ch count `== 0xFFFF` to claim the completion IRQ) and the
      re-arm timing on the single-cycle path.

## Wacky Wheels
- [ ] Setup program crashes. Triage: capture the fault (CS:EIP,
      exception vector, VM86/PM mode) and isolate the subsystem
      (DOS/DPMI/SB/other) before fixing.