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
- [ ] Doesn't boot. Launches via DOS32A; loads `HEXEN.CFG` and `HEXEN.WAD`,
      then hangs in a tight PM poll at `00c7:0x00541b2c`:
      `cmp eax, [0x005d6dc8]; jz $-6` with EAX=0. EFLAGS=0x00101046 →
      **IF=0, VIP=1**, vpic `pending=[09,08]` (timer + keyboard queued
      but undeliverable). The polled variable would be bumped by Hexen's
      timer ISR, but IRQs are masked.
- [ ] Most likely root: our virtual-IF tracking drops IF=0 across some
      boundary and never restores. Suspect paths: PM `INT 21h` reflect/IRET
      (lots in the trace before the hang), or a TF=1 single-step artifact
      around CLI/STI virtualization.
- [ ] Fix: instrument virtual-IF state at every CLI/STI/POPF/IRET site,
      re-run, find where IF=1→0 isn't paired with a 0→1.

## Monkey Island 1 / Indiana Jones IV (Atlantis) — SCUMM
- [ ] Both hang at startup before the LucasArts logo paints. Same trap
      point: stuck inside SeaBIOS `wait_irq` (`STI; HLT; CLI; CLD; RETD`
      at F000:B7C0) reached via `INT 15h` from the game (atlantis's
      caller is at `1222:0x1c89`).
- [ ] BIOS time-of-day at `0040:006C` IS advancing (~18 Hz, confirmed by
      vector_stub_reflect trace), and the BIOS keyboard ring tail
      advances when keys are pressed — but the game never reads from
      head, so it isn't waiting on INT 16. Likely AH=86 (Wait us) with
      a long count, AH=83 (Event Wait), or a per-tick callback that
      isn't firing the way SCUMM expects.
- [ ] Diagnosis: hook IVT[0x15] at boot via a CD-31 + JMP FAR stub so
      we see the entry AX/CX/DX of every INT 15h call (we don't trap
      these otherwise — IVT goes through real-mode dispatch).

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
- [ ] After commit `efe5911` (wallclock-paced 0x3DA), Build engine's
      `palto()` palette fades take ~20 s each instead of <1 s. Trace
      shows the inner spin pinned at PM EIP `00c7:0x005455CE-D8` doing
      ~140 k `inb 0x3DA` per second with `irq=` count in [prof] dropped
      ~5× vs. boot-time (timer IRQ starvation under heavy #GP traffic),
      so `get_ticks()` advances slower than wall-time → wallclock vsync
      cycle stretches well past 14.3 ms.
- [ ] Suspect: `let _real = crate::arch::inb(0x3DA);` in `emulate_inb`
      runs a real-hardware PIO per trapped read to keep the AC
      flip-flop synchronized — that's a host-exit on every iteration
      of the guest's spin and likely the dominant cost / IRQ-blocking
      culprit. Move it behind a "VGA state changed since last save"
      guard or drop it for the synthesized 0x3DA path.
- [ ] Don't revert `efe5911` — Epic Pinball's pacing fix lives there.

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