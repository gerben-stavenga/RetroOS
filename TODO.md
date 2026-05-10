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