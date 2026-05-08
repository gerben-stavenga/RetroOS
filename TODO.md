# DOS Game Compatibility — Bug Sprint

## INT 10h teletype rendering (shared root cause)
- [ ] BIOS `INT 10h AH=0Eh` (teletype char) doesn't render text in graphics
      modes under our VM86 setup. SeaBIOS's CGA/EGA/VGA-mode teletype path
      bitmap-blits glyphs into the framebuffer; the same SeaBIOS image
      works in FreeDOS+JEMM386, so the hole is somewhere in our V86
      passthrough (port/MMIO/IVT) — not SeaBIOS.
- [ ] Affects: Alley Cat (intro prompt unreadable), Digger (intro prompt
      unreadable), and likely several others. Both games run otherwise.
- [ ] Resolution options:
      (a) Find what's missing in V86 so SeaBIOS teletype works as-is.
      (b) Implement an in-kernel INT 10h hook for AH=00/02/03/09/0E with
      our own bitmap-font glyph rendering. ~150–200 lines. Self-contained.

## Offroad
- [ ] Doesn't work — failure mode TBD (capture trace)

## Test Drive 1
- [ ] Crashes — capture fault vector / address

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
</content>
</invoke>