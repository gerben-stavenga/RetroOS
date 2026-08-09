# DPMI real-mode callbacks

RetroOS implements DPMI `INT 31h`, functions `0303h` and `0304h`, which let a
protected-mode client expose a procedure that can be called from real mode.
This path is used by DOS extenders for callbacks from real-mode interrupt
handlers and drivers. Raptor's DOS/4GW mouse callback is a useful regression
case: moving the mouse enters the callback while the game is loading graphics.

This code is not yet known to have the correct general stack semantics. The
current behavior is a compatibility implementation derived from CWSDPMI and
Raptor, not a conclusion that the returned stack fields are unimportant.

## Specification contract

The DPMI 1.0 specification, "Using Real Mode Callbacks" (pages 34-35) and
function `0303h`, specifies the protected-mode callback entry state as:

- `DS:(E)SI` is a selector:offset corresponding to the real-mode `SS:SP`.
- `ES:(E)DI` points to the 32h-byte real-mode register structure (RMCS).
- `SS:(E)SP` is a locked protected-mode stack supplied by the host.
- The callback returns with `IRET` and may edit the RMCS and the real-mode
  stack. The host then loads the real-mode registers from the RMCS and resumes
  the real-mode caller.

The specification does not require one particular protected-mode mapping for
`DS:(E)SI`. A flat selector plus a linear offset and an `SS`-based selector plus
the real `SP` both identify the same byte on callback entry. It does, however,
explicitly mention that a host may allocate a descriptor for each callback to
hold the real-mode `SS` descriptor. That makes the second representation an
important intended implementation model.

The callback IRET frame has the width of the DPMI client. It must not be chosen
from the callback code descriptor's D bit. A 32-bit extender may put a callback
thunk in a 16-bit code segment and return with an explicit `66 CF` (`IRETD`).

## Behavior of existing hosts

### CWSDPMI

The vendored CWSDPMI source uses its flat, base-zero `g_core` selector for `DS`
and passes the linear address `real_SS * 16 + real_SP` in `ESI`:

- `freedos/cwsdpmi/dpmisim.asm`, `rmcb_common`, constructs `tss_esi` from the
  saved real-mode `SS:SP` and sets `tss_ds` to `g_core`.
- `freedos/cwsdpmi/control.c` creates `g_core` with base zero.

On callback return, CWSDPMI restores the internally saved real-mode stack with
`lss sp, ds_sp`. Although the handler-edited RMCS is copied back, its returned
`SS:SP` does not select the actual return stack.

This accommodates the DOS/4GW wrapper observed in Raptor. With a flat callback
pointer, that wrapper stores the low word of approximately `ESI + 8` into the
RMCS `SP` while retaining the original RMCS `SS`. Interpreting that pair
literally addresses unrelated memory, but CWSDPMI ignores it.

### HX/HDPMI

HDPMI follows the other model. In `Src/HDPMI/I31SWT.ASM` it updates a
callback-specific descriptor's base to `real_SS * 16`, loads that selector in
`DS`, and places the real `SP` in `ESI`.

On callback return, HDPMI honors RMCS `SS:SP`: it reserves six bytes below the
requested position, writes an `IP:CS:FLAGS` real-mode IRET frame there, and
executes `IRET`. After that IRET, the real-mode stack is exactly the `SS:SP`
requested by the callback.

The DOS/4GW wrapper is compatible with this representation too. Here `ESI + 8`
is a real offset within the aliased real-mode stack, so its returned RMCS `SP`
is meaningful.

## Current RetroOS behavior

`kernel/src/kernel/dos/dpmi/rm_calls.rs::callback_entry` currently uses the
CWSDPMI entry representation:

- `DS = LOW_MEM_SEL`, a flat low-memory selector.
- `ESI = real_SS * 16 + real_SP`.
- `ES:(E)DI` points to the client's RMCS.
- The protected-mode IRET frame uses the DPMI client's 16/32-bit width.

`kernel/src/kernel/dos/mode_transitions.rs::resume_continuation` currently
keeps the saved real-mode `SS` and translates the DOS/4GW/CWSDPMI-style flat
returned `SP` back to an offset on that segment. This fixes Raptor, but it is
not a general implementation of the specification: a callback that genuinely
changes RMCS `SS:SP` will not get the HDPMI result.

Do not simplify this into a claim that RMCS `SS:SP` is scratch. It is a known
compatibility workaround pending a more authoritative implementation decision.

## Likely complete implementation

The specification and HDPMI suggest this design:

1. Give each allocated callback a protected-mode data selector.
2. On each callback entry, update its base to the current real-mode
   `SS * 16`, because a callback may be reentered with a different `SS`.
3. Enter the callback with that selector in `DS` and the real `SP` in `ESI`.
4. On return, honor RMCS `SS:SP`, place the real-mode IRET frame immediately
   below it, and resume with `IRET` semantics.
5. Retest Raptor/DOS4GW, Duke3D/DOS16M, nested callbacks, 16-bit clients, and
   callbacks that deliberately change stacks.

Avoid detecting INT 33h or individual games in the DPMI machinery. Mouse input
only exposed the callback bug; it is not a mouse-specific DPMI rule.

## Remaining authoritative test

Windows 3.0/3.1 is historically important because DPMI originated in
Microsoft's Windows 3.0 protected-mode work. In 386 enhanced mode,
`WIN386.EXE`/the VMM is itself the DPMI provider for protected-mode DOS
programs in a DOS VM. Windows standard mode can instead be a client of an
external DPMI host, so it is not suitable for measuring Windows' host behavior.

When convenient, boot Windows 3.1 in 386 enhanced mode without an external
DPMI host and run a DOS callback probe inside a Windows DOS box. Record:

- the callback's live `DS`, its descriptor base and limit, and `ESI`;
- the corresponding real-mode `SS:SP`;
- whether changing RMCS `SS:SP` changes the resumed real-mode stack;
- callback behavior for both a far-call entry and an interrupt-driven entry.

The published DPMI specification remains normative, but this experiment would
show the behavior of the original widely deployed Microsoft host and is the
best compatibility reference still missing from this analysis.

## References

- DPMI Committee, *DOS Protected Mode Interface Specification*, version 1.0,
  March 12, 1991, pages 34-35 and function `0303h`.
- CWSDPMI sources: `freedos/cwsdpmi/dpmisim.asm` and
  `freedos/cwsdpmi/control.c`.
- HX/HDPMI source: `Src/HDPMI/I31SWT.ASM` in
  <https://github.com/Baron-von-Riedesel/HX>.
- Microsoft Windows 3.0 DDK, *Adaptation Guide*, "The DPMI Translation
  Services".
