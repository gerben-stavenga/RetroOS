# RetroOS Outlook: one safe core, every machine

## Thesis

RetroOS is converging on a *universal kernel framework*: a single safe-Rust
core — scheduler, process/thread model, copy-on-write fork, VFS, the event
loop, and the syscall semantic bodies — reused unchanged, with everything
machine- or ABI-specific pushed onto pluggable edges. The long-term aim is to
run code written for **any OS**, compiled for **any ISA**, on **any host
platform** — executing natively where the host ISA matches the guest's, and
interpreting where it does not.

This is not a new subsystem to build. It is the natural extension of boundaries
already in the tree.

## Why it holds together: boundaries that do double duty

Each boundary was cut once and pays off in more than one way. That is what
makes universality cheap instead of a combinatorial explosion:

| Boundary | First purpose | Second purpose it also serves |
|---|---|---|
| Recursive paging | one paging model across 2/3/4 levels | the page tables *are* the walk — no walk code |
| metal / interp `Arch` | run on the real CPU or in software | the portability seam *is* the safety boundary |
| `#![forbid(unsafe_code)]` kernel | provable kernel memory safety | replaces hardware ring-1 isolation (no wrapped segments) |
| `GuestBytes` copy-in/out | hide each backend's `unsafe` in one place | keeps external guest memory out of the Rust abstract machine |
| `Arch` associated `Regs`/`PageTable` | abstract native vs interp | abstract the guest ISA at the *same* cut |
| serialize-within-a-guest scheduling | a simple execution model | *is* the cross-ISA memory-ordering proof |

This is the recurring discipline of the whole design (see DESIGN.md):
canonicalize, find the natural joint, then let one cut serve several purposes.
Cuts at the grain cannot be added after the fact — you either found the joint
or you are fighting it — so getting them right early is the load-bearing work.

## Three axes

The design separates three things usually tangled together:

1. **Substrate** — native (host ISA == guest ISA) vs interpreted. The `Arch`
   backend choice (`arch-metal` / `arch-interp`).
2. **Guest ISA** — x86 / ARM / 68k. Selects `Arch::Regs` and the decoder.
3. **OS ABI** — DOS / Linux / Windows / AmigaOS. The kernel *personality*.

`Arch` owns axes 1 and 2: a concrete backend (`arch-metal-x86`,
`arch-interp-arm`, …) is a point in the substrate × ISA plane and exposes its
register representation. The **personality** owns axis 3.

Native execution happens only on the diagonal where host ISA == guest ISA;
every off-diagonal cell is interpreted. A single running system can therefore
host mixed guests at once — an x86 DOS game (interp on an ARM host), an
aarch64-Linux process (native), an ARM-Windows app (native) — each thread
choosing native-or-interp purely by ISA match. That is QEMU-user + Rosetta +
WINE + gVisor converged under one safe core.

## Personalities: shared semantics, thin per-ISA shell

A multi-ISA OS (Linux, Windows) is not re-implemented per ISA. The syscall
*semantic bodies* (`open`, `mmap`, `fork`, operating on the kernel's
VFS/process model) are ISA-neutral and shared. Only a thin marshalling shell
varies per ISA:

- which event signals a syscall (`INT 0x80` / `SYSCALL` / `svc`)
- the register → `Args` mapping and the return-value writeback
- the syscall-number map (i386 `openat` = 295, aarch64 = 56, same semantic)
- the in-guest-memory struct layouts (`stat`, `iovec`) that differ by word
  size and alignment

The code is already shaped for this: `extract_args(regs) -> Args` and
`SyscallResult` are exactly that seam today. It mirrors how Linux itself
separates calling-convention glue from its `do_sys_*` bodies and runs 32-on-64
compat — converging with the real thing is a sign the cut is at the joint.

Single-ISA OSes (DOS = x86, AmigaOS ≈ 68k) need no such abstraction: the
personality *is* that one ABI. Mono-ISA pins the *ISA* axis, not the
*substrate* axis — DOS still runs native on an x86 host and interpreted on an
ARM host.

## Memory ordering

Cross-ISA emulation's hard problem — faithfully emulating a stronger guest
memory model on a weaker host — is sidestepped by the scheduling model, not by
barriers:

- The kernel itself is pure Rust with explicit orderings, so `rustc` emits the
  correct fences for whatever host it is compiled to. Host-correct by
  construction.
- Guests share no memory across ISAs, so two guest models are never reconciled
  against each other.
- Within a guest, threads are **serialized onto one host thread**: the guest
  sees a sequentially-consistent interleaving, and SC dominates TSO and every
  weaker model. Any program correct under its own model is correct — for free,
  with no emulation of fences at all.

Parallelism is recovered *across* guests (separate address spaces, no shared
memory, any host core, zero ordering concern). The one configuration
deliberately **not** offered is true SMP *within* a single guest whose model is
stronger than the host's — that is the Rosetta-2 / multi-threaded-TCG cost
(per-store barriers or a hardware TSO mode), declined on purpose. For retro
workloads the loss is invisible. This rule belongs in the scheduler contract
before any thread-per-vCPU work, because x86-on-x86 is the one combination
where breaking it still happens to pass on the dev box.

## From here: labor, not research

What stands between this outlook and a compiling cross-ISA system is
engineering, not open problems:

- [ ] `Regs` → an `Arch` associated type; make the shared syscall bodies honest
      about guest pointer width (retire the 4 GiB `usize` assumption)
- [ ] Move the metal device drivers (`nvme`, `xhci`, `ac97`, `hda`, `pci`) and
      runtime plumbing (`heap`, `stacktrace`) below the arch line so the kernel
      crate compiles `#![forbid(unsafe_code)]`
- [ ] Factor the Linux personality into a per-ISA marshalling trait over the
      shared semantic core; add an aarch64 ABI shell as the first cross-ISA
      proof
- [ ] Add a second `Arch` backend ISA (`arch-interp-arm` via Unicorn), then a
      native `arch-metal-arm`
- [ ] Write the "serialize within a guest, parallelize across guests" rule into
      the scheduler contract

None of these is an open research question; they are a backlog. The skeleton is
real and load-bearing. The universality is, for now, instantiated for a single
ISA — but the cuts are in the right places, and that is the part that cannot be
added later.
