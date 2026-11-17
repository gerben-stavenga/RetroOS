# RetroOS kernel review

First written 2026-11-12 against `master` at `30ab2be8` plus the then
uncommitted SMP work. Updated 2026-11-15 against `8632920a`: the SMP work is
now committed, and the arch-related findings and line references below were
rechecked after the arch rework. The rest of the kernel was not re-reviewed,
so other line numbers may have drifted.

## Scope and confidence

Everything here comes from reading the code. Nothing was built, run or
reproduced, so each finding is a claim to verify, not a confirmed failure.

| Area | Depth |
| --- | --- |
| SMP worker model (`parallel.rs`, `arch/smp.rs`), scheduler, thread table | Read in full |
| Physical allocator, kernel heap, page supply ABI | Read in full |
| Metal paging and fault paths (`paging2.rs`, `traps.rs`) | Relevant sections only |
| Linux user-memory access, a sample of syscalls | Sampled |
| Event loop (`startup.rs:1434-1993`) | Read |
| DOS control-stub dispatch, VFS types, filesystems, block drivers | Skimmed for structure and failure paths |
| Windows and OS/2 personalities | Skimmed (module headers, panic sites) |
| `dos/machine` device emulation, DPMI internals, sound, display/GUI, WiFi stack, `arch-interp` | Not reviewed |

## Priority order

1. Finding 1: kernel panic from a read-only user pointer (root cause is in
   arch; see ARCH_REVIEW.md finding 1).
2. Finding 4: guest-triggerable panics in the DOS stub dispatchers (small fix).
3. Finding 5: silent 4 GiB file clamp (should at least be a hard error).
4. The rest as the SMP work is prepared for commit.

Finding 2 has been retracted; see below.

## Likely bugs

### 1. A Linux program can panic the kernel with a read-only pointer

Still open at `8632920a`.

- User memory access is a raw dereference: `arch-metal/src/vcpu.rs:110-150`.
- Syscalls only bounds-check the range against `0xc0000000`:
  `kernel/src/kernel/linux/high_memory.rs:46`.
- CR0.WP is set (`arch-metal/src/paging2.rs:1396,1488`), and `sys_mprotect`
  can make pages read-only (`linux/mod.rs:3124`).
- A kernel write to such a page reaches `handle_protection_fault`
  (`arch-metal/src/traps.rs:927`), which returns `None` for a non-writable
  entry, and the ring-1 fault path then calls
  `panic_with_regs("Unhandled page fault in kernel")` (`traps.rs:824`).

`read(fd, rodata_ptr, n)` or `sysinfo(text_ptr)` should trigger it. There is no
fault-recoverable user copy, so `EFAULT` can only come from the range check.

Fix direction: a recoverable user-copy primitive in `arch-abi` (fault fixup
that returns failure to the caller), and route every Linux user access through
it. There are about 190 raw `machine.read/write/copy_*` call sites in
`linux/`.

### 2. Retracted: stale kernel-heap TLB entries across CPUs

This finding was wrong. It assumed the kernel heap returns pages through
`release_heap_pages` (`arch-metal/src/paging2.rs:1093`). It does not:
`kernel/src/arch/boot.rs:392` initialises the heap without a release callback,
and the comment there says the heap grows monotonically specifically to avoid
remapping an address while another CPU holds an old TLB entry.
`release_heap_pages` has no caller.

What remains is a footprint point, not a correctness one: the kernel heap
never gives memory back (see ARCH_REVIEW.md finding 15). Since the rework the
heap is backed explicitly before use (`kernel/src/arch/boot.rs:25-67`), and
`release_heap_pages` is still dead code.

### 3. No unmapped-address faults below 3 GiB

Still open at `8632920a`. Any non-present user address is demand-zeroed
(`arch-metal/src/traps.rs:901,910`), for user code and kernel copies alike.
Kernel-space addresses are no longer treated this way; they now fail and
panic at the faulting instruction. Wild pointers materialise pages instead
of raising SIGSEGV or `EFAULT`. `sys_mremap`'s comment ("bare downward bump
with no per-mapping bookkeeping") suggests this is deliberate, but it hides
guest bugs and lets a stray loop consume RAM.

### 4. A DOS program can panic the whole machine

Entering the control-stub segment at an unassigned slot hits `compact_panic!`
in both dispatchers:

- VM86: `kernel/src/kernel/dos/dos.rs:441`
- Protected mode: `kernel/src/kernel/dos/dpmi/raw_switch.rs:121`, which also
  does `dos.dpmi.as_ref().unwrap()` on a guest-reached path.

A wild jump in one game should end that task (`KernelAction::Exit`), not the
kernel and every other session.

### 5. Files are capped at 4 GiB, silently

- `Vnode.size`, `FileEntry.offset` and the `Filesystem::read/write/resize`
  signatures are `u32` (`kernel/src/kernel/vfs.rs:317,395`).
- ext4 clamps larger files with `info.size.min(u32::MAX)`
  (`fs/portable_ext4.rs:365,405,457,534`), so the tail is invisible rather
  than an error.
- `sys_lseek` casts the offset to `i32` on the x86-64 path too
  (`linux/mod.rs:2144`), so 64-bit seeks past 2 GiB wrap.

### 6. Inode numbers are a hash of the path

`FileEntry.ino` is an FNV hash of the path (`vfs.rs:402`). A rename changes a
file's identity, hard links get different inodes, and a collision makes two
files look identical to `ld.so`, `cp`, `tar` and `make`.

## Fragile design

### 7. The placeholder-row protocol in `parallel.rs`

While a process runs on a worker, its task-table row holds a swapped-in stale
`KernelThread` with seven hand-copied fields (`parallel.rs:282-290`).
Correctness depends on `prepare_action` (`parallel.rs:398`) listing every row
each `KernelAction` may touch, with `_ => false` as the default. A new action,
or a new field read on the BSP, fails silently with stale reads or lost
writes.

Suggestion: make the on-loan row a distinct type (the state moves to the
worker, the row keeps only a metadata struct), so touching loaned state is a
compile error. This matches the project's ownership-by-move rule.

### 8. The BSP busy-spins in `wait_for_slot`

`parallel.rs:344` spins for up to a full quantum with no device service. Its
only liveness check is a 1 s watchdog assert, and any active handler on any
CPU resets that watchdog, so one stuck worker can be masked by another busy
one.

### 9. One global VFS mutex, held across synchronous disk I/O

- `static VFS: Mutex<Vfs>` (`vfs.rs:2250`) now serialises every core.
- Arch paging is now serialised the same way, by one global `PagingGuard`
  spinlock on every fault and mapping operation (ARCH_REVIEW.md N2), so
  parallel workloads have two global serialisation points.
- The ATA driver polls on spin-count budgets (`drivers/hdd.rs:309,352`), which
  also makes timeouts depend on CPU speed.

A slow read on a worker stalls the BSP event loop, and with it DOS timing and
inline audio. The owned-mounts v2 design addresses the lock; SMP makes it
urgent.

### 10. Unsynchronised `static mut` reachable from workers

The profiling paths were made worker-aware. These were not:

- `thread::prng`'s `SEED` (`thread.rs:876`): racy, and a fixed-seed LCG. It is
  written to the initial user stack at `linux/mod.rs:1062`. If that is
  AT_RANDOM, stack canaries are predictable. `random.rs`/`linux/entropy.rs`
  exist and should feed it.
- `block/cache.rs:23` `PROFILE`: plain racy counter.
- `thread.rs:864` `CONSOLE_PIPE`: safe only because it is written once.

Across `kernel`, `arch-metal`, `arch-abi` and `lib` there are 167 `static mut`
lines. Each one reachable from `linux::handle_event` needs the same audit.

### 11. The event loop is one roughly 600-line loop body

`startup.rs:1509` onward mixes device polling, audio, display publication, OSD
requests, MIDI routing, writeback, scheduling and the CPU loan. The MPU-401
UART poke at `startup.rs:1804` is driver code inline in the scheduler loop,
against the layering rule in CLAUDE.md. `sched::verdict` threads nine
arguments, including display and Sound Blaster handoff, so scheduling and
console ownership are entangled.

### 12. Only the focused application group executes

Background DOS sessions get `advance_background_timers` but no CPU
(`startup.rs:1863`, `sched.rs` header comment). It reads as intended, but a
backgrounded game or download simply stops.

## Smaller points

- **Limits:** `MAX_PIPES` is 64 system-wide with a `u8` index (`kpipe.rs:17`);
  `MAX_SOCKETS` is 64 (`net/stack.rs:18`). Both are tight for parallel
  self-builds.
- **File size:** `startup.rs` (3.8k lines), `vfs.rs` (4k) and `linux/mod.rs`
  (3.7k) each carry too much.
- **Layering:** `wifi`, `qmi`, `htc`, `htt`, `wmi` and `qrtr` sit at the kernel
  top level beside the policy APIs. The Windows and OS/2 personalities are
  missing from CLAUDE.md.
- **Hygiene:** the SMP work is now committed. The stray empty file
  `kernel/src/kernel/linux/sedy9iJPR` is still in the working tree.

## What holds up

- The page-supply boundary: arch receives owned pages as data and never calls
  back into an allocator (`arch-abi/src/page_supply.rs`). Since the rework this
  holds without exceptions; the fault-time refill redirect is gone.
- Frame refcounts are atomic and have a concurrency test.
- The pool and heap locks document and follow their no-reentry rules.
- AP bring-up is careful: resident stacks and TLS, bounded waits, a hard stop
  on an unacknowledged AP.
- Untrusted-input parsing is mostly delegated: smoltcp for the network,
  rust-fatfs for FAT, the portable engine for ext4.
- The Windows and OS/2 personalities keep API behaviour in userspace DLLs
  behind narrow `INT 83h`/`INT 82h` gates. Their `unreachable!` sites checked
  were on internal enum invariants, not guest input.
- Display and Sound Blaster ownership move as values through the event loop.
