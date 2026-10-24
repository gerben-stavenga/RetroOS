# Bare-metal entry and core startup

Link `//arch-metal:entry` alongside the library and provide the linker layout
(see `kernel/kernel.ld`) and `boot_kernel(core_id: u32, magic: u32, info: *const u8)`.
The ELF entry passes logical core ID 0. The 16-bit SIPI trampoline passes the
caller's nonzero logical ID. Both enter this same Rust function in ring 0,
with paging and interrupts off, offset CS/DS/SS, a private stack, and working
GS-based Rust TLS. The AP receives zero for the two Multiboot arguments.

Call `smp::init_core(core_id)` on both paths. It builds that CPU's page tables,
GDT, TSS and FPU/syscall state, then switches to flat segments and virtual GS.
Only `core_id == 0` should initialize devices, shared allocation, or the kernel's
scheduler. On an AP, call `smp::run_secondary()` after CPU-local initialization;
it acknowledges startup and invokes the supplied entry function with interrupts
still disabled. The regular kernel implements this split; it does not yet
choose or launch additional CPUs automatically.

`smp::start_core(apic_id, page_phys, CoreStart { .. }, delay_us)` starts one
known offline AP. Hardware APIC IDs and logical core IDs are separate. The
caller discovers CPUs, reserves a 4 KiB startup page below 1 MiB, allocates each
CPU's stacks and `smp::tls_layout()` bytes, and supplies a calibrated delay.
Requests are serialized on the BSP with interrupts disabled. Startup works
with xAPIC and x2APIC senders and has bounded delivery/acknowledgement waits.

The shared low-memory allocator is a **768 KiB array placed last in BSS** by
`kernel.ld`, using a dedicated `.boot_pool` input section. It is 128 KiB aligned
and `NOLOAD`: the ELF reserves its RAM before modules are loaded, without
storing the zero bytes in the file. `_end` and the ordinary heap follow the
whole pool, including unused capacity. The linker separately checks:

- Kernel before the pool: at most 2.125 MiB.
- Complete physical image: at most 3.875 MiB, leaving 128 KiB below 4 MiB.

The startup order is:

1. `smp::init_core(0)` performs minimal BSP arch setup and maps the whole image.
2. Claim `boot_mem::BootMemory::new()` and allocate **all** AP stacks/TLS.
3. `finish()` closes AP allocation and opens the pool's remaining tail to
   permanent allocations. Start the selected APs with `smp::start_core`.
4. Continue shared kernel initialization on core 0 while APs wait.

ISA DMA buffers are allocated per channel on first request from the same pool,
with 64 KiB alignment/size for 8-bit channels and 128 KiB for 16-bit channels.
Requests before the AP allocation phase finishes fail. Repeated requests reuse
the same buffer; exhausted pool space returns unavailable. There is no separate
768 KiB DMA array. The startup sender's APIC page table also uses the remaining
pool, so engaging APs needs neither the ordinary heap nor the frame allocator.

All storage stays in the original physical 0–4 MiB identity window. Offset
segments before paging and flat segments afterward resolve the same stack/TLS
addresses to the same RAM. The trampoline still only enters protected mode,
loads stack/GS, and calls Rust. The below-1-MiB SIPI page is separately reserved.
The kernel stack is 64 KiB; each 16 KiB trap stack fits one 64 KiB window.

The physical allocator reserves the complete image through `_end`, and the
ordinary heap starts at `heap_base()` = `_end`. Boot allocations are permanent;
this allocator is not a replacement for the runtime heap or CPU scheduler.

A successful acknowledgement allows reuse of the low startup page: the AP has
left the trampoline and loaded its own GDT. Keep its stacks, TLS, and completion
word alive. After a timeout, retain **all** startup storage, including the low
page: a delayed AP may still arrive. Do not retry or reclaim until the target
is known to be stopped. Shared devices, allocator and clock state still need
synchronization before general kernel workloads may run on secondary cores.

`//arch-metal:smp_example` is a minimal consumer with one shared Rust entry. Run
`python3 test/arch_smp.py` for four-core legacy/PAE tests, or add `--kvm` for xAPIC
and x2APIC hardware execution. It checks independent stacks, initialized/zeroed
TLS, GDTs, page roots, startup-page reuse, rejected invalid inputs, and a missing
CPU timing out. The example verifies both ISA DMA channel sizes use pool space
following the AP allocations, and that ordinary heap/physical allocations lie
outside the pool. `bazelisk test //arch-metal:boot_mem_test` checks allocation
phase ordering, alignment, exhaustion and overflow.
