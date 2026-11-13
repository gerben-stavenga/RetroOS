# Bare-metal entry and core startup

Link `//arch-metal:entry` alongside the library and provide the linker layout
(see `kernel/kernel.ld`) and `boot_kernel(core_id: u32, magic: u32, info: *const u8)`.
The ELF entry passes logical core ID 0; the SIPI trampoline passes the caller's
nonzero logical ID and zero Multiboot arguments. Assembly installs a private
stack and GS-based Rust TLS before entering Rust.

Call `smp::init_core(core_id)` on both paths. It installs that CPU's paging root,
GDT, TSS and FPU/syscall state. On an AP, `smp::run_secondary()` acknowledges
startup and invokes the supplied entry with interrupts disabled. Device setup,
allocation policy, CPU discovery and scheduling belong to the kernel.

The kernel's boot policy is `kernel/src/arch/smp.rs`. The BSP initializes the
kernel physical allocator and heap, then allocates and touches resident AP
stacks/TLS. Each AP receives a 64 KiB kernel stack, a 16 KiB trap stack contained
within one 64 KiB window, TLS and an initial fault-page reserve. These allocations
need contiguous virtual addresses, not contiguous physical pages.

`smp::start_core(apic_id, page_phys, CoreStart { .. }, delay_us)` starts a known,
stopped AP. Hardware APIC IDs and logical core IDs are separate. Startup requests
are serialized on the BSP with interrupts disabled, support xAPIC and x2APIC,
and have bounded delivery and acknowledgement waits. The trampoline borrows the
BSP's paging root and existing identity mappings. The AP installs private roots
before acknowledging; the BSP removes its boot identity mapping only after all
selected APs acknowledge. The below-1-MiB SIPI page is separately reserved.

A successful acknowledgement allows reuse of the trampoline page. Keep stacks,
TLS and completion words alive. After a timeout retain all startup storage:
a delayed AP may still arrive. The kernel stops boot after a failed startup;
it must not reclaim bootstrap mappings while that AP's state is uncertain.

The `.boot_pool` BSS storage supplies bootstrap paging structures and permanent
contiguous low-memory DMA buffers. AP stacks/TLS use the ordinary resident heap.
Physical allocation, DMA policy and fault-reserve replenishment live in
`kernel/src/kernel/phys_mm.rs`; arch has no physical allocator callback.

Arch consumes donated pages from a CPU-local `PageSupply` during page faults.
Five pages cover one data page and up to four table levels. Other mapping
operations consume explicit `PageInput` batches prepared by
`kernel/src/kernel/memory.rs`. Returned frames remain owned until the kernel
drains them. Resident ownership metadata supports atomic references to shared
data frames without entering the allocator from a fault handler.

The recursive root, PML4, hardware PAE PDPT, descriptor tables, registers,
scratch mappings and fault reserves are CPU-local. Kernel leaf tables are
shared. A canonical kernel-root portion has a lock-protected generation;
refreshing copies new kernel entries into the local root and invalidates its
TLB. This mechanism requires an ownership handoff before mappings can be reused;
it is not a general concurrent kernel-mapping or TLB-shootdown protocol.

# Parallel Linux processes

`kernel/src/kernel/parallel.rs` owns the scheduler policy and CPU handoffs.
Core 1 remains the media worker. With a calibrated TSC and LAPIC timer, remaining
APs enter ring 1, initialize private local alarms, and consume process loans.
Without a supported worker timer they stay unavailable and execution falls back
to the BSP. External device interrupts continue to target the BSP.

Independent Linux processes run concurrently, with each process pinned to one
execution CPU. Threads within one Linux process remain serialized on that CPU.
A vfork child borrows its parent's CPU/address space until exec or exit. Kernel
services, process-table updates and device work retain one BSP owner. This first
implementation rendezvous all process workers before dispatching any returned
event; it does not provide concurrent kernel syscall execution.

A loan transfers a saved paging root, registers, FPU state, TLS binding and an
absolute deadline. RUN/DONE release/acquire transitions transfer ownership
between the BSP and one worker. Workers allocate no heap storage and do not
access the process table. An IPI ends remaining loans before the BSP handles
syscalls, exits, signals or mappings. Pending events are dispatched before their
processes execute again. Scheduling quantum requests survive event draining so
processes that did not fit in a batch cannot be starved.

Before parallel execution, the kernel asks arch to detach shared page-table
pages using explicit donated inputs. Data pages remain COW-shared. Consequently
one CPU's fault handler cannot edit another running process's table metadata.
Fork invalidates this private-table status; exec builds a new address space.
Shared kernel mappings remain stable throughout the batch.

The heap has a spin lock. Physical-pool metadata already has a short resident
critical section and atomic shared references. A supervisor fault that needs
reserve replenishment while the heap is locked cannot reclaim through the heap.
The remaining kernel statics continue to rely on BSP ownership rather than
being exposed to arbitrary concurrent kernel callers.

MCP's disjoint profile is BSP wall time. Parallel preparation and rendezvous
are charged to scheduler work; worker CPU execution is excluded. Do not interpret
that ledger as aggregate CPU usage across all processors.

Validation commands (build `//:boot_disk` first):

- `python3 test/linux_parallel.py --cpus 16`: sixteen children across fifteen
  eligible CPUs, stable affinity, getcpu, shared mappings and high-address COW.
- `python3 test/linux_parallel.py --cpus 5 --bits 32`: i386 processes and inherited
  segment TLS across workers.
- `python3 test/linux_vfork_signal.py --cpus 5`: vfork exit/exec and SIGCHLD.
- `python3 test/linux_thread_signal.py --cpus 5`: pthreads and directed signals.
- `python3 test/linux_high_memory.py --cpus 5`: sparse mappings and protections.
- `python3 test/linux_local_control.py --cpus 5`: in-guest MCP and profile
  reconciliation, including a Python subprocess.

`//arch-metal:smp_example` is a minimal separate consumer. `test/arch_smp.py`
checks CPU-local startup state, resident stack/TLS handoffs, invalid inputs and
startup timeout handling; add `--kvm` for hardware execution.
