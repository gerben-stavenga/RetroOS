# RetroOS Architecture and Code Review

## Overall Assessment

RetroOS has a genuinely interesting and technically substantial architecture.
The code confirms that it is more than an architectural story: the shared
kernel/backend split is real, the hosted backend exercises meaningful kernel
paths, and the paging and mode-switching machinery has considerable depth.

The project is currently best characterized as a strong research and hobby
system, rather than a trustworthy general-purpose kernel. The largest problems
are concentrated exactly where the design says the trust boundary should be.

## Findings

### 1. Critical: User pointers are not validated before kernel access

Linux syscall arguments flow directly into `GuestBytes`. For example, `read()`
accepts a guest-controlled buffer and length and writes through it without
checking that the complete range is valid user memory below `0xC000_0000`.

Relevant code:

- `kernel/src/kernel/linux/mod.rs`, `sys_read`
- `arch-metal/src/vcpu.rs`, `GuestBytes::copy_to`
- `arch-interp/src/paging.rs`, `space_resolve` and `resolve_in`

On metal, `copy_to` converts the integer address directly into a kernel pointer
and writes through it. A malicious user program could potentially ask a syscall
to overwrite supervisor memory.

The hosted backend behaves differently but is also incorrect. `space_resolve()`
demand-maps any address without applying the range checks used by the guest
page-fault path. Null, wrapped, and kernel-range pointers therefore do not
produce Linux `EFAULT`, and backend behavior diverges.

`GuestBytes` should provide checked, fallible operations. It should validate the
complete range with checked arithmetic, distinguish read access from write
access, and never demand-map an invalid user pointer.

### 2. High: `GuestBytes::read<T: Copy>` is unsound

The trait documentation says that `T` must be valid for every bit pattern, but
the type system does not enforce this. Safe kernel code can request a `bool`,
`char`, fieldless enum, reference-containing type, or padded structure and cause
undefined behavior when the backend calls `MaybeUninit::assume_init()`.

Relevant code:

- `arch-abi/src/arch.rs`, trait `GuestBytes`
- `arch-metal/src/vcpu.rs`, `GuestBytes::read`
- `arch-interp/src/vcpu.rs`, `GuestBytes::read`

Use a sealed `Pod` or `FromBytes` trait whose safety requirements are enforced by
the implementation, or expose only byte-array and explicit integer operations.
Documentation alone is insufficient for a safe API.

### 3. High: The claimed safe-Rust kernel boundary does not exist yet

The kernel currently has no `#![forbid(unsafe_code)]`. It still contains raw
linker-symbol access, hardware glue, mutable statics, and drivers with unsafe
operations.

More subtly, some safe methods in `Arch` have contracts that are not safe for
all arguments safe Rust can construct. `Arch::activate`, for example, accepts raw
pointers that backend implementations dereference. A safe function must remain
memory-safe for every argument its caller can construct in safe code.

Relevant code:

- `kernel/src/lib.rs`
- `arch-abi/src/arch.rs`, `Arch::activate`
- `arch-interp/src/backend.rs`, `Interp::activate`
- `arch-metal/src/backend.rs`, `Metal::activate`

Safe-kernel isolation should therefore be described as a concrete design
direction, not yet as a current implementation property.

### 4. Medium: Backend state ownership is still aspirational

Both `Metal` and `Interp` are currently zero-sized handles while important state
remains in global mutable storage. Threading `&mut A` through the kernel creates
the appearance of exclusive ownership, but does not yet enforce exclusive access
to the actual backend state.

Associated descriptor functions also access ambient global state instead of the
`Arch` instance.

Relevant code:

- `arch-metal/src/backend.rs`
- `arch-interp/src/backend.rs`
- `arch-metal/src/traps.rs`, global register state
- `arch-interp/src/vcpu.rs`, global register state

This will matter for SMP, multiple hosted machines in one process, parallel
tests, and any attempt to make backend ownership a real safety invariant.

### 5. Medium: Malformed ELF input can trigger undefined behavior

The ELF parser repeatedly casts positions in an arbitrary byte slice to
references such as `&ElfHeader64` and `&ProgramHeader64`. A byte buffer does not
guarantee the required alignment at each offset, so merely forming these
references can be undefined behavior.

Calculations such as `offset + index * size` and `off + filesz` also need checked
arithmetic before being used as bounds.

Relevant code:

- `lib/src/elf.rs`

Parse fields explicitly from little-endian byte slices, or use a parser whose
unaligned and bounds behavior is explicit. This would remove unsafe code and
make malformed-input handling straightforward to test.

### 6. Medium: Syscall resource limits are weak

Several syscall paths allocate buffers directly from guest-controlled lengths.
For example, `read()` creates `vec![0; len]` before validating whether the user
buffer is accessible. A process can request a very large buffer and exhaust or
panic the kernel allocator.

Relevant code:

- `kernel/src/kernel/linux/mod.rs`, `sys_read`, `sys_write`, and related socket
  and vector-I/O paths

Use bounded or chunked I/O and return consistent `ENOMEM`, `EINVAL`, or `EFAULT`
errors as appropriate.

### 7. Architectural limitation: Scheduling is currently focus switching

The scheduler explicitly runs the focused thread. A blocked focused thread spins
unless input unblocks it or F11 moves focus. This is adequate for the current DOS
workflow, but it is task switching rather than general preemptive multitasking.
It also consumes host or CPU time while blocked.

Relevant code:

- `kernel/src/kernel/sched.rs`
- `kernel/src/kernel/startup.rs`, `event_loop`

This limitation is reasonably isolated by the current scheduler and focus
factorization, which should make later replacement possible.

## Architectural Strengths

The move-only page-table handle and explicit active/parked execution-context
model are excellent ideas. They make address-space ownership visible and avoid
casually duplicating an owned page-table root.

`ExecutionContext` makes CPU ownership transitions unusually understandable for
kernel code. The event loop also separates execution, personality dispatch,
scheduling, and focus more cleanly than the original pseudocode suggests.

The PAE/compat transition is technically impressive and well contained. The
assembly required for the transition is short, direct, and accompanied by useful
reasoning about the hardware constraints.

The testing strategy is stronger than is typical for a hobby kernel. Hosted MMU
and interpreter tests cover COW, VM86 paging, and the long-mode page-table twin.
The hosted architecture provides a practical way to exercise real kernel logic
without debugging every failure through a virtual machine.

At the time of this review, the hosted interpreter and MMU tests passed. The
hosted Clippy build failed because long-mode paging helpers were unused in the
selected TCG feature configuration.

## Recommended Priority

1. Replace `GuestBytes` with checked, fallible user-memory capabilities.
2. Remove generic `T: Copy` decoding and repair the ELF parser.
3. Make every safe `Arch` method genuinely sound.
4. Enable `#![forbid(unsafe_code)]` and move remaining unsafe facilities below
   that boundary.
5. Move backend globals into actual `Metal` and `Interp` state.
6. Add adversarial syscall-pointer, range-overflow, and malformed-binary tests.
7. Expand scheduling when background execution becomes a project requirement.

## Conclusion

The central architecture is worth continuing. The main weakness is not the core
idea, but that the implementation currently overstates how strongly Rust and the
trait boundary enforce it. Fixing the user-memory boundary would materially
raise the project from an impressive compatibility experiment toward a
defensible kernel design.
