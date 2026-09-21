# Persistent task hibernation

Status: proposed; not implemented.

The OSD must let the user save a running task to disk, release its memory,
reboot RetroOS, and resume that task at the saved execution point. A saved task
must not depend on a thread slot, allocation, handle, or other state retained
from the previous boot. Keeping a paused task resident does not meet this
requirement.

## OSD behavior

- **Save task to disk** operates on the focused task. It reports progress and
  only removes the live task after its checkpoint has been durably committed.
  A failed save leaves the task available to continue.
- **Saved tasks** lists committed checkpoints discovered on persistent storage,
  including after a reboot. Entries show the task name and compatibility or
  missing-resource errors. They are distinct from live windows.
- **Resume** reconstructs a saved task and focuses its restored window. Failure
  leaves the checkpoint intact and releases any partially restored resources.
  The checkpoint remains available after a successful resume; duplicate live
  resumes of the same checkpoint are prevented.

Use a persistent, writable checkpoint directory, provisionally
`C:\CONFIG\TASKS`. A RAM-backed module or volatile disk overlay is not a
persistent destination. The storage layer must establish durability rather
than infer it from the path or successful writes.

## Saved state

Use a versioned, explicitly encoded format with bounded section lengths,
integrity checks, and compatibility metadata. Do not dump Rust structs,
pointers, trait objects, page-table roots, or physical addresses. Initial
compatibility may require the same kernel build and supported CPU/backend
configuration; resuming after a reboot is required, whereas migration across
kernel versions or machines is a separate capability.

The checkpoint must describe:

- CPU registers and execution mode, FPU/SIMD state, guest memory contents,
  mapping permissions, and alias relationships. Reconstruct page tables and
  allocate new physical frames on restore.
- Personality state. For DOS this includes DPMI descriptors and transitions,
  XMS/EMS ownership and mappings, DOS allocations, searches, nested EXEC state,
  and pending interrupt or system-call continuations.
- Virtual devices: VGA registers and memory, PIC/PIT state, DMA, sound state,
  keyboard and mouse state, and mounted-media identities. Release hardware
  ownership while saved and reacquire it through normal kernel mechanisms.
- Open-file descriptions, descriptor sharing, offsets, access/share modes,
  locks, working directories, and backing-file identities. Reopening a file
  must not truncate it. Never restore old global file-table indexes.
- Task relationships and presentation preferences, with fresh runtime IDs.
  A waiting launcher must not receive a fabricated successful child exit.

Timers must preserve remaining guest time and resume against the new boot's
clock; time spent saved must not produce a burst of overdue interrupts.
Checkpoints do not automatically roll back external files. Record and validate
dependencies before restoring execution. Missing or changed required files
must produce a useful error rather than silently resume against different data.

## Save and restore transactions

At an event-loop boundary, freeze guest execution and device advancement,
capture hardware state, and check that every required resource can be saved.
Stream sections with bounded scratch memory so saving does not require a
second RAM-sized copy of the task.

Write a temporary checkpoint, complete and validate its contents, then publish
it using a filesystem-supported durable commit protocol. Data and publication
metadata must reach persistent storage before freeing the task. Incomplete
files must never appear as resumable entries, and a failed replacement must
preserve the previous checkpoint. Checkpoint teardown is a separate lifecycle
operation from normal process exit: it releases runtime resources without
running guest termination code or discarding the saved execution state.

Restore validates the complete format, compatibility, resource identities,
and allocation bounds before making a new task runnable. Reconstruct into
private staging state; publish the task and window only after all restoration
steps succeed. Failure rolls back staging allocations and handles without
changing the saved checkpoint or unrelated tasks.

## Current implementation seams

- `kernel/src/kernel/osd.rs` queues actions; `startup.rs` owns the event-loop
  boundary. The OSD should request hibernation rather than perform filesystem
  I/O from its key handler.
- `thread.rs` owns task state and lifecycle. Its current register save and
  scheduling suspension are in-memory operations, not persistent checkpoints.
- `arch-abi/src/arch.rs` deliberately exposes opaque page-table and FPU types.
  Add only the generic memory/context export and import mechanisms needed by
  both backends; keep checkpoint files and personality policy in the kernel.
- `dos/mod.rs` stores suspended DOS operations in boxed `FnOnce` callbacks.
  Replace persistable continuations with explicit tagged data, or reach a
  supported safe point before saving. Never serialize closure addresses.
- `vfs.rs` retains file paths and open modes, but runtime handles need an
  explicit export/reopen mechanism that preserves sharing and validates the
  backing resource.
- `block::Disk::flush` currently returns no result and has a default no-op.
  Durable checkpoint publication needs end-to-end, error-reporting storage
  guarantees, including filesystem metadata, before memory can be released.

Support must be explicit per personality and resource type. Initial DOS game
support must include DPMI games. Unsupported native-device state, external
pipes/sockets, or task relationships must reject saving before destructive
changes; they must not create a checkpoint advertised as resumable.

## Acceptance checks

1. Save real-mode and DPMI games through F12; verify task-owned guest and device
   allocations are released, leaving only small saved-task catalogue metadata.
2. Stop the emulator process completely, boot again from the persistent disk,
   discover the checkpoint in the OSD, and resume the saved execution point.
   Verify controls, graphics, sound, timers, and subsequent file writes.
3. Exercise shared mappings, aliased file descriptors, and supported pending
   DOS calls so restored state preserves relationships as well as bytes.
4. Inject disk-full, short-write, flush, and publication failures. Verify the
   original task remains usable and any previous checkpoint remains valid.
5. Reject truncated/corrupt files, incompatible builds, unavailable media,
   changed dependencies, and insufficient memory without damaging the
   checkpoint or leaking staging resources.
6. Interrupt saving before and after publication; on the next boot expose only
   committed checkpoints. Verify repeated save/reboot/resume cycles.
