# Kernel Size Opportunities

This is the working backlog for reducing RetroOS kernel size through simpler
code, shared primitives, and removal of duplicated work. The goal is not to
disable supported personalities or filesystems, hide code behind feature
flags, scatter size attributes through the tree, or trade away hot-path
performance.

## Measurement snapshot

Measured after commit `9b0a08e` (native VGA rasterization with
presentation-time scaling), using the pending repository-wide size build
policy in `.bazelrc`: `opt-level=z`, fat LTO, embedded bitcode, and one codegen
unit.

| Item | Bytes |
|---|---:|
| `kernel.elf` file | 1,055,220 |
| `.text` | 861,694 |
| `.rodata` + `.eh_frame_hdr` file content | 150,696 |
| `.data` file content | 34,936 |
| `.bss` memory | 401,408 |
| `.kstack` memory | 69,632 |
| Read/write load segment: file / memory | 34,936 / 438,272 |

The file and `.text` numbers are separate metrics. Linker page alignment means
a small `.text` reduction often changes neither `kernel.elf` nor its load
segments until a page boundary is crossed. `.bss` and `.kstack` consume RAM but
not bytes in `kernel.elf`.

Reproduce the snapshot with:

```sh
bazelisk build //kernel:kernel_elf //kernel:kernel_sym
ls -l bazel-bin/kernel/kernel.elf
objdump -h bazel-bin/kernel/kernel.elf
readelf -lW bazel-bin/kernel/kernel.elf
nm -S --size-sort -C bazel-bin/kernel/kernel.sym | tail -80
```

All namespace totals below are approximate inventories, not promised savings.
They are not necessarily additive: a symbol can match more than one category.

## Completed work

### Compact runtime cycle profiler

The F12 Profile operation now answers two permanent questions: guest versus
kernel CPU time, and the distribution of kernel time across loop/OSD work, IRQ
drain, virtual devices, audio, display, input, event dispatch, and scheduler
control. It retains the runtime toggle and periodic reports while removing the
special-purpose port/vector rankings, deepest subsystem probes, heap deltas,
and block-I/O counters. Those details belong to on-demand tracing.

When profiling is off, one enable check runs per event-loop iteration and no
timestamp is read. When it is on, phase boundaries update one eight-element
cycle array. Two generic decimal report lines replace the formatting-heavy
reporter. VGA scanout diagnostics remain available under Trace.

The metal final link also enables LLVM's size-profitable machine outliner.
Its synthetic numbered fragments are omitted from `KERNEL.SYM`; a backtrace
inside one prints the raw address and continues with the symbolized caller.

| Metric | Before | After | Change |
|---|---:|---:|---:|
| `kernel.elf` | 882,148 | 869,852 | -12,296 |
| `.text` | 722,814 | 712,062 | -10,752 |
| `.rodata` | 141,624 | 141,248 | -376 |
| `KERNEL.SYM` | 185,505 | 182,291 | -3,214 |

Repeated symbol names share one string-table entry.

### Build-time stack symbols

`KERNEL.SYM` is now a compact address table with names demangled by the build.
The kernel no longer links `rustc-demangle`, parses an ELF symbol table for
backtraces, or retains an unused copy of each Linux process's ELF image.

| Metric | Before | After | Reduction |
|---|---:|---:|---:|
| `kernel.elf` | 898,532 | 882,148 | 16,384 |
| `.text` | 741,310 | 722,814 | 18,496 |
| `.rodata` | 143,180 | 141,624 | 1,556 |
| `KERNEL.SYM` | 283,380 | 185,505 | 97,875 |

The ELF file reduction is page-rounded; `.data` stayed at 9,320 bytes. The
reported `.bss` section grew from 425,984 to 442,368 bytes because moving the
preceding sections changed the padding before the fixed 64-KiB-aligned arch
stack. No writable object was added.

### Shared generic monomorphizations

Commit `f216548` enabled reuse of generic instantiations rather than compiling
private copies in every crate.

### One size-oriented optimization policy

The pending build changes move optimization selection to `.bazelrc` and remove
the inconsistent per-target `s`, `z`, and `2` settings. This is a prerequisite
for comparable measurements, not a substitute for improving the code. It
should be committed independently of functional changes.

Fat LTO is intentional because the alternatives were measured. It does permit
cross-crate inlining, but under `opt-level=z` that global visibility removes
more call/setup code, constant branches, and duplicate IR than it introduces.
Crate boundaries remain source and ownership boundaries; they are not forced
machine-code call boundaries.

| Link policy | `kernel.elf` | `.text` | `.rodata` |
|---|---:|---:|---:|
| Fat LTO | 1,055,220 | 861,694 | 150,684 |
| No LTO, section GC | 1,108,500 | 903,806 | 160,480 |
| No LTO, section GC, `--icf=all` | 1,092,116 | 884,798 | 160,480 |

Safe ICF produced no measurable reduction. Aggressive ICF recovered 19,008
bytes of `.text` from the no-LTO build, but fat LTO remained 23,104 bytes
smaller in `.text` and 36,896 bytes smaller in the final ELF. Therefore linker
folding is not a replacement for LTO in this build. `--icf=all` also permits
identical functions to share an address, so it should not be added on top of
LTO without a separate measured benefit and an address-identity audit.

### VGA rasterization and scaling

Commit `9b0a08e` removed the fused, multiply-instantiated VGA stretch renderer.
VGA now renders one dense native-size `u32` image and presentation performs a
single destination-driven stretch.

| Metric | Before | After | Reduction |
|---|---:|---:|---:|
| `kernel.elf` | 1,075,700 | 1,055,220 | 20,480 |
| `.text` | 883,326 | 861,694 | 21,632 |
| VGA row renderer | 23,899 | 1,934 | 21,965 |

The presentation scaler is a single non-generic loop. Its output stores are
overlapping dword stores into a padded private row; only the logical row bytes
are copied to the framebuffer.

## Recommended order

### 1. Consolidate DOS service primitives

The two principal DOS service dispatchers alone occupy 54,475 bytes:

| Symbol | Bytes |
|---|---:|
| `dosabi::int_21h` | 36,050 |
| `dos::syscall` | 18,425 |

The opportunity is not merely to split the match statements into more
functions. First identify repeated operations across the real-mode and
protected-mode paths:

- register and carry/error result encoding;
- DOS pointer validation and segmented/linear buffer access;
- ASCIIZ path import and DOS/VFS path conversion;
- file handle lookup, read/write/seek, and timestamp plumbing;
- DTA and find-first/find-next result construction;
- exec parameter/environment preparation;
- common DOS error mapping.

Define each operation once around a small request/result representation, with
thin ABI adapters for the register layouts. This preserves the direct switch
dispatch while sharing the implementation behind it. Measure each extraction;
indirection and boxed trait dispatch are not appropriate replacements.

Related large DOS paths to audit after the basic primitives exist:

| Symbol | Bytes |
|---|---:|
| DPMI API dispatch | 11,371 |
| BIOS INT 10h | 8,751 |
| DOS machine MMIO fault handling | 6,667 |
| DOS display tick | 6,760 |

### 2. Collapse repeated lifecycle work in startup and the event loop

The largest individual functions are state-machine coordinators:

| Symbol | Bytes |
|---|---:|
| `startup::event_loop` | 53,712 |
| `startup::startup` | 31,459 |
| `boot_kernel` | 20,370 |
| `Personality::handle_event` | 8,572 |

Large coordinators are not automatically waste, but these paths should be
checked for repeated launch, park, resume, return, display handoff, symbol
ownership, and address-space transition sequences. The desired shape is a few
explicit lifecycle primitives shared by DOS, Linux, Windows, OS/2, and OSD
task switching—not a second generic event framework.

Keep the central state transition visible. Extract only operations whose
preconditions and ownership are genuinely identical, then compare generated
symbols before continuing.

### 3. Reuse ext4 mutation machinery

Symbols containing `portable_ext4` account for approximately 111,167 bytes,
the largest coherent code cluster in the image. Full read/write modern ext4
support is intentional, so the opportunity is internal reuse rather than
removing write support.

The largest mutation paths include:

| Symbol | Bytes |
|---|---:|
| `PortableExt4Fs::rename` | 8,096 |
| `PortableExt4Fs::new` | 5,440 |
| `prepare_inode_release` | 4,991 |
| `extend_file` | 4,825 |
| `PortableExt4Fs::mkdir` | 4,074 |
| `Transaction::commit` | 3,943 |
| `PortableExt4Fs::create` | 3,452 |
| `Transaction::resize_inode` | 3,352 |
| `PortableExt4Fs::write` | 2,765 |

Audit these for a common mutation skeleton:

- resolve and validate parent/target;
- open a metadata transaction;
- edit directory tree and inode together;
- update timestamps, link counts, checksums, and free counts;
- commit or unwind consistently.

There are already small duplicated primitives with separate copies in
`ondisk`, `transaction`, `extent_tree`, and `journal`, including endian stores,
power-of-two tests, and checksum update helpers. Consolidate those first; then
use the shared primitives to simplify the large mutation operations. Changes
should ideally live in `portable_ext4` rather than kernel-specific wrappers.

### 4. Share executable-loader and personality ABI primitives

Approximate code inventories:

| Cluster | Bytes |
|---|---:|
| Win16 | 32,557 |
| OS/2 | 20,082 |
| Linux/PE/LX loader entry functions alone | 13,648 |

Notable individual symbols include Win16 dispatch (16,264), Windows dispatch
(9,577), OS/2 API dispatch (7,676), Win16 exec (7,258), OS/2 LX loading
(6,723), and Win16 imported-target resolution (6,299).

The formats and ABIs must remain distinct. Candidate shared primitives are the
mechanics around them:

- checked image-range arithmetic;
- segment/page allocation and zero-fill/copy;
- argument and environment block construction;
- import-name normalization and module lookup;
- guest string and structure access;
- process-image replacement and rollback.

Avoid a universal loader abstraction that makes simple paths indirect. Share
small ownership and mapping operations while leaving format parsing explicit.

### 5. Reduce formatting and diagnostic machinery deliberately

Symbols whose names contain `core::fmt`/`alloc::fmt` account for roughly
13,462 bytes; this overlaps the demangler inventory. Formatting is spread
through panic, startup diagnostics, device logging, and stack traces, so a
blind replacement would harm debuggability.

After build-time demangling, inspect which remaining formatting
monomorphizations are duplicated. Prefer a small set of existing log primitives
for repeated hexadecimal addresses, register dumps, and byte strings. Do not
create many near-identical bespoke printers; that merely moves the duplication.

### 6. Simplify table-like dispatchers

Several large functions are register/API decoders rather than algorithms:

| Symbol | Bytes |
|---|---:|
| `Voodoo::write` | 15,460 |
| `osd::key` | 11,021 |
| Windows dispatch | 9,577 |
| BIOS INT 10h | 8,751 |
| OS/2 dispatch | 7,676 |

Look for repeated decode/validate/update patterns and data that can be
represented once. A data table is useful only when it replaces repeated code
and remains readable. Do not turn hot VGA, audio, or MMIO paths into indirect
function calls merely to reduce a symbol.

### 7. External parser and emulation clusters

These are meaningful but lower-priority until the surrounding shared
primitives are improved:

| Namespace inventory | Bytes |
|---|---:|
| Voodoo | 27,014 |
| Sound | 15,474 |
| VGA after refactor | 14,071 |
| ISO parser | 9,827 |

For external crates, first verify enabled features and duplicated generic
instantiations. Prefer upstreamable simplifications. Replacing a complete
implementation with an incomplete local one is not a size optimization.

## Writable-memory opportunities

These do not reduce `kernel.elf` because they are mostly `.bss`, but they
explain the large writable memory extent and matter on small machines.

| Static allocation | Bytes | Direction |
|---|---:|---|
| Kernel log buffer | 131,072 | Allocate to policy or reduce only with an explicit retention target. |
| Pipe storage | 66,308 | Allocate pipe buffers on demand instead of reserving every slot. |
| Physical page references | 65,536 | Pack counters if their proven maximum permits it, or allocate to detected RAM. |
| VFS state | 25,700 | Inspect fixed-capacity tables and move payloads to mounted/open objects. |
| Kernel page metadata | 20,480 | Size from actual kernel mapping requirements. |
| OSD windows | 20,460 | Separate small descriptors from on-demand surface/storage state. |
| Directory table | 5,313 | Replace fixed payload storage only if lookup behavior stays simple. |
| VGA fonts | 7,680 | Read-only assets should not require writable copies unless modified. |
| Voodoo reciprocal/log table | 4,104 | Compare generated-at-boot storage with a compact read-only representation. |

The read/write program segment currently has only 34,936 file bytes but
438,272 memory bytes. Reducing these statics lowers boot memory consumption,
not the on-disk kernel size.

## Link and layout opportunities

- Keep one central optimization policy and measure both speed-sensitive loops
  and total size. `z` is not permission for LLVM to introduce branches in hot
  loops; inspect generated code where behavior matters.
- Keep fat LTO and one codegen unit: the measured no-LTO alternatives above
  are larger. Do not infer source-level duplication solely from the function
  to which LTO attributes inlined code.
- Continue sharing generic monomorphizations. Search for multiple concrete
  copies before replacing a generic with dynamic dispatch.
- Treat alignment honestly: report `.text` reduction even when
  `kernel.elf` has not yet crossed the next 4 KiB boundary.
- Keep `KERNEL.SYM` outside `kernel.elf`. Its size is a distribution concern,
  while its parser/demangler code is a kernel `.text` concern.

## Explicit non-solutions

- Removing supported DOS, Windows, OS/2, Linux, filesystem, audio, or graphics
  behavior.
- Widespread `#[inline(never)]`, `#[cold]`, or per-function optimization
  attributes used to conceal structural duplication.
- Replacing direct hot loops with function pointers or trait-object dispatch.
- Re-decoding VGA pixels for every stretched destination pixel.
- Compressing the kernel and counting only the compressed file while leaving
  the in-memory code unchanged. Compression can improve boot media use later,
  but it does not meet the code-parsimony goal.
- Counting `.bss` reductions as `kernel.elf` file savings.

## Acceptance criteria for each change

1. State the duplicated work or unnecessary runtime responsibility being
   removed.
2. Preserve supported behavior and keep ownership/preconditions explicit.
3. Run the relevant unit/integration tests.
4. Record before/after `kernel.elf`, `.text`, `.rodata`, `.data`, and `.bss`.
5. Inspect hot-loop assembly when the compiler may trade branches for size.
6. Keep a change only when the result is simpler or measurably smaller without
   an unjustified performance regression.
