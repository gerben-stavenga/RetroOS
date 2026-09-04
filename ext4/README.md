# portable-ext4

`//ext4:ext4` is a synchronous, `no_std + alloc` ext filesystem engine. It has
no dependency on RetroOS, libc, threads, or an async executor. Its storage
trait is the only place persistent effects may occur.

The low-level interface is graph-based. `ext4::Ext4` exposes only `Blob`
(bytes), `Node` (labelled outgoing edges), `Object`, and owned detached edge
references. `root`, `inspect`, `edges`, `read`, `write`, `resize`, `attach`,
`detach`, `retain`, and `release` are the complete operational vocabulary.
Ext4 inode numbers are merely the on-disk encoding of those handles.

`Filesystem<S>` is the standalone owning interface. It mounts the graph over
recovered journal storage and exposes the same handles while making each
write, resize, attribute update, creation, removal, or edge move an atomic
JBD2 transaction. It introduces no path or object-type policy.

There are deliberately no paths, symlink traversal, descriptors, credentials,
or POSIX rules in this layer. RetroOS's VFS adapter interprets opaque vertex
format/owner/time attributes and implements those policies. Names exist only
while streaming or changing a node's edge records; subsequent mutation uses
an `EdgeHandle`.

The current graph reader supports inode tables, linear and HTree-indexed node
contents, extent trees, legacy direct and single/double/triple-indirect block
maps, and read-only recovery of an internal JBD2 journal. Recovery stages
complete transactions in memory and exposes committed, non-revoked blocks as
a storage view; mounting never modifies the image. JBD2 checksum v2/v3,
32/64-bit tags, circular logs, revokes, and escaped blocks are validated. It
rejects rather than guesses when an image requires:

- an external journal, JBD2 checksum v1, or fast commits;
- any unknown incompatible feature.

Read compatibility and mutation compatibility are deliberately separate.
Readonly-compatible feature bits do not prevent mounting, while every mutation
passes a narrow exact feature-profile check. Thus a modern filesystem can be
used for boot and ordinary reads without accidentally permitting a writer that
does not understand its allocation, namespace, or recovery rules. Unsupported
is different from corrupt, and neither is silently ignored.

## Storage contract

```rust
pub trait Storage {
    fn len(&self) -> u64;
    fn read(&mut self, offset: u64, dst: &mut [u8]) -> Result<(), StorageError>;
    fn write(&mut self, offset: u64, src: &[u8]) -> Result<(), StorageError>;
    fn flush(&mut self) -> Result<(), StorageError>;
}
```

A successful `flush` means every preceding successful write is ordered before
it and durable. Reads and writes are exact: a short operation is an error.

`test_support::ModelStorage` records every effect, injects an I/O error or
power loss at an exact sequence number, and keeps volatile and durable images
separate. Pending writes can be persisted one prefix at a time before power
loss, allowing transaction tests to enumerate disk states without a VM.

## Storage overlays and journal transport

`BlockOverlay` places the graph implementation over a volatile writable
storage layer. Graph algorithms may write typed records or arbitrary byte
ranges; the overlay materializes each affected filesystem block once. Reads
compose physical storage, recovered journal state, and prospective writes.
No graph operation reaches the device before the upper composition succeeds.

Dropping the overlay discards it. `finish` yields sorted complete blocks which
the JBD2 transport publishes. The initial writer requires a clean internal
journal using either checksum v3 or the ordinary unchecksummed `mke2fs` format,
enough consecutive journal space for one descriptor/data/commit sequence, and
no circular wrap. Filesystem and journal block sizes are selected at mount time
across ext4's 1--64 KiB format range. It writes and flushes
five ordered phases: journal preparation, recovery activation, commit,
home-block checkpoint, and cleanup.

Activation uses the original superblock with only `needs_recovery` added, so an
uncommitted transaction cannot leak its final counters. Checkpointing uses the
new superblock while retaining `needs_recovery`; the flag is cleared only after
every home block is durable. A failed commit consumes the transaction and the
filesystem must be remounted before further use.

The graph writer supports extent-backed and inode-inline blobs, sparse growth,
arbitrary subrange writes, shrinking and extent-tree collapse; node creation,
streaming, linear growth, indexed-node normalization, attach/replace/detach,
cycle-safe node moves, reference ownership, and final object reclamation. Fast
symlinks and `inline_data` files are the same byte-storage primitive; exceeding
their capacity converts either to extents without changing its `Blob` handle.
Allocation and release update typed inode/block bitmaps, group and superblock
counts, `itable_unused`, used-node counts, and all affected checksums. Lazy
inode and block groups are materialized from their structural reservations
before use.

The ext4 HTree is treated as an accelerator over the same graph. Reads
validate and skip hash-root/internal blocks while streaming edge leaves.
Mutation converts an indexed node to the equivalent linear edge array and
clears the accelerator flag, leaving one edge algorithm and no duplicated
namespace engine.

Tests exercise these primitives directly, apply the resulting complete blocks
through JBD2, remount, and require independent `e2fsck` acceptance.

Journal tests cut power at every storage effect. Every resulting image exposes
exactly the old or new namespace through our recovery. Successful mutations
are also required to pass an independent `e2fsck` check. Sub-block torn writes
are modeled by the test storage but are not yet claimed by this writer;
defining the device atomicity contract and testing torn control records is the
next durability step.

RetroOS uses `Filesystem<VolumeStorage>` for every ext filesystem. Its adapter
contains only VFS policy and sector-I/O translation; there is no second ext
implementation or compatibility fallback in the kernel.
