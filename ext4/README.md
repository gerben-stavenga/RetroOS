# portable-ext4

`//ext4:ext4` is a synchronous, `no_std + alloc` ext filesystem engine. It has
no dependency on RetroOS, libc, threads, or an async executor. Its storage
trait is the only place persistent effects may occur.

The production interface is inode-based. `root` supplies the starting inode,
`list` streams checked directory entries, and file operations consume the
inodes returned by those operations. Path splitting, component traversal,
mount crossings, symlink policy, and lookup caching belong to the caller's
VFS. Path-shaped conveniences exist only in `test_support` for the image and
power-loss corpus.

The current reader supports bounded ext images using inode tables, linear or HTree-indexed
directories, ext4 extent trees, legacy direct and single/double/triple-indirect
block maps, and read-only recovery of an internal JBD2 journal. Recovery stages
complete transactions in memory and exposes committed, non-revoked blocks
through a volatile overlay; mounting never modifies the image. It understands
contiguous and `meta_bg` descriptor placement, metadata and legacy GDT
checksums, and inline regular files and directories. Layout-neutral modern
features such as orphan files, MMP, large directories, EA inodes, encryption,
and casefold no longer reject an otherwise readable filesystem; encrypted
contents remain unavailable without a key. Inode-body, external-block, shared,
and EA-inode extended attributes use one checked reader; external-block and
EA-inode value checksums are validated. JBD2 checksum v2/v3, 32/64-bit
tags, circular logs, and escaped blocks are validated. Legacy
indirect blocks have no checksum in the on-disk format, so their pointers are
strictly bounds-checked. Indexed lookup currently scans validated leaf blocks
rather than using the hash index. It rejects rather than guesses when an image
requires:

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
    type Error;
    fn len(&self) -> u64;
    fn read(&mut self, offset: u64, dst: &mut [u8]) -> Result<(), Self::Error>;
    fn write(&mut self, offset: u64, src: &[u8]) -> Result<(), Self::Error>;
    fn flush(&mut self) -> Result<(), Self::Error>;
}
```

A successful `flush` means every preceding successful write is ordered before
it and durable. Reads and writes are exact: a short operation is an error.

`test_support::ModelStorage` records every effect, injects an I/O error or
power loss at an exact sequence number, and keeps volatile and durable images
separate. Pending writes can be persisted one prefix at a time before power
loss, allowing transaction tests to enumerate disk states without a VM.

## Private transactions

`Ext4::begin_transaction` creates an isolated dirty-block cache. Callers first
use `reserve_blocks` to fallibly allocate every full-block buffer and dirty
index slot they will need. Full-block replacement then performs no allocation
or read, while `modify_block` loads a block through the recovered filesystem
view and `read_block` observes the transaction's private version.

Dropping a transaction discards it and performs no storage writes.
`Transaction::commit` publishes the dirty set through the internal JBD2
journal. The initial writer is intentionally narrow: it requires a clean
internal journal using either checksum v3 or the ordinary unchecksummed
`mke2fs` format, a 4 KiB filesystem, enough consecutive journal space for one
descriptor/data/commit sequence, and no circular wrap. It writes and flushes
five ordered phases: journal preparation, recovery activation, commit,
home-block checkpoint, and cleanup.

Activation uses the original superblock with only `needs_recovery` added, so an
uncommitted transaction cannot leak its final counters. Checkpointing uses the
new superblock while retaining `needs_recovery`; the flag is cleared only after
every home block is durable. A failed commit consumes the transaction and the
filesystem must be remounted before further use.

The controlled 4 KiB mutation profile supports empty-file creation, arbitrary
writes at or before EOF, growth, arbitrary shrinking, and unlinking
link-count-one regular files whose initialized extents use trees up to the ext4
depth limit. `create_empty_file` initializes
an inode and inserts it into a checked linear directory, growing the directory
and its extent tree when no existing leaf has room. `unlink` does
not follow a final symlink and releases the inode plus fragmented data extents
across block groups while protecting structural metadata blocks. `mkdir` and
`rmdir` create and reclaim checked directories, including all data and extent
tree blocks, `.`/`..` entries, checksum tails, parent link count, and per-group
used-directory count. `rename` supports regular files, symlinks, and directories
between checked parents and grows a full linear destination. Non-directory
sources may replace a link-count-one
regular file; the replaced inode and fragmented cross-group extents are
reclaimed in the same transaction. Exclusive external xattr blocks are
reclaimed with the inode, while shared blocks receive a checksummed reference
count decrement. Directory moves walk the destination's
on-disk `..` ancestry to reject cycles, rewrite `..`, and transfer the parent
link count. Rename stages the unchanged superblock required by the JBD2 recovery
protocol. The inode-based file writer selects in-place block replacement or
extent growth, including writes which begin inside the file and cross EOF. Its
resize operation zero-fills growth and shrinks by retaining the physical
prefix, releasing the suffix and surplus extent nodes, and rebuilding the
smaller depth-N tree. Path-shaped initialization, append, overwrite, and
truncate helpers are confined to the test-support facade over those two
primitives.
Each operation updates the
relevant bitmaps, counters, and metadata checksums, while all resulting blocks
remain private until committed. Tests apply those blocks to disposable images,
remount them, require independent `e2fsck` validation, and inject failure at
every read before the dirty set becomes visible.

One prospective allocation owns all inode and block bitmap edits for an
operation. It prefers groups already in that plan, then scans remaining block
groups, uses group-local bitmap indices, and atomically updates every touched
bitmap and group descriptor. Lazy
`BLOCK_UNINIT` groups are materialized by reconstructing backup-superblock,
descriptor-table, reserved-GDT, bitmap, inode-table, and padding reservations
before allocation. Inode allocation also crosses group boundaries and
materializes `INODE_UNINIT` bitmaps when the inode table is already marked
zeroed, including the paired lazy block bitmap and `itable_unused` accounting.
Several descriptor edits sharing one descriptor-table block are merged before
staging.

Inode layout is similarly confined to a typed editor. Namespace and file
operations request link-count or extent-mapping changes without knowing inode
byte offsets, and the editor refreshes the inode checksum once after the
composed edit. `InodeMetadataUpdate` is the layout-free metadata primitive;
Linux-shaped `chmod`, `chown`, and timestamp APIs are thin wrappers over it.
Timestamps round-trip ext4 epoch extension bits and nanoseconds, including
pre-epoch and post-2038 values.

File contents are confined to `FileEditor`. It composes checked ownership,
allocation or release, partial-block preservation, tail zeroing, and
`InodeEditor` extent updates. Policy-shaped APIs no longer carry independent
extent mutation implementations.

Journal tests cut power at every storage effect and persist every ordered
whole-write prefix at each failed barrier. Every image exposes exactly the old
or new namespace through our recovery; `e2fsck` independently replays it and
then reports a clean filesystem. Sub-block torn writes are modeled by the test
storage but are not yet claimed by this writer; defining the device atomicity
contract and testing torn control records is the next durability step.

## Road to writable ext4

1. Complete modern read support (journal overlay and legacy block maps): done.
2. Add a transaction-private dirty-block cache and fallible reservations: done.
3. Add bitmap allocation and extent mutation for a controlled mkfs profile:
   done for write-at, grow, shrink, allocation/release spanning block groups,
   and a single depth-N extent writer that grows and splits trees through
   depth 5. Sparse holes remain.
4. Add directories and inode lifecycle: linear multi-block lookup, mutation,
   leaf growth, mkdir/rmdir, unlink, replacement, and cycle-safe cross-parent
   rename are done. Indexed directories can be read, removed from, and updated
   in place; hash-directed indexed insertion and splitting remain.
5. Add JBD2 transaction writing and recovery: initial non-wrapping checksum-v3
   writer done; circular reuse, revokes, and torn-control-record handling remain.
6. Validate every operation and crash point against `e2fsck` and Linux.

RetroOS uses this engine for every ext filesystem; there is no second ext
implementation or compatibility fallback in the kernel.
