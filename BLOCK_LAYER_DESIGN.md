# Block layer: from one global disk to owned devices

Design for reworking `kernel/block.rs` and everything that reads sectors
through it. Written after the `drivers/` + `fs/` restructure (b26a73b).

Three constraints shape the whole thing:

- **No statics.** Ownership is threaded or moved, never parked in a
  global. Composition happens at startup, like `threads` already does.
- **`dyn` for open sets, enums for closed ones.** Filesystems and block
  transports are defined *outside* RetroOS (ext4, ATA, NVMe, virtio) —
  those get traits. `platform::{Host, Display, Audio}` are sets RetroOS
  itself defines and closes — those stay enums with exhaustive matches.
- **Drivers report what exists and how to drive it. Startup decides
  what to do about it.** A driver never knows it holds "the boot disk";
  the block layer never picks a root. Discovery is mechanism, the mount
  tree is policy, and they live in different places.

## 0. Where policy currently leaks downward

The third constraint indicts more than `block.rs`. `platform::probe_media`
reads the MBR, walks the GPT, sniffs each ext partition for `/etc`+`/usr`,
and returns a *decision*:

```rust
Media::DiskRoot { ext4_lba, extra_ext: [u32; 3], hostfs }
//                ^^^^^^^^  "this one is root"  ^^^^^^^^^ "these are not"
```

`platform.media` has exactly one consumer in the tree —
`startup::mount_filesystems`. So the machine probe is choosing the VFS
root on behalf of the only caller that has any business choosing it, and
`platform.rs` carries ~150 lines of MBR/GPT parsing to do it.

Under the rule above that splits three ways:

- **How to read a partition table** → `block/partition.rs` (mechanism).
- **What partitions this disk has** → a `Vec<Partition>` (fact).
- **Which one becomes `/`, where the others land** → startup (policy).

`Media` therefore leaves `platform` entirely. `platform` keeps the
verdicts that really are machine facts — `Host`, `Display`, `Audio`,
and whether a hostfs transport answered — and stops reading sectors.
That also relaxes the current ordering constraint where `block::init`
must run *before* `platform::probe` because the probe needs the MBR.

## 1. What's actually wrong

### 1.1 One disk, chosen by an if/else, stored in a `u8`

```rust
static KIND: AtomicU8 = AtomicU8::new(NONE);

pub fn init<A: Arch>(machine: &mut A) {
    if hdd::probe()             { KIND.store(ATA) }
    else if nvme::init(machine) { KIND.store(NVME) }
}

pub fn read_sectors(lba: u32, buffer: &mut [u8]) -> u32 {
    match KIND.load(Relaxed) { ATA => hdd::read_sectors(..), NVME => .. }
}
```

`read_sectors` takes no device argument, so there is exactly one disk in
the system, forever. ATA *and* NVMe simultaneously is not a missing
feature — it is unrepresentable. Same for ATA secondary/slave, or a
second NVMe namespace.

### 1.2 The drivers have no instance state either

`hdd::read_sectors` is a free function hardwired to the primary
controller's master drive. `nvme` keeps a single `static NVME:
Mutex<Option<Nvme>>`. Neither can describe "which disk" because neither
has a value to describe it with.

### 1.3 lwext4 is handed the device handle and throws it away

The sharpest symptom. lwext4 already models partitions correctly — one
`Ext4Blockdev` per mount, each with its own `part_offset` — and it
passes that struct into every callback:

```rust
unsafe extern "C" fn bdev_bread(_bdev: *mut Ext4Blockdev, buf: *mut u8, blk_id: u64, ...) {
    crate::kernel::block::read_sectors(blk_id as u32, slice);   // _bdev discarded
}
```

The one argument that could name the device is `_`-prefixed. So: many
partitions, one disk.

All mounts also share one `static IFACE` and one `static PH_BBUF`
scratch buffer — safe today only because the fs layer is single-threaded.

### 1.4 Partition identity is a bare `u32` LBA

```rust
Media::DiskRoot { ext4_lba: u32, extra_ext: [u32; 3], hostfs: bool }
```

A partition is a start sector with no device and no length.

- **No device.** Every consumer implicitly means "the global disk".
- **No length.** The fs re-derives its extent from the superblock
  (`part_size_from_superblock`) because the partition table's extent was
  discarded. A wrong value silently reads EMPTY past the ceiling — this
  has already bitten us once.
- **Fixed cap of 3 extras**, and `u32` sectors caps a disk at 2 TiB.
  `gpt_collect_ext` already has to skip partitions past 4 G-sectors.

### 1.5 The overlay is a global on/off

`arm_ram_overlay()` diverts *all* writes system-wide, via a
`static mut OVERLAY`. On a real laptop you want the internal disk
overlayed but an attached scratch disk written through; unexpressible.

### 1.6 The partition scan lives in `platform.rs`

`probe_media`, `is_ext_partition`, `gpt_collect_ext`,
`is_protective_mbr` all do raw `block::read_sectors`. MBR/GPT parsing is
block-layer knowledge, not machine-probe knowledge.

### 1.7 Dead code found in passing

`TarFs::Source::Disk` is vestigial: `startup.rs:10` sets
`ROOT_TARFS = TarFs::new(0)` as a const placeholder and line 132 always
overwrites it with `new_ram`. If `bootfs()` returned `None` we'd mount a
TAR aimed at sector 0 with an unbuilt index. Delete the variant.

## 2. The target model

Two types. No registry, no handle table, no statics.

```rust
// kernel/block.rs

/// What a driver implements. One value per physical disk / namespace,
/// owning everything that disk needs (ports, queues, BAR mapping).
/// `dyn` because the transport set is open — ATA, NVMe, virtio, USB MSC
/// are standards from outside RetroOS.
pub trait Disk {
    fn read (&self, lba: u64, buf: &mut [u8]) -> u32;
    fn write(&self, lba: u64, buf: &[u8])     -> u32;
    fn sectors(&self) -> u64;
    fn name(&self) -> &str;               // "ata0", "nvme0n1"
}

/// A contiguous extent on a disk — what a filesystem mounts.
/// Replaces every bare `part_lba: u32` in the tree.
#[derive(Clone, Copy)]
pub struct Volume {
    disk:  &'static dyn Disk,
    start: u64,
    pub sectors: u64,
}

impl Volume {
    /// Volume-relative and bounds-checked; past the end yields zeros.
    pub fn read (&self, lba: u64, buf: &mut [u8]) -> u32;
    pub fn write(&self, lba: u64, buf: &[u8])     -> u32;
}
```

**`Volume` holds the device reference directly, so there is no registry
and no `DiskId`.** The handle *is* the reference. This is strictly
simpler than an index-into-a-global-table, and it's the reason `KIND`
disappears rather than being replaced by something.

`&'static` comes from `Box::leak` at startup — exactly how `vfs` already
takes `&'static dyn Filesystem`. Leaked boot-lifetime ownership, not
mutable global state. (`Filesystem` carries no `Sync` bound and
`Lwext4Fs` already holds a `RefCell` behind such a reference, so the
pattern is established.)

### The overlay becomes a disk, not a flag

```rust
struct RamOverlay {
    inner: &'static dyn Disk,
    map:   RefCell<BTreeMap<u64, Box<[u8; 512]>>>,
}
impl Disk for RamOverlay {
    fn read(&self, lba, buf)  { self.inner.read(lba, buf); /* patch from map */ }
    fn write(&self, lba, buf) { /* into map only */ }
}
```

A `Disk` that wraps a `Disk`. Startup decides per-device whether to wrap,
and a wrapped disk is simply the only reference anyone holds — the
protection is structural, not a boolean anyone can forget to check.
`static mut OVERLAY` and `arm_ram_overlay()` both die, and this is the
"ownership by move, not flags" rule applied literally.

### Enumeration returns a value

```rust
pub fn probe<A: Arch>(machine: &mut A) -> Vec<&'static dyn Disk>;
```

Not winner-takes-all: every ATA channel/drive that answers, every NVMe
namespace. Stable ordering (ATA before NVMe) keeps the boot root
predictable. Startup owns the `Vec` and hands it to the platform probe —
the same shape as `init_threading()` returning an owned `Vec`.

### Partition table → `block/partition.rs`

```rust
pub enum PartKind { Ext, Fat, BootBundle, Other(u8) }   // closed set → enum
pub struct Partition { pub volume: Volume, pub kind: PartKind }

/// Parse MBR, or GPT behind a protective MBR. Extents come from the TABLE.
pub fn scan(disk: &'static dyn Disk) -> Vec<Partition>;
```

The partition's length now comes from the partition table, so
`part_size_from_superblock` demotes from source-of-truth to a
cross-check: warn on mismatch, take the smaller.

### The mount decision moves up, as a `MountPlan`

`Media` leaves `platform` and becomes a plan startup *derives* from the
facts, rather than a verdict handed down to it:

```rust
// kernel/startup.rs
enum RootSource { Disk(Volume), Host, None }        // closed set → enum

struct MountPlan {
    root:   RootSource,
    extra:  Vec<(&'static [u8], Volume)>,   // mount point → volume
    hostfs: bool,
}

fn plan_mounts(parts: &[Partition], hostfs: bool) -> MountPlan;
```

This keeps the ADT discipline CLAUDE.md asks for — `mount_filesystems`
still does one exhaustive match, nothing probes lazily — while putting
the choice in the layer that owns it. The `/etc`+`/usr` sniff that picks
the real root out of a multi-ext disk moves here too; it is the
definition of mount policy.

Three things fall out: the `[u32; 3]` cap disappears, the extra mount
points stop being hardcoded at the point of use, and `plan_mounts` is a
pure function over facts — testable without a disk.

### The resulting startup spine

`platform` no longer touches storage, so the probe ordering inverts and
the storage story becomes one readable run of steps:

```rust
klog::init();

let platform = platform::probe(machine, boot);   // no sector reads now
let disks    = block::probe(machine);            // mechanism: what's there
let disks    = apply_write_policy(platform, disks);   // policy: wrap in RamOverlay?
let parts    = disks.iter().flat_map(partition::scan).collect();

let plan = plan_mounts(&parts, hostfs_available());  // policy: pure fn over facts
mount(plan);
```

Note `block::init` no longer has to run *before* `platform::probe` —
that constraint existed solely because `probe_media` needed the MBR.
And the overlay decision is a visible step that consumes the platform
verdict and *transforms the disk list*, rather than a flag flipped
inside the block layer.

### lwext4 uses the handle it's already given

Per-mount `Ext4BlockdevIface` (its own `ph_bbuf`), with the mount's
`Volume` behind `p_user` — the pointer lwext4 provides for exactly this:

```rust
unsafe extern "C" fn bdev_bread(bdev: *mut Ext4Blockdev, buf: *mut u8, blk_id: u64, cnt: u32) -> i32 {
    let vol = &*((*(*bdev).bdif).p_user as *const Volume);
    vol.read_device_absolute(blk_id, slice);
    EOK
}
```

`Lwext4Fs::new(volume: Volume, index: usize)`. Kills `static mut IFACE`
and `static mut PH_BBUF` together.

### Statics removed

| Static | Becomes |
|---|---|
| `block::KIND` | gone — `Volume` holds the device |
| `block::OVERLAY` (+ `overlay()`) | `RamOverlay` decorator, owned by composition |
| `nvme::NVME` | `NvmeNamespace` value per namespace, leaked |
| `lwext4::IFACE`, `lwext4::PH_BBUF` | per-mount, owned by `Lwext4Fs` |
| `startup::ROOT_TARFS` | `Box::leak`, like the other mounts |
| `startup::EXT4_FS` | dropped — only the leaked `&'static` is needed |
| `startup::HOSTFS` | `Box::leak` at mount time |

What legitimately remains: lwext4's own C-side device/mount registry
(library state we don't own), and the `portio` injected hook table
(composition-root injection, a separate concern).

## 3. Sequencing

Each step builds and boots on its own; no flag day.

| # | Step | Notes |
|---|---|---|
| 1 | `Disk` trait; `hdd`/`nvme` become owned instances | The bulk of the mechanical work: `AtaDisk { base_port, drive }`, `NvmeNamespace { .. }`. Kills `NVME`. Still one disk in use. |
| 2 | `Volume`; widen LBA to `u64`; thread through the ~13 call sites | Kills `KIND`. Removes the 2 TiB cap and the `>u32` skip in `gpt_collect_ext`. |
| 3 | `block/partition.rs`; `Media` → `MountPlan` in startup | Moves ~150 lines of MBR/GPT parsing out of `platform.rs` and the root-sniff into policy. Extents now come from the table. Biggest diff, still behaviour-preserving. |
| 4 | `Volume` into `lwext4` (per-mount iface + `p_user`) and `tarfs`; drop `Source::Disk` | Where `_bdev` stops being discarded. Kills `IFACE`/`PH_BBUF`. |
| 5 | `RamOverlay` decorator; startup composes it per-disk | Kills `OVERLAY`. |
| 6 | Enumerate multiple disks | ATA secondary + slaves, NVMe namespaces >1. **First step with new behaviour.** |

Steps 1–5 are refactors with an unchanged boot. Step 6 is the payoff.

## 4. Verification

Per step: build metal + hosted, then boot
`QEMU_DISPLAY=none ./run.sh qemu` and confirm the three storage lines
still appear —

```
Storage: ATA (PIO)
ext4 root at sector 0x10000
TAR: indexed 19 entries from embedded bootfs
```

— through to DN starting. Step 3 wants the big-disk case from the
`part_size` bug re-run, since that's where extents change hands. Step 6
wants a QEMU run with two disks attached (`-drive` IDE + `-device nvme`)
showing both enumerated and both mountable.

## 5. Open decisions

**Settled:** dispatch is `dyn` for the open transport/fs sets, enums for
RetroOS-closed sets. Nothing picks a boot disk below startup — `block`
enumerates, `startup` decides. **`platform` does not touch storage at
all**; startup owns the disk list and the partition scan both.

1. **Does `Volume` bounds-check, or trust the caller?** Checking makes
   the `part_size` class of bug structurally impossible at one compare
   per read. I'd check.
2. **Where do extra partitions mount?** Today `/disk1../disk3`,
   hardcoded. With N disks × M partitions that doesn't scale;
   `/mnt/<diskname><part>` (`/mnt/nvme0n1p3`) is self-describing, and
   the naming now lives in `plan_mounts` rather than at the mount site.
