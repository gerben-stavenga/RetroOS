//! Partition tables — MBR, and GPT behind a protective MBR.
//!
//! This is mechanism: it reports what the table says is on a disk. It does not
//! decide which partition becomes the root, where anything mounts, or whether
//! a partition is interesting — `startup` owns all of that.
//!
//! Extents come from the TABLE. That matters: a [`Volume`] built here carries
//! the partition's real length, so a filesystem mounted on it cannot read past
//! its own end into the neighbouring partition — see `Volume::read`.

use alloc::vec::Vec;
use super::Volume;

/// What the table claims a partition holds.
///
/// A closed set — these are the categories RetroOS itself acts on — so an
/// enum, and adding one breaks every match that has to care.
/// What the TABLE claims — a declaration, not a verdict. Whether a partition
/// really holds a given filesystem is that filesystem's question: it reads the
/// superblock. This layer parses tables and nothing else.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum PartKind {
    /// Linux (MBR type 0x83) — conventionally ext, but only a probe knows.
    Linux,
    /// FAT of some flavour.
    Fat,
    /// RetroOS's own 0xDA boot bundle — the bootloader's business, never
    /// mounted.
    BootBundle,
    /// Anything else, carrying the raw type byte (0 for GPT entries).
    Other(u8),
}

/// One entry from a partition table.
pub struct Partition {
    /// The partition's extent, ready to hand to a filesystem.
    pub volume: Volume,
    pub kind: PartKind,
}

impl PartKind {
    /// Classify an MBR type byte.
    fn from_mbr(ty: u8) -> PartKind {
        match ty {
            0x83 => PartKind::Linux,
            0x01 | 0x04 | 0x06 | 0x0B | 0x0C | 0x0E => PartKind::Fat,
            0xDA => PartKind::BootBundle,
            other => PartKind::Other(other),
        }
    }
}

/// Read the partition table off `disk` (a whole-disk volume) and return every
/// entry it declares, in table order. An unpartitioned or unreadable disk
/// yields an empty list — never an error, since "no partitions" is a perfectly
/// ordinary answer.
pub fn scan(disk: Volume) -> Vec<Partition> {
    let mut mbr = [0u8; 512];
    disk.read(0, &mut mbr);
    if is_protective_mbr(&mbr) {
        gpt(disk)
    } else {
        self_mbr(disk, &mbr)
    }
}

/// True if sector 0 is a GPT *protective* MBR — an entry of type 0xEE
/// covering the disk. GPT disks (every UEFI machine) put this at LBA 0 so
/// legacy tooling leaves the real layout alone.
fn is_protective_mbr(mbr: &[u8; 512]) -> bool {
    (0..4).any(|i| mbr[0x1BE + i * 16 + 4] == 0xEE)
}

/// The four primary MBR entries. Extended partitions are not walked — RetroOS
/// has never needed one, and a chain walk is easy to add here if it ever does.
fn self_mbr(disk: Volume, mbr: &[u8; 512]) -> Vec<Partition> {
    let mut out = Vec::new();
    for i in 0..4 {
        let base = 0x1BE + i * 16;
        let ty = mbr[base + 4];
        let start = u32::from_le_bytes(mbr[base + 8..base + 12].try_into().unwrap()) as u64;
        let sectors = u32::from_le_bytes(mbr[base + 12..base + 16].try_into().unwrap()) as u64;
        if ty == 0 || start == 0 || sectors == 0 {
            continue; // empty slot
        }
        out.push(Partition {
            volume: Volume::new(disk.disk(), start, sectors),
            kind: PartKind::from_mbr(ty),
        });
    }
    out
}

/// Walk the GPT. LBA 1 holds the header (signature "EFI PART", then the
/// partition-array LBA, entry count and entry stride); the array follows.
///
/// Type GUIDs are deliberately not interpreted: an ext partition is one with
/// an ext superblock at its start, whatever the installer typed it as.
fn gpt(disk: Volume) -> Vec<Partition> {
    let mut out = Vec::new();
    let mut hdr = [0u8; 512];
    disk.read(1, &mut hdr);
    if &hdr[0..8] != b"EFI PART" {
        return out;
    }
    let entry_lba = u64::from_le_bytes(hdr[0x48..0x50].try_into().unwrap());
    let num_entries = u32::from_le_bytes(hdr[0x50..0x54].try_into().unwrap()).min(256) as usize;
    let entry_size = u32::from_le_bytes(hdr[0x54..0x58].try_into().unwrap()) as usize;
    // Standard entries are 128 bytes (4 per 512-byte sector) and never straddle
    // a sector. Bail on anything that doesn't divide a sector cleanly.
    if entry_size == 0 || entry_lba == 0 || 512 % entry_size != 0 {
        return out;
    }
    let per_sector = 512 / entry_size;
    let mut buf = [0u8; 512];
    for s in 0..num_entries.div_ceil(per_sector) {
        disk.read(entry_lba + s as u64, &mut buf);
        for e in 0..per_sector {
            let off = e * entry_size;
            // Type GUID all-zero ⇒ unused slot.
            if buf[off..off + 16].iter().all(|&b| b == 0) {
                continue;
            }
            let first = u64::from_le_bytes(buf[off + 32..off + 40].try_into().unwrap());
            let last = u64::from_le_bytes(buf[off + 40..off + 48].try_into().unwrap());
            if first == 0 || last < first {
                continue;
            }
            // GPT type GUIDs are deliberately not interpreted — an ext root is
            // one with an ext superblock, whatever the installer typed it as,
            // and only the fs layer can tell.
            out.push(Partition {
                volume: Volume::new(disk.disk(), first, last - first + 1),
                kind: PartKind::Other(0),
            });
        }
    }
    out
}

