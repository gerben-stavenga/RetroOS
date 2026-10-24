//! Small ACPI table reader for early hardware discovery.
//!
//! The Multiboot v1 entry path does not pass an RSDP pointer, so find the
//! standard PC RSDP locations, validate the checksums, and walk the root table
//! for hardware descriptions. Boot reads borrow a temporary PTE without a heap.
//! Call on the BSP at ring 0 with IRQs off, before entering the runtime.

const RSDP_SIGNATURE: &[u8; 8] = b"RSD PTR ";

fn read_physical(address: u64, out: &mut [u8]) -> bool {
    crate::paging2::read_boot_physical(address, out)
}

fn checksum(address: u64, length: usize) -> Option<u8> {
    let mut sum = 0u8;
    let mut offset = 0usize;
    let mut chunk = [0u8; 256];
    while offset < length {
        let count = (length - offset).min(chunk.len());
        if !read_physical(address.checked_add(offset as u64)?, &mut chunk[..count]) {
            return None;
        }
        for &byte in &chunk[..count] {
            sum = sum.wrapping_add(byte);
        }
        offset += count;
    }
    Some(sum)
}

fn read_u32(address: u64) -> Option<u32> {
    let mut bytes = [0u8; 4];
    read_physical(address, &mut bytes).then(|| u32::from_le_bytes(bytes))
}

fn valid_rsdp(address: u64) -> bool {
    let mut prefix = [0u8; 36];
    if !read_physical(address, &mut prefix[..20])
        || &prefix[..8] != RSDP_SIGNATURE
        || checksum(address, 20) != Some(0)
    {
        return false;
    }
    if prefix[15] < 2 {
        return true;
    }
    if !read_physical(address, &mut prefix) {
        return false;
    }
    let length = u32::from_le_bytes(prefix[20..24].try_into().unwrap()) as usize;
    (36..=4096).contains(&length) && checksum(address, length) == Some(0)
}

fn scan_rsdp(start: u64, end: u64) -> Option<u64> {
    let mut candidate = (start + 15) & !15;
    while candidate.checked_add(20).is_some_and(|last| last <= end) {
        let mut signature = [0u8; 8];
        if read_physical(candidate, &mut signature)
            && &signature == RSDP_SIGNATURE
            && valid_rsdp(candidate)
        {
            return Some(candidate);
        }
        candidate += 16;
    }
    None
}

fn find_rsdp() -> Option<u64> {
    // The first 1 KiB of the EBDA is searched before the BIOS ROM area.
    let ebda_segment = read_u32(0x40E)? as u16;
    let ebda = u64::from(ebda_segment) << 4;
    if (0x80000..0xA0000).contains(&ebda)
        && let Some(rsdp) = scan_rsdp(ebda, (ebda + 1024).min(0xA0000))
    {
        return Some(rsdp);
    }
    scan_rsdp(0xE0000, 0x100000)
}

fn table_header(address: u64) -> Option<([u8; 4], usize)> {
    let mut header = [0u8; 36];
    if !read_physical(address, &mut header) {
        return None;
    }
    let length = u32::from_le_bytes(header[4..8].try_into().ok()?) as usize;
    (length >= header.len() && length <= 1_048_576)
        .then(|| (header[..4].try_into().unwrap(), length))
}

fn find_in_root(
    root: u64,
    signature: &[u8; 4],
    entry_bytes: usize,
    wanted: &[u8; 4],
) -> Option<u64> {
    let (root_signature, length) = table_header(root)?;
    if &root_signature != signature
        || (length - 36) % entry_bytes != 0
        || checksum(root, length) != Some(0)
    {
        return None;
    }
    let mut entry = [0u8; 8];
    for offset in (36..length).step_by(entry_bytes) {
        let slot = &mut entry[..entry_bytes];
        if !read_physical(root.checked_add(offset as u64)?, slot) {
            return None;
        }
        let address = if entry_bytes == 8 {
            u64::from_le_bytes(entry)
        } else {
            u64::from(u32::from_le_bytes(entry[..4].try_into().unwrap()))
        };
        let Some((child_signature, child_length)) = table_header(address) else {
            continue;
        };
        if &child_signature == wanted && checksum(address, child_length) == Some(0) {
            return Some(address);
        }
    }
    None
}

fn table_from_rsdp_fields(prefix: &[u8], wanted: &[u8; 4]) -> Option<u64> {
    let rsdt = u64::from(u32::from_le_bytes(prefix.get(16..20)?.try_into().ok()?));
    let xsdt = if prefix.get(15).copied()? >= 2 {
        u64::from_le_bytes(prefix.get(24..32)?.try_into().ok()?)
    } else {
        0
    };
    if xsdt != 0
        && let Some(base) = find_in_root(xsdt, b"XSDT", 8, wanted)
    {
        return Some(base);
    }
    (rsdt != 0)
        .then(|| find_in_root(rsdt, b"RSDT", 4, wanted))
        .flatten()
}

/// Find a validated table through a copied Multiboot2 RSDP tag.
fn table_from_rsdp(rsdp: &[u8], wanted: &[u8; 4]) -> Option<u64> {
    if rsdp.len() < 20
        || &rsdp[..8] != RSDP_SIGNATURE
        || rsdp[..20]
            .iter()
            .fold(0u8, |sum, byte| sum.wrapping_add(*byte))
            != 0
    {
        return None;
    }
    let prefix = if rsdp[15] >= 2 {
        if rsdp.len() < 36 {
            return None;
        }
        let length = u32::from_le_bytes(rsdp[20..24].try_into().ok()?) as usize;
        if !(36..=rsdp.len()).contains(&length)
            || rsdp[..length]
                .iter()
                .fold(0u8, |sum, byte| sum.wrapping_add(*byte))
                != 0
        {
            return None;
        }
        &rsdp[..36]
    } else {
        &rsdp[..20]
    };
    table_from_rsdp_fields(prefix, wanted)
}

/// Locate and validate an RSDP through the legacy PC search areas. This is the
/// fallback for Multiboot1 or a loader that omits the Multiboot2 ACPI tag.
fn table_from_legacy_scan(wanted: &[u8; 4]) -> Option<u64> {
    let rsdp = find_rsdp()?;
    let mut prefix = [0u8; 36];
    if !read_physical(rsdp, &mut prefix[..20]) {
        return None;
    }
    if prefix[15] >= 2 && !read_physical(rsdp, &mut prefix) {
        return None;
    }
    let length = if prefix[15] >= 2 {
        u32::from_le_bytes(prefix[20..24].try_into().ok()?) as usize
    } else {
        20
    };
    if !(20..=prefix.len()).contains(&length) || checksum(rsdp, length) != Some(0) {
        return None;
    }
    table_from_rsdp_fields(&prefix, wanted)
}

fn hpet_base(address: u64) -> Option<u64> {
    if table_header(address)?.1 < 56 {
        return None;
    }
    let mut hpet = [0; 56];
    if !read_physical(address, &mut hpet) || hpet[40] != 0 || hpet[41] == 0 {
        return None;
    }
    let base = u64::from_le_bytes(hpet[44..52].try_into().ok()?);
    (base != 0).then_some(base)
}

pub fn hpet_base_from_rsdp(rsdp: &[u8]) -> Option<u64> {
    hpet_base(table_from_rsdp(rsdp, b"HPET")?)
}
pub fn hpet_base_from_legacy_scan() -> Option<u64> {
    hpet_base(table_from_legacy_scan(b"HPET")?)
}

/// Enumerate enabled local APIC/x2APIC IDs into caller storage, without a heap.
/// Returns the number stored; an oversized list or malformed MADT is rejected.
/// Disabled/online-capable-only CPUs require hotplug and are not boot targets.
pub fn processor_ids(rsdp: &[u8], ids: &mut [u32]) -> Option<usize> {
    let address = table_from_rsdp(rsdp, b"APIC").or_else(|| table_from_legacy_scan(b"APIC"))?;
    let length = table_header(address)?.1;
    madt_ids(
        length,
        |offset, bytes| read_physical(address + offset as u64, bytes),
        ids,
    )
}

fn madt_ids(
    length: usize,
    mut read: impl FnMut(usize, &mut [u8]) -> bool,
    ids: &mut [u32],
) -> Option<usize> {
    if length < 44 {
        return None;
    }
    let mut offset = 44;
    let mut count = 0;
    while offset < length {
        let mut record = [0u8; 16];
        if length - offset < 2 || !read(offset, &mut record[..2]) {
            return None;
        }
        let size = record[1] as usize;
        if size < 2 || size > length - offset {
            return None;
        }
        let required = match record[0] {
            0 => 8,
            9 => 16,
            _ => 2,
        };
        if size < required || !read(offset, &mut record[..required]) {
            return None;
        }
        let cpu = match record[0] {
            0 => Some((
                u32::from(record[3]),
                u32::from_le_bytes(record[4..8].try_into().ok()?),
            )),
            9 => Some((
                u32::from_le_bytes(record[4..8].try_into().ok()?),
                u32::from_le_bytes(record[8..12].try_into().ok()?),
            )),
            _ => None,
        };
        if let Some((id, flags)) = cpu
            && flags & 1 != 0
            && !ids[..count].contains(&id)
        {
            if count == ids.len() || id == u32::MAX {
                return None;
            }
            ids[count] = id;
            count += 1;
        }
        offset += size;
    }
    Some(count)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn parse(records: &[u8], ids: &mut [u32]) -> Option<usize> {
        madt_ids(
            44 + records.len(),
            |offset, out| {
                let Some(bytes) = records.get(offset - 44..offset - 44 + out.len()) else {
                    return false;
                };
                out.copy_from_slice(bytes);
                true
            },
            ids,
        )
    }
    #[test]
    fn enabled_sparse_ids_and_duplicates() {
        let mut ids = [0; 4];
        let records = [
            0, 8, 0, 7, 1, 0, 0, 0, // enabled, BSP need not be zero
            0, 8, 1, 2, 2, 0, 0, 0, // online-capable only
            0, 8, 2, 9, 0, 0, 0, 0, // disabled
            9, 16, 0, 0, 0, 1, 0, 0, 1, 0, 0, 0, 3, 0, 0, 0, 0, 8, 0, 7, 1, 0, 0,
            0, // duplicate
            42, 3, 0, // unknown record
        ];
        assert_eq!(parse(&records, &mut ids), Some(2));
        assert_eq!(&ids[..2], &[7, 256]);
        assert_eq!(parse(&records, &mut [0; 1]), None);
    }
    #[test]
    fn malformed_records_are_rejected() {
        for records in [
            &[0][..],
            &[0, 0],
            &[0, 2],
            &[9, 8, 0, 0, 0, 0, 0, 0],
            &[42, 3],
        ] {
            assert_eq!(parse(records, &mut [0; 4]), None);
        }
        assert_eq!(madt_ids(43, |_, _| true, &mut [0; 4]), None);
        assert_eq!(madt_ids(46, |_, _| false, &mut [0; 4]), None);
    }
}
