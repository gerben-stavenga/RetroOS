//! Small ACPI table reader for early hardware discovery.
//!
//! The Multiboot v1 entry path does not pass an RSDP pointer, so find the
//! standard PC RSDP locations, validate the checksums, and walk the root table
//! to locate the HPET description table. Reads use the existing physical
//! aperture and do not assume ACPI tables are below 4 GiB.

const APERTURE_SIZE: u64 = 64 * 1024;
const RSDP_SIGNATURE: &[u8; 8] = b"RSD PTR ";

fn read_physical(mut address: u64, mut out: &mut [u8]) -> bool {
    while !out.is_empty() {
        let base = address & !(APERTURE_SIZE - 1);
        let offset = (address - base) as usize;
        let count = out.len().min(APERTURE_SIZE as usize - offset);
        if !crate::aperture::remap(base) {
            return false;
        }
        unsafe {
            core::ptr::copy_nonoverlapping(
                (crate::aperture::APERTURE_BASE + offset) as *const u8,
                out.as_mut_ptr(),
                count,
            );
        }
        address += count as u64;
        out = &mut out[count..];
    }
    true
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

fn find_hpet_in_root(root: u64, signature: &[u8; 4], entry_bytes: usize) -> Option<u64> {
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
        if &child_signature != b"HPET" || child_length < 56
            || checksum(address, child_length) != Some(0)
        {
            continue;
        }
        let mut hpet = [0u8; 56];
        if !read_physical(address, &mut hpet) {
            continue;
        }
        // HPET's ACPI Generic Address Structure: System Memory, address at 44.
        if hpet[40] == 0 && hpet[41] != 0 {
            let base = u64::from_le_bytes(hpet[44..52].try_into().unwrap());
            if base != 0 {
                return Some(base);
            }
        }
    }
    None
}

fn hpet_base_from_rsdp_fields(prefix: &[u8]) -> Option<u64> {
    let rsdt = u64::from(u32::from_le_bytes(prefix.get(16..20)?.try_into().ok()?));
    let xsdt = if prefix.get(15).copied()? >= 2 {
        u64::from_le_bytes(prefix.get(24..32)?.try_into().ok()?)
    } else {
        0
    };
    if xsdt != 0
        && let Some(base) = find_hpet_in_root(xsdt, b"XSDT", 8)
    {
        return Some(base);
    }
    (rsdt != 0)
        .then(|| find_hpet_in_root(rsdt, b"RSDT", 4))
        .flatten()
}

/// Find the HPET register block from a copied Multiboot2 RSDP tag. The tag is
/// firmware data copied by GRUB; its root-table pointers still address physical
/// memory, which this module reads through the aperture.
pub fn hpet_base_from_rsdp(rsdp: &[u8]) -> Option<u64> {
    if rsdp.len() < 20 || &rsdp[..8] != RSDP_SIGNATURE || rsdp[..20]
        .iter().fold(0u8, |sum, byte| sum.wrapping_add(*byte)) != 0
    {
        return None;
    }
    let prefix = if rsdp[15] >= 2 {
        if rsdp.len() < 36 {
            return None;
        }
        let length = u32::from_le_bytes(rsdp[20..24].try_into().ok()?) as usize;
        if !(36..=rsdp.len()).contains(&length)
            || rsdp[..length].iter().fold(0u8, |sum, byte| sum.wrapping_add(*byte)) != 0
        {
            return None;
        }
        &rsdp[..36]
    } else {
        &rsdp[..20]
    };
    hpet_base_from_rsdp_fields(prefix)
}

/// Locate and validate an RSDP through the legacy PC search areas. This is the
/// fallback for Multiboot1 or a loader that omits the Multiboot2 ACPI tag.
pub fn hpet_base_from_legacy_scan() -> Option<u64> {
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
    hpet_base_from_rsdp_fields(&prefix)
}
