//! Single-byte NLS services for the personality's US country settings.
use super::*;

fn country_info(page: u16) -> [u8; 44] {
    // OS/2 COUNTRYINFO is packed: its character arrays must not introduce
    // Rust/C alignment padding before the later USHORT fields.
    let mut info = [0; 44];
    info[..4].copy_from_slice(&1u32.to_le_bytes());
    info[4..8].copy_from_slice(&u32::from(page).to_le_bytes());
    info[12] = b'$';
    info[17] = b',';
    info[19] = b'.';
    info[21] = b'/';
    info[23] = b':';
    info[26] = 2;
    info[32] = b',';
    info
}

pub(super) fn dispatch<A: crate::Arch>(machine: &mut A, regs: &Regs, api: Api) -> u32 {
    let length = arg32(machine, regs, 0) as usize;
    let country = arg32(machine, regs, 1) as usize;
    let buffer = arg32(machine, regs, 2) as usize;
    if country == 0 || (length != 0 && buffer == 0) { return ERROR_INVALID_PARAMETER; }
    let country_id = machine.read::<u32>(country);
    if country_id != 0 && country_id != 1 { return 398; } // ERROR_NLS_NO_CTRY_CODE
    let page = machine.read::<u32>(country + 4);
    let page = if page == 0 { u32::from(lib::codepage::current_codepage().id) } else { page };
    let Some(page) = u16::try_from(page).ok().and_then(lib::codepage::codepage) else {
        return 472; // ERROR_INVALID_CODE_PAGE
    };
    match api {
        Api::DosMapCase => {
            // Map exactly cb bytes, including embedded NULs, in place.
            for offset in 0..length {
                let byte = machine.read::<u8>(buffer + offset);
                machine.write::<u8>(buffer + offset, page.uppercase(byte));
            }
            NO_ERROR
        }
        Api::DosQueryCtryInfo | Api::DosQueryCollate => {
            let actual = arg32(machine, regs, 3) as usize;
            if actual == 0 { return ERROR_INVALID_PARAMETER; }
            let size = if api == Api::DosQueryCtryInfo { 44 } else { 256 };
            let copied = length.min(size);
            if api == Api::DosQueryCtryInfo {
                machine.copy_to(buffer, &country_info(page.id)[..copied]);
            } else {
                // A case-insensitive OEM ordering: equivalent upper/lower
                // characters share a weight, as they do in DOS file lookup.
                for byte in 0..copied {
                    machine.write::<u8>(buffer + byte, page.uppercase(byte as u8));
                }
            }
            machine.write::<u32>(actual, copied as u32);
            if copied < size { 399 } else { NO_ERROR } // ERROR_NLS_TABLE_TRUNCATED
        }
        _ => unreachable!(),
    }
}
