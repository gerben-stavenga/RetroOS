//! Single-byte NLS services backed by shared regional profiles.
use super::*;

pub(super) fn dispatch<A: crate::Arch>(machine: &mut A, regs: &Regs, api: Api) -> u32 {
    let length = arg32(machine, regs, 0) as usize;
    let country = arg32(machine, regs, 1) as usize;
    let buffer = arg32(machine, regs, 2) as usize;
    if country == 0 || (length != 0 && buffer == 0) { return ERROR_INVALID_PARAMETER; }
    let country_id = machine.read::<u32>(country);
    let profile = if country_id == 0 { Some(lib::locale::current()) }
        else { u16::try_from(country_id).ok().and_then(lib::locale::by_country) };
    let Some(profile) = profile else { return 398; }; // ERROR_NLS_NO_CTRY_CODE
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
                machine.copy_to(buffer, &crate::kernel::locale::os2_country(profile, page.id)[..copied]);
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
