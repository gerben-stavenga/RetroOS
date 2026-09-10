//! INT 21h/71xx: Windows 95 DOS long-filename API.
//! Register layouts: RBIL 61, INT 21/7139..71A8. Namespace policy lives in
//! DFS, never in the backing filesystem or the generic VFS.
use super::*;
use alloc::vec::Vec;
use crate::kernel::vfs;
use dfs::lfn::{self as names, Found, PATH_MAX};

fn word(reg: &mut u64, value: u16) { *reg = (*reg & !0xffff) | u64::from(value); }
fn errno(rc: i32) -> Result<(), u16> {
    if rc >= 0 { Ok(()) } else { Err(dos_error_from_errno(rc)) }
}

fn string<A: crate::Arch>(machine: &mut A, dos: &thread::DosState<A>, regs: &Regs, seg: u16, off: u32) -> Result<Vec<u8>, u16> {
    let address = linear(machine, dos, regs, seg, off) as usize;
    let mut name = Vec::new();
    for i in 0..=PATH_MAX {
        let byte = machine.read::<u8>(address + i);
        if byte == 0 { return Ok(name); }
        name.push(byte);
    }
    Err(206)
}

fn put_string<A: crate::Arch>(machine: &mut A, address: usize, value: &[u8]) {
    machine.copy_to(address, value);
    machine.write::<u8>(address + value.len(), 0);
}

fn writable(path: &[u8]) -> Result<(), u16> {
    if immutable_media_path(path) { Err(5) } else { Ok(()) }
}

fn attributes(path: &[u8]) -> Result<u16, u16> {
    vfs::dos_attributes(path).map(u16::from).ok_or(2)
}

fn set_attributes(path: &[u8], attributes: u16) -> Result<(), u16> {
    writable(path)?;
    if attributes & !0x37 != 0 { return Err(13); }
    errno(vfs::set_dos_attributes(path, attributes as u8))
}

const FILETIME_EPOCH: u64 = 11_644_473_600;
fn filetime(unix: u32) -> u64 {
    if unix == 0 { 0 } else { (u64::from(unix) + FILETIME_EPOCH) * 10_000_000 }
}

fn find_data(found: &Found, format: u16) -> Result<Vec<u8>, u16> {
    if format > 1 { return Err(1); }
    if found.name.len() > names::NAME_MAX || found.alias.len() > 12 { return Err(206); }
    let mut out = alloc::vec![0; 318];
    out[..4].copy_from_slice(&u32::from(found.attributes).to_le_bytes());
    // Creation/access times remain zero (unsupported), not fabricated.
    let time = if format == 0 { filetime(found.mtime) } else {
        let (time, date) = unix_to_dos_datetime(found.mtime);
        u64::from(time) | (u64::from(date) << 16)
    };
    out[20..28].copy_from_slice(&time.to_le_bytes());
    out[32..36].copy_from_slice(&found.size.to_le_bytes());
    out[44..44 + found.name.len()].copy_from_slice(&found.name);
    out[304..304 + found.alias.len()].copy_from_slice(&found.alias);
    Ok(out)
}

pub(super) fn dispatch<A: crate::Arch>(machine: &mut A, kt: &mut thread::KernelThread<A>, dos: &mut thread::DosState<A>, regs: &mut Regs) -> DosExit {
    match call(machine, kt, dos, regs) {
        Ok(Some(ax)) => DosExit::Ax(ax),
        Ok(None) => DosExit::Ok,
        Err(error) => DosExit::Error(error),
    }
}

#[inline(never)]
fn call<A: crate::Arch>(machine: &mut A, kt: &mut thread::KernelThread<A>, dos: &mut thread::DosState<A>, regs: &mut Regs) -> Result<Option<u16>, u16> {
    match regs.rax as u8 {
        0x39..=0x3b => {
            let name = string(machine, dos, regs, regs.ds as u16, regs.rdx as u32)?;
            if regs.rax as u8 == 0x3b { dos.dfs.chdir_lfn(&name)?; }
            else {
                let path = dos.dfs.lfn_path(&name, regs.rax as u8 == 0x39)?;
                writable(&path.vfs)?;
                errno(if regs.rax as u8 == 0x39 { vfs::mkdir(&path.vfs) } else { vfs::rmdir(&path.vfs) })?;
            }
        }
        0x41 => {
            let name = string(machine, dos, regs, regs.ds as u16, regs.rdx as u32)?;
            match regs.rsi as u16 {
                0 => {
                    let path = dos.dfs.lfn_path(&name, false)?;
                    writable(&path.vfs)?;
                    if attributes(&path.vfs)? & 0x11 != 0 { return Err(5); }
                    errno(vfs::delete(&path.vfs))?;
                }
                1 => {
                    // Collect first: deleting invalidates/reorders directory caches.
                    let mut search = dos.dfs.lfn_search(&name, regs.rcx as u16)?;
                    let mut paths = Vec::new();
                    while let Some(found) = search.next() {
                        if found.attributes & 0x10 == 0 {
                            writable(&found.path)?;
                            if found.attributes & 1 != 0 { return Err(5); }
                            paths.push(found.path);
                        }
                    }
                    if paths.is_empty() { return Err(2); }
                    for path in paths { errno(vfs::delete(&path))?; }
                }
                _ => return Err(1),
            }
        }
        0x43 => {
            let name = string(machine, dos, regs, regs.ds as u16, regs.rdx as u32)?;
            let path = dos.dfs.lfn_path(&name, false)?.vfs;
            match regs.rbx as u8 {
                0 => word(&mut regs.rcx, attributes(&path)?),
                1 => set_attributes(&path, regs.rcx as u16)?,
                3 | 4 => {
                    let fd = vfs::open(&path, &mut kt.fds);
                    if fd < 0 { return Err(dos_error_from_errno(fd)); }
                    let result = if regs.rbx as u8 == 3 {
                        match dos_to_unix_datetime(regs.rcx as u16, regs.rdi as u16) {
                            Some(time) => errno(vfs::set_handle_mtime(fd, time, &kt.fds)),
                            None => Err(13),
                        }
                    } else {
                        let (time, date) = unix_to_dos_datetime(vfs::handle_mtime(fd, &kt.fds).unwrap_or(0));
                        word(&mut regs.rcx, time); word(&mut regs.rdi, date);
                        Ok(())
                    };
                    vfs::close(fd, &mut kt.fds);
                    result?;
                }
                _ => return Err(0x7100),
            }
        }
        0x47 => {
            let dl = regs.rdx as u8;
            if dl > 26 { return Err(15); }
            let drive = if dl == 0 { b'A' + dos.dfs.current_drive_number() } else { b'A' + dl - 1 };
            let cwd = dos.dfs.cwd_lfn(drive)?;
            let address = linear(machine, dos, regs, regs.ds as u16, regs.rsi as u32) as usize;
            put_string(machine, address, &cwd);
        }
        0x4e | 0x4f => {
            let format = regs.rsi as u16;
            if format > 1 { return Err(1); }
            let first = regs.rax as u8 == 0x4e;
            let (handle, found) = if first {
                let name = string(machine, dos, regs, regs.ds as u16, regs.rdx as u32)?;
                let mut search = dos.dfs.lfn_search(&name, regs.rcx as u16)?;
                let found = search.next().ok_or(2u16)?;
                // Validate the record before allocating a search handle.
                find_data(&found, format)?;
                (dos.dfs.lfn_searches.insert(search)?, found)
            } else {
                let handle = regs.rbx as u16;
                (handle, dos.dfs.lfn_searches.next(handle)?)
            };
            let output = find_data(&found, format)?;
            let address = linear(machine, dos, regs, regs.es as u16, regs.rdi as u32) as usize;
            machine.copy_to(address, &output);
            word(&mut regs.rcx, found.conversion);
            return Ok(Some(if first { handle } else { 0x4f00 | (handle & 0xff) }));
        }
        0x56 => {
            let old = string(machine, dos, regs, regs.ds as u16, regs.rdx as u32)?;
            let new = string(machine, dos, regs, regs.es as u16, regs.rdi as u32)?;
            let old = dos.dfs.lfn_path(&old, false)?;
            let new = dos.dfs.lfn_path(&new, true)?;
            if old.long[0] != new.long[0] { return Err(17); }
            writable(&old.vfs)?; writable(&new.vfs)?;
            errno(vfs::rename(&old.vfs, &new.vfs))?;
        }
        0x60 => {
            let name = string(machine, dos, regs, regs.ds as u16, regs.rsi as u32)?;
            let output = match regs.rcx as u8 {
                0 => dos.dfs.resolve_lfn(&name)?.iter().map(u8::to_ascii_uppercase).collect(),
                1 => dos.dfs.lfn_path(&name, false)?.short,
                2 => dos.dfs.lfn_path(&name, false)?.long,
                _ => return Err(1),
            };
            let address = linear(machine, dos, regs, regs.es as u16, regs.rdi as u32) as usize;
            put_string(machine, address, &output);
        }
        0x6c => return open(machine, kt, dos, regs).map(Some),
        0xa0 => {
            let name = string(machine, dos, regs, regs.ds as u16, regs.rdx as u32)?;
            let path = dos.dfs.lfn_path(&name, false)?;
            if path.long.len() != 3 { return Err(3); }
            // Report the DOS namespace, not the underlying disk format.
            let filesystem = b"RetroOS";
            if regs.rcx as u16 as usize <= filesystem.len() { return Err(122); }
            let address = linear(machine, dos, regs, regs.es as u16, regs.rdi as u32) as usize;
            put_string(machine, address, filesystem);
            word(&mut regs.rbx, 0x4002); // LFN + case-preserving; never case-sensitive
            word(&mut regs.rcx, names::NAME_MAX as u16);
            word(&mut regs.rdx, PATH_MAX as u16);
            return Ok(Some(0));
        }
        0xa1 => dos.dfs.lfn_searches.close(regs.rbx as u16)?,
        0xa6 => {
            let (stat, mtime) = vfs::fd_info(regs.rbx as u16 as i32, &kt.fds).ok_or(6u16)?;
            let mut out = [0u8; 52];
            let attributes = u32::from(vfs::fd_dos_attributes(regs.rbx as u16 as i32, &kt.fds).ok_or(6u16)?);
            out[..4].copy_from_slice(&attributes.to_le_bytes());
            out[20..28].copy_from_slice(&filetime(mtime).to_le_bytes());
            out[36..40].copy_from_slice(&stat.size.to_le_bytes());
            out[40..44].copy_from_slice(&1u32.to_le_bytes());
            out[44..48].copy_from_slice(&((stat.ino >> 32) as u32).to_le_bytes());
            out[48..52].copy_from_slice(&(stat.ino as u32).to_le_bytes());
            let address = linear(machine, dos, regs, regs.ds as u16, regs.rdx as u32) as usize;
            machine.copy_to(address, &out);
        }
        // The clock currently has no configurable timezone: DOS timestamps
        // and UTC use the same clock, as in the existing AH=57h implementation.
        0xa7 => match regs.rbx as u8 {
            0 => {
                let address = linear(machine, dos, regs, regs.ds as u16, regs.rsi as u32) as usize;
                let ft = machine.read::<u64>(address);
                let (time, date, hundredths) = filetime_to_dos(ft).ok_or(13u16)?;
                word(&mut regs.rcx, time); word(&mut regs.rdx, date);
                regs.rbx = (regs.rbx & !0xff00) | (u64::from(hundredths) << 8);
            }
            1 => {
                let ft = dos_to_filetime(regs.rcx as u16, regs.rdx as u16, (regs.rbx >> 8) as u8).ok_or(13u16)?;
                let address = linear(machine, dos, regs, regs.es as u16, regs.rdi as u32) as usize;
                machine.write::<u64>(address, ft);
            }
            _ => return Err(1),
        },
        0xa8 => {
            // OEM input/output only; ANSI and UTF-16 need separate conversion.
            if regs.rdx as u8 != 0x11 { return Err(0x7100); }
            let name = string(machine, dos, regs, regs.ds as u16, regs.rsi as u32)?;
            let output = short_without_tail(&name, (regs.rdx >> 8) as u8)?;
            let address = linear(machine, dos, regs, regs.es as u16, regs.rdi as u32) as usize;
            if regs.rdx & 0xff00 == 0 { machine.copy_to(address, &output); }
            else { put_string(machine, address, &output); }
        }
        _ => return Err(0x7100),
    }
    Ok(None)
}

#[inline(never)]
fn open<A: crate::Arch>(machine: &mut A, kt: &mut thread::KernelThread<A>, dos: &mut thread::DosState<A>, regs: &mut Regs) -> Result<u16, u16> {
    let action = regs.rdx as u16;
    if !matches!(action, 1 | 2 | 0x10 | 0x11 | 0x12) { return Err(1); }
    let flags = regs.rbx as u16;
    if flags & 0x0400 != 0 { return Err(0x7100); } // explicit alias hint unsupported
    let mode = if flags & 7 == 4 { (flags as u8) & !7 } else { flags as u8 };
    if flags & 7 > 4 || flags & 7 == 3 || open_policies(mode).is_none() { return Err(12); }
    if regs.rcx as u16 & !0x27 != 0 { return Err(13); }
    let name = string(machine, dos, regs, regs.ds as u16, regs.rsi as u32)?;
    let path = dos.dfs.lfn_path(&name, action & 0x10 != 0)?.vfs;
    let exists = vfs::path_exists(&path);
    if exists && vfs::dir_exists(&path) { return Err(5); }
    if exists && (mode & 3 != 0 || action & 2 != 0) && attributes(&path)? & 1 != 0 { return Err(5); }
    let taken = if exists {
        match action & 3 { 0 => return Err(80), 1 => 1, 2 => 3, _ => return Err(1) }
    } else if action & 0x10 != 0 { 2 } else { return Err(2) };
    if taken != 1 { writable(&path)?; }
    if taken == 3 {
        // Check access/share policy before allowing any truncation.
        if mode & 3 == 0 { return Err(5); }
        let fd = vfs::open(&path, &mut kt.fds);
        if fd < 0 { return Err(dos_error_from_errno(fd)); }
        let (access, share) = open_policies(mode).ok_or(12u16)?;
        let rc = if vfs::fd_writable(fd, &kt.fds) { vfs::configure_open(fd, access, share, &kt.fds) } else { -13 };
        vfs::close(fd, &mut kt.fds);
        errno(rc)?;
    }
    let fd = if taken == 1 { vfs::open(&path, &mut kt.fds) } else { vfs::create(&path, &mut kt.fds) };
    if fd < 0 { return Err(dos_error_from_errno(fd)); }
    let handle = accept_open_file(machine, kt, dos, fd, mode).map_err(dos_error_from_errno)?;
    if taken != 1 && let Err(error) = set_attributes(&path, regs.rcx as u16 | 0x20) {
        vfs::close(fd, &mut kt.fds);
        sft_clear(machine, handle);
        Psp::clear_jft(machine, psp_struct_seg(dos), handle as usize);
        return Err(error);
    }
    word(&mut regs.rcx, taken);
    Ok(handle)
}

fn short_without_tail(name: &[u8], format: u8) -> Result<Vec<u8>, u16> {
    if format > 1 || name.is_empty() || name.iter().any(|b| *b < 32 || b"\\/:*?\"<>|".contains(b)) { return Err(123); }
    let dot = name.iter().rposition(|b| *b == b'.');
    let (base, extension) = dot.map_or((name, &b""[..]), |d| (&name[..d], &name[d + 1..]));
    let clean = |part: &[u8], max: usize| -> Vec<u8> {
        part.iter().filter(|b| **b != b' ' && **b != b'.').take(max)
            .map(|b| if b.is_ascii_alphanumeric() || b"!#$%&'()-@^_`{}~".contains(b) { b.to_ascii_uppercase() } else { b'_' }).collect()
    };
    let base = clean(base, 8); let extension = clean(extension, 3);
    if base.is_empty() { return Err(123); }
    if format == 0 {
        let mut out = alloc::vec![b' '; 11];
        out[..base.len()].copy_from_slice(&base); out[8..8 + extension.len()].copy_from_slice(&extension);
        Ok(out)
    } else {
        let mut out = base;
        if !extension.is_empty() { out.push(b'.'); out.extend(extension); }
        Ok(out)
    }
}

fn dos_to_filetime(time: u16, date: u16, hundredths: u8) -> Option<u64> {
    if hundredths > 199 { return None; }
    let year = 1980 + u32::from(date >> 9);
    let month = u32::from((date >> 5) & 15);
    let day = u32::from(date & 31);
    let (hour, minute, second) = (u64::from(time >> 11), u64::from((time >> 5) & 63), u64::from(time & 31) * 2);
    if !(1..=12).contains(&month) || day == 0 || hour > 23 || minute > 59 || second > 59 { return None; }
    let leap = year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400));
    let days = [31,28,31,30,31,30,31,31,30,31,30,31][month as usize - 1] + u32::from(month == 2 && leap);
    if day > days { return None; }
    let unix = u64::from(epoch_days_fast(year, month, day)) * 86400 + hour * 3600 + minute * 60 + second;
    Some((unix + FILETIME_EPOCH) * 10_000_000 + u64::from(hundredths) * 100_000)
}

fn filetime_to_dos(time: u64) -> Option<(u16, u16, u8)> {
    let unix = (time / 10_000_000).checked_sub(FILETIME_EPOCH)?;
    // Binary search DOS years, avoiding the u32 Unix-time ceiling in AH=57h.
    let mut year = 1980;
    while year < 2108 && unix >= u64::from(epoch_days_fast(year + 1, 1, 1)) * 86400 { year += 1; }
    if year > 2107 || unix < u64::from(epoch_days_fast(1980, 1, 1)) * 86400 { return None; }
    let mut month = 1;
    while month < 12 && unix >= u64::from(epoch_days_fast(year, month + 1, 1)) * 86400 { month += 1; }
    let day = unix / 86400 - u64::from(epoch_days_fast(year, month, 1)) + 1;
    let seconds = unix % 86400;
    let packed_time = ((seconds / 3600) << 11) | (((seconds / 60) % 60) << 5) | ((seconds % 60) / 2);
    let packed_date = ((year - 1980) << 9) | (month << 5) | day as u32;
    Some((packed_time as u16, packed_date as u16, ((unix % 2) * 100 + time % 10_000_000 / 100_000) as u8))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn time_conversion_full_dos_range() {
        for date in [0x0021, 0x285d, 0xff9f] {
            let ft = dos_to_filetime(0xbf7d, date, 199).unwrap();
            assert_eq!(filetime_to_dos(ft), Some((0xbf7d, date, 199)));
        }
        assert!(dos_to_filetime(0, 0, 0).is_none());
        assert!(dos_to_filetime(0, 0x0021, 200).is_none());
        assert!(filetime_to_dos(0).is_none());
    }
    #[test]
    fn generated_short_name_has_no_numeric_tail() {
        assert_eq!(short_without_tail(b"A long filename.txt", 1).unwrap(), b"ALONGFIL.TXT");
        assert_eq!(short_without_tail(b"A long filename.txt", 0).unwrap(), b"ALONGFILTXT");
    }
    #[test]
    fn packed_find_record() {
        let found = Found { name: b"Long name.txt".to_vec(), alias: b"LONGNA~1.TXT".to_vec(), path: Vec::new(),
            size: 42, mtime: 315532800, attributes: 0x20, conversion: 0 };
        let record = find_data(&found, 1).unwrap();
        assert_eq!(record.len(), 318);
        assert_eq!(&record[20..24], &0x00210000u32.to_le_bytes());
        assert_eq!(&record[32..36], &42u32.to_le_bytes());
        assert_eq!(&record[44..58], b"Long name.txt\0");
        assert_eq!(&record[304..317], b"LONGNA~1.TXT\0");
    }
}
