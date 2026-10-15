//! INT 13h floppy BIOS services and CHS translation.

use crate::Regs;
use crate::kernel::thread;

use super::lowmem::{LOW_MEM_BASE, LowMem};

// ============================================================================
// BIOS INT 13h — Disk services
// ============================================================================

/// Diskette status of the last INT 13h operation, per drive — what AH=01h
/// reports (a real BIOS keeps this in BDA 0x441; only the AH=01h view is
/// implemented, nothing reads the raw byte).
static FLOPPY_LAST_STATUS: [core::sync::atomic::AtomicU8; 2] =
    [core::sync::atomic::AtomicU8::new(0), core::sync::atomic::AtomicU8::new(0)];

/// INT 13h error codes used below.
const DISK_OK: u8 = 0x00;
const DISK_ERR_INVALID: u8 = 0x01; // invalid function/parameter
const DISK_ERR_SECTOR_NOT_FOUND: u8 = 0x04;
const DISK_ERR_CHANGED: u8 = 0x06; // change line active
const DISK_ERR_NOT_READY: u8 = 0x80;

pub(super) fn int_13h<A: crate::Arch>(machine: &mut A, regs: &mut Regs) -> thread::KernelAction {
    let ah = (regs.rax >> 8) as u8;
    let dl = regs.rdx as u8; // drive number
    if dl < 0x80 {
        floppy_int13(machine, regs, ah, dl);
        return thread::KernelAction::Done;
    }
    // Hard drives: the minimal fixed answers DOS-era probes expect.
    match ah {
        // AH=00h Reset Disk
        0x00 => {
            regs.rax &= !0xFF00; // AH=0 success
            regs.clear_flag32(1);
        }
        // AH=08h Get Drive Parameters
        0x08 => {
            regs.rax &= !0xFF00; // AH=0 success
            regs.rbx &= !0xFF; // BL=drive type (0 for HD)
            regs.rcx = (regs.rcx & !0xFFFF) | ((32 << 8) | 63); // CH=max cyl low, CL=max sect
            regs.rdx = (regs.rdx & !0xFFFF) | ((1 << 8) | 1); // DH=max head, DL=number of drives
            regs.clear_flag32(1);
        }
        // AH=15h Get Disk Type
        0x15 => {
            regs.rax = (regs.rax & !0xFF00) | (0x03 << 8); // AH=03 = hard disk
            regs.clear_flag32(1);
        }
        _ => {
            regs.rax = (regs.rax & !0xFF00) | ((DISK_ERR_NOT_READY as u64) << 8);
            regs.set_flag32(1);
        }
    }
    thread::KernelAction::Done
}

/// INT 13h for DL=00h/01h, backed by the floppy image slots. Media presence
/// is per operation: geometry/type questions answer for the DRIVE (which
/// always exists — the BDA equipment word advertises two), data access
/// needs a disk in it.
fn floppy_int13<A: crate::Arch>(machine: &mut A, regs: &mut Regs, ah: u8, dl: u8) {
    use crate::kernel::fs::floppy;
    use core::sync::atomic::Ordering;

    let mut status = DISK_OK;
    let drive = dl as usize;
    if dl >= 2 {
        // No third floppy unit. AH=08h answers with zeroed geometry + CF.
        status = if ah == 0x08 { DISK_ERR_INVALID } else { DISK_ERR_NOT_READY };
        if ah == 0x08 {
            regs.rbx &= !0xFF;
            regs.rcx &= !0xFFFF;
            regs.rdx &= !0xFFFF;
        }
        regs.rax = (regs.rax & !0xFF00) | ((status as u64) << 8);
        regs.set_flag32(1);
        return;
    }

    match ah {
        // AH=00h reset / AH=0Dh alternate reset: nothing to spin up.
        0x00 | 0x0D => {
            FLOPPY_LAST_STATUS[drive].store(0, Ordering::Relaxed);
        }
        // AH=01h: status of the last operation, then reset it.
        0x01 => {
            let last = FLOPPY_LAST_STATUS[drive].swap(0, Ordering::Relaxed);
            regs.rax = (regs.rax & !0xFF) | last as u64;
            // CF reflects that status; AH untouched per convention.
            if last != 0 {
                regs.set_flag32(1);
            } else {
                regs.clear_flag32(1);
            }
            return; // does not overwrite AH or the stored status below
        }
        // AH=02h read / AH=03h write / AH=04h verify: CHS against the
        // inserted image (writes go through to the image file).
        0x02..=0x04 => match floppy_chs_to_lba(regs, drive) {
            Ok((lba, count)) => {
                let mut addr = (regs.es as usize) * 16 + (regs.rbx as u16) as usize;
                let mut sector = [0u8; 512];
                for i in 0..count {
                    let ok = match ah {
                        0x02 => match floppy::read_sector(drive, lba + i as u32, &mut sector) {
                            Ok(()) => {
                                machine.copy_to(addr, &sector);
                                true
                            }
                            Err(_) => false,
                        },
                        0x03 => {
                            for (j, byte) in sector.iter_mut().enumerate() {
                                *byte = machine.read::<u8>(addr + j);
                            }
                            floppy::write_sector(drive, lba + i as u32, &sector).is_ok()
                        }
                        _ => true, // verify: the range check above suffices
                    };
                    if !ok {
                        status = DISK_ERR_SECTOR_NOT_FOUND;
                        regs.rax = (regs.rax & !0xFF) | i as u64; // AL = done
                        break;
                    }
                    addr += 512;
                }
            }
            Err(e) => status = e,
        },
        // AH=08h get drive parameters — answers for the drive, media or not.
        0x08 => {
            let (cylinders, heads, spt, drive_type) = match floppy::chs_geometry(drive) {
                Some(g) => (g.cylinders, g.heads, g.sectors_per_track, g.drive_type),
                // Empty drive: report the unit as a 1.44M drive.
                None => (80, 2, 18, 4),
            };
            let max_cyl = cylinders.saturating_sub(1);
            regs.rbx = (regs.rbx & !0xFF) | drive_type as u64;
            regs.rcx = (regs.rcx & !0xFFFF)
                | (((max_cyl as u64 & 0xFF) << 8) | ((max_cyl as u64 >> 8) << 6) | spt as u64);
            regs.rdx = (regs.rdx & !0xFFFF) | (((heads as u64 - 1) << 8) | 2); // DL = drive count
            // ES:DI → the diskette drive parameter table (same one IVT 1Eh
            // points at).
            let ddpt = LOW_MEM_BASE + core::mem::offset_of!(LowMem, ddpt) as u32;
            regs.es = (ddpt >> 4) as u64;
            regs.rdi = (regs.rdi & !0xFFFF) | (ddpt & 0xF) as u64;
        }
        // AH=15h get disk type: floppy with change-line support.
        0x15 => {
            regs.rax = (regs.rax & !0xFF00) | (0x02 << 8);
            regs.clear_flag32(1);
            return; // AH is the answer, not a status
        }
        // AH=16h media change: report-once change line.
        0x16 => {
            if floppy::take_change_line(drive) {
                status = DISK_ERR_CHANGED;
            }
        }
        _ => status = DISK_ERR_INVALID,
    }

    FLOPPY_LAST_STATUS[drive].store(status, Ordering::Relaxed);
    regs.rax = (regs.rax & !0xFF00) | ((status as u64) << 8);
    if status == DISK_OK {
        regs.clear_flag32(1);
    } else {
        regs.set_flag32(1);
    }
}

/// Decode the CHS+count register convention of INT 13h AH=02/03/04 and
/// bounds-check it against the inserted medium. Returns (lba, count) or the
/// INT 13h status to report.
fn floppy_chs_to_lba(regs: &Regs, drive: usize) -> Result<(u32, usize), u8> {
    use crate::kernel::fs::floppy;
    let Some(g) = floppy::chs_geometry(drive) else {
        return Err(DISK_ERR_NOT_READY);
    };
    let count = regs.rax as u8 as usize;
    let cl = regs.rcx as u8;
    let cylinder = ((regs.rcx >> 8) as u8 as u32) | (((cl as u32) & 0xC0) << 2);
    let sector = (cl & 0x3F) as u32;
    let head = (regs.rdx >> 8) as u8 as u32;
    if count == 0 || sector == 0 {
        return Err(DISK_ERR_INVALID);
    }
    if sector > g.sectors_per_track as u32
        || head >= g.heads as u32
        || cylinder >= g.cylinders as u32
    {
        return Err(DISK_ERR_SECTOR_NOT_FOUND);
    }
    let lba = (cylinder * g.heads as u32 + head) * g.sectors_per_track as u32 + sector - 1;
    if lba + count as u32 > g.total_sectors {
        return Err(DISK_ERR_SECTOR_NOT_FOUND);
    }
    Ok((lba, count))
}
