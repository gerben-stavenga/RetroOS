//! INT 21h DOS service dispatch.

use core::sync::atomic::{AtomicU16, Ordering};
use crate::Regs;
use crate::kernel::thread;
use crate::kernel::dos::{
    dfs, dos_alloc_block, dos_free_block, dos_resize_block, dpmi,
    machine, seg_offset,
};
use crate::kernel::dos::ems::{EMS_DEVICE_HANDLE, EMS_ENABLED};
use crate::kernel::dos::machine::{clear_bios_keyboard_buffer, read_u16, write_u16};
use super::{DosSuspension, ResumeEntry};
use super::clock::{bios_time_of_day, cmos_date, current_dos_timestamp};
use super::console::{buffered_input_resume, dos_putchar, poll_dos_console_char};
use super::exec::{exec_program, exec_return, return_to_psp_parent, terminate_resident};
use super::files::{
    FIRST_USER_HANDLE, PathTarget, accept_open_file, alloc_search_slot, cdrom_read_resume,
    create_file_handle, dfs_create_path, dfs_open_existing, dos_dup_fdkind,
    dos_error_from_errno, dos_wildcard_match, find_matching_file, finish_file_read,
    immutable_media_path, read_asciiz, resolve_guest_path, resolve_search_path,
    write_search_state,
};
use super::clock::{dos_to_unix_datetime, unix_to_dos_datetime};
use super::lowmem::{
    INDOS_FLAG_OFFSET, LOW_MEM_BASE, LowMem, PSP_JFT_LEN, Psp, SLOT_COUNTRY_UPCASE,
    ctrl_slot_off, psp_struct_seg, sft_clear, sft_set_file,
};

#[path = "lfn.rs"]
mod lfn;

/// Dummy file handle returned for /dev/null semantics.
const NULL_FILE_HANDLE: u16 = 99;
static TEMP_FILE_SEQUENCE: AtomicU16 = AtomicU16::new(0);

// ============================================================================
// DOS INT 21h — DOS services
// ============================================================================

pub(super) enum DosExit {
    Ok,
    Ax(u16),
    Error(u16),
    Errno(i32),
}

pub(super) fn int_21h<A: crate::Arch>(
    machine: &mut A,
    bios_display: &mut crate::kernel::bios_display::BiosDisplayWorkspace<A>,
    kt: &mut thread::KernelThread<A>,
    dos: &mut thread::DosState<A>,
    regs: &mut Regs,
    suspension: &mut Option<DosSuspension<A>>,
) -> thread::KernelAction {
    let ah = (regs.rax >> 8) as u8;
    let exit = match ah {
        // AH=0x02: Display character (DL)
        0x02 => {
            let ch = regs.rdx as u8; dos_putchar(machine, dos, ch);
            return thread::KernelAction::Done;
        }
        // AH=0x06: Direct console I/O (DL=0xFF=input, else output DL)
        0x06 => {
            let dl = regs.rdx as u8;
            if dl == 0xFF {
                if let Some(ch) = poll_dos_console_char(machine, dos, regs) {
                    regs.rax = (regs.rax & !0xFF) | ch as u64;
                    regs.clear_flag32(0x40); // clear ZF = char available
                } else {
                    regs.set_flag32(0x40); // set ZF = no char available
                }
            } else {
                dos_putchar(machine, dos, dl);
            }
            return thread::KernelAction::Done;
        }
        // AH=0x01: STDIN read with echo. Blocks; echoes the char.
        // AH=0x07: Direct STDIN read, no echo, no Ctrl-C check.
        // AH=0x08: STDIN read, no echo (Ctrl-C raises INT 23h — we don't).
        // All three block until a key is available. TC's getch() uses
        // AH=07h; without this AX falls through unmodified and getch()
        // returns garbage (often the AL=0xFF that AH=0Bh just set on
        // kbhit). Block-and-retry via SLOT_RESUME — the continuation owns the
        // original return computation while the active interrupt returns to
        // the stub with a balanced guest stack.
        0x01 | 0x07 | 0x08 => {
            let echo = ah == 0x01;
            // Console reads only reach here from VM86: PM/DPMI clients run under
            // an extender that installs its own INT 21h chain, so the pmdos
            // short-circuit never services char input. The INT 16 round-trip
            // below relies on real-mode INT framing (vm86_push, real-mode IVT).
            // Second byte of a prior extended key takes precedence (DOS returns
            // AL=0 then the scancode on the next read).
            if let Some(ch) = dos.dos_pending_char.take() {
                regs.rax = (regs.rax & !0xFF) | ch as u64;
                if echo && ch != 0 { dos_putchar(machine, dos, ch); }
            } else {
                // Real DOS services console input through INT 16h — so do we.
                // Enter the guest's IVT[0x16] (AH=00, wait-for-key) with an
                // iret frame that returns to SLOT_RESUME, where
                // `int16_finish_resume` applies DOS char-read semantics to the
                // returned AX and enters the stored INT 21 continuation. A guest that
                // hooks INT 16/INT 9 (and keeps 40:1A empty) is honoured; an
                // unhooked guest just runs the BIOS INT 16h, reading the same
                // 40:1A the old fast path did.
                *suspension = Some(DosSuspension {
                    entry: ResumeEntry::Int16 { echo, func: ah },
                });
            }
            return thread::KernelAction::Done;
        }
        // AH=0x09: Display $-terminated string at DS:DX
        0x09 => {
            let start = seg_offset(dos, regs, regs.ds as u16, regs.rdx as u32);
            let mut addr = start;
            loop {
                let ch = machine.read::<u8>((addr) as usize);
                if ch == b'$' { break; }
                dos_putchar(machine, dos, ch);
                addr = addr.wrapping_add(1);
                // Safety limit: cap at 64 KiB from start
                if addr.wrapping_sub(start) > 0xFFFF { break; }
            }
            return thread::KernelAction::Done;
        }
        // AH=0x0A: Buffered Keyboard Input. DS:DX → buffer.
        //   buffer[0] = max chars including the CR terminator (caller sets)
        //   buffer[1] = count actually typed, NOT including CR (we set)
        //   buffer[2..count+2] = typed characters
        //   buffer[count+2]    = 0x0D (CR terminator)
        // Blocks until Enter; backspace erases. Sokoban's "ENTER YOUR SYSTEM:"
        // prompt is the canonical reason this needs to exist — without it the
        // game spins forever asking for input.
        0x0A => {
            let buf_lin = seg_offset(dos, regs, regs.ds as u16, regs.rdx as u32);
            let max_chars = machine.read::<u8>((buf_lin) as usize);
            if max_chars == 0 {
                machine.write::<u8>((buf_lin + 1) as usize, 0);
                return thread::KernelAction::Done;
            }
            *suspension = Some(DosSuspension {
                entry: ResumeEntry::Poll(buffered_input_resume(
                    machine, buf_lin, max_chars, 0,
                )),
            });
            return thread::KernelAction::Done;
        }
        // AH=0x0B: Check Standard Input Status — AL=0 no char, 0xFF char ready.
        // Reflect the BIOS keyboard buffer state (head != tail = char ready).
        // Some Borland C builds back kbhit() with this rather than INT 16h
        // AH=01h, so a hardcoded "no char" silently breaks polling.
        0x0B => {
            let al = if crate::kernel::dos::Bda::keyboard_buffer_nonempty(machine) { 0xFFu8 } else { 0u8 };
            regs.rax = (regs.rax & !0xFF) | al as u64;
            return thread::KernelAction::Done;
        }
        // AH=0x25: Set interrupt vector (AL=int, DS:DX=handler)
        0x25 => {
            let int_num = regs.rax as u8;
            if dos.dpmi.is_some() && regs.frame.rflags as u32 & machine::VM_FLAG == 0 {
                // 16-bit DPMI clients pass a 16-bit handler offset in DX; the
                // high EDX bits are undefined. Storing the full EDX captures
                // stale garbage that later makes the default-stub check in
                // deliver_pm_irq fail, delivering a HW IRQ to VECTOR_STUB:garbage
                // → #GP on the VME 32-bit iret (Jazz Jackrabbit / Borland RTM,
                // which chain the default vector back via AH=35→AH=25).
                let use32 = dos.dpmi.as_ref().is_some_and(|d| d.client_use32);
                let off = if use32 { regs.rdx as u32 } else { regs.rdx as u16 as u32 };
                dos.pm_vectors[int_num as usize] = (regs.ds as u16, off);
                return thread::KernelAction::Done;
            }
            let (seg, off) = (regs.ds as u16, regs.rdx as u16);
            write_u16(machine, 0, (int_num as u32) * 4, off);
            write_u16(machine, 0, (int_num as u32) * 4 + 2, seg);
            return thread::KernelAction::Done;
        }
        // AH=0x33: Get/Set Ctrl-Break check state
        0x33 => {
            let al = regs.rax as u8;
            match al {
                0x00 => {
                    regs.rdx &= !0xFF; // DL=0: break checking off
                    DosExit::Ok
                }
                0x01 => DosExit::Ok, // set break — accepted but ignored
                _ => DosExit::Error(1),
            }
        }
        // AH=0x34: Get INDOS Flag pointer — returns ES:BX → byte that is
        // nonzero while DOS is executing. We're never "in DOS" from the
        // guest's perspective (kernel services calls synchronously), so
        // point at a permanently-zero byte inside SYSPSP.
        0x34 => {
            if dos.dpmi.is_some() && regs.frame.rflags as u32 & machine::VM_FLAG == 0 {
                regs.es = dpmi::LOW_MEM_SEL as u64;
                // Full 32-bit write: the offset via LOW_MEM_SEL is a linear
                // address, and PM clients may capture the whole register (LES
                // EBX). A 16-bit merge leaks the caller's stale high half into
                // the pointer (DOS/16M saved such a DS:ESI and faulted on it).
                regs.rbx = ((LOW_MEM_BASE + core::mem::offset_of!(LowMem, boot_psp) as u32) + INDOS_FLAG_OFFSET as u32) as u64;
            } else {
                regs.es = ((LOW_MEM_BASE + core::mem::offset_of!(LowMem, boot_psp) as u32) >> 4) as u64;
                regs.rbx = (regs.rbx & !0xFFFF) | INDOS_FLAG_OFFSET as u64;
            }
            return thread::KernelAction::Done;
        }
        // AH=0x47: Get current directory (DL=drive, DS:SI=64-byte buffer)
        // Returns ASCIIZ path without drive letter or leading backslash
        // DL: 0=default, 1=A, 2=B, 3=C
        0x47 => {
            let dl = regs.rdx as u8;
            let drive = if dl == 0 {
                b'A' + dos.dfs.current_drive_number()
            } else {
                b'A' + (dl - 1)
            };
            if let Some(cwd) = dos.dfs.get_cwd_for(drive) {
                if cwd.len() >= dfs::DFS_CWD_MAX {
                    regs.rax = (regs.rax & !0xffff) | 206;
                    regs.set_flag32(1);
                    return thread::KernelAction::Done;
                }
                let addr = seg_offset(dos, regs, regs.ds as u16, regs.rsi as u32) as usize;
                machine.copy_to(addr, cwd);
                machine.write::<u8>(addr + cwd.len(), 0);
                DosExit::Ok
            } else {
                DosExit::Error(0x0F)
            }
        }
        // AH=0x19: Get current default drive (returns AL=drive, 0=A, 2=C, 3=D)
        0x19 => {
            regs.rax = (regs.rax & !0xFF) | dos.dfs.current_drive_number() as u64;
            return thread::KernelAction::Done;
        }
        // AH=0x0C: Flush input buffer then execute function in AL
        0x0C => {
            clear_bios_keyboard_buffer(machine, regs);
            dos.dos_pending_char = None;
            let sub_ah = regs.rax as u8;
            if sub_ah == 0x06 {
                if let Some(ch) = poll_dos_console_char(machine, dos, regs) {
                    regs.rax = (regs.rax & !0xFF) | ch as u64;
                    regs.clear_flag32(0x40);
                } else {
                    regs.set_flag32(0x40); // ZF=1
                }
            }
            return thread::KernelAction::Done;
        }
        // AH=0x0D: Disk Reset (flush buffers) — no-op on RAM-backed FS
        0x0D => {
            return thread::KernelAction::Done;
        }
        // AH=0x1A: Set DTA (Disk Transfer Area) address to DS:DX
        0x1A => {
            // Store DTA address — NC needs this for FindFirst/FindNext
            let dta = seg_offset(dos, regs, regs.ds as u16, regs.rdx as u32);
            dos.dta = dta;
            return thread::KernelAction::Done;
        }
        // AH=0x2F: Get DTA address (returns ES:BX)
        0x2F => {
            let dta = dos.dta;
            if dos.dpmi.is_some() && regs.frame.rflags as u32 & machine::VM_FLAG == 0 {
                regs.es = dpmi::LOW_MEM_SEL as u64;
                // Full 32-bit write (see AH=34): a linear offset — and the DTA
                // commonly exceeds 0xFFFF, which the 16-bit merge also mangled.
                regs.rbx = dta as u64;
            } else {
                regs.es = (dta >> 4) as u64;
                regs.rbx = (regs.rbx & !0xFFFF) | (dta & 0x0F) as u64;
            }
            return thread::KernelAction::Done;
        }
        // AH=0x30: Get DOS version (return AL=major, AH=minor)
        0x30 => {
            // Report DOS 5.00 (DOS/32A and other extenders require >= 4.0)
            regs.rax = (regs.rax & !0xFFFF) | 0x0005; // AL=5 (major), AH=0 (minor)
            regs.rbx = 0; // OEM serial
            regs.rcx = 0;
            return thread::KernelAction::Done;
        }
        // AH=0x35: Get interrupt vector (AL=int, returns ES:BX=handler)
        0x35 => {
            let int_num = regs.rax as u8;
            if dos.dpmi.is_some() && regs.frame.rflags as u32 & machine::VM_FLAG == 0 {
                let (sel, off) = dos.pm_vectors[int_num as usize];
                regs.es = sel as u64;
                let client_use32 = dos.dpmi.as_ref().map(|d| d.client_use32).unwrap_or(false);
                if client_use32 {
                    regs.rbx = (regs.rbx & !0xFFFF_FFFF) | off as u64;
                } else {
                    regs.rbx = (regs.rbx & !0xFFFF) | (off & 0xFFFF) as u64;
                }
            } else {
                let off = read_u16(machine, 0, (int_num as u32) * 4);
                let seg = read_u16(machine, 0, (int_num as u32) * 4 + 2);
                regs.es = seg as u64;
                regs.rbx = (regs.rbx & !0xFFFF) | off as u64;
            }
            return thread::KernelAction::Done;
        }
        // AH=0x38: Get country information
        //
        // DOS 2.x uses a 32-byte buffer; DOS 3.0+ extended it to 34 bytes.
        // Many programs (including NC 2.0) allocate only 32 bytes, so write
        // field-by-field rather than blindly zeroing 34 bytes.
        0x38 => 'country: {
            if regs.rdx as u16 == 0xffff { break 'country DosExit::Error(1); } // Setting a country is not implemented.
            let country = match regs.rax as u8 { 0xff => regs.rbx as u16, n => u16::from(n) };
            let profile = if country == 0 { Some(lib::locale::current()) } else { lib::locale::by_country(country) };
            let Some(profile) = profile else { break 'country DosExit::Error(2); };
            let addr = seg_offset(dos, regs, regs.ds as u16, regs.rdx as u32) as usize;
            let data = crate::kernel::locale::dos_country(profile, lib::codepage::current_codepage().id);
            machine.copy_to(addr, &data);
            // DOS programs call the far pointer at +12h to uppercase a byte
            // in AL. A zero pointer makes callers jump into the IVT.
            machine.write::<u32>(addr + 0x12, ctrl_slot_off(SLOT_COUNTRY_UPCASE) as u32);
            regs.rbx = (regs.rbx & !0xFFFF) | u64::from(profile.country);
            regs.rax = (regs.rax & !0xFFFF) | u64::from(profile.country);
            DosExit::Ok
        }
        // AH=0x39: Create directory (DS:DX=ASCIIZ path)
        0x39 => {
            let rc = match resolve_guest_path(
                machine, dos, regs, regs.ds as u16, regs.rdx as u32, PathTarget::New,
            ) {
                Ok(path) if immutable_media_path(path.as_bytes()) => -30,
                Ok(path) => crate::kernel::vfs::mkdir(path.as_bytes()),
                Err(e) => -e,
            };
            if rc == 0 { DosExit::Ok } else { DosExit::Errno(rc) }
        }
        // AH=0x3A: Remove directory (DS:DX=ASCIIZ path)
        0x3A => {
            let rc = match resolve_guest_path(
                machine, dos, regs, regs.ds as u16, regs.rdx as u32, PathTarget::Existing,
            ) {
                Ok(path) if immutable_media_path(path.as_bytes()) => -30,
                Ok(path) => crate::kernel::vfs::rmdir(path.as_bytes()),
                Err(e) => -e,
            };
            if rc == 0 { DosExit::Ok } else { DosExit::Errno(rc) }
        }
        // AH=0x3B: Change directory (DS:DX=ASCIIZ path)
        0x3B => {
            let addr = seg_offset(dos, regs, regs.ds as u16, regs.rdx as u32);
            let mut path = [0u8; dfs::DFS_PATH_MAX];
            let i = read_asciiz(machine, addr, &mut path);
            let err = dos.dfs.chdir(&path[..i]);
            if err == 0 { DosExit::Ok } else { DosExit::Error(err as u16) }
        }
        // AH=0x3D: Open file (DS:DX=ASCIIZ filename, AL=access mode)
        0x3D => {
            let open_mode = regs.rax as u8;
            let addr = seg_offset(dos, regs, regs.ds as u16, regs.rdx as u32);
            let mut name = [0u8; dfs::DFS_PATH_MAX];
            let i = read_asciiz(machine, addr, &mut name);
            // Check for device names (before normalization)
            if EMS_ENABLED && name[..i].eq_ignore_ascii_case(b"EMMXXXX0") {
                DosExit::Ax(EMS_DEVICE_HANDLE)
            } else {
                let fd = match dfs_open_existing(dos, &name[..i]) {
                    Ok((path, len)) => crate::kernel::vfs::open(&path[..len], &mut kt.fds),
                    Err(e) => -e,
                };
                if crate::kernel::dos::should_trace() {
                    crate::compact_println!("[DOS FILE] open {:?} mode={:02X} fd={}",
                        core::str::from_utf8(&name[..i]).unwrap_or("<non-utf8>"), open_mode, fd);
                }
                match accept_open_file(machine, kt, dos, fd, open_mode) {
                    Ok(handle) => DosExit::Ax(handle),
                    Err(err) => DosExit::Errno(err),
                }
            }
        }
        // AH=0x3E: Close file handle (BX=handle)
        0x3E => {
            let handle = regs.rbx as u16;
            let hidx = handle as usize;
            // A redirected std handle (AH=46h put a file in slot 0-2) or a
            // dup'd console handle closes via the thread table: the VFS
            // refcount drops there, and a std slot reverts to the console.
            let redirected = hidx < thread::MAX_FDS
                && ((handle <= 2 && matches!(kt.fds[hidx], thread::FdKind::Vfs(_)))
                    || kt.fds[hidx] == thread::FdKind::ConsoleOut);
            let result = if redirected {
                kt.close_fd(hidx);
                sft_clear(machine, handle);
                Psp::clear_jft(machine, psp_struct_seg(dos), hidx);
                0
            } else if handle <= 2 || handle == NULL_FILE_HANDLE || (EMS_ENABLED && handle == EMS_DEVICE_HANDLE) {
                Psp::clear_jft(machine, psp_struct_seg(dos), handle as usize);
                0
            } else {
                let rv = crate::kernel::vfs::close(handle as i32, &mut kt.fds);
                if rv >= 0 {
                    sft_clear(machine, handle);
                    Psp::clear_jft(machine, psp_struct_seg(dos), handle as usize);
                }
                rv
            };
            if result >= 0 { DosExit::Ok } else { DosExit::Errno(result) }
        }
        // AH=0x3F: Read from file (BX=handle, CX=count, DS:DX=buffer)
        0x3F => {
            let handle = regs.rbx as u16 as i32;
            let count = regs.rcx as u16 as usize;
            let buf_addr = seg_offset(dos, regs, regs.ds as u16, regs.rdx as u32);
            // A std handle redirected to a file (AH=46h) reads the file.
            let vfs_backed = (handle as usize) < thread::MAX_FDS
                && matches!(kt.fds[handle as usize], thread::FdKind::Vfs(_));
            let empty = !vfs_backed
                && (handle <= 2
                    || (handle as usize) < thread::MAX_FDS
                        && kt.fds[handle as usize] == thread::FdKind::ConsoleOut)
                || handle == NULL_FILE_HANDLE as i32
                || count == 0
                || buf_addr == 0;
            if empty {
                DosExit::Ax(0)
            } else {
                let cdrom = crate::kernel::vfs::mount_prefix(handle, &kt.fds)
                    == Some(b"cdrom/" as &[u8]);
                let mut buf = alloc::vec![0u8; count];
                let read_offset = crate::kernel::dos::should_trace()
                    .then(|| crate::kernel::vfs::seek(handle, 0, 1, &kt.fds));
                let read_started = machine.now();
                let fetch_started = crate::kernel::startup::profile_enabled()
                    .then(|| machine.rdtsc());
                let n = crate::kernel::vfs::read(handle, &mut buf, &kt.fds);
                if let Some(offset) = read_offset {
                    let prefix = (n.max(0) as usize).min(buf.len()).min(16);
                    crate::compact_println!("[DOS FILE] read fd={} offset={:08X} requested={} returned={} data={:02X?}",
                        handle, offset, count, n, &buf[..prefix]);
                }
                if let Some(start) = fetch_started {
                    crate::kernel::event_profile::record_dos_read_fetch(
                        count as u16,
                        machine.rdtsc().wrapping_sub(start),
                    );
                }
                if n >= 0 {
                    let got = (n as usize).min(count);
                    buf.truncate(got);
                    let cdrom_delay = if cdrom {
                        crate::kernel::fs::cdrom::transfer_ns(got)
                    } else {
                        None
                    };
                    if got > 0 && let Some(delay) = cdrom_delay
                    {
                        // Count time already spent fetching the backing image;
                        // the setting is a minimum total transfer duration, not
                        // an extra delay added after slow physical storage.
                        let deadline = read_started.saturating_add(delay);
                        *suspension = Some(DosSuspension {
                            entry: ResumeEntry::Poll(cdrom_read_resume(
                                machine, deadline, buf_addr, buf,
                            )),
                        });
                    } else {
                        let copy_started = crate::kernel::startup::profile_enabled()
                            .then(|| machine.rdtsc());
                        finish_file_read(machine, dos, regs, buf_addr, &buf);
                        if let Some(start) = copy_started {
                            crate::kernel::event_profile::record_dos_read_copy(
                                count as u16,
                                machine.rdtsc().wrapping_sub(start),
                            );
                        }
                    }
                    return thread::KernelAction::Done;
                } else {
                    DosExit::Error(6) // invalid handle
                }
            }
        }
        // AH=0x4E: Find first matching file (CX=attr, DS:DX=filespec)
        0x4E => 'find: {
            let addr = seg_offset(dos, regs, regs.ds as u16, regs.rdx as u32);
            let mut raw = [0u8; 80];
            let raw_len = read_asciiz(machine, addr, &mut raw);
            let mut composed = alloc::vec![0u8; crate::kernel::vfs::PATH_KEY_MAX];
            let pos = match resolve_search_path(&dos.dfs, &raw[..raw_len], &mut composed) {
                Ok(len) => len,
                Err(e) => break 'find DosExit::Error(e as u16),
            };
            // Claim a search slot and stamp its identity into the caller's DTA,
            // so a FindNext knows which enumeration it is continuing even if
            // another search ran in between.
            let slot = alloc_search_slot(dos);
            composed.truncate(pos);
            dos.searches[slot].path = composed;
            dos.searches[slot].attributes = regs.rcx as u8;
            let generation = dos.searches[slot].generation;
            let dta = dos.dta as usize;
            machine.zero(dta, 43);
            write_search_state(machine, dta, slot as u8, generation, 0);
            find_matching_file(machine, dos)
        }
        // AH=0x4F: Find next matching file
        0x4F => find_matching_file(machine, dos),
        // AH=00h terminates with status zero; AH=4Ch takes its status in AL.
        0x00 | 0x4C => {
            let status = if ah == 0 { 0 } else { regs.rax as u8 };
            // An AH=55h child may be nested inside an EXEC'd program. Only
            // termination of that EXEC program consumes its saved parent.
            if dos.exec_parent.as_ref().is_some_and(|parent| parent.child_psp == dos.current_psp)
                && let Some(parent) = dos.exec_parent.take()
            {
                // Termination type 00h (normal) | return code in AL.
                dos.last_child_exit_status = u16::from(status);
                return exec_return(machine, dos, regs, parent, /*preserve_pm_env=*/false);
            }
            if return_to_psp_parent(machine, dos, regs, u16::from(status), None) {
                return thread::KernelAction::Done;
            }
            return thread::KernelAction::Exit(i32::from(status));
        }
        // AH=0x31: Terminate and Stay Resident (TSR)
        // AL = return code, DX = paragraphs to keep (from child's PSP)
        // Like AH=4Ch but the child's memory stays committed: heap_seg
        // remains above the resident block so subsequent parent allocations
        // don't overlap. INT vector hooks the child installed in the IVT
        // remain valid because the IVT is part of the address space and the
        // child's code at heap_seg+offset is still mapped.
        0x31 => {
            let keep = regs.rdx as u16;
            return terminate_resident(machine, dos, regs, keep);
        }
        // AH=0x48: Allocate memory (BX=paragraphs needed)
        0x48 => {
            let need = regs.rbx as u16;
            match dos_alloc_block(machine, dos, regs, need) {
                Ok(seg) => DosExit::Ax(seg),
                Err(avail) => {
                    regs.rbx = (regs.rbx & !0xFFFF) | avail as u64;
                    DosExit::Error(8) // insufficient memory
                }
            }
        }
        // AH=0x49: Free memory (ES=segment)
        0x49 => {
            let es = regs.es as u16;
            match dos_free_block(machine, dos, regs, es) {
                Ok(()) => DosExit::Ok,
                Err(err) => DosExit::Error(err),
            }
        }
        // AH=0x4A: Resize memory block (ES=segment, BX=new size in paragraphs)
        0x4A => {
            let es = regs.es as u16;
            let new_paras = regs.rbx as u16;
            match dos_resize_block(machine, dos, regs, es, new_paras) {
                Ok(()) => DosExit::Ok,
                Err((err, max)) => {
                    regs.rbx = (regs.rbx & !0xFFFF) | max as u64;
                    DosExit::Error(err)
                }
            }
        }
        // AH=0x44: IOCTL (various subfunctions)
        0x44 => {
            let al = regs.rax as u8;
            match al {
                // AL=0x00: Get Device Information (BX=handle, returns DX=info word)
                0x00 => {
                    let handle = regs.rbx as u16;
                    let hidx = handle as usize;
                    // A redirected std handle must report FILE, not device —
                    // it's how programs detect their output is captured.
                    let vfs_backed = hidx < thread::MAX_FDS
                        && matches!(kt.fds[hidx], thread::FdKind::Vfs(_));
                    let console = !vfs_backed
                        && (handle <= 2
                            || (hidx < thread::MAX_FDS && kt.fds[hidx] == thread::FdKind::ConsoleOut));
                    if console {
                        // stdin/stdout/stderr: bit 7=1 (device), bit 0=1 (stdin), bit 1=1 (stdout)
                        let info: u16 = 0x80 | match handle {
                            0 => 0x01, // stdin
                            _ => 0x02, // stdout/stderr (and dup'd console handles)
                        };
                        regs.rdx = (regs.rdx & !0xFFFF) | info as u64;
                        DosExit::Ok
                    } else if EMS_ENABLED && handle == EMS_DEVICE_HANDLE {
                        // EMMXXXX0 device: bit 7=1 (device)
                        regs.rdx = (regs.rdx & !0xFFFF) | 0x80;
                        DosExit::Ok
                    } else {
                        // File handle: bit 7=0 (file), bit 6=1 (not written
                        // via this handle since open), bits 5-0 = the drive
                        // the file actually lives on, bit 15 = remote.
                        // Installers cross-check both against the drive they
                        // opened from (Tomb Raider scans X:\data\title.phd,
                        // then asks the handle which drive answered) — and a
                        // CD-ROM under MSCDEX is a network-REDIRECTOR drive,
                        // so its files must report remote; hostfs really is.
                        let info = crate::kernel::vfs::mount_prefix(handle as i32, &kt.fds)
                            .map_or(2u64, |prefix| match prefix {
                                b"floppya/" => 0,
                                b"floppyb/" => 1,
                                b"cdrom/" => 0x8000 | 3,
                                b"host/" => 0x8000 | 7,
                                _ => (b'E'..=b'Z').find(|&letter| dfs::extra_drive_prefix(letter) == Some(prefix))
                                    .map_or(2, |letter| u64::from(letter - b'A')),
                            });
                        regs.rdx = (regs.rdx & !0xFFFF) | 0x0040 | info;
                        DosExit::Ok
                    }
                }
                // AL=0x07: Check device output status (BX=handle)
                0x07 => {
                    // AL=FFh = ready
                    regs.rax = (regs.rax & !0xFF) | 0xFF;
                    DosExit::Ok
                }
                // AL=0x08: Check if block device is removable (BL=drive, 0=default,1=A,3=C)
                0x08 => {
                    // AX=0 = removable, AX=1 = fixed
                    let drive = regs.rbx as u8;
                    let drive = if drive == 0 {
                        dos.dfs.current_drive_number() + 1
                    } else {
                        drive
                    };
                    // Removable: A: (1), B: (2), and the CD-ROM D: (4).
                    regs.rax = (regs.rax & !0xFFFF) | u64::from(!matches!(drive, 1 | 2 | 4));
                    DosExit::Ok
                }
                // AL=0x09: Check if block device is remote (BL=drive)
                0x09 => {
                    let drive = regs.rbx as u8;
                    let drive = if drive == 0 {
                        dos.dfs.current_drive_number() + 1
                    } else {
                        drive
                    };
                    regs.rdx = (regs.rdx & !0xFFFF) | if drive == 8 { 0x1000 } else { 0 };
                    DosExit::Ok
                }
                _ => DosExit::Error(1),
            }
        }
        // AH=0x45: Duplicate file handle (BX=handle). Returns AX=new handle
        // sharing the same file position. Borland's IDE uses 45h/46h to save
        // std handles and force them into its message pipe around a transfer
        // (TASM via TASM2MSG, FILTER.H's BI#PIP#OK protocol).
        0x45 => {
            let src = regs.rbx as u16 as usize;
            match (dos_dup_fdkind(kt, src), kt.alloc_fd(FIRST_USER_HANDLE)) {
                (Some(kind), Some(fd)) => {
                    if let thread::FdKind::Vfs(h) = kind { crate::kernel::vfs::add_vfs_ref(h); }
                    kt.fds[fd] = kind;
                    if Psp::set_jft(machine, psp_struct_seg(dos), fd, fd as u8).is_err() {
                        // Nowhere to record the duplicate: same answer the
                        // no-free-fd arm below gives.
                        kt.close_fd(fd);
                        DosExit::Error(4) // too many open files
                    } else {
                        DosExit::Ax(fd as u16)
                    }
                }
                (Some(_), None) => DosExit::Error(4), // too many open files
                (None, _) => DosExit::Error(6), // invalid handle
            }
        }
        // AH=0x46: Force duplicate (BX=src, CX=target): close target, make it
        // refer to src's file. Redirection of the std handles happens here.
        0x46 => {
            let src = regs.rbx as u16 as usize;
            let dst = regs.rcx as u16 as usize;
            match dos_dup_fdkind(kt, src) {
                Some(kind) if dst < thread::MAX_FDS => {
                    if dst != src
                        && Psp::set_jft(machine, psp_struct_seg(dos), dst, dst as u8).is_err()
                    {
                        // Claim the destination slot first. A destination the
                        // JFT cannot hold is not a handle this process can
                        // name, so report an invalid handle — and do it before
                        // closing dst, so a rejected dup2 leaves it untouched.
                        DosExit::Error(6)
                    } else {
                        if dst != src {
                            kt.close_fd(dst);
                            sft_clear(machine, dst as u16);
                            if let thread::FdKind::Vfs(h) = kind { crate::kernel::vfs::add_vfs_ref(h); }
                            kt.fds[dst] = kind;
                        }
                        DosExit::Ok
                    }
                }
                _ => DosExit::Error(6), // invalid handle
            }
        }
        // AH=0x0E: Select disk (DL=drive, 0=A, 2=C, 3=D)
        0x0E => {
            let drive = b'A'.wrapping_add(regs.rdx as u8);
            let _ = dos.dfs.select_drive(drive);
            let last_drive = dfs::last_drive(crate::kernel::platform::get().hostfs);
            regs.rax = (regs.rax & !0xFF) | u64::from(last_drive);
            return thread::KernelAction::Done;
        }
        // AH=0x3C: Create file (CX=attr, DS:DX=filename) — RAM-backed via VFS overlay
        0x3C => {
            let result = match resolve_guest_path(
                machine, dos, regs, regs.ds as u16, regs.rdx as u32, PathTarget::New,
            ) {
                // Immutable removable media must refuse CREATE with a real
                // error rather than the RAM-scratch substitution read-only
                // archive mounts get: CD installers write-test the drive to
                // tell a CD from a hard disk (Tomb Raider creates and
                // deletes a random D:\ name; success = "not a CD").
                Ok(path) if immutable_media_path(path.as_bytes()) => Err(-13),
                Ok(path) => create_file_handle(machine, kt, dos, path.as_bytes()),
                Err(e) => Err(-e),
            };
            match result {
                Ok(handle) => DosExit::Ax(handle),
                Err(err) => DosExit::Errno(err),
            }
        }
        // AH=0x40: Write to file (BX=handle, CX=count, DS:DX=buffer)
        0x40 => {
            let handle = regs.rbx as u16;
            let count = regs.rcx as u16;
            let hidx = handle as usize;
            // Std handles write to the console only while their fd slot is
            // not redirected to a file; a dup'd console handle (AH=45h of an
            // unredirected 1/2) is a console too.
            let vfs_backed = hidx < thread::MAX_FDS
                && matches!(kt.fds[hidx], thread::FdKind::Vfs(_));
            let console = !vfs_backed
                && (handle == 1 || handle == 2
                    || (hidx < thread::MAX_FDS && kt.fds[hidx] == thread::FdKind::ConsoleOut));
            if console {
                let addr = seg_offset(dos, regs, regs.ds as u16, regs.rdx as u32);
                for i in 0..count as u32 {
                    let ch = machine.read::<u8>((addr + i) as usize);
                    dos_putchar(machine, dos, ch);
                }
                DosExit::Ax(count)
            } else if handle == NULL_FILE_HANDLE {
                DosExit::Ax(count)
            } else {
                let addr = seg_offset(dos, regs, regs.ds as u16, regs.rdx as u32);
                let mut data = alloc::vec![0u8; count as usize];
                machine.copy_from(addr as usize, &mut data);
                let n = crate::kernel::vfs::write(machine, handle as i32, &data, &kt.fds);
                if n >= 0 {
                    if n > 0 {
                        let (time, date) = current_dos_timestamp(machine, regs);
                        if let Some(unix) = dos_to_unix_datetime(time, date) {
                            // DOS updates a file's modification time after a
                            // successful write. Keep the backing filesystem
                            // and directory listings in sync with AH=57h.
                            let _ = crate::kernel::vfs::set_handle_mtime(
                                handle as i32, unix, &kt.fds,
                            );
                        }
                    }
                    let size = crate::kernel::vfs::file_size(handle as i32, &kt.fds);
                    sft_set_file(machine, handle, size);
                    DosExit::Ax(n as u16)
                } else {
                    DosExit::Errno(n)
                }
            }
        }
        // AH=0x42: Seek (BX=handle, CX:DX=offset, AL=origin)
        0x42 => {
            let handle = regs.rbx as u16 as i32;
            if handle == NULL_FILE_HANDLE as i32 {
                // /dev/null — always at position 0
                regs.rdx &= !0xFFFF;
                DosExit::Ax(0)
            } else {
                let offset = ((regs.rcx as u16 as u32) << 16 | regs.rdx as u16 as u32) as i32;
                let whence = regs.rax as u8 as i32; // AL = origin
                let result = crate::kernel::vfs::seek(handle, offset, whence, &kt.fds);
                if result >= 0 {
                    // Return new position in DX:AX
                    regs.rdx = (regs.rdx & !0xFFFF) | ((result as u32 >> 16) as u64);
                    DosExit::Ax(result as u16)
                } else {
                    DosExit::Error(6) // invalid handle
                }
            }
        }
        // AH=0x43: Get/Set File Attributes (AL=0: get, AL=1: set)
        // DS:DX = ASCIIZ filename, CX = attributes (for set)
        0x43 => {
            let al = regs.rax as u8;
            let resolved = resolve_guest_path(
                machine, dos, regs, regs.ds as u16, regs.rdx as u32, PathTarget::Existing,
            );
            match (al, resolved) {
                (0, Ok(path)) => match crate::kernel::vfs::dos_attributes(path.as_bytes()) {
                    Some(attrs) => {
                        regs.rcx = (regs.rcx & !0xFFFF) | attrs as u64;
                        DosExit::Ok
                    }
                    None => DosExit::Error(2),
                },
                (1, Ok(path)) => {
                    let rc = crate::kernel::vfs::set_dos_attributes(path.as_bytes(), regs.rcx as u8);
                    if rc == 0 { DosExit::Ok } else { DosExit::Errno(rc) }
                }
                (_, Err(e)) => DosExit::Error(e as u16),
                _ => DosExit::Error(1),
            }
        }
        // AH=0x11h FCB FindFirst / AH=0x12h FCB FindNext.
        //
        // The CP/M-era file-find API. Caller fills an "unopened FCB"
        // at DS:DX with `drive(1B) + name(8B,space-pad) + ext(3B,
        // space-pad)`; DOS scans the drive's directory for matches
        // against the (`?`/`*`-wildcarded) pattern, writes a
        // "search FCB" into the current DTA on a hit, returns AL=00
        // (found) or AL=FF (no match). FindNext (AH=12) takes no
        // input — it reads the previous DTA + our find_idx state
        // and continues the scan.
        //
        // Standard FCB layout in DTA after FindFirst:
        //   off 0x00 : drive (1=A, 2=B, ...) of matched file
        //   off 0x01 : 8-byte matched filename, space-padded
        //   off 0x09 : 3-byte matched extension, space-padded
        //   off 0x0C : 2B current block (we set 0)
        //   off 0x0E : 2B record size (we set 128)
        //   off 0x10 : 4B file size (DWORD)
        //   off 0x14 : 2B date (DOS format)
        //   off 0x16 : 2B time (DOS format)
        //   off 0x18 : 8B reserved (DOS-internal next-search state)
        //
        // Extended FCB (caller's FCB[0] == 0xFF): 7-byte prefix
        // before the standard FCB. Marker, 5 reserved, attribute
        // byte. Our DTA write mirrors that prefix.
        0x11 | 0x12 => {
            #[inline(never)]
            fn fcb_find<A: crate::Arch>(
                machine: &mut A,
                dos: &mut thread::DosState<A>,
                regs: &mut Regs,
                ah: u8,
            ) -> thread::KernelAction {
            if ah == 0x11 {
                // FindFirst: parse FCB → compose DOS path → seed
                // dos.find_path / dos.find_idx, then drop into the
                // shared scan loop below.
                let addr = seg_offset(dos, regs, regs.ds as u16, regs.rdx as u32);
                let (is_ext, fcb_off) = if machine.read::<u8>(addr as usize) == 0xFF { (true, 7) } else { (false, 0) };
                let fcb_base = addr.wrapping_add(fcb_off);
                let drive_byte = machine.read::<u8>((fcb_base) as usize);
                let mut name = [0u8; 8];
                machine.copy_from((fcb_base + 1) as usize, &mut name);
                let mut ext = [0u8; 3];
                machine.copy_from((fcb_base + 9) as usize, &mut ext);
                // Build "[X:][cwd\]NAME[.EXT]" — wildcards stay as-is
                // ('?' for single, real chars for literal). resolve()
                // uppercases and applies cwd.
                let mut dos_path = [0u8; 96];
                let mut dpos = 0;
                if drive_byte != 0 && drive_byte <= 26 {
                    dos_path[0] = b'A' - 1 + drive_byte;
                    dos_path[1] = b':';
                    dos_path[2] = b'\\';
                    dpos = 3;
                }
                let name_len = name.iter().position(|&c| c == b' ').unwrap_or(name.len());
                dos_path[dpos..dpos + name_len].copy_from_slice(&name[..name_len]);
                dpos += name_len;
                let ext_len = ext.iter().position(|&c| c == b' ').unwrap_or(ext.len());
                if ext_len != 0 {
                    dos_path[dpos] = b'.';
                    dpos += 1;
                    dos_path[dpos..dpos + ext_len].copy_from_slice(&ext[..ext_len]);
                    dpos += ext_len;
                }
                let pos = match resolve_search_path(
                    &dos.dfs, &dos_path[..dpos], &mut dos.find_path,
                ) {
                    Ok(len) => len,
                    Err(_) => {
                        regs.rax = (regs.rax & !0xFF) | 0xFF;
                        return thread::KernelAction::Done;
                    }
                };
                dos.find_path_len = pos as u8;
                dos.find_idx = 0;
                // Stash the drive number + extended-marker for the
                // DTA write below. Drive 0 in the FCB means "current",
                // which our DTA result must report as the actual drive.
                dos.fcb_search_drive = if drive_byte == 0 {
                    dos.dfs.current_drive_number() + 1
                } else { drive_byte };
                dos.fcb_search_ext = is_ext;
            }
            // Shared FindFirst/FindNext scan: walk DFS CI cache from
            // dos.find_idx, return on first match.
            let path_len = dos.find_path_len as usize;
            let full = &dos.find_path[..path_len];
            let split = full.iter().rposition(|&b| b == b'/').map(|i| i + 1).unwrap_or(0);
            let dir = &full[..split];
            let mut pat_buf = [0u8; 32];
            let plen = (path_len - split).min(pat_buf.len());
            pat_buf[..plen].copy_from_slice(&full[split..split + plen]);
            let pat = &pat_buf[..plen];
            let dir_for_ci = if dir.last() == Some(&b'/') { &dir[..dir.len() - 1] } else { dir };
            let mut idx = dos.find_idx as usize;
            let drive = dos.fcb_search_drive;
            let is_ext = dos.fcb_search_ext;
            loop {
                match dfs::ci::entry_at(dir_for_ci, idx) {
                    // `ent`, not `e` — the extension slice below owns that name.
                    Some((alias, ent)) => {
                        idx += 1;
                        if !dos_wildcard_match(pat, alias) { continue; }
                        dos.find_idx = idx as u16;
                        let (is_dir, size) = (ent.is_dir, ent.size);
                        // Write search FCB into DTA. Layout above.
                        let dta = dos.dta as usize;
                        // Zero the (extended-prefix + 32-byte) area first.
                        let total = if is_ext { 7 + 32 } else { 32 };
                        machine.zero(dta, total);
                        let fcb_base = if is_ext {
                            machine.write::<u8>(dta, 0xFF);
                            machine.write::<u8>(dta + 6, if is_dir { 0x10 } else { 0x20 });
                            dta + 7
                        } else {
                            dta
                        };
                        machine.write::<u8>(fcb_base, drive);
                        // Split alias (e.g. "CIV.EXE" or "AUTOEXEC.BAT")
                        // into 8-char name + 3-char ext, space-padded.
                        let mut name_buf = [b' '; 8];
                        let mut ext_buf = [b' '; 3];
                        let dot = alias.iter().position(|&c| c == b'.');
                        let (n, e) = match dot {
                            Some(d) => (&alias[..d], &alias[d + 1..]),
                            None => (alias, &[][..]),
                        };
                        for (i, &c) in n.iter().take(8).enumerate() {
                            name_buf[i] = c.to_ascii_uppercase();
                        }
                        for (i, &c) in e.iter().take(3).enumerate() {
                            ext_buf[i] = c.to_ascii_uppercase();
                        }
                        machine.copy_to(fcb_base + 1, &name_buf);
                        machine.copy_to(fcb_base + 9, &ext_buf);
                        // current block = 0 (offsets 0x0C-0x0D), record
                        // size = 128 (0x0E-0x0F), file size at 0x10-0x13.
                        machine.write::<u16>(fcb_base + 0x0E, 128);
                        machine.write::<u32>(fcb_base + 0x10, size);
                        // Real mtime; (0, 0) when the backing fs has none.
                        let (time, date) = unix_to_dos_datetime(ent.mtime);
                        machine.write::<u16>(fcb_base + 0x14, date);
                        machine.write::<u16>(fcb_base + 0x16, time);
                        regs.rax &= !0xFF;
                        return thread::KernelAction::Done;
                    }
                    None => {
                        regs.rax = (regs.rax & !0xFF) | 0xFF;
                        return thread::KernelAction::Done;
                    }
                }
            }
            }
            return fcb_find(machine, dos, regs, ah);
        }
        // AH=0x29: Parse filename into FCB (DS:SI=string, ES:DI=FCB)
        // AL bits: 0=skip leading separators, 1=set drive only if specified,
        //          2=set filename only if specified, 3=set extension only if specified
        0x29 => {
            #[inline(never)]
            fn parse_fcb<A: crate::Arch>(
                machine: &mut A,
                dos: &mut thread::DosState<A>,
                regs: &mut Regs,
            ) -> thread::KernelAction {
            let ds_base = seg_offset(dos, regs, regs.ds as u16, 0);
            let mut si = regs.rsi as u16;
            let fcb = seg_offset(dos, regs, regs.es as u16, regs.rdi as u32);

            // Skip leading whitespace/separators if bit 0 set
            let flags = regs.rax as u8;
            if flags & 1 != 0 {
                loop {
                    let ch = machine.read::<u8>((ds_base.wrapping_add(si as u32)) as usize);
                    if ch == b' ' || ch == b'\t' || ch == b';' || ch == b',' {
                        si += 1;
                    } else {
                        break;
                    }
                }
            }

            // Zero-fill the 11-byte name field in FCB (drive byte at +0, name at +1..+12)
            machine.copy_to((fcb + 1) as usize, &[b' '; 11]);

            // Check for drive letter (e.g., "C:")
            let ch0 = machine.read::<u8>((ds_base.wrapping_add(si as u32)) as usize);
            let ch1 = machine.read::<u8>((ds_base.wrapping_add(si as u32 + 1)) as usize);
            if ch1 == b':' && ch0.is_ascii_alphabetic() {
                machine.write::<u8>((fcb) as usize, ch0.to_ascii_uppercase() - b'A' + 1);
                si += 2;
            } else {
                machine.write::<u8>((fcb) as usize, 0); // default drive
            }

            // Parse filename (up to 8 chars) into FCB+1
            let mut pos = 0u32;
            loop {
                let ch = machine.read::<u8>((ds_base.wrapping_add(si as u32)) as usize);
                if ch == b'.' || ch == 0 || ch == b' ' || ch == b'/' || ch == b'\\' || ch == b'\r' { break; }
                if ch == b'*' {
                    while pos < 8 { machine.write::<u8>((fcb + 1 + pos) as usize, b'?'); pos += 1; }
                    si += 1;
                    break;
                }
                if pos < 8 {
                    machine.write::<u8>((fcb + 1 + pos) as usize, ch.to_ascii_uppercase());
                    pos += 1;
                }
                si += 1;
            }

            // Parse extension (up to 3 chars) into FCB+9
            let ch = machine.read::<u8>((ds_base.wrapping_add(si as u32)) as usize);
            if ch == b'.' {
                si += 1;
                pos = 0;
                loop {
                    let ch = machine.read::<u8>((ds_base.wrapping_add(si as u32)) as usize);
                    if ch == 0 || ch == b' ' || ch == b'/' || ch == b'\\' || ch == b'\r' { break; }
                    if ch == b'*' {
                        while pos < 3 { machine.write::<u8>((fcb + 9 + pos) as usize, b'?'); pos += 1; }
                        si += 1;
                        break;
                    }
                    if pos < 3 {
                        machine.write::<u8>((fcb + 9 + pos) as usize, ch.to_ascii_uppercase());
                        pos += 1;
                    }
                    si += 1;
                }
            }

            // Update SI to point past parsed name
            regs.rsi = (regs.rsi & !0xFFFF) | si as u64;
            // AL=0: no wildcards, AL=1: wildcards present, AL=0xFF: drive invalid
            let mut fcb_name = [0u8; 11];
            machine.copy_from((fcb + 1) as usize, &mut fcb_name);
            let has_wildcards = fcb_name.contains(&b'?');
            regs.rax = (regs.rax & !0xFF) | if has_wildcards { 1 } else { 0 };
            thread::KernelAction::Done
            }
            return parse_fcb(machine, dos, regs);
        }
        // AH=0x4B: EXEC — Load and Execute Program
        // AL=00: load+execute, DS:DX=ASCIIZ filename, ES:BX=param block
        0x4B => {
            return exec_program(machine, kt, dos, regs);
        }
        // AH=2Ah — Get System Date
        0x2A => {
            let (year, month, day, dow) = cmos_date(machine);
            regs.rcx = (regs.rcx & !0xFFFF) | year as u64; // CX = year
            regs.rdx = (regs.rdx & !0xFFFF) | ((month as u64) << 8) | day as u64; // DH = month, DL = day
            regs.rax = (regs.rax & !0xFF) | dow as u64; // AL = day of week (0=Sun, 6=Sat)
            return thread::KernelAction::Done;
        }
        // AH=2Bh — Set System Date. Date changes are not supported; DOS
        // reports failure in AL, rather than through CF/AX. DESQview's
        // installation probe uses an invalid date (CX='DE', DX='SQ') and
        // treats any AL other than FFh as an installed multitasker.
        0x2B => {
            regs.rax = (regs.rax & !0xFF) | 0xFF;
            return thread::KernelAction::Done;
        }
        // AH=2Ch — Get System Time
        0x2C => {
            let (hours, mins, secs, centisecs) = bios_time_of_day(machine);
            regs.rcx = (regs.rcx & !0xFFFF) | ((hours as u64) << 8) | mins as u64;
            regs.rdx = (regs.rdx & !0xFFFF) | ((secs as u64) << 8) | centisecs as u64;
            return thread::KernelAction::Done;
        }
        // AH=0x56: Rename file or directory (DS:DX=old, ES:DI=new)
        0x56 => {
            let old = resolve_guest_path(
                machine, dos, regs, regs.ds as u16, regs.rdx as u32, PathTarget::Existing,
            );
            let new = resolve_guest_path(
                machine, dos, regs, regs.es as u16, regs.rdi as u32, PathTarget::New,
            );
            let rc = match (old, new) {
                (Ok(old), Ok(new)) if immutable_media_path(old.as_bytes())
                    || immutable_media_path(new.as_bytes()) => -30,
                (Ok(old), Ok(new)) => crate::kernel::vfs::rename(
                    old.as_bytes(), new.as_bytes(),
                ),
                (Err(e), _) | (_, Err(e)) => -e,
            };
            if rc == 0 { DosExit::Ok } else { DosExit::Errno(rc) }
        }
        // AH=0x57: Get/Set File Date and Time (AL=0: get, AL=1: set, BX=handle)
        0x57 => {
            let al = regs.rax as u8;
            if al == 0 {
                let (time, date) = match crate::kernel::vfs::handle_mtime(regs.rbx as u16 as i32, &kt.fds) {
                    Some(unix) if unix != 0 => unix_to_dos_datetime(unix),
                    _ => current_dos_timestamp(machine, regs),
                };
                regs.rcx = (regs.rcx & !0xFFFF) | time as u64;
                regs.rdx = (regs.rdx & !0xFFFF) | date as u64;
                DosExit::Ok
            } else if al == 1 {
                let rc = match dos_to_unix_datetime(regs.rcx as u16, regs.rdx as u16) {
                    Some(unix) => crate::kernel::vfs::set_handle_mtime(regs.rbx as u16 as i32, unix, &kt.fds),
                    None => -22,
                };
                if rc == 0 { DosExit::Ok } else { DosExit::Errno(rc) }
            } else {
                DosExit::Error(1)
            }
        }
        // AH=0x60: Canonicalize path (DS:SI=input, ES:DI=output buffer)
        0x60 => {
            let src = seg_offset(dos, regs, regs.ds as u16, regs.rsi as u32);
            let dst = seg_offset(dos, regs, regs.es as u16, regs.rdi as u32);
            // Read input path
            let mut name = [0u8; 128];
            let len = read_asciiz(machine, src, &mut name);
            // Build canonical path: if no drive letter, prepend the current drive.
            let mut out = [0u8; 128];
            let mut pos;
            if len >= 2 && name[1] == b':' {
                // Already has drive letter — uppercase it
                out[0] = name[0].to_ascii_uppercase();
                out[1] = b':';
                out[2] = b'\\';
                pos = 3;
                let skip = if len > 2 && (name[2] == b'/' || name[2] == b'\\') { 3 } else { 2 };
                for item in name.iter().take(len).skip(skip) {
                    if pos >= 127 { break; }
                    out[pos] = if *item == b'/' { b'\\' } else { item.to_ascii_uppercase() };
                    pos += 1;
                }
            } else {
                // Relative — prepend current X:\ + its CWD (already DOS form).
                out[0] = b'A' + dos.dfs.current_drive_number();
                out[1] = b':'; out[2] = b'\\';
                pos = 3;
                let cwds = dos.dfs.get_cwd();
                for &ch in cwds {
                    if pos >= 127 { break; }
                    out[pos] = ch;
                    pos += 1;
                }
                if pos > 3 && out[pos - 1] != b'\\' { out[pos] = b'\\'; pos += 1; }
                for item in name.iter().take(len) {
                    if pos >= 127 { break; }
                    out[pos] = if *item == b'/' { b'\\' } else { item.to_ascii_uppercase() };
                    pos += 1;
                }
            }
            out[pos] = 0;
            // Write to ES:DI
            machine.copy_to(dst as usize, &out[..pos + 1]);
            DosExit::Ok
        }
        // AH=0x52: Get List of Lists (returns ES:BX → DOS internal structure)
        // Programs read [ES:BX - 2] WORD = first MCB segment (the chain
        // head). LOL doesn't need to be paragraph-aligned: ES:BX expresses
        // any linear address.
        0x52 => {
            let lol_addr = LOW_MEM_BASE + core::mem::offset_of!(LowMem, lol) as u32;
            if dos.dpmi.is_some() && regs.frame.rflags as u32 & machine::VM_FLAG == 0 {
                regs.es = dpmi::LOW_MEM_SEL as u64;
                // Full 32-bit write (see AH=34): the offset is a linear address.
                regs.rbx = lol_addr as u64;
            } else {
                regs.es = (lol_addr >> 4) as u64;
                regs.rbx = (regs.rbx & !0xFFFF) | (lol_addr & 0xF) as u64;
            }
            DosExit::Ok
        }
        // AH=0x36: Get Disk Free Space (DL=drive, 0=default,1=A,2=B,3=C...)
        // Returns: AX=sectors/cluster, BX=free clusters, CX=bytes/sector, DX=total clusters
        // On error: AX=0xFFFF
        0x36 => {
            let dl = regs.rdx as u8;
            // Map drive: 0=default, 1=A, 2=B, 3=C, 4=D
            let drive = if dl == 0 { dos.dfs.current_drive_number() + 1 } else { dl };
            if matches!(drive, 1 | 2) {
                // A:/B: — real geometry and free space from the inserted FAT
                // image. An empty drive is AX=FFFF (invalid drive; the
                // not-ready critical error needs INT 24h plumbing that does
                // not exist yet).
                match crate::kernel::fs::floppy::geometry(drive as usize - 1) {
                    Some((spc, bps, total, free)) => {
                        regs.rax = (regs.rax & !0xFFFF) | spc as u64;
                        regs.rbx = (regs.rbx & !0xFFFF) | free as u64;
                        regs.rcx = (regs.rcx & !0xFFFF) | bps as u64;
                        regs.rdx = (regs.rdx & !0xFFFF) | total as u64;
                    }
                    None => {
                        regs.rax = (regs.rax & !0xFFFF) | 0xFFFF;
                    }
                }
            } else if drive == 3 {
                // C: drive — report a synthetic 128MB disk with 96MB free.
                // VFS has no capacity query, but installers use this call to
                // reject destinations that cannot hold their selected payload.
                // 512 bytes/sector * 8 sectors/cluster * 32768 clusters = 128MB.
                regs.rax = (regs.rax & !0xFFFF) | 8;    // AX = sectors per cluster
                regs.rbx = (regs.rbx & !0xFFFF) | 24576; // BX = free clusters (96MB)
                regs.rcx = (regs.rcx & !0xFFFF) | 512;  // CX = bytes per sector
                regs.rdx = (regs.rdx & !0xFFFF) | 32768; // DX = total clusters
            } else if drive == 4 && crate::kernel::fs::cdrom::is_inserted() {
                // Read-only CD-ROM. DOS's free-space API has no read-only bit;
                // report the conventional 2048-byte sector geometry and zero free.
                regs.rax = (regs.rax & !0xFFFF) | 1;
                regs.rbx &= !0xFFFF;
                regs.rcx = (regs.rcx & !0xFFFF) | 2048;
                regs.rdx = (regs.rdx & !0xFFFF) | 0xFFFF;
            } else if dfs::extra_drive_prefix(b'A'.wrapping_add(drive.wrapping_sub(1))).is_some() {
                // Secondary partitions are read-only. VFS has no capacity
                // query yet; use the same synthetic 128 MiB geometry as C:,
                // with zero available clusters rather than promising writes.
                regs.rax = (regs.rax & !0xFFFF) | 8;
                regs.rbx &= !0xFFFF;
                regs.rcx = (regs.rcx & !0xFFFF) | 512;
                regs.rdx = (regs.rdx & !0xFFFF) | 32768;
            } else if drive == 8 && crate::kernel::vfs::dir_exists(b"host") {
                // Hostfs has no portable capacity query; report the same
                // synthetic geometry as C: while marking it remote via 4409h.
                regs.rax = (regs.rax & !0xFFFF) | 8;
                regs.rbx = (regs.rbx & !0xFFFF) | 24576;
                regs.rcx = (regs.rcx & !0xFFFF) | 512;
                regs.rdx = (regs.rdx & !0xFFFF) | 32768;
            } else {
                // Unknown — invalid drive
                regs.rax = (regs.rax & !0xFFFF) | 0xFFFF;
            }
            return thread::KernelAction::Done;
        }
        // AH=0x37: Get/set switch character. DOS 5+ fixes it at '/' (set is a
        // no-op). Returning DL='/' is load-bearing: the Borland/Microsoft C
        // runtime uses '/' as the *path separator* whenever the switch char is
        // not '/'. A missing/error answer (our old catch-all returned AX=1,CF=1)
        // made bc.exe emit forward-slash paths everywhere — e.g. the TASM object
        // spec "OBJ/H_LDIV.OBJ", where TASM parses the "/H" as the help switch
        // and prints its syntax screen instead of assembling (Wolf3D .PRJ build).
        0x37 => {
            match regs.rax as u8 {
                0x00 => {
                    regs.rax &= !0xFF;                       // AL=00: success
                    regs.rdx = (regs.rdx & !0xFF) | b'/' as u64;
                    DosExit::Ok
                }
                0x01 => {
                    regs.rax &= !0xFF;                       // accept set, no-op
                    DosExit::Ok
                }
                _ => {
                    regs.rax = (regs.rax & !0xFF) | 0xFF;    // invalid subfunction
                    return thread::KernelAction::Done;
                }
            }
        }
        // AX=6601h/6602h: query or select the global DOS code page. The
        // display font is installed before byte-to-Unicode conversion changes.
        0x66 => match regs.rax as u8 {
            0x01 => {
                regs.rbx = (regs.rbx & !0xffff) | u64::from(lib::codepage::current_codepage().id);
                regs.rdx = (regs.rdx & !0xffff) | u64::from(lib::locale::system_oem());
                DosExit::Ok
            }
            0x02 => {
                let id = regs.rbx as u16;
                match lib::codepage::codepage(id) {
                    Some(page) if page.id == lib::codepage::current_codepage().id => DosExit::Ok,
                    Some(page) if crate::kernel::dos::bios::video::install_codepage_font(machine, bios_display, dos, page) => {
                        lib::codepage::select_codepage(id);
                        DosExit::Ok
                    }
                    _ => DosExit::Error(0x26), // code page not prepared
                }
            }
            _ => DosExit::Error(1),
        },
        // AH=0x67: Set Handle Count
        0x67 => {
            let requested = (regs.rbx as u16) as usize;
            let psp_seg = psp_struct_seg(dos);
            // The PSP always has room for its original 20 handles. DOS treats
            // requests at or below that size as successful no-ops.
            if requested <= PSP_JFT_LEN {
                DosExit::Ok
            } else if requested <= thread::MAX_FDS {
                let old_count = Psp::max_files(machine, psp_seg) as usize;
                let old_addr = Psp::jft_addr(machine, psp_seg);
                let old_external_seg = Psp::external_jft_seg(machine, psp_seg);
                let paras = requested.div_ceil(16) as u16;

                match dos_alloc_block(machine, dos, regs, paras) {
                    Ok(new_seg) => {
                        let new_addr = (new_seg as usize) << 4;
                        for i in 0..requested {
                            machine.write::<u8>(new_addr + i, 0xFF);
                        }
                        for i in 0..old_count.min(requested) {
                            let entry = machine.read::<u8>(old_addr + i);
                            machine.write::<u8>(new_addr + i, entry);
                        }
                        Psp::set_jft_location(machine, psp_seg, requested as u16, 0, new_seg);
                        if let Some(old_seg) = old_external_seg {
                            let _ = dos_free_block(machine, dos, regs, old_seg);
                        }
                        DosExit::Ok
                    }
                    Err(_) => DosExit::Error(8),
                }
            } else {
                DosExit::Error(8) // insufficient memory for an external JFT
            }
        }
        // AH=0x41: Delete file (DS:DX=filename)
        0x41 => {
            match resolve_guest_path(
                machine, dos, regs, regs.ds as u16, regs.rdx as u32, PathTarget::Existing,
            ) {
                Ok(path) if immutable_media_path(path.as_bytes()) => DosExit::Error(5),
                Ok(path) => {
                    let rv = if crate::kernel::vfs::dos_attributes(path.as_bytes()).is_some_and(|a| a & 1 != 0) { -13 }
                        else { crate::kernel::vfs::delete(path.as_bytes()) };
                    if rv >= 0 { DosExit::Ok } else { DosExit::Error(5) }
                }
                Err(e) => DosExit::Error(e as u16),
            }
        }
        // AH=0x59: Get Extended Error Information
        0x59 => {
            // Report the most recent failed DOS call. In particular, FindNext
            // ends with error 18 (no more files); reporting error 2 instead
            // makes file managers treat a completed listing as a disk fault.
            let code = dos.last_dos_error;
            let (class, action, locus) = match code {
                0 => (0u16, 0u16, 0u16),
                2 | 3 => (8, 3, 1),   // item not found; correct input
                18 => (8, 6, 1),      // no more files; informational
                _ => (12, 4, 1),      // other error; terminate with cleanup
            };
            regs.rbx = (regs.rbx & !0xFFFF) | ((class << 8) | action) as u64;
            regs.rcx = (regs.rcx & !0xFFFF) | (locus << 8) as u64;
            DosExit::Ax(code)
        }
        // AH=5Ah: Create temporary file. DS:DX names a directory/prefix; DOS
        // appends a unique 8.3 name in the caller's buffer and returns a handle.
        0x5A => {
            let addr = seg_offset(dos, regs, regs.ds as u16, regs.rdx as u32);
            let mut prefix = [0u8; dfs::DFS_PATH_MAX];
            let plen_limit = dfs::DFS_PATH_MAX - 12;
            let mut plen = read_asciiz(machine, addr, &mut prefix[..plen_limit]);
            if plen > 0 && prefix[plen - 1] != b'\\' && prefix[plen - 1] != b'/' {
                prefix[plen] = b'\\'; plen += 1;
            }
            let mut created = -17;
            let mut final_len = plen;
            for _ in 0..u16::MAX {
                let seq = TEMP_FILE_SEQUENCE.fetch_add(1, Ordering::Relaxed);
                let hex = b"0123456789ABCDEF";
                let suffix = [
                    b'T', b'M', b'P',
                    hex[(seq >> 12) as usize], hex[((seq >> 8) & 15) as usize],
                    hex[((seq >> 4) & 15) as usize], hex[(seq & 15) as usize],
                    b'.', b'$', b'$', b'$',
                ];
                prefix[plen..plen + suffix.len()].copy_from_slice(&suffix);
                final_len = plen + suffix.len();
                let Ok((path, len)) = dfs_create_path(dos, &prefix[..final_len]) else { created = -3; break; };
                if crate::kernel::vfs::path_exists(&path[..len]) { continue; }
                created = match create_file_handle(machine, kt, dos, &path[..len]) {
                    Ok(handle) => handle as i32,
                    Err(err) => err,
                };
                break;
            }
            if created >= 0 {
                machine.copy_to(addr as usize, &prefix[..final_len]);
                machine.write::<u8>((addr + final_len as u32) as usize, 0);
                DosExit::Ax(created as u16)
            } else {
                DosExit::Errno(created)
            }
        }
        // AH=5Bh: Create new file, failing with error 80 if it already exists.
        0x5B => {
            let result = match resolve_guest_path(
                machine, dos, regs, regs.ds as u16, regs.rdx as u32, PathTarget::New,
            ) {
                Ok(path) if crate::kernel::vfs::path_exists(path.as_bytes()) => Err(-80),
                Ok(path) => create_file_handle(machine, kt, dos, path.as_bytes()),
                Err(e) => Err(-e),
            };
            match result {
                Ok(handle) => DosExit::Ax(handle),
                Err(-80) => DosExit::Error(80),
                Err(err) => DosExit::Errno(err),
            }
        }
        // AH=5Ch: Lock/unlock byte range.
        0x5C => {
            let al = regs.rax as u8;
            let start = ((regs.rcx as u16 as u32) << 16) | regs.rdx as u16 as u32;
            let len = ((regs.rsi as u16 as u32) << 16) | regs.rdi as u16 as u32;
            let rc = if al <= 1 {
                crate::kernel::vfs::lock_range(regs.rbx as u16 as i32, al == 1, start, len, &kt.fds)
            } else { -22 };
            if rc == 0 {
                DosExit::Ok
            } else if rc == -33 {
                DosExit::Error(33)
            } else {
                DosExit::Errno(rc)
            }
        }
        // AH=0x58: DOS 5+ allocation strategy / UMB link state
        0x58 => {
            let al = regs.rax as u8;
            match al {
                0x00 => DosExit::Ax(dos.alloc_strategy),
                0x01 => {
                    dos.alloc_strategy = regs.rbx as u16;
                    DosExit::Ok
                }
                0x02 => DosExit::Ax(dos.umb_link_state),
                0x03 => {
                    dos.umb_link_state = regs.rbx as u16;
                    DosExit::Ok
                }
                _ => DosExit::Error(1),
            }
        }
        // AH=0x4D: Get Return Code of Subprocess
        // Returns AL = code passed to AH=4Ch/AH=31h, AH = termination type
        // (00h normal, 01h Ctrl-Break, 02h critical error, 03h TSR).
        0x4D => {
            let status = dos.last_child_exit_status;
            regs.rax = (regs.rax & !0xFFFF) | status as u64;
            return thread::KernelAction::Done;
        }
        // AH=0x50: Set Current Process ID (BX = new PSP). In PM, client
        // passes a selector cached in `psp_cache` (HDPMI behavior); reverse
        // it to a segment before storing. If BX isn't a known selector
        // treat it as a segment value directly (matches HDPMI's
        // `bx_sel2segm` fallthrough).
        0x50 => {
            let bx = regs.rbx as u16;
            let in_pm = regs.mode() != crate::UserMode::VM86;
            let seg = if in_pm {
                crate::kernel::dos::dpmi::psp_sel_to_segment(dos, bx).unwrap_or(bx)
            } else {
                bx
            };
            dos.current_psp = seg;
            DosExit::Ok
        }
        // AH=0x51 / AH=0x62: Get PSP. In PM, return the per-segment
        // selector from `psp_cache` (HDPMI's getpspsel); the client can
        // load it into ES and address its PSP. In RM, return the raw
        // segment.
        0x51 | 0x62 => {
            let in_pm = regs.mode() != crate::UserMode::VM86;
            let bx = if in_pm {
                crate::kernel::dos::dpmi::get_or_alloc_psp_sel(dos, dos.current_psp)
            } else {
                dos.current_psp
            };
            regs.rbx = (regs.rbx & !0xFFFF) | bx as u64;
            DosExit::Ok
        }
        // AH=55h: create a child PSP in caller-allocated memory. DOS copies
        // the current PSP, takes INT 22h/23h/24h from the IVT, initializes an
        // inline inherited handle table, and makes DX the current PSP.
        0x55 => {
            let child = regs.rdx as u16;
            let top = regs.rsi as u16;
            let parent_seg = dos.current_psp;
            let parent = machine.read::<Psp>(Psp::base(parent_seg));
            let allocated = dos.dos_blocks.iter().any(|block| {
                block.owner == parent_seg && block.seg <= child
                    && u32::from(child) + 0x10 <= u32::from(block.seg) + u32::from(block.paras)
                    && u32::from(top) <= u32::from(block.seg) + u32::from(block.paras)
            });
            if parent.int_20 != [0xCD, 0x20] || !allocated
                || top < child.saturating_add(0x10) || top > 0xA000
            {
                DosExit::Error(9)
            } else {
                let mut psp = parent;
                psp.top_of_mem = top;
                psp.parent_psp = parent_seg;
                psp._terminate_addr = machine.read::<u32>(0x22 * 4);
                psp._ctrl_break_addr = machine.read::<u32>(0x23 * 4);
                psp._critical_err = machine.read::<u32>(0x24 * 4);
                psp.max_files = 20;
                psp.jft_far_off = 0x18;
                psp.jft_far_seg = child;
                psp.jft.fill(0xFF);
                let parent_jft = Psp::jft_addr(machine, parent_seg);
                let inherited = usize::from(parent.max_files.min(20));
                if inherited != 0 && parent_jft <= 0x100000 - inherited {
                    machine.copy_from(parent_jft, &mut psp.jft[..inherited]);
                }
                // PSP:38h is the previous-PSP pointer; each child starts
                // with two empty default FCBs rather than its parent's FCBs.
                psp._reserved_38[..4].copy_from_slice(&(u32::from(parent_seg) << 16).to_le_bytes());
                for offset in [0x5C - 0x38, 0x6C - 0x38] {
                    psp._reserved_38[offset] = 0;
                    psp._reserved_38[offset + 1..offset + 12].fill(b' ');
                }
                Psp::store(machine, child, psp);
                dos.current_psp = child;
                DosExit::Ok
            }
        }
        // AH=68h/6Ah: Commit file. VFS writes are synchronous; the backend
        // hook additionally drains any filesystem cache when it has one.
        0x68 | 0x6A => {
            let handle = regs.rbx as u16 as i32;
            let rc = if handle == NULL_FILE_HANDLE as i32 { 0 }
                else { crate::kernel::vfs::flush(handle, &kt.fds) };
            if rc == 0 { DosExit::Ok } else { DosExit::Errno(rc) }
        }
        // AH=0x6C: Extended Open/Create (DOS 4.0+)
        // BX=mode, CX=attributes, DX=action, DS:SI=ASCIIZ filename
        // Action: bit0=open-if-exists, bit1=replace-if-exists, bit4=create-if-not-exists
        0x6C => {
            #[inline(never)]
            fn extended_open<A: crate::Arch>(
                machine: &mut A,
                kt: &mut thread::KernelThread<A>,
                dos: &mut thread::DosState<A>,
                regs: &mut Regs,
            ) -> DosExit {
            let action = regs.rdx as u16;
            let open_mode = regs.rbx as u16;
            let addr = seg_offset(dos, regs, regs.ds as u16, regs.rsi as u32);
            let mut name = [0u8; dfs::DFS_PATH_MAX];
            let i = read_asciiz(machine, addr, &mut name);
            let open_exists = action & 0x01 != 0;
            let replace_exists = action & 0x02 != 0;
            let create_not = action & 0x10 != 0;

            // Try open first
            let fd = match dfs_open_existing(dos, &name[..i]) {
                Ok((path, len)) => crate::kernel::vfs::open(&path[..len], &mut kt.fds),
                Err(e) => -e,
            };
            if fd >= 0 {
                if open_exists {
                    match accept_open_file(machine, kt, dos, fd, open_mode as u8) {
                        Ok(handle) => {
                            regs.rcx = (regs.rcx & !0xFFFF) | 1; // opened
                            DosExit::Ax(handle)
                        }
                        Err(err) => DosExit::Errno(err),
                    }
                } else if replace_exists {
                    crate::kernel::vfs::close(fd, &mut kt.fds);
                    let result = match dfs_create_path(dos, &name[..i]) {
                        Ok((path, len)) => create_file_handle(machine, kt, dos, &path[..len]),
                        Err(e) => Err(-e),
                    };
                    match result {
                        Ok(handle) => {
                            regs.rcx = (regs.rcx & !0xFFFF) | 3; // replaced
                            DosExit::Ax(handle)
                        }
                        Err(err) => DosExit::Errno(err),
                    }
                } else {
                    crate::kernel::vfs::close(fd, &mut kt.fds);
                    DosExit::Error(80) // file exists
                }
            } else if create_not {
                let result = match dfs_create_path(dos, &name[..i]) {
                    Ok((path, len)) => create_file_handle(machine, kt, dos, &path[..len]),
                    Err(e) => Err(-e),
                };
                match result {
                    Ok(handle) => {
                        regs.rcx = (regs.rcx & !0xFFFF) | 2; // created
                        DosExit::Ax(handle)
                    }
                    Err(err) => DosExit::Errno(err),
                }
            } else {
                DosExit::Error(2) // file not found
            }
            }
            extended_open(machine, kt, dos, regs)
        }
        // AH=0x5D: Server function — subfunction in AL
        0x5D => {
            let al = regs.rax as u8;
            match al {
                // AL=06: Get DOS Swappable Data Area address
                //   Returns DS:SI→ swap area, CX=total size, DX=size that must
                //   always be swapped. Point at SYSPSP (zeroed) with a nominal
                //   size; DPMILOAD just needs a plausible pointer.
                0x06 => {
                    let syspsp_addr = LOW_MEM_BASE + core::mem::offset_of!(LowMem, boot_psp) as u32;
                    if dos.dpmi.is_some() && regs.frame.rflags as u32 & machine::VM_FLAG == 0 {
                        regs.ds = dpmi::LOW_MEM_SEL as u64;
                        // Full 32-bit write (see AH=34): DOS/16M's DPMILOAD
                        // stores this DS:ESI whole (LDS ESI) and dereferences
                        // it later — a stale ESI31:16 became a kernel address
                        // (the DUKE3D music-start SEGV).
                        regs.rsi = syspsp_addr as u64;
                    } else {
                        regs.ds = (syspsp_addr >> 4) as u64;
                        regs.rsi &= !0xFFFF;
                    }
                    let sz = core::mem::size_of::<Psp>() as u64;
                    regs.rcx = (regs.rcx & !0xFFFF) | sz;
                    regs.rdx = (regs.rdx & !0xFFFF) | sz;
                    DosExit::Ok
                }
                _ => DosExit::Error(1), // invalid function
            }
        }
        0x71 => {
            lfn::dispatch(machine, kt, dos, regs)
        }
        0xFF => {
            regs.set_flag32(1);
            return thread::KernelAction::Done;
        }
        _ => DosExit::Error(1),
    };
    let failed = match exit {
        DosExit::Ok => false,
        DosExit::Ax(value) => {
            regs.rax = (regs.rax & !0xFFFF) | u64::from(value);
            false
        }
        DosExit::Error(error) => {
            regs.rax = (regs.rax & !0xFFFF) | u64::from(error);
            true
        }
        DosExit::Errno(error) => {
            regs.rax = (regs.rax & !0xFFFF) | u64::from(dos_error_from_errno(error));
            true
        }
    };
    if failed {
        dos.last_dos_error = regs.rax as u16;
        regs.set_flag32(1);
    } else {
        regs.clear_flag32(1);
    }
    thread::KernelAction::Done
}

/// Whether an INT 21h service can complete entirely inside one dispatcher
/// invocation. DPMI 0302h uses this to avoid constructing a real-mode stack
/// excursion when the real-mode vector still names RetroOS's own DOS stub.
///
/// Keep the state-changing/blocking calls on the ordinary path: that path
/// owns the continuation and guest stack frames needed while execution is
/// parked, replaced by EXEC, or returned to a parent. AH=3F remains there as
/// well because reads from deliberately paced CD media may suspend.
pub(in crate::kernel::dos) fn int21_is_synchronous(ah: u8) -> bool {
    !matches!(ah, 0x00 | 0x01 | 0x07 | 0x08 | 0x0A | 0x31 | 0x3F | 0x4B | 0x4C)
}

/// Dispatch a synchronous real-mode INT 21h register image without attaching
/// interrupt/continuation frames. The caller supplies a VM86-flavoured Regs
/// value, so pointer translation retains real-mode segment semantics.
pub(in crate::kernel::dos) fn dispatch_synchronous_rm_int21<A: crate::Arch>(
    machine: &mut A,
    bios_display: &mut crate::kernel::bios_display::BiosDisplayWorkspace<A>,
    kt: &mut thread::KernelThread<A>,
    dos: &mut thread::DosState<A>,
    regs: &mut Regs,
) -> thread::KernelAction {
    let mut suspension = None;
    let action = int_21h(machine, bios_display, kt, dos, regs, &mut suspension);
    debug_assert!(suspension.is_none());
    action
}
