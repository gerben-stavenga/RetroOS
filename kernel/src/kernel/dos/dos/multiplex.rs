//! INT 2Fh multiplex services and XMS/DPMI discovery.

use crate::Regs;
use crate::kernel::thread;
use crate::kernel::dos::seg_offset;
use super::lowmem::{CTRL_STUB_SEG, LOW_MEM_BASE, LowMem, SLOT_DPMI_ENTRY, SLOT_XMS, ctrl_slot_off};

// ============================================================================
// INT 2Fh — Multiplex interrupt (XMS + DPMI detection)
// ============================================================================

/// Fill regs with DPMI 0.90 installation-check reply (shared by INT 2F/1687h
/// and DOS/32A's INT 21h AX=FF87h probe).
fn dpmi_install_check(regs: &mut Regs) {
    regs.rax &= !0xFFFF; // AX=0: DPMI available
    regs.rbx = (regs.rbx & !0xFFFF) | 0x0001; // BX bit0 = 32-bit supported
    regs.rcx = (regs.rcx & !0xFF) | 0x03; // CL = 386
    regs.rdx = (regs.rdx & !0xFFFF) | 0x005A; // DX = DPMI 0.90
    regs.rsi &= !0xFFFF; // SI = 0 paragraphs needed
    regs.es = CTRL_STUB_SEG as u64;
    regs.rdi = (regs.rdi & !0xFFFF) | ctrl_slot_off(SLOT_DPMI_ENTRY) as u64;
}

pub(super) fn int_2fh<A: crate::Arch>(machine: &mut A, dos: &mut thread::DosState<A>, regs: &mut Regs) -> thread::KernelAction {
    let ax = regs.rax as u16;
    match ax {
        // AX=1500h — MSCDEX installation check. The CD-ROM drive remains
        // installed while its media slot is empty, just like a physical
        // drive; an empty slot affects readiness, not driver detection.
        0x1500 => {
            regs.rbx = (regs.rbx & !0xFFFF) | 1; // one CD-ROM drive
            regs.rcx = (regs.rcx & !0xFFFF) | 3; // first drive is D: (A:=0)
            regs.rax = (regs.rax & !0xFF) | 0xFF; // conventional installed marker
            regs.clear_flag32(1);
            thread::KernelAction::Done
        }
        // AX=1501h — one five-byte record: subunit byte followed by the
        // far address of its DOS device header. Some installers use this
        // header, rather than 150Bh, to verify their current drive is a CD.
        0x1501 => {
            let dest = seg_offset(dos, regs, regs.es as u16, regs.rbx as u32) as usize;
            let header = LOW_MEM_BASE + core::mem::offset_of!(LowMem, cdrom_header) as u32;
            let far_ptr = ((header >> 4) << 16) | (header & 0xF);
            machine.write::<u8>(dest, 0); // driver subunit zero
            machine.write::<u32>(dest + 1, far_ptr);
            regs.clear_flag32(1);
            thread::KernelAction::Done
        }
        // AX=150Bh — MSCDEX v2+ drive check. BX is the MSCDEX signature;
        // AX is nonzero only for the requested CD-ROM drive.
        0x150B => {
            regs.rbx = (regs.rbx & !0xFFFF) | 0xADAD;
            let supported = regs.rcx as u16 == 3;
            regs.rax = (regs.rax & !0xFFFF) | if supported { 0x5AD8 } else { 0 };
            regs.clear_flag32(1);
            thread::KernelAction::Done
        }
        // AX=150Ch — report the MSCDEX 2.00 interface level. Do not advertise
        // the v2.10 device-request extensions until AX=1510h is implemented.
        0x150C => {
            regs.rbx = (regs.rbx & !0xFFFF) | 0x0200;
            regs.clear_flag32(1);
            thread::KernelAction::Done
        }
        // AX=150Dh — return one byte per installed CD-ROM drive at ES:BX.
        0x150D => {
            let dest = seg_offset(dos, regs, regs.es as u16, regs.rbx as u32);
            machine.write::<u8>(dest as usize, 3); // D: (A:=0)
            regs.clear_flag32(1);
            thread::KernelAction::Done
        }
        // AX=1687h — DPMI installation check
        0x1687 => {
            dpmi_install_check(regs);
            thread::KernelAction::Done
        }
        // AX=168Ah — DPMI 1.0 Get Vendor-Specific API Entry Point.
        // We do not implement any vendor-specific entry points. Return
        // failure; AL=0 is the success value for this multiplex call.
        0x168A => {
            regs.rax = (regs.rax & !0xFF) | 0x80; // AL!=0: unsupported
            thread::KernelAction::Done
        }
        // AX=4300h — XMS installation check
        0x4300 => {
            regs.rax = (regs.rax & !0xFF) | 0x80; // AL=80h: XMS driver installed
            thread::KernelAction::Done
        }
        // AX=4310h — Get XMS driver entry point
        0x4310 => {
            regs.es = CTRL_STUB_SEG as u64;
            regs.rbx = (regs.rbx & !0xFFFF) | ctrl_slot_off(SLOT_XMS) as u64;
            thread::KernelAction::Done
        }
        // Multiplex probes expect unknown services to return "not installed"
        // with AL unchanged.
        _ => thread::KernelAction::Done,
    }
}
