//! Settle the "Unicorn mis-decodes `les di,[bp+6]`" claim definitively, by
//! observing the *memory write effect* rather than a register read (register
//! reads inside a code hook lag TCG's writeback within a TB and are unreliable).
//!
//! Exact bytes from DN's faulting site (/tmp/les.bin), 16-bit:
//!   C4 7E 06        les di,[bp+6]      ; DI <- [ss:bp+6], ES <- [ss:bp+8]
//!   26 89 45 0A     mov [es:di+0a],ax
//!   26 89 55 0C     mov [es:di+0c],dx
//!
//! If Unicorn decodes it correctly, AX/DX land at es:di+0a / es:di+0c.

use unicorn_engine::unicorn_const::{Arch, Mode, Prot};
use unicorn_engine::{RegisterX86 as R, Unicorn};

use std::sync::Mutex;
static HOOK_ADDRS: Mutex<Vec<u64>> = Mutex::new(Vec::new());

/// Reproduce the EXACT mechanism the [INSN] trace uses: a per-instruction
/// `add_code_hook` over a running `emu_start` (not single-step), in VM86. Record
/// every address Unicorn reports the hook at. If it reports 0x500,0x502,0x503…
/// (i.e. a spurious 0x502 inside the les), that's the "+2/+1" artifact seen in
/// the trace — a hook reporting quirk, NOT a real IP/decode bug.
#[test]
fn code_hook_addresses_over_les_block_vm86() {
    HOOK_ADDRS.lock().unwrap().clear();
    let mut uc = Unicorn::new(Arch::X86, Mode::MODE_32).expect("uc");
    uc.mem_map(0, 0x11_0000, Prot::ALL).expect("map");
    let code = [0xC4, 0x7E, 0x06, 0x26, 0x89, 0x45, 0x0A, 0x26, 0x89, 0x55, 0x0C, 0xF4]; // +HLT
    let code_lin = 0x0500u64;
    uc.mem_write(code_lin, &code).unwrap();
    let ss = 0x3F4Au64;
    let bp = 0x40B8u64;
    uc.mem_write((ss << 4) + bp + 6, &0x0123u16.to_le_bytes()).unwrap();
    uc.mem_write((ss << 4) + bp + 8, &0x6000u16.to_le_bytes()).unwrap();
    let cr0 = uc.reg_read(R::CR0).unwrap();
    uc.reg_write(R::CR0, cr0 | 1).unwrap();
    uc.reg_write(R::EFLAGS, 0x2_0002).unwrap();
    uc.reg_write(R::CS, 0).unwrap();
    uc.reg_write(R::SS, ss).unwrap();
    uc.reg_write(R::EBP, bp).unwrap();
    uc.reg_write(R::EIP, code_lin).unwrap();
    uc.add_code_hook(0, 0x10_0000, |_uc, addr, _sz| {
        HOOK_ADDRS.lock().unwrap().push(addr);
    })
    .expect("hook");
    // Run the whole block (stops at HLT). emu_start with a code hook installed.
    let _ = uc.emu_start(code_lin, code_lin + 11, 0, 0);
    let addrs = HOOK_ADDRS.lock().unwrap().clone();
    eprintln!("[CODEHOOK] reported addrs: {addrs:#06x?}  (expect [0x500, 0x503, 0x507])");
    assert_eq!(
        addrs,
        vec![0x500u64, 0x503, 0x507],
        "code hook reported instruction boundaries other than les(+3)/mov(+4)/mov(+4)"
    );
}

/// The decisive test: run `C4 7E 06` in the SAME configuration the interp uses —
/// a `Mode::MODE_32` instance with VM86 active (CR0.PE=1, EFLAGS.VM=1). In VM86
/// `C4` must decode as 3-byte LES; if Unicorn instead treats it as a VEX prefix
/// (its 32-bit meaning), the instruction length / IP comes out wrong.
#[test]
fn les_ip_advances_by_3_in_vm86() {
    let mut uc = Unicorn::new(Arch::X86, Mode::MODE_32).expect("uc");
    uc.mem_map(0, 0x11_0000, Prot::ALL).expect("map");
    let code = [0xC4, 0x7E, 0x06, 0x26, 0x89, 0x45, 0x0A, 0x26, 0x89, 0x55, 0x0C];
    let code_lin = 0x0500u64;
    uc.mem_write(code_lin, &code).expect("code");
    let ss = 0x3F4Au64;
    let bp = 0x40B8u64;
    let slot_lin = (ss << 4) + bp + 6;
    uc.mem_write(slot_lin, &0x0123u16.to_le_bytes()).unwrap();
    uc.mem_write(slot_lin + 2, &0x6000u16.to_le_bytes()).unwrap();

    // Enter VM86: PE=1, EFLAGS.VM=1 (bit17) + reserved bit1.
    let cr0 = uc.reg_read(R::CR0).unwrap();
    uc.reg_write(R::CR0, cr0 | 1).unwrap();
    uc.reg_write(R::EFLAGS, 0x2_0002).unwrap();
    uc.reg_write(R::CS, 0).unwrap();
    uc.reg_write(R::SS, ss).unwrap();
    uc.reg_write(R::ES, 0x1111).unwrap();
    uc.reg_write(R::EBP, bp).unwrap();
    uc.reg_write(R::EAX, 0xAAAA).unwrap();
    uc.reg_write(R::EDX, 0xDDDD).unwrap();
    uc.reg_write(R::EIP, code_lin).unwrap();

    let expect = [0x503u64, 0x507, 0x50B];
    let mut ip = code_lin;
    let mut got = Vec::new();
    for _ in 0..3 {
        match uc.emu_start(ip, code_lin + code.len() as u64, 0, 1) {
            Ok(()) => {}
            Err(e) => {
                eprintln!("VM86 step from {ip:#x} errored: {e:?}");
                break;
            }
        }
        ip = uc.reg_read(R::EIP).unwrap();
        got.push(ip);
    }
    eprintln!(
        "[VM86] EIP after each insn: got {got:02x?}  expected {expect:02x?}  (VM flag set? eflags={:#x})",
        uc.reg_read(R::EFLAGS).unwrap()
    );
    assert_eq!(got.first().copied(), Some(0x503), "les did not advance IP by 3 in VM86 (C4 treated as VEX?)");
}

#[test]
fn les_di_bp6_writes_to_correct_far_target() {
    let mut uc = Unicorn::new(Arch::X86, Mode::MODE_16).expect("uc");
    // Flat 1.1 MB of conventional RAM (covers every linear we touch).
    uc.mem_map(0, 0x11_0000, Prot::ALL).expect("map");

    let code = [0xC4, 0x7E, 0x06, 0x26, 0x89, 0x45, 0x0A, 0x26, 0x89, 0x55, 0x0C];
    let code_lin = 0x0500u64;
    uc.mem_write(code_lin, &code).expect("code");

    // Match DN's frame: SS=0x3F4A, BP=0x40B8 -> slot [bp+6] at lin 0x434BE.
    let ss = 0x3F4Au64;
    let bp = 0x40B8u64;
    let slot_lin = (ss << 4) + bp + 6; // 0x434BE
    // Far pointer in the slot: offset=0x0123, segment=0x6000 (both distinctive).
    let ptr_off = 0x0123u16;
    let ptr_seg = 0x6000u16;
    uc.mem_write(slot_lin, &ptr_off.to_le_bytes()).expect("off");
    uc.mem_write(slot_lin + 2, &ptr_seg.to_le_bytes()).expect("seg");

    uc.reg_write(R::CS, 0).unwrap();
    uc.reg_write(R::SS, ss).unwrap();
    uc.reg_write(R::DS, 0).unwrap();
    uc.reg_write(R::ES, 0x1111).unwrap(); // wrong on purpose; les must overwrite it
    uc.reg_write(R::EBP, bp).unwrap();
    uc.reg_write(R::EDI, 0x9999).unwrap(); // wrong on purpose; les must overwrite it
    uc.reg_write(R::EAX, 0xAAAA).unwrap();
    uc.reg_write(R::EDX, 0xDDDD).unwrap();
    uc.reg_write(R::EIP, code_lin).unwrap();

    // Single-step each instruction and record EIP after it retires.
    // Expected lengths: les=3 (C4 7E 06), mov=4, mov=4  -> 0x503, 0x507, 0x50B.
    let expect_eips = [0x503u64, 0x507, 0x50B];
    let mut ip = code_lin;
    let mut got_eips = Vec::new();
    for _ in 0..3 {
        uc.emu_start(ip, code_lin + code.len() as u64, 0, 1).expect("step");
        ip = uc.reg_read(R::EIP).unwrap();
        got_eips.push(ip);
    }
    eprintln!("EIP after each insn: got {got_eips:02x?}  expected {expect_eips:02x?}");
    assert_eq!(got_eips[0], expect_eips[0], "les did not advance IP by 3 (C4 mis-decoded?)");
    assert_eq!(got_eips, expect_eips, "IP advancement wrong across the 3 insns");

    // Correct decode: ES=ptr_seg, DI=ptr_off; writes at es:di+0a / +0c.
    let base = (ptr_seg as u64) << 4; // 0x60000
    let want_ax = base + ptr_off as u64 + 0x0A; // 0x6012D
    let want_dx = base + ptr_off as u64 + 0x0C; // 0x6012F
    let mut buf = [0u8; 2];
    uc.mem_read(want_ax, &mut buf).unwrap();
    let got_ax = u16::from_le_bytes(buf);
    uc.mem_read(want_dx, &mut buf).unwrap();
    let got_dx = u16::from_le_bytes(buf);

    let es = uc.reg_read(R::ES).unwrap();
    let di = uc.reg_read(R::EDI).unwrap() & 0xFFFF;
    eprintln!(
        "after run: ES={es:#06x} DI={di:#06x}; [es:di+0a={want_ax:#x}]={got_ax:#06x} [es:di+0c={want_dx:#x}]={got_dx:#06x}"
    );

    assert_eq!(es, ptr_seg as u64, "les loaded wrong ES (segment)");
    assert_eq!(di, ptr_off as u64, "les loaded wrong DI (offset)");
    assert_eq!(got_ax, 0xAAAA, "AX did not land at es:di+0a (decode/EA wrong)");
    assert_eq!(got_dx, 0xDDDD, "DX did not land at es:di+0c (decode/EA wrong)");
}
