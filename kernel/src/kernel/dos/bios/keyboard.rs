//! BIOS keyboard services: INT 09h and INT 16h.
use crate::Regs;
use crate::kernel::dos::{dos, machine, DosState};
use crate::kernel::dos::dosabi::STUB_SEG;
use machine::{read_u16, vm86_iret, vm86_push, vm86_set_return_flag};
use super::Bda;

/// Ring head/tail values as the guest stores them: segment-0x40 offsets.
pub(super) const KB_RING_FIRST: u16 = core::mem::offset_of!(Bda, kb_ring) as u16;
pub(super) const KB_RING_END: u16 = KB_RING_FIRST + (16 * 2);

// ============================================================================
// INT 16h: keyboard
// ============================================================================

#[derive(PartialEq)]
pub(super) enum Parked {
    Yes,
    No,
}

/// BDA 40:96 bit 4 — an enhanced (101/102-key) keyboard is installed. A real
/// POST sets it; software reads it to decide between the conventional
/// (AH=00/01) and enhanced (AH=10/11) INT 16h calls.
pub(super) const KB3_ENHANCED: u8 = 0x10;

/// Fold an enhanced keystroke back to what the *conventional* INT 16h calls
/// (AH=00/01) report: they predate the 101-key keyboard, so the gray keys must
/// look like the 83-key ones whose scancodes they share. AL=0xE0 becomes 0x00
/// (an extended key with no ASCII), and gray Enter / gray `/` — which carry the
/// 0xE0 in the scancode slot — get their real scancodes back. AH=10/11 report
/// the word untouched; that difference is the whole point of the enhanced calls.
fn conventional(word: u16) -> u16 {
    match ((word >> 8) as u8, word as u8) {
        (0xE0, 0x0D) => 0x1C0D, // gray Enter → the main Enter's scancode
        (0xE0, 0x2F) => 0x352F, // gray /     → the main /'s scancode
        (scan, 0xE0) if scan != 0 => word & 0xFF00, // gray cursor block: AL=0
        _ => word,
    }
}

pub(super) fn int16<A: crate::Arch>(machine: &mut A, regs: &mut Regs, stub_ip: u16) -> Parked {
    // A real INT 16h opens with `STI`, and its wait loop keeps interrupts on
    // (IBM's K16 spins `sti; nop; cli; check-buffer`) — so calling it is how a
    // program with interrupts OFF gets them back on, and the only reason the
    // very IRQ1 it is waiting for can ever arrive. We are that ROM here, so
    // raise virtual IF the same way; `vm86_iret` restores the caller's
    // own IF from its stacked FLAGS on return, exactly as the ROM's IRET does.
    //
    // Without this, a guest that CLI'd before the call parked forever: VIF
    // stayed 0, so `pick_pending_vec` delivered neither the keystroke nor the
    // timer (Xenon 2's video-mode menu hung on "press ENTER" — its keys were
    // queued in the vkbd and never surfaced as an INT 09). Native-BIOS boots
    // were unaffected because there the ROM's own `sti` did this, which is
    // what made it look like a firmware bug.
    regs.frame.rflags |= machine::VIF_FLAG as u64;

    let ah = (regs.rax >> 8) as u8;
    let head: u16 = bda_field!(machine, kb_head);
    let tail: u16 = bda_field!(machine, kb_tail);
    match ah {
        0x00 | 0x10 => {
            // Blocking read. Empty ring: park by rewinding IP onto the
            // stub's own CD 31 — the thread re-traps and re-polls every
            // slice until the host keyboard IRQ (INT 09 below) fills the
            // ring. Guest-visibly identical to the C BIOS's in-guest spin,
            // but the kernel never blocks, and a parked launch_int16_read
            // continuation (INT 21 console reads) stays parked alongside.
            if head == tail {
                machine::set_vm86_ip(regs, stub_ip.wrapping_sub(2));
                return Parked::Yes;
            }
            let key: u16 = machine.read(Bda::BASE + head as usize);
            let mut next = head + 2;
            if next >= KB_RING_END {
                next = KB_RING_FIRST;
            }
            bda_field!(machine, kb_head = next);
            let key = if ah == 0x00 { conventional(key) } else { key };
            regs.rax = (regs.rax & !0xFFFF) | key as u64;
        }
        0x01 | 0x11 => {
            // Peek: ZF in the caller's stacked FLAGS (popped on return).
            vm86_set_return_flag(machine, regs, 0x40, head == tail);
            if head != tail {
                let key: u16 = machine.read(Bda::BASE + head as usize);
                let key = if ah == 0x01 { conventional(key) } else { key };
                regs.rax = (regs.rax & !0xFFFF) | key as u64;
            }
        }
        0x02 | 0x12 => {
            let fl: u8 = bda_field!(machine, kb_flags);
            regs.rax = (regs.rax & !0xFF) | fl as u64;
        }
        _ => {}
    }
    Parked::No
}

// ============================================================================
// INT 09h: keyboard IRQ1
// ============================================================================

/// The kernel raises IRQ1 with a scancode readable at port 0x60 (the
/// virtual 8042 on interp, the real one on metal). Translate to ASCII,
/// track shift/ctrl/alt in the BDA flag byte, push (scancode:ascii) into the
/// ring for INT 16h. Extended keys (arrows, F-keys) push ascii=0.
/// Start BIOS INT 9 processing. Returns true when a guest INT 15h/AH=4Fh
/// intercept was launched and will finish through SLOT_KBD_INTERCEPT_RETURN.
pub(super) fn int09<A: crate::Arch>(machine: &mut A, dos: &mut DosState<A>, regs: &mut Regs) -> bool {
    let sc = dos.pc.vkbd.read_port60();
    let int15_off = read_u16(machine, 0, 0x15 * 4);
    let int15_seg = read_u16(machine, 0, 0x15 * 4 + 2);
    if int15_seg != STUB_SEG {
        // IBM-compatible BIOSes offer every keyboard byte to INT 15h/AH=4Fh
        // before translating it. CF enters set; the hook may replace AL and
        // returns CF set to continue normal BIOS handling, clear to consume.
        // This is an asynchronous host-Rust equivalent of a BIOS subroutine
        // call, so retain INT 9's registers until the control-slot return.
        dos.int09_registers = [
            regs.rax, regs.rbx, regs.rcx, regs.rdx, regs.rsi, regs.rdi, regs.rbp,
            regs.ds, regs.es, regs.fs, regs.gs,
        ];
        regs.rax = (regs.rax & !0xFFFF) | u64::from(0x4F00 | u16::from(sc));
        let flags = (machine::vm86_flags(regs) as u16) | 1;
        vm86_push(machine, regs, flags);
        vm86_push(machine, regs, dos::CTRL_STUB_SEG);
        vm86_push(machine, regs,
            dos::ctrl_slot_off(dos::SLOT_KBD_INTERCEPT_RETURN));
        machine::set_vm86_cs(regs, int15_seg);
        machine::set_vm86_ip(regs, int15_off);
        regs.set_flag32(1);
        return true;
    }
    finish_int09(machine, dos, sc, true);
    false
}

/// Continue INT 9 after the guest's INT 15h/AH=4Fh hook returns.
pub(in crate::kernel::dos) fn int09_intercept_return<A: crate::Arch>(
    machine: &mut A,
    dos: &mut DosState<A>,
    regs: &mut Regs,
) {
    let accepted = machine::vm86_flags(regs) & 1 != 0;
    let sc = regs.rax as u8;
    finish_int09(machine, dos, sc, accepted);
    let [rax, rbx, rcx, rdx, rsi, rdi, rbp, ds, es, fs, gs] = dos.int09_registers;
    [regs.rax, regs.rbx, regs.rcx, regs.rdx, regs.rsi, regs.rdi, regs.rbp,
     regs.ds, regs.es, regs.fs, regs.gs] =
        [rax, rbx, rcx, rdx, rsi, rdi, rbp, ds, es, fs, gs];
    // The nested INT 15 frame was consumed on entry to this slot; unwind the
    // original hardware INT 9 frame after completing BIOS processing.
    vm86_iret(machine, regs);
}

fn finish_int09<A: crate::Arch>(
    machine: &mut A,
    dos: &mut DosState<A>,
    sc: u8,
    accepted: bool,
) {
    if !accepted {
        dos.pc.vpic.master_ocw2(0x61); // Specific EOI: IRQ1
        return;
    }
    let event = dos.bios_keyboard.feed(lib::keyboard::current(),sc);
    let keyboard = &dos.bios_keyboard;
    let flags = u8::from(keyboard.down(0x36,false))
        | (u8::from(keyboard.down(0x2a,false)) << 1)
        | (u8::from(keyboard.ctrl()) << 2) | (u8::from(keyboard.alt()) << 3)
        | (u8::from(keyboard.scroll) << 4) | (u8::from(keyboard.num) << 5)
        | (u8::from(keyboard.caps) << 6);
    bda_field!(machine, kb_flags = flags);
    // Enhanced keyboard flags: retain the installed bit, expose right modifiers.
    let flags3: u8 = bda_field!(machine,kb_flags3);
    bda_field!(machine,kb_flags3 = (flags3 & !0x0c)
        | (u8::from(keyboard.down(0x1d,true)) << 2)
        | (u8::from(keyboard.down(0x38,true)) << 3));
    if !event.pressed || matches!(event.scan,0x1d | 0x2a | 0x36 | 0x38 | 0x3a | 0x45 | 0x46)
        || (event.dead && event.length == 0) {
        dos.pc.vpic.master_ocw2(0x61); // Specific EOI: IRQ1
        return;
    }
    let alt_shortcut = keyboard.alt() && !keyboard.altgr();
    for index in 0..event.length.max(1) {
        let asc = if event.length == 0 { 0 } else {
            let character = if event.text[index] == '\n' { '\r' } else { event.text[index] };
            crate::kernel::keyboard::oem_character(character)
        };
        let word = if alt_shortcut { alt_key_word(event.scan,event.extended) }
            else if event.extended { enhanced_key_word(event.scan) }
            else { (u16::from(event.scan) << 8) | u16::from(asc) };
        let tail: u16 = bda_field!(machine,kb_tail);
        let next = if tail + 2 >= KB_RING_END { KB_RING_FIRST } else { tail + 2 };
        let head: u16 = bda_field!(machine,kb_head);
        if next != head {
            machine.write::<u16>(Bda::BASE + tail as usize,word);
            bda_field!(machine,kb_tail = next);
        }
    }
    dos.pc.vpic.master_ocw2(0x61); // Specific EOI: IRQ1
}

fn enhanced_key_word(key: u8) -> u16 {
    match key {
        0x1C => 0xE00D, // gray Enter
        0x35 => 0xE02F, // gray /
        _ => ((key as u16) << 8) | 0x00E0,
    }
}

fn alt_function_key_word(key: u8) -> Option<u16> {
    match key {
        0x3B..=0x44 => Some((u16::from(0x68 + key - 0x3B)) << 8), // Alt+F1..F10
        0x57 => Some(0x8B00),                                    // Alt+F11
        0x58 => Some(0x8C00),                                    // Alt+F12
        _ => None,
    }
}

fn alt_key_word(key: u8, e0: bool) -> u16 {
    // BIOS Alt combinations carry a zero ASCII byte. Borland's menu handling
    // consequently recognizes Alt+F as 0x2100 and Alt+X as 0x2D00, not as the
    // ordinary `f`/`x` character paired with its physical scan code.
    alt_function_key_word(key).unwrap_or_else(|| {
        if e0 { enhanced_key_word(key) } else { u16::from(key) << 8 }
    })
}

#[cfg(test)]
mod keyboard_tests {
    use super::{alt_function_key_word, alt_key_word};

    #[test]
    fn bios_alt_function_scan_codes() {
        assert_eq!(alt_function_key_word(0x3B), Some(0x6800));
        assert_eq!(alt_function_key_word(0x3C), Some(0x6900));
        assert_eq!(alt_function_key_word(0x44), Some(0x7100));
        assert_eq!(alt_function_key_word(0x57), Some(0x8B00));
        assert_eq!(alt_function_key_word(0x58), Some(0x8C00));
        assert_eq!(alt_function_key_word(0x1C), None);
    }

    #[test]
    fn bios_alt_letters_have_no_ascii_byte() {
        assert_eq!(alt_key_word(0x21, false), 0x2100); // Alt+F
        assert_eq!(alt_key_word(0x2d, false), 0x2d00); // Alt+X
    }
}
