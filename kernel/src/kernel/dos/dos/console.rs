//! DOS console input, output and keyboard continuations.

use crate::Regs;
use crate::kernel::thread;
use crate::kernel::dos::machine;
use crate::kernel::dos::machine::{pop_bios_keyboard_word, read_u16};
use super::lowmem::{CTRL_STUB_SEG, SLOT_RESUME, ctrl_slot_off};

pub(super) fn poll_dos_console_char<A: crate::Arch>(machine: &mut A, dos: &mut thread::DosState<A>, regs: &mut Regs) -> Option<u8> {
    if let Some(ch) = dos.dos_pending_char.take() {
        return Some(ch);
    }

    let word = pop_bios_keyboard_word(machine, regs)?;
    let ascii = word as u8;
    let scan = (word >> 8) as u8;
    if ascii == 0 && scan != 0 {
        dos.dos_pending_char = Some(scan);
    }
    Some(ascii)
}

/// Build a resume closure for AH=0Ah Buffered Keyboard Input:
/// accumulates typed chars in the caller's DS:DX buffer until Enter is
/// pressed (or the buffer fills, which rings the bell). Backspace erases.
/// On completion, writes count to buffer[1] and appends 0x0D at
/// buffer[count+2], echoes CR+LF. Returns `Some(next)` while still
/// gathering input; `None` once Enter is pressed.
pub(super) fn buffered_input_resume<A: crate::Arch>(_machine: &mut A, buf_lin: u32, max_chars: u8, count: u8) -> crate::kernel::dos::ResumeCallback<A> {
    crate::kernel::dos::ResumeCallback(alloc::boxed::Box::new(move |machine: &mut A,
              _kt: &mut thread::KernelThread<A>,
              dos: &mut thread::DosState<A>,
              regs: &mut Regs| -> Option<crate::kernel::dos::ResumeCallback<A>> {
            let Some(ch) = poll_dos_console_char(machine, dos, regs) else {
                return Some(buffered_input_resume(machine, buf_lin, max_chars, count));
            };
            match ch {
                0x0D => {
                    machine.write::<u8>((buf_lin + 1) as usize, count);
                    machine.write::<u8>((buf_lin + 2 + count as u32) as usize, 0x0D);
                    dos_putchar(machine, dos, 0x0D);
                    dos_putchar(machine, dos, 0x0A);
                    None
                }
                0x08 => {
                    if count > 0 {
                        dos_putchar(machine, dos, 0x08);
                        dos_putchar(machine, dos, b' ');
                        dos_putchar(machine, dos, 0x08);
                        Some(buffered_input_resume(machine, buf_lin, max_chars, count - 1))
                    } else {
                        Some(buffered_input_resume(machine, buf_lin, max_chars, count))
                    }
                }
                _ => {
                    if (count as u32) + 1 < max_chars as u32 {
                        machine.write::<u8>((buf_lin + 2 + count as u32) as usize, ch);
                        dos_putchar(machine, dos, ch);
                        Some(buffered_input_resume(machine, buf_lin, max_chars, count + 1))
                    } else {
                        dos_putchar(machine, dos, 0x07); // bell — no room
                        Some(buffered_input_resume(machine, buf_lin, max_chars, count))
                    }
                }
            }
        }))
}

/// DOS character output — writes via VGA putchar and syncs the BDA cursor
/// Build a resume closure that polls the console keyboard.
/// Returns `Some(self)` while waiting; on Some(ch), writes AL=ch (and
/// optionally echoes) then returns `None` to signal completion.
/// `echo`: whether to also `dos_putchar` the read character (AH=01h does
/// this; AH=07h/AH=08h don't).
/// Set up a guest INT 16h AH=00 (wait-for-key) call that returns to the
/// `SLOT_RESUME` stub. Mirrors what a real `INT 16h` does: push FLAGS/CS/IP
/// (the return frame, pointing back at SLOT_RESUME) and enter `IVT[0x16]`.
/// IF is forced so the guest's wait loop can receive the keypress IRQ.
pub(super) fn launch_int16_read<A: crate::Arch>(machine: &mut A, regs: &mut Regs) {
    let ivt_off = read_u16(machine, 0, 0x16 * 4);
    let ivt_seg = read_u16(machine, 0, 0x16 * 4 + 2);
    let ret_flags = machine::guest_flags_if_on(regs) as u16;
    machine::vm86_push(machine, regs, ret_flags);
    machine::vm86_push(machine, regs, CTRL_STUB_SEG);
    machine::vm86_push(machine, regs, ctrl_slot_off(SLOT_RESUME));
    machine::set_vm86_cs(regs, ivt_seg);
    machine::set_vm86_ip(regs, ivt_off);
    // AH = 00: the CONVENTIONAL read, deliberately. DOS char input reports an
    // extended key as AL=0x00 + the scancode on the next call, and programs
    // branch on exactly that (`test al,al`) — the enhanced call's AL=0xE0
    // marker would send them down the plain-ASCII path instead.
    regs.rax &= !0xFF00;
    regs.frame.rflags |= machine::VIF_FLAG as u64; // guest VIF=1 while INT 16 runs
}

/// Protected-mode counterpart to the guest INT 16h round-trip. PMDOS clients
/// cannot enter a real-mode IVT handler directly, so the continuation polls
/// the same BIOS buffer while preserving the DOS character-read ABI.
pub(super) fn dos_char_resume<A: crate::Arch>(
    _machine: &mut A,
    echo: bool,
    func: u8,
) -> crate::kernel::dos::ResumeCallback<A> {
    crate::kernel::dos::ResumeCallback(alloc::boxed::Box::new(move |machine: &mut A,
              _kt: &mut thread::KernelThread<A>,
              dos: &mut thread::DosState<A>,
              regs: &mut Regs| -> Option<crate::kernel::dos::ResumeCallback<A>> {
        let Some(ascii) = poll_dos_console_char(machine, dos, regs) else {
            return Some(dos_char_resume(machine, echo, func));
        };
        regs.rax = (regs.rax & !0xFFFF) | ((func as u64) << 8) | ascii as u64;
        if echo && ascii != 0 {
            dos_putchar(machine, dos, ascii);
        }
        None
    }))
}

/// Completion closure for an INT-16-routed DOS char read. Fires once the
/// guest's INT 16h handler IRETs back to SLOT_RESUME, with AX = the key
/// (AL=ASCII, AH=scancode). Applies DOS char-read semantics and returns
/// `None` so SLOT_RESUME enters the stored INT 21 return computation.
///
/// `func` is the INT 21h function number the guest called with. DOS leaves AH
/// alone across a char read — only AL is a result — and programs lean on it:
/// Prince of Persia 2's SETUP reads an extended key with `int 21h` / `test al,al`
/// / `int 21h`, the second call carrying no `mov ah,7` of its own. Handing back
/// the INT 16h scancode in AH turned that into function 50h (set PSP), so the
/// scancode was never delivered and its menus ignored every arrow key.
pub(super) fn int16_finish_resume<A: crate::Arch>(_machine: &mut A, echo: bool, func: u8) -> crate::kernel::dos::ResumeCallback<A> {
    crate::kernel::dos::ResumeCallback(alloc::boxed::Box::new(move |machine: &mut A,
              _kt: &mut thread::KernelThread<A>,
              dos: &mut thread::DosState<A>,
              regs: &mut Regs| -> Option<crate::kernel::dos::ResumeCallback<A>> {
            let ax = regs.rax as u16;
            let ascii = ax as u8;
            let scan = (ax >> 8) as u8;
            // Extended key: DOS returns AL=0 now, the scancode on the next read.
            if ascii == 0 && scan != 0 {
                dos.dos_pending_char = Some(scan);
            }
            regs.rax = (regs.rax & !0xFFFF) | ((func as u64) << 8) | ascii as u64;
            if echo && ascii != 0 { dos_putchar(machine, dos, ascii); }
            None
        }))
}

pub(super) fn log_dos_byte(c: u8) {
    if c < 0x80 {
        lib::log::debug_byte(c);
    } else {
        let mut utf8 = [0u8; 4];
        for &byte in lib::codepage::current_codepage().decode(c).encode_utf8(&mut utf8).as_bytes() {
            lib::log::debug_byte(byte);
        }
    }
}

pub(super) fn dos_putchar<A: crate::Arch>(machine: &mut A, dos: &mut thread::DosState<A>, c: u8) {
    // Mirror to the log stream. This is the half worth keeping: the log is
    // unowned and non-ephemeral, so a program's output survives the scroll and
    // shows up in order next to everything else, whoever holds the screen.
    log_dos_byte(c);
    // Render through DOS's own teletype — the same one INT 10h AH=0Eh uses,
    // on the BDA cursor that DOS programs read directly.
    crate::kernel::dos::bios::video::teletype(machine, dos, c, 0x07);
}
