#![no_std]

pub mod elf;
pub mod heap;
pub mod md5;
pub mod tar;
pub mod pipe;
pub mod log;
pub mod term;
pub mod vga_fonts;
pub mod unicode_font;
pub mod cp437;
pub mod codepage;
pub mod locale;
pub mod keyboard;
mod ansi_tables;
mod codepage_tables;
pub mod unicode_lookalike;

pub mod worker_queue;

/// Transform an owned value in place on abort-on-panic targets.
#[cfg(panic = "abort")]
pub fn replace_with<T, R>(slot: &mut T, transform: impl FnOnce(T) -> (T, R)) -> R {
    // The exclusive borrow prevents observation during the move. If the
    // transform panics, this target aborts before anyone can read the slot.
    unsafe {
        let (value, result) = transform(core::ptr::read(slot));
        core::ptr::write(slot, value);
        result
    }
}
