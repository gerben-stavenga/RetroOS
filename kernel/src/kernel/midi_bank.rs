//! The GM instrument bank, as ROM.
//!
//! A General MIDI device is a ROM-bank instrument — an SC-55 does not stream
//! its piano from disk — so the kernel burns the bank in ONCE at boot, where
//! long work is legal (no guest exists yet to starve). The bank is parsed
//! straight into a [`sound::midi::Bank`] and leaked: every program\'s synth
//! references the same `&\'static Bank`, fully resident from its first byte.
//! No disk in the audio path, no per-program duplication, and no race
//! between a song\'s first notes and a background load (metal disks lost
//! DOOM demo1\'s opening violins to exactly that race).
//!
//! This is a kernel asset like a driver\'s firmware blob: `startup` decides
//! the location (the shipped bank under the C: root) and calls [`load`];
//! the DOS machine\'s MPU device only ever reads [`get`].

static BANK: spin::Mutex<Option<&'static sound::midi::Bank>> = spin::Mutex::new(None);

/// Ids swept: the GM melodic range plus percussion (128 + note).
const BANK_IDS: u16 = 256;

/// Burn the ROM: read every instrument under `dir_vfs` (a VFS directory of
/// `<STEM>.PAT` files). Missing files are absent ids; an absent or empty
/// directory leaves an empty bank (GM stays silent, loudly noted here).
pub fn load(dir_vfs: &[u8]) {
    let mut bank = sound::midi::Bank::new();
    for id in 0..BANK_IDS {
        let Some(stem) = sound::midi::patch_stem(id) else { continue };
        let mut path = alloc::vec::Vec::with_capacity(dir_vfs.len() + stem.len() + 5);
        path.extend_from_slice(dir_vfs);
        path.push(b'/');
        for &b in stem.as_bytes() {
            path.push(b.to_ascii_uppercase());
        }
        path.extend_from_slice(b".PAT");
        if let Ok(bytes) = crate::kernel::exec::load_file_resolved(&path) {
            bank.load_patch(id, &bytes);
        }
    }
    let (count, pool) = bank.stats();
    if count == 0 {
        crate::println!("midi: no GM bank under the C: root — General MIDI silent");
        return;
    }
    crate::println!("midi: GM bank ROM: {} instruments, {} KB", count, pool / 1024);
    *BANK.lock() = Some(alloc::boxed::Box::leak(alloc::boxed::Box::new(bank)));
}

/// The ROM, once burned. `None` on a bankless boot. Read at synth build —
/// once per program, never in the mix path.
pub fn get() -> Option<&'static sound::midi::Bank> {
    *BANK.lock()
}
