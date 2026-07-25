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

/// Burn the ROM: enumerate `dir_vfs` (a VFS directory of `<STEM>.PAT`
/// files) and match names to patch stems CASE-INSENSITIVELY — a real disk's
/// bank may be upper- or lowercase (DOS wrote uppercase, Linux installers
/// write lowercase; guessing one case silently emptied the bank on the
/// laptop's ext4). Missing instruments are absent ids; an absent or empty
/// directory leaves an empty bank, loudly noted here.
/// Resolve one child of `base` by name, case-insensitively, to its real
/// on-disk spelling. `None` when no entry matches.
fn resolve_child(base: &[u8], want: &[u8], want_dir: bool) -> Option<alloc::vec::Vec<u8>> {
    let mut index = 0;
    while let Some(e) = crate::kernel::vfs::readdir(base, index) {
        index += 1;
        if e.is_dir == want_dir
            && crate::kernel::vfs::eq_ignore_case(&e.name[..e.name_len], want)
        {
            let mut path = alloc::vec::Vec::with_capacity(base.len() + e.name_len + 1);
            path.extend_from_slice(base);
            path.push(b'/');
            path.extend_from_slice(&e.name[..e.name_len]);
            return Some(path);
        }
    }
    None
}

/// Burn the ROM from `<c_root>/ULTRASND/MIDI`, every path component matched
/// case-insensitively against the real disk (DOS wrote uppercase, Linux
/// installers write lowercase; guessing either way empties the bank).
pub fn load_from_c_root(c_root: &[u8]) {
    let Some(ultrasnd) = resolve_child(c_root, b"ULTRASND", true) else {
        crate::println!("midi: no ULTRASND under the C: root — General MIDI silent");
        return;
    };
    let Some(midi) = resolve_child(&ultrasnd, b"MIDI", true) else {
        crate::println!("midi: no MIDI dir under {} — General MIDI silent",
            core::str::from_utf8(&ultrasnd).unwrap_or("?"));
        return;
    };
    load(&midi);
}

pub fn load(dir_vfs: &[u8]) {
    let mut bank = sound::midi::Bank::new();
    let mut index = 0;
    while let Some(e) = crate::kernel::vfs::readdir(dir_vfs, index) {
        index += 1;
        if e.is_dir || e.name_len < 5 {
            continue;
        }
        let name = &e.name[..e.name_len];
        let (stem_part, ext) = name.split_at(e.name_len - 4);
        if !crate::kernel::vfs::eq_ignore_case(ext, b".PAT") {
            continue;
        }
        for id in 0..BANK_IDS {
            let Some(stem) = sound::midi::patch_stem(id) else { continue };
            if !crate::kernel::vfs::eq_ignore_case(stem_part, stem.as_bytes()) {
                continue;
            }
            let mut path = alloc::vec::Vec::with_capacity(dir_vfs.len() + name.len() + 1);
            path.extend_from_slice(dir_vfs);
            path.push(b'/');
            path.extend_from_slice(name);
            if let Ok(bytes) = crate::kernel::exec::load_file_resolved(&path) {
                bank.load_patch(id, &bytes);
            }
        }
    }
    let (count, pool) = bank.stats();
    if count == 0 {
        crate::println!("midi: no GM bank under the C: root — General MIDI silent");
        return;
    }
    crate::println!("midi: GM bank ROM: {} instruments, {} KB", count, pool / 1024);
    // Any hole in the melodic range is an instrument some song will reach
    // for and get silence — worth one boot line to make "missing violin"
    // diagnosable from klog instead of by ear.
    let mut missing = alloc::string::String::new();
    for id in 0..128u16 {
        if sound::midi::patch_stem(id).is_some() && !bank.has_patch(id) {
            if !missing.is_empty() {
                missing.push(' ');
            }
            missing.push_str(itoa(id).as_str());
        }
    }
    if !missing.is_empty() {
        crate::println!("midi: melodic ids absent from the bank: {}", missing);
    }
    *BANK.lock() = Some(alloc::boxed::Box::leak(alloc::boxed::Box::new(bank)));
}

/// The ROM, once burned. `None` on a bankless boot. Read at synth build —
/// once per program, never in the mix path.
pub fn get() -> Option<&'static sound::midi::Bank> {
    *BANK.lock()
}

/// Tiny integer formatter (no_std, no fmt machinery in the loop).
fn itoa(mut v: u16) -> alloc::string::String {
    let mut s = alloc::string::String::new();
    if v == 0 {
        s.push('0');
        return s;
    }
    let mut digits = [0u8; 5];
    let mut n = 0;
    while v > 0 {
        digits[n] = b'0' + (v % 10) as u8;
        v /= 10;
        n += 1;
    }
    for i in (0..n).rev() {
        s.push(digits[i] as char);
    }
    s
}
