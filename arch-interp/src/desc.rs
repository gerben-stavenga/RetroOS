//! Software descriptor tables for the interpreter — just enough for the kernel
//! to resolve protected-mode segment selectors (`monitor::seg_base`/`seg_is_32`).
//!
//! The kernel hands us:
//! * the active LDT via `arch_load_ldt(base, limit)` — `base` is a host pointer
//!   to the kernel's LDT array (DPMI descriptors live there), so we read
//!   descriptors straight out of it; and
//! * per-thread TLS entries via `arch_set_tls_entry` — GDT slots with a base.
//!
//! Flat kernel/user GDT selectors (CS/DS/SS at base 0) and real-mode/VM86
//! segments don't come through here — VM86 code uses `seg << 4` directly.

use std::cell::RefCell;

/// First GDT index used for TLS (Linux `set_thread_area` convention).
const TLS_MIN: usize = 13;
const TLS_SLOTS: usize = 8;

#[derive(Clone, Copy, Default)]
struct Tls {
    base: u32,
    limit: u32,
    present: bool,
}

/// Software-interrupt redirection bitmap — which VM86 `INT n` vectors trap to
/// the kernel vs. reflect to the guest's real-mode IVT. This mirrors the metal
/// TSS redirection bitmap set by `descriptors::setup_vm86_bitmaps`: only the DOS
/// `STUB_INT` (0x31) traps; every other intercepted INT reaches the kernel by
/// reflecting to an IVT stub that itself does `int 0x31`. The policy lives in
/// this bitmap, not as a hardcoded vector in the run loop.
const INT_REDIR_INIT: [u8; 32] = {
    let mut a = [0u8; 32];
    a[0x31 / 8] = 1 << (0x31 % 8);
    a
};

struct Desc {
    // Raw parts of the kernel's LDT slice (the borrow can't live in a static;
    // the table itself outlives every read, in the kernel's DosState).
    ldt: *const u64,
    ldt_len: usize,
    tls: [Tls; TLS_SLOTS],
    int_redir: [u8; 32],
    // The SYS-frame GDT/LDT are arch's materialized copy of the ACTIVE thread's
    // descriptors (persistent guest memory). `dirty` means they need a rewrite
    // before the next guest entry; it is set on swap / descriptor edit / TLS
    // change and cleared by `ensure_tables`. `ldt_limit` caches the last
    // materialized LDTR limit so a clean entry needs no recompute.
    ldt_limit: u32,
    dirty: bool,
}

thread_local! {
    static DESC: RefCell<Desc> = const {
        RefCell::new(Desc {
            ldt: core::ptr::null(),
            ldt_len: 0,
            tls: [Tls { base: 0, limit: 0, present: false }; TLS_SLOTS],
            int_redir: INT_REDIR_INIT,
            ldt_limit: 0,
            dirty: true,
        })
    };
}

/// Whether VM86 `INT n` traps to the kernel (bit set) rather than reflecting to
/// the real-mode IVT. Mirrors `descriptors::int_intercepted`.
pub fn int_intercepted(n: u8) -> bool {
    DESC.with(|d| d.borrow().int_redir[(n / 8) as usize] & (1 << (n % 8)) != 0)
}

/// Copy the loaded LDT straight into the SYS LDT frame at `dst` (no heap), for
/// `sysdesc::materialize`. Returns the LDTR limit. Mirrors the old `write_tables`
/// cap of `LDT_MAX_BYTES/8` descriptors.
pub(crate) fn copy_ldt_into(dst: *mut u8) -> u32 {
    DESC.with(|d| {
        let d = d.borrow();
        if d.ldt.is_null() {
            return 0;
        }
        let n = d.ldt_len.min(crate::sysdesc::LDT_MAX_BYTES / 8);
        for i in 0..n {
            let desc = unsafe { core::ptr::read_unaligned(d.ldt.add(i)) };
            unsafe {
                core::ptr::copy_nonoverlapping(desc.to_le_bytes().as_ptr(), dst.add(i * 8), 8);
            }
        }
        if n == 0 { 0 } else { (n * 8 - 1) as u32 }
    })
}

/// Mark the materialized descriptor tables stale (rewrite before next entry).
/// Called on descriptor edits (`on_ldt_changed`) and thread swap (`activate`).
pub fn mark_ldt_dirty() {
    DESC.with(|d| d.borrow_mut().dirty = true);
}

/// Consume the dirty flag: true (and clear) if the tables need materializing.
pub(crate) fn take_dirty() -> bool {
    DESC.with(|d| {
        let mut d = d.borrow_mut();
        core::mem::replace(&mut d.dirty, false)
    })
}

pub(crate) fn ldt_limit() -> u32 {
    DESC.with(|d| d.borrow().ldt_limit)
}

pub(crate) fn set_ldt_limit(l: u32) {
    DESC.with(|d| d.borrow_mut().ldt_limit = l);
}

/// Visit each present TLS slot as `(gdt_index, base, limit)` so cpu.rs can place
/// the matching flat data descriptor in the software CPU's GDT.
pub fn for_each_tls(mut f: impl FnMut(usize, u32, u32)) {
    DESC.with(|d| {
        let d = d.borrow();
        for (i, t) in d.tls.iter().enumerate() {
            if t.present {
                f(TLS_MIN + i, t.base, t.limit);
            }
        }
    });
}

pub fn load_ldt(ldt: &[u64]) {
    DESC.with(|d| {
        let mut d = d.borrow_mut();
        d.ldt = ldt.as_ptr();
        d.ldt_len = ldt.len();
        d.dirty = true; // new active LDT ⇒ re-materialize before next entry
    });
}

pub fn set_tls_entry(index: i32, base: u32, limit: u32) -> i32 {
    DESC.with(|d| {
        let mut d = d.borrow_mut();
        let slot = if index >= TLS_MIN as i32 && ((index as usize) - TLS_MIN) < TLS_SLOTS {
            index as usize - TLS_MIN
        } else {
            d.tls.iter().position(|t| !t.present).unwrap_or(0)
        };
        d.tls[slot] = Tls { base, limit, present: true };
        d.dirty = true; // GDT TLS slot changed ⇒ re-materialize
        (TLS_MIN + slot) as i32
    })
}

impl Desc {
    /// Read LDT descriptor `index`, bounds-checked against the loaded length.
    #[inline]
    fn ldt_desc(&self, index: usize) -> Option<u64> {
        if self.ldt.is_null() || index >= self.ldt_len {
            return None;
        }
        Some(unsafe { core::ptr::read_unaligned(self.ldt.add(index)) })
    }
}

/// Linear base of selector `sel`.
pub fn seg_base(sel: u16) -> u32 {
    let index = (sel >> 3) as usize;
    let is_ldt = (sel >> 2) & 1 == 1;
    DESC.with(|d| {
        let d = d.borrow();
        if is_ldt {
            match d.ldt_desc(index) {
                Some(desc) => {
                    let b0 = ((desc >> 16) & 0xFFFF) as u32;
                    let b1 = ((desc >> 32) & 0xFF) as u32;
                    let b2 = ((desc >> 56) & 0xFF) as u32;
                    b0 | (b1 << 16) | (b2 << 24)
                }
                None => 0,
            }
        } else if index >= TLS_MIN && index - TLS_MIN < TLS_SLOTS && d.tls[index - TLS_MIN].present {
            d.tls[index - TLS_MIN].base
        } else {
            0 // flat kernel/user GDT segment
        }
    })
}

/// Whether selector `sel` is a 32-bit (D/B = 1) segment.
pub fn seg_is_32(sel: u16) -> bool {
    if sel == 0 {
        return true;
    }
    let index = (sel >> 3) as usize;
    let is_ldt = (sel >> 2) & 1 == 1;
    DESC.with(|d| {
        let d = d.borrow();
        match (is_ldt, d.ldt_desc(index)) {
            (true, Some(desc)) => desc & (1u64 << 54) != 0,
            _ => true, // flat/TLS GDT segments are 32-bit
        }
    })
}
