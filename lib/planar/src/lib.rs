//! Allocation-free planar VGA device, shared by the kernel and supervisor.
#![no_std]
#[cfg(test)] extern crate alloc;
pub mod instruction;
use core::sync::atomic::{AtomicU8, AtomicU16, AtomicU32, Ordering};
#[repr(transparent)]
#[derive(Debug)]
pub struct Word(AtomicU16);
impl Word {
    pub fn new(value: u16) -> Self { Self(AtomicU16::new(value)) }
    pub fn get(&self) -> u16 { self.0.load(Ordering::Relaxed) }
    pub fn set(&self, value: u16) { self.0.store(value, Ordering::Relaxed); }
}
#[repr(transparent)]
#[derive(Debug)]
pub struct Dword(AtomicU32);
impl Dword {
    pub const fn new(value: u32) -> Self { Self(AtomicU32::new(value)) }
    pub fn get(&self) -> u32 { self.0.load(Ordering::Relaxed) }
    pub fn set(&self, value: u32) { self.0.store(value, Ordering::Relaxed); }
}

#[repr(transparent)]
#[derive(Debug)]
pub struct Byte(AtomicU8);
impl Byte {
    pub fn new(value: u8) -> Self { Self(AtomicU8::new(value)) }
    #[inline] pub fn get(&self) -> u8 { self.0.load(Ordering::Relaxed) }
    #[inline] pub fn set(&self, value: u8) { self.0.store(value, Ordering::Relaxed); }
}
#[repr(transparent)]
#[derive(Debug)]
pub struct Bytes<const N: usize>([AtomicU8; N]);
impl<const N: usize> Bytes<N> {
    pub fn new(values: [u8; N]) -> Self { Self(values.map(AtomicU8::new)) }
    #[inline] pub fn get(&self, index: usize) -> u8 { self.0[index].load(Ordering::Relaxed) }
    #[inline] pub fn set(&self, index: usize, value: u8) { self.0[index].store(value, Ordering::Relaxed); }
    pub fn read(&self) -> [u8; N] { core::array::from_fn(|i| self.get(i)) }
    pub fn write(&self, values: [u8; N]) { self.write_range(0, &values); }
    pub fn write_range(&self, start: usize, values: &[u8]) {
        assert!(start <= N && values.len() <= N - start);
        for (i, value) in values.iter().enumerate() { self.set(start + i, *value); }
    }
}

#[repr(C, align(4096))]
pub struct Registers {
    /// Legacy VGA decoding is disabled while the device presents VBE memory.
    pub enabled: Byte,
    pub profile_enabled: Byte,
    pub profile: Profile,
    pub seq_index: Byte,
    pub gc_index: Byte,
    pub latches: Bytes<4>,
    pub latches_valid: Byte,
    pub misc_output: Byte,
    pub feature_ctl: Byte,
    pub cga_mode_ctl: Byte,
    pub cga_color_select: Byte,
    pub seq: Bytes<5>,
    pub crtc: Bytes<25>,
    pub gc: Bytes<9>,
    pub ac: Bytes<21>,
    pub dac: Bytes<768>,
    pub dac_mask: Byte,
    #[doc(hidden)]
    pub trap_mode_bits: Dword,
}
#[inline]
fn vga_alu(func: u8, val: u8, latch: u8) -> u8 {
    match func & 3 {
        0 => val,
        1 => val & latch,
        2 => val | latch,
        _ => val ^ latch,
    }
}

/// Apply one CPU store of `cpu` at a plane offset whose current plane bytes are
/// `cur` and whose VGA latches (loaded by the most recent read) are `latches`.
/// Returns the new 4 plane bytes. Planes not selected by the map mask are
/// returned unchanged. Implements write modes 0/1/2/3 incl. set/reset, ALU
/// function, and the bit mask. Write mode 1 is the latched copy (the `cpu`
/// value is ignored — the latches are written straight through), which is how
/// Mode X plane-parallel blits move 4 pixels per store.
pub fn planar_write(cur: [u8; 4], latches: [u8; 4], gc: &[u8; 9], map_mask: u8, cpu: u8) -> [u8; 4] {
    let write_mode = gc[5] & 3;
    let rotate = (gc[3] & 7) as u32;
    let func = (gc[3] >> 3) & 3;
    let bit_mask = gc[8];
    let esr = gc[1] & 0x0F;
    let sr = gc[0] & 0x0F;
    let rotated = cpu.rotate_right(rotate);

    let mut out = cur;
    for p in 0..4 {
        if map_mask & (1 << p) == 0 {
            continue;
        }
        let latch = latches[p];
        out[p] = match write_mode {
            // Write mode 0: per-plane set/reset or rotated CPU data, through the
            // ALU against the latch, then merged with the latch by the bit mask.
            0 => {
                let val = if esr & (1 << p) != 0 {
                    if sr & (1 << p) != 0 { 0xFF } else { 0x00 }
                } else {
                    rotated
                };
                let v = vga_alu(func, val, latch);
                (v & bit_mask) | (latch & !bit_mask)
            }
            // Write mode 1: latched copy — write the latch directly (CPU ignored).
            1 => latch,
            // Write mode 2: each CPU bit selects the whole plane (0x00/0xFF),
            // through the ALU and bit mask. Used for fast solid-colour fills.
            2 => {
                let val = if cpu & (1 << p) != 0 { 0xFF } else { 0x00 };
                let v = vga_alu(func, val, latch);
                (v & bit_mask) | (latch & !bit_mask)
            }
            // Write mode 3: rotated CPU data AND bit-mask forms the effective
            // mask; the colour comes from set/reset (always, no enable gate).
            _ => {
                let eff_mask = rotated & bit_mask;
                let val = if sr & (1 << p) != 0 { 0xFF } else { 0x00 };
                let v = vga_alu(func, val, latch);
                (v & eff_mask) | (latch & !eff_mask)
            }
        };
    }
    out
}

/// Read one offset: always loads all 4 plane bytes into the latches (returned
/// as the second tuple element) and returns the byte the CPU sees. Read mode 0
/// returns the plane chosen by Read Map Select; read mode 1 returns the
/// color-compare result (1 bits where all don't-care planes match Color Compare).
pub fn planar_read(cur: [u8; 4], gc: &[u8; 9]) -> (u8, [u8; 4]) {
    let data = if (gc[5] >> 3) & 1 == 0 {
        cur[(gc[4] & 3) as usize]
    } else {
        let cc = gc[2] & 0x0F;
        let dc = gc[7] & 0x0F;
        let mut r = 0xFFu8;
        for (p, &plane) in cur.iter().enumerate() {
            if dc & (1 << p) != 0 {
                r &= if cc & (1 << p) != 0 { plane } else { !plane };
            }
        }
        r
    };
    (data, cur)
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VramLayout {
    /// Four adjacent bytes are the four maps at one offset:
    /// `index = 4 * offset + plane`. Chain-4's standard 64K window is the
    /// first 64K of this ordering.
    PlaneMinor,
    /// Two complete 128K plane sets. Set 0 interleaves maps 0/1 and set 1
    /// interleaves maps 2/3:
    /// `index = (plane >> 1) * 128K + 2 * offset + (plane & 1)`.
    OddEven,
}

impl VramLayout {
    #[inline]
    pub const fn index(self, plane: usize, offset: usize) -> usize {
        match self {
            Self::PlaneMinor => 4 * offset + plane,
            Self::OddEven => (plane >> 1) * 0x20000 + 2 * offset + (plane & 1),
        }
    }
}

#[derive(Clone, Copy)]
pub struct Memory<'a> { bytes: &'a [AtomicU8] }
impl<'a> Memory<'a> {
    /// # Safety
    /// The range remains mapped for 'a. Concurrent kernel accesses must be
    /// atomic byte accesses; no mutable Rust slice may alias this storage.
    pub unsafe fn mapped(base: *mut u8, len: usize) -> Self {
        Self { bytes: unsafe { core::slice::from_raw_parts(base.cast(), len) } }
    }
    pub fn from_bytes(bytes: &'a [AtomicU8]) -> Self { Self { bytes } }
    pub fn len(self) -> usize { self.bytes.len() }
    pub fn is_empty(self) -> bool { self.bytes.is_empty() }
    #[inline] pub fn get(self, index: usize) -> Option<u8> {
        self.bytes.get(index).map(|v| v.load(Ordering::Relaxed))
    }
    #[inline] pub fn put(self, index: usize, value: u8) {
        self.bytes[index].store(value, Ordering::Relaxed);
    }
    pub fn range(self, start: usize, len: usize) -> Self {
        Self { bytes: &self.bytes[start..start + len] }
    }
    pub fn copy_from(self, source: &[u8]) {
        assert_eq!(source.len(), self.len());
        for (i, value) in source.iter().enumerate() { self.put(i, *value); }
    }
    pub fn fill(self, value: u8) {
        for byte in self.bytes { byte.store(value, Ordering::Relaxed); }
    }
}

impl Registers {
    /// Complete physical ordering implied by the sequencer memory-mode
    /// register. Chain-4 and sequential access use plane-minor storage;
    /// odd/even access interleaves the selected plane pair into its 128K set.
    pub fn layout(&self) -> VramLayout {
        if self.seq.get(4) & 0x08 != 0 || self.seq.get(4) & 0x04 != 0 {
            VramLayout::PlaneMinor
        } else {
            VramLayout::OddEven
        }
    }

    /// Shared CPU address translation for reads and writes. Plane selection
    /// is separate: it must never change the byte offset within a plane.
    /// Chain-4 consumes A1:A0 to select the plane. Otherwise,
    /// GC6 controls address pairing independently of the read/write plane
    /// selectors. Normalize paired word-mode addresses to our compact text
    /// backing on both paths, even when only one side selects odd/even planes.
    /// Byte-mode scanout (Jazz's scrolling playfield) uses the full offset.
    fn cpu_offset(&self, address: usize) -> usize {
        if self.seq.get(4) & 0x08 != 0 {
            return (address >> 2) & 0xFFFF;
        }
        let paired = self.gc.get(6) & 0x02 != 0;
        let address = if paired { address & !1 } else { address };
        let address = if paired && self.crtc.get(0x17) & 0x40 == 0 { address >> 1 } else { address };
        address & 0xFFFF
    }

    /// Resolve one CPU read in the decoded VGA aperture to the logical plane
    /// byte selected by the sequencer/graphics-controller addressing mode.
    /// The returned offset is always an offset *within a plane*; callers then
    /// use `layout()` to locate that byte in the physical backing.
    pub fn cpu_read_address(&self, address: usize) -> (usize, usize) {
        let offset = self.cpu_offset(address);
        if self.seq.get(4) & 0x08 != 0 {
            return (offset, address & 3);
        }
        if self.gc.get(5) & 0x10 != 0 {
            return (offset, usize::from(self.gc.get(4) & 2) | (address & 1));
        }
        (offset, usize::from(self.gc.get(4) & 3))
    }

    /// Resolve one CPU write to its logical per-plane offset and effective map
    /// mask. Chain-4 selects one map with A1:A0; odd/even selects one map from
    /// each pair with A0; sequential addressing leaves the sequencer map mask
    /// untouched.
    pub fn cpu_write_address(&self, address: usize) -> (usize, u8) {
        let offset = self.cpu_offset(address);
        let map_mask = self.seq.get(2) & 0x0F;
        if self.seq.get(4) & 0x08 != 0 {
            let plane = address & 3;
            return (offset, map_mask & (1 << plane));
        }
        if self.seq.get(4) & 0x04 == 0 {
            let parity_mask = if address & 1 == 0 { 0x05 } else { 0x0A };
            return (offset, map_mask & parity_mask);
        }
        (offset, map_mask)
    }

    pub fn simple_alu(&self) -> bool {
        self.gc.get(5) & 0x0B == 0
            && self.gc.get(3) & 0x1F == 0
            && self.gc.get(1) & 0x0F == 0
            && self.gc.get(8) == 0xFF
    }

    /// Decode the sequential write operation. Valid until VGA registers change.
    pub fn sequential_write(&self) -> Option<SequentialWrite> {
        (self.seq.get(4) & 0x0c == 4 && self.gc.get(6) & 2 == 0 && self.simple_alu())
            .then(|| SequentialWrite { mask: self.seq.get(2) & 15 })
    }

    /// Consecutive CPU writes with fixed, sequential planar addressing.
    /// Declining performs no accesses.
    pub fn write_sequential_span(&self, memory: Memory<'_>, address: usize,
        len: usize, read: impl FnMut(usize) -> u8) -> bool {
        let Some(write) = self.sequential_write() else { return false };
        if memory.len() < 4 * 65536 { return false; }
        write.write(memory, address, len, read);
        true
    }


    pub fn read(&self, memory: Memory<'_>, address: usize) -> u8 {
        let (offset, plane) = self.cpu_read_address(address);
        let layout = self.layout();
        let cur = core::array::from_fn(|p| memory.get(layout.index(p, offset)).unwrap());
        let mut gc = self.gc.read();
        gc[4] = plane as u8;
        let (data, latches) = planar_read(cur, &gc);
        self.latches.write(latches);
        self.latches_valid.set(1);
        data
    }
    pub fn write(&self, memory: Memory<'_>, address: usize, byte: u8) {
        let (offset, mask) = self.cpu_write_address(address);
        let layout = self.layout();
        if self.simple_alu() {
            for p in 0..4 { if mask & (1 << p) != 0 { memory.put(layout.index(p, offset), byte); } }
        } else {
            let cur = core::array::from_fn(|p| memory.get(layout.index(p, offset)).unwrap());
            let out = planar_write(cur, self.latches.read(), &self.gc.read(), mask, byte);
            for p in 0..4 { if out[p] != cur[p] { memory.put(layout.index(p, offset), out[p]); } }
        }
    }
    /// Register selection and sequential map-mask writes cannot remap VRAM.
    pub fn mask_out(&self, port: u16, value: u16, word: bool) -> bool {
        match (port, word) {
            (0x3c4, false) => self.seq_index.set(value as u8),
            (0x3c4, true) if value & 31 == 2 && self.seq.get(4) & 12 == 4 => {
                self.seq_index.set(value as u8); self.seq.set(2, (value >> 8) as u8);
            }
            (0x3c5, false) if self.seq_index.get() & 31 == 2 && self.seq.get(4) & 12 == 4 => self.seq.set(2, value as u8),
            _ => return false,
        }
        true
    }
}
const _: () = assert!(core::mem::size_of::<Registers>() == 4096);

/// Decoded simple planar write, reusable between register changes. It never
/// reads latches or destination bytes; all writes use the canonical VGA layout.
#[derive(Clone, Copy)]
pub struct SequentialWrite { mask: u8 }
impl SequentialWrite {
    pub fn set_mask(&mut self, mask: u8) { self.mask = mask & 15; }

    #[inline]
    pub fn write(self, memory: Memory<'_>, address: usize, len: usize,
        mut read: impl FnMut(usize) -> u8) {
        assert!(memory.len() >= 4 * 65536);
        for i in 0..len {
            let value = read(i);
            let offset = (address.wrapping_add(i) & 65535) * 4;
            // Fixed planes let the compiler use direct stores, without a
            // population count, inner loop, or repeated device-register reads.
            if self.mask & 1 != 0 { memory.put(offset, value); }
            if self.mask & 2 != 0 { memory.put(offset + 1, value); }
            if self.mask & 4 != 0 { memory.put(offset + 2, value); }
            if self.mask & 8 != 0 { memory.put(offset + 3, value); }
        }
    }
}

/// A CPU loan of resident device storage. The owner must detach before moving,
/// freeing, or changing its mapping. Registers and VRAM are page aligned;
/// VRAM contains 256 KiB of atomic bytes. Only scanout may access concurrently.
#[derive(Clone, Copy)]
pub struct Binding {
    pub registers: *const Registers,
    pub planes: *mut u8,
}
#[derive(Clone, Copy, Default)]
pub struct Report {
    pub cycles: u64,
    pub details: [[u32; 4]; 7],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ApertureRange {
    pub start_page: u16,
    pub end_page: u16,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CpuAperture {
    None,
    Direct { range: ApertureRange, pages: u16 },
    Trapped { range: ApertureRange },
}


impl Registers {
    fn decoded_aperture(&self) -> ApertureRange {
        let (start_page, end_page) = match (self.gc.get(6) >> 2) & 3 {
            0 => (0xA0, 0xC0),
            1 => (0xA0, 0xB0),
            2 => (0xB0, 0xB8),
            _ => (0xB8, 0xC0),
        };
        ApertureRange { start_page, end_page }
    }

    fn direct_layout(&self) -> Option<VramLayout> {
        if !self.simple_alu() {
            return None;
        }
        // Chain-4 overrides both odd/even controls. A standard VGA exposes
        // only one 64K chained page even when GC6 decodes 128K.
        if self.seq.get(4) & 0x08 != 0 {
            return (self.seq.get(2) & 0x0F == 0x0F).then_some(self.layout());
        }
        // A direct odd/even alias is valid only for the conventional matched
        // read/write setup, compact word-mode offsets and plane set 0. Other
        // legal combinations remain trapped and use layout-aware indexing.
        let write_oe = self.seq.get(4) & 0x04 == 0;
        let read_oe = self.gc.get(5) & 0x10 != 0;
        if write_oe && read_oe
            && self.crtc.get(0x17) & 0x40 == 0
            && self.gc.get(6) & 0x02 != 0
            && self.seq.get(2) & 0x0F == 0x03
            && self.gc.get(4) & 0x02 == 0
        {
            return Some(self.layout());
        }
        None
    }

    pub fn cpu_aperture(&self) -> CpuAperture {
        if self.enabled.get() == 0 { return CpuAperture::None; }
        let range = self.decoded_aperture();
        match self.direct_layout() {
            Some(VramLayout::PlaneMinor) => CpuAperture::Direct {
                range,
                pages: 16.min(range.end_page - range.start_page),
            },
            Some(VramLayout::OddEven) => CpuAperture::Direct {
                range,
                pages: (range.end_page - range.start_page).min(32),
            },
            None => CpuAperture::Trapped { range },
        }
    }

    /// Publish the prepared aperture and write mode after programming VGA
    /// registers or installing their mappings. Mask-only hook writes leave
    /// the mode intact and the handler reads the current mask from SEQ[2].
    pub fn refresh_trap_mode(&self) {
        let aperture = if self.direct_layout().is_none() {
            let range = self.decoded_aperture();
            u32::from(range.start_page) | (u32::from(range.end_page) << 8)
        } else {
            0
        };
        let sequential = u32::from(self.sequential_write().is_some()) << 16;
        self.trap_mode_bits.set((1 << 31) | sequential | aperture);
    }

    fn trap_mode(&self) -> Option<(core::ops::Range<u32>, Option<SequentialWrite>)> {
        if self.enabled.get() == 0 { return None; }
        let bits = self.trap_mode_bits.get();
        if bits == 0 {
            let CpuAperture::Trapped { range } = self.cpu_aperture() else { return None };
            return Some(((u32::from(range.start_page) << 12)..(u32::from(range.end_page) << 12),
                self.sequential_write()));
        }
        let start = (bits & 255) << 12;
        let end = ((bits >> 8) & 255) << 12;
        if start == end { return None; }
        let write = (bits & (1 << 16) != 0).then(|| SequentialWrite { mask: self.seq.get(2) & 15 });
        Some((start..end, write))
    }

    /// Reset the same device allocation during a BIOS mode change.
    pub fn copy_from(&self, source: &Self) {
        macro_rules! byte { ($($field:ident),*) => { $(self.$field.set(source.$field.get());)* }; }
        macro_rules! bytes { ($($field:ident),*) => { $(self.$field.write(source.$field.read());)* }; }
        byte!(enabled, seq_index, gc_index, latches_valid, misc_output, feature_ctl,
            cga_mode_ctl, cga_color_select, dac_mask);
        bytes!(latches, seq, crtc, gc, ac, dac);
        self.refresh_trap_mode();
    }
}
/// Written by the executing CPU and read and cleared by its kernel owner.
/// Fixed-width atomics keep the same layout in the 32-bit VM and 64-bit host.
#[repr(C)]
pub struct Profile([Dword; 30]);
impl Profile {
    pub const fn new() -> Self { Self([const { Dword::new(0) }; 30]) }
    pub(crate) fn record(&self, kind: usize, cycles: u64) {
        fn add(words: &[Dword], value: u64) {
            let sum = (u64::from(words[0].get()) | u64::from(words[1].get()) << 32)
                .wrapping_add(value);
            words[0].set(sum as u32);
            words[1].set((sum >> 32) as u32);
        }
        add(&self.0[..2], cycles);
        let base = 2 + kind * 4;
        add(&self.0[base..base + 2], 1);
        add(&self.0[base + 2..base + 4], cycles);
    }
    pub fn take(&self) -> Report {
        let mut report = Report { cycles: u64::from(self.0[0].get()) | (u64::from(self.0[1].get()) << 32), ..Report::default() };
        for (value, cell) in report.details.iter_mut().flatten().zip(&self.0[2..]) { *value = cell.get(); }
        for cell in &self.0 { cell.set(0); }
        report
    }
}

pub const TRAP_NAME: &str = "vga-planar";

/// Lend the active VGA to the execution context until it is suspended.
/// # Safety
/// Both regions must remain resident and valid until detached.
pub unsafe fn bind(arch: &mut impl arch_abi::X86, binding: Option<Binding>) {
    use arch_abi::entry::{HookRegion, TrapHook};
    let hook = binding.map(|binding| {
        unsafe { (&*binding.registers).refresh_trap_mode(); }
        TrapHook {
            name: TRAP_NAME,
            handler: instruction::trap_handler,
            regions: [
                HookRegion { base: binding.registers.cast_mut().cast(), bytes: 4096 },
                HookRegion { base: binding.planes, bytes: 4 * 65536 },
            ],
        }
    });
    unsafe { arch.install_trap_hook(hook); }
}
