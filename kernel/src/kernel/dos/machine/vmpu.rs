//! The machine's MPU-401 / General MIDI device.
//!
//! Two library cards behind one port pair: [`sound::mpu401::Mpu401`] is the
//! wire (UART mode at `P<port>`, 0x330 by convention) and
//! [`sound::midi::Synth`] is the sound generator. Everything here is the part
//! neither of them may have — presence, the port base from `BLASTER=`, and
//! above all **the filesystem**.
//!
//! Instruments are the interesting bit. A General MIDI device needs a bank,
//! and unlike the AWE32 (whose GM set lives in Creative's ROM) or the MT-32
//! (Roland's), ours is already on the disk: the Gravis `.PAT` set at
//! `C:\ULTRASND\MIDI` that the emulated GUS uses. So "Roland" costs no asset
//! we are not allowed to ship. The synth cannot read it — a card in
//! `//lib:sound` has no business knowing what a file is — so it *asks*: it
//! names a patch id, this file resolves it to `<ULTRADIR>\MIDI\<stem>.PAT`,
//! reads it, and hands the bytes back.
//!
//! Loading is spread across ticks on purpose. A program change can touch an
//! instrument that is not resident, and a `.PAT` read is a real filesystem
//! round trip; doing a whole bank inside one audio quantum would stall the
//! pump. A note whose instrument has not arrived yet is simply silent for a
//! tick or two — which is exactly what a real GUS does while ULTRAMID is
//! still uploading.

use super::*;
use crate::kernel::dos::dfs::{DFS_PATH_MAX, DfsState};

/// Bytes of instrument file read per audio quantum. A bank load is megabytes;
/// whole-file reads stalled the event loop for a real disk's latency per
/// instrument (music started seconds late; the stall also bunched PIT ticks
/// under DOS/4GW). One bounded chunk of one file per tick keeps every tick
/// short while the bank streams in over a few hundred ticks.
const LOAD_CHUNK: usize = 16 * 1024;

/// The GM device models a ROM-bank instrument (an SC-55 does not stream its
/// piano from disk), so the whole bank preloads from the first tick the
/// synth exists — by the first note of any song the instruments are already
/// resident. Ids above the GM melodic+percussion range have no stem and are
/// skipped instantly.
const PRELOAD_IDS: u16 = 256;

/// One instrument file mid-read: the chunked loader's only in-flight state.
struct PatchLoad {
    id: u16,
    handle: i32,
    size: usize,
    buf: alloc::vec::Vec<u8>,
    start_ms: u64,
    /// Explicitly demanded by the synth (vs background bank preload):
    /// failures are worth a log line.
    demanded: bool,
}

/// Where the bank lives when the guest declares no `ULTRADIR`. We ship the
/// set at this path, so this is not a guess that could mask a bad read.
const DEFAULT_ULTRADIR: &[u8] = b"C:\\ULTRASND";

pub struct Mpu {
    /// `BLASTER=... P<port>` declared an MPU-401. Absent hardware stays
    /// absent: `owns` gates on this, so probes read floating.
    pub present: bool,
    pub base: u16,
    card: sound::mpu401::Mpu401,
    /// Built on first use — the synth carries a sample pool and 32 voices,
    /// and a program that never opens the port pays nothing.
    synth: Option<alloc::boxed::Box<sound::midi::Synth>>,
    /// `ULTRADIR` from the guest's environment (the bank's parent directory).
    dir: [u8; 64],
    dir_len: usize,
    /// Patch ids we tried and could not read, so a missing instrument costs
    /// one failed open rather than one per note.
    denied: [u64; 4],
    /// Patch ids already installed in the synth (the loader's own record, so
    /// the preload sweep skips what a demand load already brought in).
    loaded: [u64; 4],
    /// The chunked loader's in-flight file, if any.
    loading: Option<PatchLoad>,
    /// Next id the background bank preload will fetch; `PRELOAD_IDS` = done.
    preload: u16,
}

impl Mpu {
    pub fn new() -> Self {
        let mut m = Mpu {
            present: false,
            base: 0x330,
            card: sound::mpu401::Mpu401::new(0x330),
            synth: None,
            dir: [0; 64],
            dir_len: 0,
            denied: [0; 4],
            loaded: [0; 4],
            loading: None,
            preload: PRELOAD_IDS,
        };
        m.set_dir(DEFAULT_ULTRADIR);
        m
    }

    fn set_dir(&mut self, d: &[u8]) {
        let n = d.len().min(self.dir.len());
        self.dir[..n].copy_from_slice(&d[..n]);
        self.dir_len = n;
    }

    /// Ports this device decodes, once the machine says it exists.
    pub fn owns(&self, p: u16) -> bool {
        self.present && self.card.owns(p)
    }

    /// Apply the guest's environment: the MPU port comes from `BLASTER`'s
    /// `P<port>` token (our CONFIG.SYS ships `P330`), the bank location from
    /// `ULTRADIR` — the same variable the GUS patches use, because it is the
    /// same bank.
    pub fn configure_from_env(&mut self, env: &[u8]) {
        if let Some(val) = env_var(env, b"ULTRADIR") {
            self.set_dir(val);
        }
        let Some(blaster) = env_var(env, b"BLASTER") else { return };
        for tok in blaster.split(|&b| b == b' ').filter(|t| !t.is_empty()) {
            if tok[0].eq_ignore_ascii_case(&b'P')
                && let Some(n) = parse_uint(&tok[1..], 16)
            {
                self.base = n as u16;
                self.card.set_base(self.base);
                self.present = true;
            }
        }
        if self.present {
            crate::dbg_println!(
                "[mpu] MPU-401 at {:03X}, patches in {}\\MIDI",
                self.base,
                core::str::from_utf8(&self.dir[..self.dir_len]).unwrap_or("?")
            );
        }
    }

    /// Program-exit cleanup: drop the synth and its whole sample pool so the
    /// next program starts from a power-on device.
    pub fn reset(&mut self) {
        self.card.reset();
        self.synth = None;
        self.denied = [0; 4];
        self.loaded = [0; 4];
        if let Some(ld) = self.loading.take() {
            crate::kernel::vfs::close_vfs_handle(ld.handle);
        }
        self.preload = PRELOAD_IDS;
        self.present = false;
    }

    pub fn io_read(&mut self, p: u16) -> u8 {
        self.card.port_in(p)
    }

    pub fn io_write(&mut self, p: u16, val: u8) {
        self.card.port_out(p, val);
    }

    fn deny(&mut self, id: u16) {
        let i = (id as usize) >> 6;
        if i < self.denied.len() {
            self.denied[i] |= 1 << (id & 63);
        }
    }

    fn denied(&self, id: u16) -> bool {
        let i = (id as usize) >> 6;
        i < self.denied.len() && self.denied[i] & (1 << (id & 63)) != 0
    }

    fn mark_loaded(&mut self, id: u16) {
        let i = (id as usize) >> 6;
        if i < self.loaded.len() {
            self.loaded[i] |= 1 << (id & 63);
        }
    }

    fn is_loaded(&self, id: u16) -> bool {
        let i = (id as usize) >> 6;
        i < self.loaded.len() && self.loaded[i] & (1 << (id & 63)) != 0
    }

    /// Open one instrument's `.PAT` for the chunked loader. `None` when the
    /// id has no stem or the file is missing/empty — the caller denies it.
    fn open_patch(&mut self, id: u16) -> Option<(i32, usize)> {
        let stem = sound::midi::patch_stem(id)?;
        // "<ULTRADIR>\MIDI\<STEM>.PAT", uppercase — DOS canonical case.
        let mut dos = [0u8; DFS_PATH_MAX];
        let mut n = 0usize;
        let put = |s: &[u8], dos: &mut [u8; DFS_PATH_MAX], n: &mut usize| {
            for &b in s {
                if *n < dos.len() {
                    dos[*n] = b.to_ascii_uppercase();
                    *n += 1;
                }
            }
        };
        put(&self.dir[..self.dir_len], &mut dos, &mut n);
        put(b"\\MIDI\\", &mut dos, &mut n);
        put(stem.as_bytes(), &mut dos, &mut n);
        put(b".PAT", &mut dos, &mut n);

        let mut vfs_buf = [0u8; DFS_PATH_MAX];
        let vlen = DfsState::to_vfs_open(&dos[..n], &mut vfs_buf).ok()?;
        let handle = crate::kernel::vfs::open_to_handle(&vfs_buf[..vlen]);
        if handle < 0 {
            return None;
        }
        let size = crate::kernel::vfs::file_size_by_handle(handle) as usize;
        if size == 0 {
            crate::kernel::vfs::close_vfs_handle(handle);
            return None;
        }
        Some((handle, size))
    }

    /// Advance the in-flight instrument read, or start the next one — the
    /// synth's explicit requests first, then the background bank preload.
    /// At most one bounded chunk of one file per tick: the bank streams in
    /// without the event loop ever stalling for a whole file read.
    fn service_loads<A: crate::Arch>(&mut self, machine: &mut A) {
        if let Some(mut ld) = self.loading.take() {
            let off = ld.buf.len();
            let want = (ld.size - off).min(LOAD_CHUNK);
            ld.buf.resize(off + want, 0);
            let got = crate::kernel::vfs::read_by_handle(ld.handle, &mut ld.buf[off..off + want]);
            if got != want as i32 {
                crate::kernel::vfs::close_vfs_handle(ld.handle);
                self.deny(ld.id);
                crate::dbg_println!("[mpu] patch {}: short read", ld.id);
                return;
            }
            if ld.buf.len() < ld.size {
                self.loading = Some(ld);
                return; // next chunk next tick
            }
            crate::kernel::vfs::close_vfs_handle(ld.handle);
            let Some(synth) = self.synth.as_mut() else { return };
            if synth.load_patch(ld.id, &ld.buf) {
                self.mark_loaded(ld.id);
                if ld.demanded {
                    crate::dbg_println!(
                        "[mpu] patch {} loaded in {} ms ({} KB)",
                        ld.id,
                        machine.get_ticks().saturating_sub(ld.start_ms),
                        ld.size / 1024,
                    );
                }
            } else {
                self.deny(ld.id);
                if ld.demanded {
                    crate::dbg_println!("[mpu] no patch for id {}", ld.id);
                }
            }
            return;
        }
        // Nothing in flight: demanded instruments jump the preload queue.
        loop {
            let (id, demanded) = {
                let Some(s) = self.synth.as_mut() else { return };
                if let Some(id) = s.take_patch_request() {
                    (id, true)
                } else if self.preload < PRELOAD_IDS {
                    let id = self.preload;
                    self.preload += 1;
                    (id, false)
                } else {
                    return;
                }
            };
            if self.denied(id) || self.is_loaded(id) {
                continue;
            }
            let Some((handle, size)) = self.open_patch(id) else {
                self.deny(id);
                if demanded {
                    crate::dbg_println!("[mpu] no patch for id {}", id);
                }
                continue;
            };
            self.loading = Some(PatchLoad {
                id,
                handle,
                size,
                buf: alloc::vec::Vec::with_capacity(size),
                start_ms: machine.get_ticks(),
                demanded,
            });
            return;
        }
    }

    /// Per-quantum service: drain the port's MIDI bytes into the synth, then
    /// satisfy a bounded number of its instrument requests. `arrival_frame` is
    /// the current mix-frame the bytes arrived at — the synth applies each at
    /// that frame so note onset timing is independent of the mix block size.
    pub fn tick<A: crate::Arch>(&mut self, machine: &mut A, arrival_frame: u64) {
        if !self.present {
            return;
        }
        // Only build the synth once the guest actually drives the port —
        // detection alone (reset/ACK) must not cost a sample pool.
        if self.synth.is_none() {
            if !self.card.in_uart() {
                return;
            }
            let mut s = sound::midi::Synth::new_boxed();
            s.init();
            self.synth = Some(s);
            // ROM-bank device: start streaming the whole bank in now, so the
            // instruments are resident before the first song's first note.
            self.preload = 0;
        }
        while let Some(b) = self.card.take() {
            if let Some(s) = self.synth.as_mut() {
                s.write_at(arrival_frame, b);
            }
        }
        self.service_loads(machine);
    }

    /// Whether the synth currently owes the sink audio.
    pub(super) fn mixing(&self) -> bool {
        // Also true while stamped bytes are still queued: they will start notes
        // at a future frame, so the producer must keep the stream running until
        // they are consumed (otherwise production stops before they render).
        self.synth
            .as_ref()
            .is_some_and(|s| s.mixing() || s.has_pending())
    }

    /// Sum the GM synth into the pump block. The scale is mix policy, like
    /// the GUS's, and is *not* the GUS's: the bank is the same, but a GM
    /// sequence drives far more simultaneous voices, so it needs its own
    /// measured level (see `vsb::GM_SCALE_Q16`).
    pub(super) fn mix_into<A: crate::Arch>(
        &mut self,
        _machine: &mut A,
        rate: u32,
        base: u64,
        block: &mut [(i32, i32)],
    ) {
        let g = super::vsb::GM_SCALE_Q16;
        if let Some(s) = self.synth.as_mut() {
            s.mix_into(rate, base, (g, g), block);
        }
    }
}

impl Default for Mpu {
    fn default() -> Self {
        Self::new()
    }
}
