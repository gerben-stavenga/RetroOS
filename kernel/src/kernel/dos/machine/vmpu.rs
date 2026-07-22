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

/// Patch reads per audio quantum. A bank load is dozens of files; letting them
/// all land in one tick stalls the mixer, and spreading them costs only the
/// first bar of a song.
const LOADS_PER_TICK: usize = 2;

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
            if tok[0].to_ascii_uppercase() == b'P'
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

    /// Read one instrument off the disk and install it. `false` when the file
    /// is missing or unparseable — the id is then denied and never retried.
    fn load_patch(&mut self, id: u16) -> bool {
        let Some(stem) = sound::midi::patch_stem(id) else {
            return false;
        };
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
        let Ok(vlen) = DfsState::to_vfs_open(&dos[..n], &mut vfs_buf) else {
            return false;
        };
        let Ok(bytes) = crate::kernel::exec::load_file_resolved(&vfs_buf[..vlen]) else {
            return false;
        };
        let Some(synth) = self.synth.as_mut() else { return false };
        synth.load_patch(id, &bytes)
    }

    /// Per-quantum service: drain the port's MIDI bytes into the synth, then
    /// satisfy a bounded number of its instrument requests.
    pub fn tick(&mut self) {
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
        }
        while let Some(b) = self.card.take() {
            if let Some(s) = self.synth.as_mut() {
                s.write(b);
            }
        }
        for _ in 0..LOADS_PER_TICK {
            let Some(s) = self.synth.as_mut() else { break };
            let Some(id) = s.take_patch_request() else { break };
            if self.denied(id) {
                continue;
            }
            if !self.load_patch(id) {
                self.deny(id);
                crate::dbg_println!("[mpu] no patch for id {}", id);
            }
        }
    }

    /// Whether the synth currently owes the sink audio.
    pub(super) fn mixing(&self) -> bool {
        self.synth.as_ref().is_some_and(|s| s.mixing())
    }

    /// Sum the GM synth into the pump block. The scale is mix policy, like
    /// the GUS's, and is *not* the GUS's: the bank is the same, but a GM
    /// sequence drives far more simultaneous voices, so it needs its own
    /// measured level (see `vsb::GM_SCALE_Q16`).
    pub(super) fn mix_into<A: crate::Arch>(
        &mut self,
        _machine: &mut A,
        rate: u32,
        _base: u64,
        block: &mut [(i32, i32)],
    ) {
        let g = super::vsb::GM_SCALE_Q16;
        if let Some(s) = self.synth.as_mut() {
            s.mix_into(rate, (g, g), block);
        }
    }
}

impl Default for Mpu {
    fn default() -> Self {
        Self::new()
    }
}
