//! The 3dfx Voodoo Graphics board as PC hardware: PCI config space, the
//! memory aperture, and the memory the card is handed on every call.
//!
//! The card itself is `//third_party/voodoo`, which owns no memory and has no
//! clock. This file is the machine side of that contract: it holds the video
//! and texture RAM, decides which parts of the aperture trap, and hands the
//! slices down. Everything policy-shaped — where the BAR lands, what the guest
//! is allowed to see, when a frame is presented — lives here, not in the card.

use alloc::boxed::Box;
use alloc::vec;
use alloc::vec::Vec;
use voodoo::{Beam, Events, Kind, Voodoo};

/// A retail Voodoo Graphics board: 2 MB of frame buffer, 2 MB on the TMU.
const FB_BYTES: usize = 2 << 20;
const TEX_BYTES: usize = 2 << 20;

/// The synthetic physical address the BAR reports. The guest asks DPMI to map
/// it, and DPMI hands back a linear window whose pages we deliberately leave
/// absent so every access faults into `dos::mmio_fault`.
pub const BAR_PHYS: u32 = 0xF800_0000;
/// SST-1 aperture size: 4 MB of registers, 4 MB of LFB, 8 MB of texture.
pub const BAR_SIZE: u32 = 16 << 20;

const VENDOR_3DFX: u32 = 0x121A;
const DEVICE_SST1: u32 = 0x0001;

/// PCI configuration space, as much of it as a Glide driver looks at.
#[derive(Debug)]
struct Config {
    command: u32,
    bar0: u32,
    /// `initEnable`, which the driver writes at config offset 0x40 and which
    /// gates the fbiInit registers.
    init_enable: u32,
}

impl Config {
    fn read(&self, off: u8) -> u32 {
        match off & 0xFC {
            0x00 => (DEVICE_SST1 << 16) | VENDOR_3DFX,
            // Status (no capabilities) : command.
            0x04 => 0x0200_0000 | (self.command & 0xFFFF),
            // Class 0x00 (pre-2.0 "other display"), revision 2.
            0x08 => 0x0000_0002,
            0x0C => 0,
            0x10 => self.bar0,
            0x2C => (DEVICE_SST1 << 16) | VENDOR_3DFX,
            // No interrupt line: the SST-1 does not raise one for Glide.
            0x3C => 0,
            0x40 => self.init_enable,
            _ => 0,
        }
    }

    fn write(&mut self, off: u8, val: u32) {
        match off & 0xFC {
            0x04 => self.command = val & 0xFFFF,
            0x10 => {
                // Size probe: all-ones reads back as the alignment mask.
                self.bar0 = if val == 0xFFFF_FFFF {
                    !(BAR_SIZE - 1)
                } else {
                    (val & !(BAR_SIZE - 1)) | (BAR_PHYS & (BAR_SIZE - 1))
                };
            }
            0x40 => self.init_enable = val,
            _ => {}
        }
    }
}

/// Which part of the 16 MB aperture an offset lands in.
enum Region {
    /// 0x000000-0x3FFFFF — registers.
    Register,
    /// 0x400000-0x7FFFFF — linear frame buffer.
    Lfb,
    /// 0x800000-0xFFFFFF — texture download.
    Texture,
}

fn region(off: u32) -> Region {
    match off >> 22 {
        0 => Region::Register,
        1 => Region::Lfb,
        _ => Region::Texture,
    }
}

/// Coalesces the byte-granular writes the instruction decoder produces back
/// into the dwords the card expects.
///
/// The decoder is byte-oriented because that is what planar VGA needs. A
/// Voodoo register is a *command* — four partial writes to `triangleCMD` would
/// draw three garbage triangles — so bytes are gathered per aligned dword and
/// committed when the dword is complete or the access moves on.
#[derive(Debug, Default)]
struct WriteCombine {
    dword_off: u32,
    bytes: [u8; 4],
    /// Which of the four bytes the guest actually wrote.
    valid: u8,
}

pub struct VVoodoo {
    /// Boxed: the card's register files are ~20 KB, and `PcMachine` is built
    /// by value on the 64 KB kernel stack. Inline it and construction alone
    /// overflows the guard page.
    card: Box<Voodoo>,
    /// Video memory. The guest maps no part of it directly yet — see the
    /// module docs on the LFB fast path.
    fb: Vec<u8>,
    /// TMU 0 texture memory.
    tex: Vec<u8>,
    cfg: Config,
    wc: WriteCombine,
    /// Linear base DPMI handed the guest for the BAR, once it has asked.
    pub linear_base: Option<u32>,
    /// Set when the guest has swapped and the frame has not been presented.
    pub frame_ready: bool,
}

impl VVoodoo {
    pub fn new() -> Self {
        let mut card = Box::<Voodoo>::new_uninit();
        Voodoo::init(&mut card, Kind::Voodoo1, FB_BYTES, TEX_BYTES);
        Self {
            card: unsafe { card.assume_init() },
            fb: vec![0u8; FB_BYTES],
            tex: vec![0u8; TEX_BYTES],
            cfg: Config { command: 0, bar0: BAR_PHYS, init_enable: 0 },
            wc: WriteCombine::default(),
            linear_base: None,
            frame_ready: false,
        }
    }

    /// True once the guest has mapped the aperture, i.e. a Glide program is
    /// driving the card and its output should own the display.
    pub fn active(&self) -> bool {
        self.linear_base.is_some() && self.card.output_on
    }

    pub fn config_read(&self, off: u8) -> u32 {
        self.cfg.read(off)
    }

    pub fn config_write(&mut self, off: u8, val: u32) {
        self.cfg.write(off, val);
        if off & 0xFC == 0x40 {
            self.card.set_init_enable(val);
        }
    }

    /// Does a guest linear address fall inside the mapped aperture?
    pub fn aperture_offset(&self, addr: u32) -> Option<u32> {
        let base = self.linear_base?;
        let off = addr.wrapping_sub(base);
        (off < BAR_SIZE).then_some(off)
    }

    /// One byte of a guest store. Buffered; see [`WriteCombine`].
    pub fn write8(&mut self, off: u32, val: u8) {
        let dword = off & !3;
        if self.wc.valid != 0 && self.wc.dword_off != dword {
            self.flush();
        }
        self.wc.dword_off = dword;
        self.wc.bytes[(off & 3) as usize] = val;
        self.wc.valid |= 1 << (off & 3);
        if self.wc.valid == 0xF {
            self.flush();
        }
    }

    /// Commit a buffered partial dword. Called when the access moves to a new
    /// dword and at the end of every faulting instruction.
    pub fn flush(&mut self) {
        if self.wc.valid == 0 {
            return;
        }
        let data = u32::from_le_bytes(self.wc.bytes);
        // A byte lane the guest did not write must not disturb the register.
        let mut mask = 0u32;
        for b in 0..4 {
            if self.wc.valid & (1 << b) != 0 {
                mask |= 0xFF << (b * 8);
            }
        }
        let off = self.wc.dword_off;
        self.wc = WriteCombine::default();

        let mut tex: [&mut [u8]; 1] = [&mut self.tex];
        let events = self.card.write(&mut self.fb, &mut tex, off, data, mask);
        if events.swap {
            self.frame_ready = true;
        }
    }

    pub fn read8(&mut self, off: u32) -> u8 {
        self.flush();
        let dword = self.card.read(&self.fb, off & !3, Beam::default());
        (dword >> ((off & 3) * 8)) as u8
    }

    /// The host reports a vertical retrace; a deferred swap may complete on it.
    pub fn vblank(&mut self) -> Events {
        let events = self.card.vblank();
        if events.swap {
            self.frame_ready = true;
        }
        events
    }

    /// Visible resolution the guest programmed.
    pub fn dimensions(&self) -> (u32, u32) {
        self.card.dimensions()
    }

    /// Clock the visible buffer out into `out`, in whatever encoding `dac`
    /// describes, `pitch` BYTES per row.
    pub fn scanout(&mut self, out: &mut [u8], pitch: usize, dac: &voodoo::Dac) {
        self.flush();
        self.card.render(&self.fb, dac, out, pitch);
        self.frame_ready = false;
    }

    pub fn scanout_raw(&mut self, out: &mut [u8], pitch: usize, dac: &voodoo::Dac) {
        self.flush();
        self.card.render_raw(&self.fb, dac, out, pitch);
        self.frame_ready = false;
    }

    pub fn vbe_ramp(&mut self, out: &mut [u8; 256 * 4]) -> u64 {
        self.flush();
        self.card.vbe_ramp(out)
    }

    /// Which region an aperture offset addresses, for logging and for the
    /// LFB fast path when it lands.
    pub fn is_register(&self, off: u32) -> bool {
        matches!(region(off), Region::Register)
    }
}

impl Default for VVoodoo {
    fn default() -> Self {
        Self::new()
    }
}
