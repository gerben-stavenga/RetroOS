//! The 3dfx Voodoo Graphics board as PC hardware: PCI config space, the
//! memory aperture, and the memory the card is handed on every call.
//!
//! The card itself is `//third_party/voodoo`, which owns no memory and has no
//! clock. This file is the machine side of that contract: it holds the video
//! and texture RAM, decides which parts of the aperture trap, and hands the
//! slices down. Everything policy-shaped — where the BAR lands, what the guest
//! is allowed to see, when a frame is presented — lives here, not in the card.

use alloc::boxed::Box;
use alloc::vec::Vec;
use voodoo::{Beam, Events, Kind, Voodoo};
use crate::kernel::voodoo_profile::{Sample, Stage};

/// A retail Voodoo Graphics board: 2 MB of frame buffer, 2 MB on the TMU.
const FB_BYTES: usize = 2 << 20;
const TEX_BYTES: usize = 2 << 20;

/// Buffer bursts without increasing the worker's 256-command service batch.
pub(crate) const COMMAND_CAPACITY: usize = 4096;

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
    output: alloc::sync::Arc<VoodooOutput>,
    work: crate::kernel::media::DeviceService<alloc::sync::Arc<VoodooOutput>>,
    allocated: bool,
    cfg: Config,
    wc: WriteCombine,
    /// Linear base DPMI handed the guest for the BAR, once it has asked.
    pub linear_base: Option<u32>,
    /// Set when the guest has swapped and the frame has not been presented.
    pub frame_ready: bool,
}

// Only resident card-owned buffers cross to the media worker. PCI state,
// guest addresses and allocation stay with the BSP.
struct Render {
    card: Box<Voodoo>,
    fb: Vec<u8>,
    tex: Vec<u8>,
    command: (u32, u32, u32),
    swapped: bool,
}
impl Render {
    fn execute(&mut self) {
        let (off, data, mask) = self.command;
        let events = self
            .card
            .write(&mut self.fb, &mut [&mut self.tex], off, data, mask);
        if events.swap { crate::kernel::voodoo_profile::swap(); }
        self.swapped |= events.swap;
    }
}


#[derive(Clone, Copy)]
enum Command { Write(u32, u32, u32), Init(u32) }

/// The renderer owns the card and its buffers; guest writes enter an ordered
/// command ring without joining the preceding triangle.
pub(crate) struct VoodooOutput {
    render: crate::kernel::media::Shared<Render>,
    commands: crate::kernel::media::Commands<Command, COMMAND_CAPACITY>,
    active: core::sync::atomic::AtomicBool,
    width: core::sync::atomic::AtomicU32,
    height: core::sync::atomic::AtomicU32,
    ready: core::sync::atomic::AtomicBool,
}
use core::sync::atomic::Ordering;
impl VoodooOutput {
    fn publish(&self, render: &Render) {
        let (w, h) = render.card.dimensions();
        self.width.store(w, Ordering::Release);
        self.height.store(h, Ordering::Release);
        self.active.store(render.card.output_on, Ordering::Release);
        self.ready.store(render.swapped, Ordering::Release);
    }
    fn drain(&self, render: &mut Render) {
        // Bound each batch so a producer cannot starve timed scanout.
        for _ in 0..256 {
            let Some(command) = (unsafe { self.commands.pop() }) else { break };
            match command {
                Command::Write(off, data, mask) => { render.command = (off, data, mask); render.execute(); }
                Command::Init(value) => render.card.set_init_enable(value),
            }
            crate::kernel::media::checkpoint();
        }
        self.publish(render);
    }
    fn run(output: &alloc::sync::Arc<Self>) {
        if let Some(mut render) = output.render.try_lock() { output.drain(&mut render); }
    }
    pub(crate) fn dimensions(&self) -> (usize, usize) {
        (self.width.load(Ordering::Acquire) as usize, self.height.load(Ordering::Acquire) as usize)
    }
    /// Media core only: consume commands and clock/display the front buffer.
    pub(crate) fn scanout(&self, out: &mut [u8], width: usize, height: usize,
        pitch: usize, dac: &voodoo::Dac) -> bool {
        let Some(mut render) = self.render.try_lock() else { return false };
        self.drain(&mut render);
        let events = render.card.vblank();
        if events.swap { crate::kernel::voodoo_profile::swap(); }
        render.swapped |= events.swap;
        self.publish(&render);
        if render.card.dimensions() != (width as u32, height as u32) { return false; }
        render.card.render(&render.fb, dac, out, pitch);
        render.swapped = false;
        self.publish(&render);
        true
    }
}

impl VVoodoo {
    pub fn new() -> Self {
        let mut card = Box::<Voodoo>::new_uninit();
        Voodoo::init(&mut card, Kind::Voodoo1, FB_BYTES, TEX_BYTES);
        let mut card = unsafe { card.assume_init() };
        card.set_checkpoint(crate::kernel::media::checkpoint);
        let output = alloc::sync::Arc::new(VoodooOutput {
            render: crate::kernel::media::Shared::new(Render {
                card, fb: Vec::new(), tex: Vec::new(), command: (0, 0, 0), swapped: false,
            }),
            commands: crate::kernel::media::Commands::new(),
            active: core::sync::atomic::AtomicBool::new(false),
            width: core::sync::atomic::AtomicU32::new(0),
            height: core::sync::atomic::AtomicU32::new(0),
            ready: core::sync::atomic::AtomicBool::new(false),
        });
        Self {
            work: unsafe { crate::kernel::media::DeviceService::new(output.clone(),
                |output| output.commands.pending(), VoodooOutput::run) }, output, allocated: false,
            cfg: Config {
                command: 0,
                bar0: BAR_PHYS,
                init_enable: 0,
            },
            wc: WriteCombine::default(),
            linear_base: None,
            frame_ready: false,
        }
    }

    /// True once the guest has mapped the aperture, i.e. a Glide program is
    /// driving the card and its output should own the display.
    pub fn active(&self) -> bool {
        self.linear_base.is_some() && self.output.active.load(Ordering::Acquire)
    }

    fn ensure_memory(&mut self) {
        if !self.allocated {
            let mut render = self.output.render.lock();
            render.fb.resize(FB_BYTES, 0);
            render.tex.resize(TEX_BYTES, 0);
            self.allocated = true;
        }
        self.frame_ready |= self.output.ready.load(Ordering::Acquire);
    }
    fn kick(&mut self) { self.work.poll_inline(); }
    fn submit(&mut self, command: Command) {
        if !unsafe { self.output.commands.push(command) } {
            let _sample = Sample::start(Stage::QueueFull);
            loop {
                self.kick();
                core::hint::spin_loop();
                if unsafe { self.output.commands.push(command) } { break; }
            }
        }
        self.kick();
    }
    fn fence(&mut self) {
        // Leave the consumer's lock alone while it still has queued work.
        // Repeatedly acquiring it here can starve the worker's try_lock.
        while self.output.commands.pending() {
            self.kick();
            core::hint::spin_loop();
        }
        // The last command leaves the ring before it finishes executing.
        // This sole producer cannot enqueue more commands during the fence;
        // taking the lock once therefore waits for all preceding execution.
        let _render = self.output.render.lock();
    }
    pub(crate) fn output(&mut self) -> alloc::sync::Arc<VoodooOutput> {
        self.flush();
        self.kick();
        self.output.clone()
    }

    pub fn config_read(&self, off: u8) -> u32 {
        self.cfg.read(off)
    }

    pub fn config_write(&mut self, off: u8, val: u32) {
        self.cfg.write(off, val);
        if off & 0xFC == 0x40 {
            self.submit(Command::Init(val));
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
        self.ensure_memory();
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

        self.submit(Command::Write(off, data, mask));
    }

    pub fn read8(&mut self, off: u32) -> u8 {
        let _sample = Sample::start(Stage::Read);
        self.ensure_memory();
        self.flush();
        let wait = Sample::start(if off < 0x40_0000 && (off >> 2) & 0xff == 0 {
            Stage::StatusFence
        } else { Stage::OtherFence });
        self.fence();
        let render = self.output.render.lock();
        drop(wait);
        let dword = render.card.read(&render.fb, off & !3, Beam::default());
        (dword >> ((off & 3) * 8)) as u8
    }

    /// The host reports a vertical retrace; a deferred swap may complete on it.
    pub fn vblank(&mut self) -> Events {
        self.fence();
        let mut render = self.output.render.lock();
        self.frame_ready |= core::mem::take(&mut render.swapped);
        let events = render.card.vblank();
        if events.swap {
            self.frame_ready = true;
        }
        self.output.publish(&render);
        events
    }

    /// Visible resolution the guest programmed.
    pub fn dimensions(&self) -> (u32, u32) {
        let (w, h) = self.output.dimensions();
        (w as u32, h as u32)
    }

    /// Clock the visible buffer out into `out`, in whatever encoding `dac`
    /// describes, `pitch` BYTES per row.
    pub fn scanout(&mut self, out: &mut [u8], pitch: usize, dac: &voodoo::Dac) {
        self.ensure_memory();
        self.flush();
        self.fence();
        let render = self.output.render.lock();
        unsafe {
            crate::kernel::media::graphics(|| render.card.render(&render.fb, dac, out, pitch));
        }
        drop(render);
        self.output.render.lock().swapped = false;
        self.output.ready.store(false, Ordering::Release);
        self.frame_ready = false;
    }

    pub fn scanout_raw(&mut self, out: &mut [u8], pitch: usize, dac: &voodoo::Dac) {
        self.ensure_memory();
        self.flush();
        self.fence();
        let render = self.output.render.lock();
        unsafe {
            crate::kernel::media::graphics(|| render.card.render_raw(&render.fb, dac, out, pitch));
        }
        drop(render);
        self.output.render.lock().swapped = false;
        self.output.ready.store(false, Ordering::Release);
        self.frame_ready = false;
    }

    pub fn vbe_ramp(&mut self, out: &mut [u8; 256 * 4]) -> u64 {
        self.flush();
        self.fence();
        self.output.render.lock().card.vbe_ramp(out)
    }

    /// Which region an aperture offset addresses, for logging and for the
    /// LFB fast path when it lands.
    pub fn is_register(&self, off: u32) -> bool {
        matches!(region(off), Region::Register)
    }
}

impl Drop for VVoodoo {
    fn drop(&mut self) { self.flush(); self.fence(); }
}

impl Default for VVoodoo {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pci_presence_does_not_allocate_vram_but_first_mmio_does() {
        let mut board = VVoodoo::new();
        let _ = board.config_read(0);
        board.flush();
        { let render = board.output.render.lock(); assert!(render.fb.is_empty() && render.tex.is_empty()); }
        let _ = board.read8(0);
        assert_eq!(board.output.render.lock().fb.len(), FB_BYTES);
        assert_eq!(board.output.render.lock().tex.len(), TEX_BYTES);
        {
            let render = board.output.render.lock();
            assert!(render.fb.iter().chain(render.tex.iter()).all(|&b| b == 0));
        }
        board.output.render.lock().fb[0] = 0x5a;
        let _ = board.read8(0);
        assert_eq!(board.output.render.lock().fb[0], 0x5a);
    }
}
