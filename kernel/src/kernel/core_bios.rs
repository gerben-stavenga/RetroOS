//! Private native video-BIOS execution environment.
//!
//! DOS always runs the Rust substitute BIOS. Native video firmware executes
//! only in this kernel-owned persistent workspace, synchronously servicing
//! operations on a move-only `NativeVga`.

use crate::{Arch, Regs, Vcpu};
use arch_abi::IoSize;
use alloc::vec::Vec;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BiosError {
    NoNativeBios,
    Rejected(u16),
    InvalidStateSize,
    InvalidFrame,
    UnexpectedEvent,
}

impl compact_fmt::Format for BiosError {
    fn format(
        &self,
        out: &mut dyn compact_fmt::Write,
        _: compact_fmt::FormatSpec,
    ) -> compact_fmt::Result {
        match *self {
            Self::NoNativeBios => out.write_str("NoNativeBios"),
            Self::Rejected(code) => compact_fmt::write!(out, "Rejected({:#x})", code),
            Self::InvalidStateSize => out.write_str("InvalidStateSize"),
            Self::InvalidFrame => out.write_str("InvalidFrame"),
            Self::UnexpectedEvent => out.write_str("UnexpectedEvent"),
        }
    }
}

/// Short-lived controller checkpoint produced by VBE 4F04h. Its layout belongs
/// to the machine's video BIOS. It may bracket destructive hardware inspection
/// but must never become runnable process state.
pub(crate) struct FirmwareCheckpoint(Vec<u8>);

/// Software VGA state owned by the core INT 10h/video-BIOS driver.
pub struct EmulatedVga {
    /// Registers plus a suspended VRAM snapshot. Empty `planes` means this
    /// device occupies the shared live store; capacity is retained for saving.
    pub state: vga::VgaState,
    /// Size of the active shared framebuffer mapping.
    pub svga_pages: usize,
    /// Suspended SVGA framebuffer. Empty while this device owns LiveVram.
    pub(crate) svga_vram: Vec<u8>,
}

/// A VGA paired with an output target. Native VGA intrinsically owns physical
/// scanout; an emulated VGA targets a real, composited, hosted, or headless
/// display.
pub enum FullscreenVga {
    Native(crate::kernel::platform::NativeVga),
    Emulated(EmulatedVga, crate::kernel::display::Display),
}

/// VGA state stored by a DOS personality. A plain VGA participates in the
/// event-loop compositor; a fullscreen VGA owns the machine's output and is
/// the only state which can be handed from one foreground thread to another.
pub enum DosVideo {
    Vga(EmulatedVga),
    Fullscreen(FullscreenVga),
}

/// Target visible through the VGA register window. VBE remains a BIOS API,
/// but exposes a deliberately small compatibility surface for programs which
/// incorrectly poll 3DAh or program the DAC in an SVGA mode.
pub(crate) enum LegacyVgaIo<'a> {
    Emulated(&'a mut vga::LegacyVgaState),
    Vbe(&'a mut vga::VbePalette),
    Native,
}

impl DosVideo {
    pub fn emulated(&self) -> Option<&EmulatedVga> {
        match self {
            Self::Vga(vga) | Self::Fullscreen(FullscreenVga::Emulated(vga, _)) => Some(vga),
            Self::Fullscreen(FullscreenVga::Native(_)) => None,
        }
    }

    pub fn emulated_mut(&mut self) -> Option<&mut EmulatedVga> {
        match self {
            Self::Vga(vga) | Self::Fullscreen(FullscreenVga::Emulated(vga, _)) => Some(vga),
            Self::Fullscreen(FullscreenVga::Native(_)) => None,
        }
    }

    pub fn native(&self) -> Option<&crate::kernel::platform::NativeVga> {
        match self {
            Self::Fullscreen(FullscreenVga::Native(native)) => Some(native),
            _ => None,
        }
    }

    pub fn native_mut(&mut self) -> Option<&mut crate::kernel::platform::NativeVga> {
        match self {
            Self::Fullscreen(FullscreenVga::Native(native)) => Some(native),
            _ => None,
        }
    }

    pub fn is_native(&self) -> bool { self.native().is_some() }
    pub fn is_fullscreen(&self) -> bool { matches!(self, Self::Fullscreen(_)) }

    pub(crate) fn native_legacy_vga<A: Arch>(&self, bios: &BiosDisplayWorkspace<A>) -> bool {
        matches!(self,
            Self::Fullscreen(FullscreenVga::Native(_))
                if bios.native_legacy_active())
    }

    pub(crate) fn legacy_vga_io(&mut self) -> LegacyVgaIo<'_> {
        match self {
            Self::Vga(dev) | Self::Fullscreen(FullscreenVga::Emulated(dev, _)) => {
                match &mut dev.state {
                    vga::VgaState::Legacy(state) => LegacyVgaIo::Emulated(state),
                    vga::VgaState::Vbe(state) => LegacyVgaIo::Vbe(&mut state.palette),
                }
            }
            Self::Fullscreen(FullscreenVga::Native(_)) => LegacyVgaIo::Native,
        }
    }
}

impl EmulatedVga {
    pub(crate) fn vbe_state_mut(&mut self) -> Option<&mut vga::SvgaState> {
        match &mut self.state {
            vga::VgaState::Vbe(state) => Some(state),
            vga::VgaState::Legacy(_) => None,
        }
    }

    /// Construct the conventional initial PC text display image without
    /// publishing it into any particular guest address space.
    pub fn initial_mode3() -> Self {
        Self {
            state: vga::VgaState::new_mode3(),
            svga_pages: 0,
            svga_vram: Vec::new(),
        }
    }

    pub(crate) fn clone_for_fork(&self) -> Self {
        Self {
            state: self.state.clone(),
            svga_pages: self.svga_pages,
            svga_vram: self.svga_vram.clone(),
        }
    }
}

/// Runtime native-video firmware service. The object is always present so it
/// can flow through backend-independent scheduling code; only a native-BIOS
/// platform has an execution workspace inside it. The interior is deliberately
/// private and can only be opened by a [`VgaCap`](crate::kernel::platform::VgaCap).
pub struct BiosDisplayWorkspace<A: Arch> {
    /// State of the one physical display. VBE state belongs here regardless
    /// of whether its implementation is GOP or a real-mode video BIOS.
    active: PhysicalVideoState,
    /// Optional real-mode firmware driver. It is an implementation detail of
    /// BIOS machines, never the owner of DOS-visible VBE state.
    native: Option<NativeBiosWorkspace<A>>,
}

enum BankedSource<'a> {
    Packed(&'a [u8]),
    Sized {
        width: usize,
        pixels: &'a [u8],
        row: &'a mut alloc::vec::Vec<u8>,
    },
}

/// Split a contiguous framebuffer span only at aperture boundaries, not rows.
fn banked_span(
    mut offset: usize,
    mut source: &[u8],
    window_size: usize,
    granularity: usize,
    mut copy: impl FnMut(u16, usize, &[u8]) -> Result<(), BiosError>,
) -> Result<(), BiosError> {
    while !source.is_empty() {
        let window_base = offset / window_size * window_size;
        let bank = u16::try_from(window_base / granularity)
            .map_err(|_| BiosError::InvalidFrame)?;
        let inside = offset - window_base;
        let count = source.len().min(window_size - inside);
        copy(bank, inside, &source[..count])?;
        source = &source[count..];
        offset += count;
    }
    Ok(())
}

#[cfg(test)]
mod banked_tests {
    use super::*;

    #[test]
    fn packed_canvas_copies_once_per_bank() {
        let source: Vec<u8> = (0..800 * 600 * 2).map(|i| (i * 37) as u8).collect();
        let mut output = alloc::vec![0; source.len()];
        let mut copies = 0;
        banked_span(0, &source, 65536, 4096, |bank, inside, bytes| {
            assert_eq!(usize::from(bank), copies * 16);
            assert_eq!(inside, 0);
            assert_eq!(bytes.len(), (source.len() - copies * 65536).min(65536));
            let offset = usize::from(bank) * 4096 + inside;
            unsafe {
                crate::kernel::display::copy_bytes(
                    output.as_mut_ptr().add(offset), bytes.as_ptr(), bytes.len(), false,
                );
            }
            copies += 1;
            Ok(())
        }).unwrap();
        assert_eq!(copies, 15);
        assert_eq!(output, source);
    }

    #[test]
    fn bank_splits_preserve_unaligned_rgb888_rows_and_pitch_gaps() {
        let source: Vec<u8> = (0..321 * 3).map(|i| (i * 53) as u8).collect();
        let mut output = alloc::vec![0xEE; 70000];
        let mut expected = output.clone();
        for offset in [65533, 66533] {
            expected[offset..offset + source.len()].copy_from_slice(&source);
            banked_span(offset, &source, 65536, 4096, |bank, inside, bytes| {
                assert!(inside + bytes.len() <= 65536);
                let address = usize::from(bank) * 4096 + inside;
                unsafe {
                    crate::kernel::display::copy_bytes(
                        output.as_mut_ptr().add(address), bytes.as_ptr(), bytes.len(), false,
                    );
                }
                Ok(())
            }).unwrap();
        }
        assert_eq!(output, expected);
    }

    #[test]
    fn bank_copy_stops_on_failure() {
        let mut copies = 0;
        let result = banked_span(65535, &[1, 2, 3], 65536, 4096, |_, _, _| {
            copies += 1;
            Err(BiosError::Rejected(0x014F))
        });
        assert_eq!(result, Err(BiosError::Rejected(0x014F)));
        assert_eq!(copies, 1);
        assert_eq!(banked_span(65536, &[1], 65536, 1, |_, _, _| {
            panic!("unrepresentable bank must not be selected");
        }), Err(BiosError::InvalidFrame));
    }
}

enum BiosTransfer<'a> {
    None,
    Input(usize, &'a [u8]),
    Output(usize, &'a mut [u8]),
    InOut(usize, &'a mut [u8]),
}

#[repr(C, packed)]
struct VbeControllerInfo {
    signature: [u8; 4],
    version: u16,
    oem_string: u32,
    capabilities: u32,
    video_modes: u32,
    total_memory: u16,
    reserved: [u8; 492],
}

#[repr(C, packed)]
struct VbeModeInfo {
    attributes: u16,
    window_a_attributes: u8,
    window_b_attributes: u8,
    window_granularity_kb: u16,
    window_size_kb: u16,
    window_a_segment: u16,
    window_b_segment: u16,
    window_function: u32,
    banked_pitch: u16,
    width: u16,
    height: u16,
    character_width: u8,
    character_height: u8,
    planes: u8,
    bits_per_pixel: u8,
    banks: u8,
    memory_model: u8,
    bank_size_kb: u8,
    banked_image_pages: u8,
    reserved0: u8,
    red_mask_size: u8,
    red_position: u8,
    green_mask_size: u8,
    green_position: u8,
    blue_mask_size: u8,
    blue_position: u8,
    reserved_mask_size: u8,
    reserved_position: u8,
    direct_color_attributes: u8,
    physical_base: u32,
    offscreen_offset: u32,
    offscreen_kb: u16,
    linear_pitch: u16,
    banked_image_pages_v3: u8,
    linear_image_pages: u8,
    linear_red_mask_size: u8,
    linear_red_position: u8,
    linear_green_mask_size: u8,
    linear_green_position: u8,
    linear_blue_mask_size: u8,
    linear_blue_position: u8,
    linear_reserved_mask_size: u8,
    linear_reserved_position: u8,
    maximum_pixel_clock: u32,
    reserved1: [u8; 190],
}

const _: [(); 512] = [(); core::mem::size_of::<VbeControllerInfo>()];
const _: [(); 256] = [(); core::mem::size_of::<VbeModeInfo>()];

impl VbeControllerInfo {
    fn request() -> Self {
        let mut info: Self = unsafe { core::mem::zeroed() };
        info.signature = *b"VBE2";
        info
    }

    fn bytes_mut(&mut self) -> &mut [u8] {
        unsafe {
            core::slice::from_raw_parts_mut(
                core::ptr::from_mut(self).cast(),
                core::mem::size_of::<Self>(),
            )
        }
    }
}

impl VbeModeInfo {
    fn empty() -> Self { unsafe { core::mem::zeroed() } }

    fn bytes_mut(&mut self) -> &mut [u8] {
        unsafe {
            core::slice::from_raw_parts_mut(
                core::ptr::from_mut(self).cast(),
                core::mem::size_of::<Self>(),
            )
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct PhysicalVbeState {
    pub mode: crate::kernel::platform::VbeMode,
    pub svga: vga::SvgaState,
}

#[derive(Clone, Copy, Debug)]
#[allow(clippy::large_enum_variant)] // Inline, Copy snapshot of the physical video state.
enum PhysicalVideoState { Legacy, Vbe(PhysicalVbeState) }

struct NativeBiosWorkspace<A: Arch> {
    /// Original firmware IVT/BDA view, used only for native video-ROM calls.
    bios_vcpu: Vcpu<A>,
    fx: A::Fx,
    modes: Vec<crate::kernel::platform::VbeMode>,
    state_bytes: Option<usize>,
    state_probed: bool,
}

impl<A: Arch> BiosDisplayWorkspace<A> {
    pub fn new(machine: &mut A) -> Self {
        let native = (crate::kernel::platform::get().firmware
            == crate::kernel::platform::Firmware::NativeBios)
            .then(|| NativeBiosWorkspace::new(machine));
        Self { active: PhysicalVideoState::Legacy, native }
    }

    /// Backend paths which deliberately bypass platform probing (the hosted
    /// bare-ELF runner) have no native video firmware.
    pub(crate) fn absent() -> Self {
        Self { active: PhysicalVideoState::Legacy, native: None }
    }

    /// Immutable, sanitized mode catalogue discovered at boot. Consulting it
    /// does not operate the adapter and therefore requires no live `VgaCap`.
    pub fn curated_mode(&self, number: u16) -> Option<crate::kernel::platform::VbeMode> {
        self.native.as_ref()?.mode(number)
    }

    pub fn curated_modes(&self) -> Option<&[crate::kernel::platform::VbeMode]> {
        Some(self.native.as_ref()?.modes())
    }

    pub(crate) fn native_legacy_active(&self) -> bool {
        matches!(self.active, PhysicalVideoState::Legacy)
    }

    pub(crate) fn vbe_state(&self) -> Option<&PhysicalVbeState> {
        match &self.active { PhysicalVideoState::Vbe(state) => Some(state), _ => None }
    }

    pub(crate) fn vbe_state_mut(&mut self) -> Option<&mut PhysicalVbeState> {
        match &mut self.active { PhysicalVideoState::Vbe(state) => Some(state), _ => None }
    }

    pub(crate) fn vbe_port_read(&mut self, port: u16) -> Option<u8> {
        Some(self.vbe_state_mut()?.svga.palette.port_read(port))
    }

    pub(crate) fn vbe_port_write(
        &mut self,
        port: u16,
        value: u8,
    ) -> bool {
        let Some(state) = self.vbe_state_mut() else { return false };
        state.svga.palette.port_write(port, value);
        true
    }

    /// Publish raw DAC compatibility writes as one VBE operation. The guest
    /// never touches physical VGA ports, and a 256-entry palette load does not
    /// turn into 256 real-mode BIOS excursions.
    pub(crate) fn flush_vbe_ports(
        &mut self,
        machine: &mut A,
        display: &mut crate::kernel::platform::VgaCap,
    ) {
        let BiosDisplayWorkspace { active, native } = self;
        let PhysicalVideoState::Vbe(state) = active else { return };
        let Some(range) = state.svga.palette.dirty_range() else { return };
        let (start, end) = (range.start, range.end);
        let mut entries = alloc::vec![0; usize::from(end - start) * 4];
        assert!(state.svga.palette.read(start, &mut entries), "dirty palette range");
        let physical_dac = state.mode.vga_compatible
            && matches!(state.mode.format, crate::kernel::display::FormatSpec::Indexed8);
        let published = native.as_mut().is_some_and(|firmware| {
            firmware.indexed_palette_call(
                machine, display, &mut state.svga.palette, physical_dac,
                0, start, &mut entries,
            ).is_ok()
        });
        if published {
            state.svga.palette.clear_dirty();
        }
    }

    fn mark_legacy(&mut self) { self.active = PhysicalVideoState::Legacy; }

    fn mark_vbe(&mut self, mode: crate::kernel::platform::VbeMode, request: u16) {
        let access = if request & 0x4000 != 0 {
            vga::SvgaAccess::Linear
        } else {
            vga::SvgaAccess::Banked { bank: 0 }
        };
        self.active = PhysicalVideoState::Vbe(PhysicalVbeState {
            mode,
            svga: vga::SvgaState::new(mode.number, access, mode.svga_config()),
        });
    }
}

impl<A: Arch> NativeBiosWorkspace<A> {
    /// Build the persistent real-mode driver address space from the original
    /// firmware view and park it outside every personality.
    fn new(machine: &mut A) -> Self {
        // Snapshot the firmware view before the DOS substitute BIOS replaces
        // the IVT. This address space is never handed to a personality.
        machine.map_low_mem();
        let mut bios_space = A::PageTable::default();
        machine.user_fork(&mut bios_space);

        Self {
            bios_vcpu: Vcpu::new(Regs::empty(), bios_space),
            fx: machine.clean_fx_template(),
            modes: Vec::new(),
            state_bytes: None,
            state_probed: false,
        }
    }

    const STATE_BUFFER: usize = 0x70000;
    const MAX_STATE_BYTES: usize = 0x10000;
    // Hardware, DAC and extended-controller state. BIOS data-area state is
    // deliberately excluded: it persists in the native driver's address
    // space, while each DOS personality owns its independent substitute BDA.
    const STATE_COMPONENTS: u64 = 0x000D;

    /// Probe VBE's chipset-independent full controller save/restore service.
    /// Framebuffer memory is deliberately not part of 4F04h; it remains
    /// display-owner data in `VgaState`.
    fn probe_state_size(
        &mut self,
        machine: &mut A,
        display: &crate::kernel::platform::VgaCap,
    ) -> Option<usize> {
        if crate::kernel::platform::get().firmware
            != crate::kernel::platform::Firmware::NativeBios
        {
            return None;
        }
        let mut regs = Regs::empty();
        regs.rax = 0x4F04;
        regs.rcx = Self::STATE_COMPONENTS;
        regs.rdx = 0;
        self.call_buffer(machine, display, &mut regs, BiosTransfer::None).ok()?;
        if regs.rax as u16 != 0x004F { return None; }
        let bytes = usize::from(regs.rbx as u16).checked_mul(64)?;
        (bytes != 0 && bytes <= Self::MAX_STATE_BYTES).then_some(bytes)
    }

    /// Save all firmware-visible controller state. Failure means the caller
    /// should retain its direct-register fallback; it is not a fatal display
    /// error because many plain VGA BIOSes predate VBE.
    fn checkpoint(
        &mut self,
        machine: &mut A,
        display: &crate::kernel::platform::VgaCap,
    ) -> Option<FirmwareCheckpoint> {
        if !self.state_probed {
            self.state_bytes = self.probe_state_size(machine, display);
            self.state_probed = true;
        }
        let bytes = self.state_bytes?;
        let mut regs = Regs::empty();
        let mut state = alloc::vec![0; bytes];
        regs.rax = 0x4F04;
        regs.rcx = Self::STATE_COMPONENTS;
        regs.rdx = 1;
        regs.es = (Self::STATE_BUFFER >> 4) as u64;
        regs.rbx = (Self::STATE_BUFFER & 0xF) as u64;
        self.call_buffer(
            machine,
            display,
            &mut regs,
            BiosTransfer::InOut(Self::STATE_BUFFER, &mut state),
        ).ok()?;
        (regs.rax as u16 == 0x004F).then_some(FirmwareCheckpoint(state))
    }

    /// Restore a blob returned by [`checkpoint`](Self::checkpoint). The blob
    /// exists only long enough to undo destructive inspection of the adapter;
    /// it is never retained as process state.
    fn restore_checkpoint(
        &mut self,
        machine: &mut A,
        display: &crate::kernel::platform::VgaCap,
        state: &FirmwareCheckpoint,
    ) -> Result<(), BiosError> {
        if state.0.is_empty() || state.0.len() > Self::MAX_STATE_BYTES {
            return Err(BiosError::InvalidStateSize);
        }
        let mut regs = Regs::empty();
        regs.rax = 0x4F04;
        regs.rcx = Self::STATE_COMPONENTS;
        regs.rdx = 2;
        regs.es = (Self::STATE_BUFFER >> 4) as u64;
        regs.rbx = (Self::STATE_BUFFER & 0xF) as u64;
        self.call_buffer(
            machine,
            display,
            &mut regs,
            BiosTransfer::Input(Self::STATE_BUFFER, &state.0),
        )?;
        let status = regs.rax as u16;
        if status == 0x004F { Ok(()) } else { Err(BiosError::Rejected(status)) }
    }

    /// Set a legacy (00h..FFh) or VBE (100h and above) mode through the
    /// machine's own video BIOS. This is a regular
    /// synchronous Rust call: the stopped guest's address space and FPU state
    /// are restored before it returns. The ROM runs in its isolated persistent
    /// driver address space, so guest memory remains unreachable while the
    /// firmware's own BDA and scratch state remain coherent with native VGA.
    /// Execute a guest-requested native mode set. `request` retains VBE's LFB
    /// bit. Firmware applies the operation, then the RetroOS shadow becomes
    /// authoritative for the resulting VBE state.
    fn set_mode_request(
        &mut self,
        machine: &mut A,
        bios_display: &mut crate::kernel::platform::VgaCap,
        request: u16,
    ) -> Result<(), BiosError> {
        if crate::kernel::platform::get().firmware
            != crate::kernel::platform::Firmware::NativeBios
        {
            return Err(BiosError::NoNativeBios);
        }

        let number = request & 0x3FFF;
        if number <= 0xFF {
            let mut regs = Regs::empty();
            regs.rax = u64::from(number);
            self.call_buffer(machine, bios_display, &mut regs, BiosTransfer::None)?;
            return Ok(());
        }
        let Some(_mode) = self.mode(number) else {
            return Err(BiosError::Rejected(0x014F));
        };
        let mut regs = Regs::empty();
        regs.rax = 0x4F02;
        regs.rbx = u64::from(request);
        self.call_buffer(machine, bios_display, &mut regs, BiosTransfer::None)?;
        let status = regs.rax as u16;
        if status == 0x004F {
            Ok(())
        } else {
            crate::compact_println!("VBE: physical mode set returned {:#x}", status);
            Err(BiosError::Rejected(status))
        }
    }

    /// Apply VBE 4F07h display-start changes to the physical backend. Reads
    /// are answered exclusively from RetroOS's authoritative shadow.
    fn display_start(
        &mut self,
        machine: &mut A,
        display: &mut crate::kernel::platform::VgaCap,
        state: &mut PhysicalVbeState,
        caller: &mut Regs,
    ) -> Result<(), BiosError> {
        if caller.rbx as u8 == 1 {
            let (x, y) = state.svga.display_start(None)
                .ok_or(BiosError::InvalidFrame)?;
            caller.rax = (caller.rax & !0xFFFF) | 0x004F;
            caller.rcx = (caller.rcx & !0xFFFF) | u64::from(x);
            caller.rdx = (caller.rdx & !0xFFFF) | u64::from(y);
            return Ok(());
        }
        if !matches!(caller.rbx as u8, 0 | 0x80) {
            return Err(BiosError::Rejected(0x014F));
        }
        let input = [caller.rax, caller.rbx, caller.rcx, caller.rdx];
        let mut next = state.svga;
        next.display_start(Some((input[2] as u16, input[3] as u16)))
            .ok_or(BiosError::InvalidFrame)?;
        let mut regs = Regs::empty();
        regs.rax = input[0];
        regs.rbx = input[1];
        regs.rcx = input[2];
        regs.rdx = input[3];
        self.call_buffer(machine, display, &mut regs, BiosTransfer::None)?;
        let status = regs.rax as u16;
        caller.rax = regs.rax;
        caller.rbx = regs.rbx;
        caller.rcx = regs.rcx;
        caller.rdx = regs.rdx;
        if status != 0x004F { return Err(BiosError::Rejected(status)); }
        state.svga = next;
        Ok(())
    }

    /// Apply VBE 4F06h logical scan-line changes to the physical backend.
    /// Query operations are answered from RetroOS's authoritative shadow.
    fn scan_line_length(
        &mut self,
        machine: &mut A,
        display: &mut crate::kernel::platform::VgaCap,
        state: &mut PhysicalVbeState,
        caller: &mut Regs,
    ) -> Result<(), BiosError> {
        if matches!(caller.rbx as u8, 1 | 3) {
            let result = state.svga.scan_line(None)
                .ok_or(BiosError::InvalidFrame)?;
            caller.rax = (caller.rax & !0xFFFF) | 0x004F;
            caller.rbx = (caller.rbx & !0xFFFF) | u64::from(result.bytes);
            caller.rcx = (caller.rcx & !0xFFFF) | u64::from(result.pixels);
            caller.rdx = (caller.rdx & !0xFFFF) | u64::from(result.lines);
            return Ok(());
        }
        if !matches!(caller.rbx as u8, 0 | 2) {
            return Err(BiosError::Rejected(0x014F));
        }
        let input = [caller.rax, caller.rbx, caller.rcx, caller.rdx];
        let mut next = state.svga;
        next.scan_line(Some((input[2] as u16, caller.rbx as u8 == 2)))
            .ok_or(BiosError::InvalidFrame)?;
        let mut regs = Regs::empty();
        regs.rax = input[0];
        regs.rbx = input[1];
        regs.rcx = input[2];
        regs.rdx = input[3];
        self.call_buffer(machine, display, &mut regs, BiosTransfer::None)?;
        let status = regs.rax as u16;
        caller.rax = regs.rax;
        caller.rbx = regs.rbx;
        caller.rcx = regs.rcx;
        caller.rdx = regs.rdx;
        if status != 0x004F { return Err(BiosError::Rejected(status)); }
        let pitch = regs.rbx as u16;
        if pitch == 0 { return Err(BiosError::InvalidFrame); }
        next.scan_line(Some((pitch, true)))
            .ok_or(BiosError::InvalidFrame)?;
        state.svga = next;
        Ok(())
    }

    /// Apply VBE 4F05h bank changes to the physical backend. Bank queries are
    /// answered from the RetroOS shadow, including calls through WinFuncPtr.
    fn window(
        &mut self,
        machine: &mut A,
        display: &mut crate::kernel::platform::VgaCap,
        state: &mut PhysicalVbeState,
        set: Option<u16>,
    ) -> Result<u16, BiosError> {
        let current = state.svga.window(None).ok_or(BiosError::Rejected(0x014F))?;
        let Some(bank) = set else { return Ok(current); };
        if state.mode.window_segment == 0 && state.mode.physical_base != 0 {
            let physical = u64::from(state.mode.physical_base)
                + u64::from(bank) * 64 * 1024;
            machine.map_phys_range(
                0xA0000 >> 12,
                0x10,
                physical >> 12,
                arch_abi::MAP_PHYS_CACHE_DISABLE | arch_abi::MAP_PHYS_FOREIGN,
            );
            state.svga.window(Some(bank)).ok_or(BiosError::InvalidFrame)?;
            return Ok(bank);
        }
        let granularity = state.mode.window_granularity_kb;
        if granularity == 0 { return Err(BiosError::InvalidFrame); }
        let physical_bank = bank.checked_mul(64)
            .map(|offset_kb| offset_kb / granularity)
            .ok_or(BiosError::InvalidFrame)?;
        let mut regs = Regs::empty();
        regs.rax = 0x4F05;
        regs.rbx = 0;
        regs.rdx = u64::from(physical_bank);
        self.call_buffer(machine, display, &mut regs, BiosTransfer::None)?;
        let status = regs.rax as u16;
        if status != 0x004F { return Err(BiosError::Rejected(status)); }
        state.svga.window(Some(bank)).ok_or(BiosError::InvalidFrame)?;
        Ok(bank)
    }

    pub fn mode(&self, number: u16) -> Option<crate::kernel::platform::VbeMode> {
        self.modes.iter().copied().find(|mode| mode.number == number)
    }

    pub fn modes(&self) -> &[crate::kernel::platform::VbeMode] { &self.modes }

    fn set_bank(
        &mut self,
        machine: &mut A,
        display: &mut crate::kernel::platform::VgaCap,
        mode: crate::kernel::platform::VbeMode,
        bank: u16,
    ) -> Result<(), BiosError> {
        let mut regs = self.bios_vcpu.regs;
        let caller_space = machine.activate(
            core::mem::take(&mut self.bios_vcpu.space),
            &mut self.fx,
            core::ptr::null_mut(),
        );
        let return_ip = prepare_bank_call(machine, &mut regs, mode, bank);
        let io = crate::kernel::io_policy::bios_display(display);
        let completed = run_bios_until(machine, &mut regs, return_ip, &io);
        self.bios_vcpu.space = machine.activate(
            caller_space,
            &mut self.fx,
            core::ptr::null_mut(),
        );
        completed?;
        let status = regs.rax as u16;
        if status != 0x004F {
            return Err(BiosError::Rejected(status));
        }
        Ok(())
    }

    /// RetroOS VBE palette/ramp service. Reads never enter the physical ROM or
    /// access the DAC. Successful writes commit the same values to the shadow.
    #[allow(clippy::too_many_arguments)] // Explicit BIOS register/buffer contract.
    fn indexed_palette_call(
        &mut self,
        machine: &mut A,
        display: &mut crate::kernel::platform::VgaCap,
        palette: &mut vga::VbePalette,
        physical_dac: bool,
        subfn: u8,
        start: u16,
        entries: &mut [u8],
    ) -> Result<(), BiosError> {
        if !vga::VbePalette::valid_range(start, entries.len()) {
            return Err(BiosError::InvalidFrame);
        }
        match subfn {
            1 => return palette.read(start, entries)
                .then_some(()).ok_or(BiosError::InvalidFrame),
            0 | 0x80 => {}
            _ => return Err(BiosError::Rejected(0x014F)),
        }
        if entries.is_empty() { return Ok(()); }
        let mut next = *palette;
        if !next.write(start, entries) { return Err(BiosError::InvalidFrame); }
        let mut physical = alloc::vec![0; entries.len()];
        let mut six = next;
        six.width = 6;
        if !six.read(start, &mut physical) { return Err(BiosError::InvalidFrame); }
        if physical_dac {
            crate::kernel::drivers::vga_hw::set_vbe_palette(display, start as u8, &physical);
        } else {
            let mut regs = Regs::empty();
            regs.rax = 0x4F09;
            regs.rbx = u64::from(subfn);
            regs.rcx = (entries.len() / 4) as u64;
            regs.rdx = u64::from(start);
            if let Err(error) = self.palette_call(machine, display, &mut regs, Some(&mut physical), true, true) {
                crate::compact_println!("VBE: physical palette write failed: {:?}", error);
                return Err(error);
            }
        }
        *palette = next;
        Ok(())
    }

    /// Execute a native video-BIOS palette call with an optional caller buffer.
    /// The ROM can only address its private real-mode workspace, so protected-
    /// mode DOS buffers are bounced through [`STATE_BUFFER`]. `offset_in_di`
    /// selects VBE's ES:DI convention; legacy AH=10h uses ES:DX.
    fn palette_call(
        &mut self,
        machine: &mut A,
        display: &mut crate::kernel::platform::VgaCap,
        caller: &mut Regs,
        buffer: Option<&mut [u8]>,
        copy_to_bios: bool,
        offset_in_di: bool,
    ) -> Result<(), BiosError> {
        if crate::kernel::platform::get().firmware
            != crate::kernel::platform::Firmware::NativeBios
        {
            return Err(BiosError::NoNativeBios);
        }
        let len = buffer.as_ref().map_or(0, |b| b.len());
        if len > Self::MAX_STATE_BYTES {
            return Err(BiosError::InvalidStateSize);
        }

        let input = [caller.rax, caller.rbx, caller.rcx, caller.rdx];
        let mut regs = Regs::empty();
        regs.rax = input[0];
        regs.rbx = input[1];
        regs.rcx = input[2];
        regs.rdx = input[3];
        if len != 0 {
            regs.es = (Self::STATE_BUFFER >> 4) as u64;
            if offset_in_di {
                regs.rdi = (Self::STATE_BUFFER & 0xF) as u64;
            } else {
                regs.rdx = (Self::STATE_BUFFER & 0xF) as u64;
            }
        }
        let transfer = match buffer {
            Some(buffer) if copy_to_bios => BiosTransfer::Input(Self::STATE_BUFFER, buffer),
            Some(buffer) => BiosTransfer::Output(Self::STATE_BUFFER, buffer),
            None => BiosTransfer::None,
        };
        self.call_buffer(machine, display, &mut regs, transfer)?;

        // VBE reports status in AX. Legacy AH=10h/AL=15h additionally returns
        // one DAC entry in DH/CH/CL. Do not leak the bounce-buffer offset back
        // through DX/DI for pointer-bearing calls.
        caller.rax = regs.rax;
        if input[0] as u16 == 0x4F09 && regs.rax as u16 != 0x004F {
            return Err(BiosError::Rejected(regs.rax as u16));
        }
        if input[0] as u16 == 0x1015 {
            caller.rcx = regs.rcx;
            caller.rdx = regs.rdx;
        }
        Ok(())
    }

    /// Execute INT 10h AH=11h in the native BIOS workspace. User-font calls
    /// carry their glyph buffer in ES:BP, so the guest pointer is bounced into
    /// the workspace just like palette tables, but with the font convention.
    fn font_call(
        &mut self,
        machine: &mut A,
        display: &mut crate::kernel::platform::VgaCap,
        caller: &mut Regs,
        font: Option<&[u8]>,
    ) -> Result<(), BiosError> {
        if crate::kernel::platform::get().firmware
            != crate::kernel::platform::Firmware::NativeBios
        {
            return Err(BiosError::NoNativeBios);
        }
        let len = font.map_or(0, <[u8]>::len);
        if len > Self::MAX_STATE_BYTES {
            return Err(BiosError::InvalidStateSize);
        }
        let input = [caller.rax, caller.rbx, caller.rcx, caller.rdx];
        let mut regs = Regs::empty();
        regs.rax = input[0];
        regs.rbx = input[1];
        regs.rcx = input[2];
        regs.rdx = input[3];
        let transfer = if let Some(font) = font {
            regs.es = (Self::STATE_BUFFER >> 4) as u64;
            regs.rbp = (Self::STATE_BUFFER & 0xF) as u64;
            BiosTransfer::Input(Self::STATE_BUFFER, font)
        } else {
            BiosTransfer::None
        };
        self.call_buffer(machine, display, &mut regs, transfer)?;
        caller.rax = regs.rax;
        Ok(())
    }

    /// Publish a compact packed shadow through a VBE bank window. The native
    /// BIOS workspace already owns the live VGA state, so keep that persistent
    /// workspace active for the whole frame; only 4F05 itself repeats.
    fn present_banked(
        &mut self,
        machine: &mut A,
        display: &mut crate::kernel::platform::VgaCap,
        mode: crate::kernel::platform::VbeMode,
        bank_state: &mut u16,
        shadow_height: usize,
        shadow: &[u8],
    ) -> Result<usize, BiosError> {
        self.present_banked_source(
            machine,
            display,
            mode,
            bank_state,
            shadow_height,
            BankedSource::Packed(shadow),
            None,
        )
    }

    fn present_banked_packed(
        &mut self,
        machine: &mut A,
        display: &mut crate::kernel::platform::VgaCap,
        mode: crate::kernel::platform::VbeMode,
        bank_state: &mut u16,
        source: crate::kernel::display::PackedSource<'_>,
    ) -> Result<usize, BiosError> {
        let crate::kernel::display::PackedSource { width, height, pixels, row } = source;
        self.present_banked_source(
            machine,
            display,
            mode,
            bank_state,
            height,
            BankedSource::Sized { width, pixels, row },
            None,
        )
    }

    #[allow(clippy::too_many_arguments)] // Hardware capabilities, bank state, and source stay distinct.
    fn present_banked_packed_regions(
        &mut self,
        machine: &mut A,
        display: &mut crate::kernel::platform::VgaCap,
        mode: crate::kernel::platform::VbeMode,
        bank_state: &mut u16,
        width: usize,
        height: usize,
        pixels: &[u8],
        regions: &[crate::kernel::gui::Rect],
    ) -> Result<usize, BiosError> {
        let mut row = alloc::vec::Vec::new();
        self.present_banked_source(
            machine,
            display,
            mode,
            bank_state,
            height,
            BankedSource::Sized { width, pixels, row: &mut row },
            Some(regions),
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn present_banked_source(
        &mut self,
        machine: &mut A,
        display: &mut crate::kernel::platform::VgaCap,
        mode: crate::kernel::platform::VbeMode,
        bank_state: &mut u16,
        shadow_height: usize,
        mut source: BankedSource<'_>,
        regions: Option<&[crate::kernel::gui::Rect]>,
    ) -> Result<usize, BiosError> {
        let crate::kernel::display::FormatSpec::Packed(rgb) = mode.format else {
            return Err(BiosError::InvalidFrame);
        };
        let panel_w = usize::from(mode.width);
        let panel_h = usize::from(mode.height);
        let (out_w, out_h) = match &source {
            BankedSource::Packed(_) => crate::kernel::display::fit_vga(panel_w, panel_h),
            BankedSource::Sized { width, .. } => crate::kernel::display::native_output_size(
                panel_w, panel_h, *width, shadow_height,
            ),
        };
        let shadow_width = out_w;
        let step = usize::from(rgb.bytes_per_pixel);
        let row_bytes = shadow_width.checked_mul(step).ok_or(BiosError::InvalidFrame)?;
        let needed = row_bytes.checked_mul(shadow_height).ok_or(BiosError::InvalidFrame)?;
        let pitch = usize::from(mode.pitch);
        let granularity = usize::from(mode.window_granularity_kb) * 1024;
        let window_size = usize::from(mode.window_size_kb) * 1024;
        let source_valid = match &source {
            BankedSource::Packed(shadow) => shadow.len() >= needed,
            BankedSource::Sized { width, pixels, .. } => *width != 0
                && pixels.len() >= width.saturating_mul(shadow_height).saturating_mul(step),
        };
        if shadow_height == 0 || !source_valid
            || shadow_width > panel_w || row_bytes > pitch
            || granularity == 0 || window_size == 0 || window_size % granularity != 0
            || mode.window_segment == 0
        {
            return Err(BiosError::InvalidFrame);
        }

        let caller_space = machine.activate(
            core::mem::take(&mut self.bios_vcpu.space),
            &mut self.fx,
            core::ptr::null_mut(),
        );
        let io = crate::kernel::io_policy::bios_display(display);

        let result = (|| {
            let bx = (panel_w - out_w) / 2;
            let by = (panel_h - out_h) / 2;
            let (ybase, yrem) = (out_h / shadow_height, out_h % shadow_height);
            let aperture = usize::from(mode.window_segment) * 16;
            let mut current_bank = None;
            let mut write_span = |machine: &mut A, offset, bytes: &[u8]| {
                banked_span(offset, bytes, window_size, granularity, |bank, inside, chunk| {
                    if current_bank != Some(bank) {
                        let bank_sample = crate::kernel::osd_profile::Sample::start(machine);
                        let mut regs = self.bios_vcpu.regs;
                        let return_ip = prepare_bank_call(machine, &mut regs, mode, bank);
                        run_bios_until(machine, &mut regs, return_ip, &io)?;
                        let status = regs.rax as u16;
                        if status != 0x004F { return Err(BiosError::Rejected(status)); }
                        bank_sample.finish(machine, crate::kernel::osd_profile::Stage::Bank, 0);
                        *bank_state = bank;
                        current_bank = Some(bank);
                    }
                    let copy_sample = crate::kernel::osd_profile::Sample::start(machine);
                    // Only native firmware creates this workspace. Its active
                    // address space maps the hardware aperture directly; this
                    // is framebuffer memory, not a generic guest/MMIO copy.
                    unsafe {
                        crate::kernel::display::copy_bytes(
                            (aperture + inside) as *mut u8, chunk.as_ptr(), chunk.len(), false,
                        );
                    }
                    copy_sample.finish(machine, crate::kernel::osd_profile::Stage::Copy, chunk.len() / step);
                    Ok(())
                })
            };

            // A compositor canvas already matches the selected mode. Copy
            // only its changed row spans; `banked_span` splits a row if it
            // crosses an aperture boundary and preserves the current bank
            // across adjacent rows and rectangles.
            if let Some(regions) = regions {
                let BankedSource::Sized { width, pixels, .. } = &source else {
                    return Err(BiosError::InvalidFrame);
                };
                if *width != panel_w || shadow_height != panel_h {
                    return Err(BiosError::InvalidFrame);
                }
                let mut copied = 0usize;
                for rect in regions {
                    let x0 = rect.x.max(0) as usize;
                    let y0 = rect.y.max(0) as usize;
                    let x1 = (i64::from(rect.x) + i64::from(rect.width))
                        .clamp(0, panel_w as i64) as usize;
                    let y1 = (i64::from(rect.y) + i64::from(rect.height))
                        .clamp(0, panel_h as i64) as usize;
                    if x0 >= x1 || y0 >= y1 {
                        continue;
                    }
                    let bytes = (x1 - x0) * step;
                    for y in y0..y1 {
                        let source_at = (y * panel_w + x0) * step;
                        write_span(
                            machine,
                            y * pitch + x0 * step,
                            &pixels[source_at..source_at + bytes],
                        )?;
                    }
                    copied += (x1 - x0) * (y1 - y0);
                }
                return Ok(copied);
            }

            // A matching packed canvas is one span, just like linear present.
            // For 800x600 RGB565 this is 15 aperture copies, not 600 row copies
            // plus another 14 splits at bank boundaries.
            let contiguous = match &source {
                BankedSource::Packed(pixels) => Some(*pixels),
                BankedSource::Sized { width, pixels, .. } if *width == out_w => Some(*pixels),
                _ => None,
            };
            if pitch == row_bytes && shadow_height == out_h
                && let Some(pixels) = contiguous
            {
                write_span(machine, by * pitch + bx * step, &pixels[..needed])?;
                return Ok(out_w * out_h);
            }

            let mut oy = 0usize;
            let mut yerr = 0usize;

            for sy in 0..shadow_height {
                yerr += yrem;
                let carry = usize::from(yerr >= shadow_height);
                let rows = ybase + carry;
                yerr -= carry * shadow_height;
                let src = match &mut source {
                    BankedSource::Packed(shadow) =>
                        &shadow[sy * row_bytes..(sy + 1) * row_bytes],
                    BankedSource::Sized { width, pixels, row } => {
                        let src = &pixels[sy * *width * step..(sy + 1) * *width * step];
                        if *width == out_w {
                            src
                        } else {
                            let pack_sample = crate::kernel::osd_profile::Sample::start(machine);
                            row.resize(row_bytes, 0);
                            if !crate::kernel::display::stretch_packed_row(src, row, out_w, step) {
                                return Err(BiosError::InvalidFrame);
                            }
                            pack_sample.finish(machine, crate::kernel::osd_profile::Stage::Pack, out_w);
                            &row[..row_bytes]
                        }
                    }
                };
                for _ in 0..rows {
                    write_span(machine, (by + oy) * pitch + bx * step, src)?;
                    oy += 1;
                }
            }
            Ok(out_w * out_h)
        })();

        self.bios_vcpu.space = machine.activate(
            caller_space,
            &mut self.fx,
            core::ptr::null_mut(),
        );
        result
    }

    /// Enumerate the native ROM's VBE modes and choose a conservative packed
    /// display for the host monitor. Discovery does not change the current mode.
    fn discover_vbe(
        &mut self,
        machine: &mut A,
        bios_display: &crate::kernel::platform::VgaCap,
    ) -> Option<crate::kernel::platform::VbeDisplayMode> {
        if crate::kernel::platform::get().firmware
            != crate::kernel::platform::Firmware::NativeBios
        {
            return None;
        }
        self.state_bytes = self.probe_state_size(machine, bios_display);
        self.state_probed = true;
        if let Some(bytes) = self.state_bytes {
            crate::compact_println!("VGA: VBE 4F04 capture checkpoint available ({} bytes)", bytes);
        } else if crate::kernel::platform::get().vga_readback {
            crate::compact_println!("VGA: VBE 4F04 unavailable — using Cirrus CR22/24/26 readbacks");
        } else {
            crate::compact_println!("VGA: WARNING no VBE state service or Cirrus readbacks — full process VGA restore NOT supported");
        }
        const INFO: usize = 0x9000;
        const MODE_INFO: usize = 0x9200;

        let mut info = VbeControllerInfo::request();
        let mut regs = Regs::empty();
        regs.rax = 0x4F00;
        regs.es = (INFO >> 4) as u64;
        regs.rdi = (INFO & 0xF) as u64;
        self.call_buffer(
            machine,
            bios_display,
            &mut regs,
            BiosTransfer::InOut(INFO, info.bytes_mut()),
        ).ok()?;
        if regs.rax as u16 != 0x004F {
            return None;
        }
        let far = info.video_modes;
        let list = usize::from((far >> 16) as u16) * 16 + usize::from(far as u16);
        let mut raw_modes = [0u8; 1024];
        self.read_workspace(machine, list, &mut raw_modes);

        let mut candidates = Vec::new();
        for raw in raw_modes.chunks_exact(2) {
            let number = u16::from_le_bytes([raw[0], raw[1]]);
            if number == 0xFFFF {
                break;
            }
            let mut regs = Regs::empty();
            let mut info = VbeModeInfo::empty();
            regs.rax = 0x4F01;
            regs.rcx = u64::from(number);
            regs.es = (MODE_INFO >> 4) as u64;
            regs.rdi = (MODE_INFO & 0xF) as u64;
            self.call_buffer(
                machine,
                bios_display,
                &mut regs,
                BiosTransfer::InOut(MODE_INFO, info.bytes_mut()),
            ).ok()?;
            if regs.rax as u16 == 0x004F
                && let Some(mode) = parse_vbe_mode(&info, number)
            {
                candidates.push(mode);
            }
        }

        // The OSD needs a useful packed high-resolution surface. Within that
        // class an LFB is strictly preferable to a bank window; only after the
        // publication mechanism is chosen do we minimize framebuffer traffic.
        // An indexed 8-bit mode never displaces a packed high-resolution mode.
        // Prefer the smallest mode that can contain every legacy VGA source.
        // Text scanout is 720 pixels wide because VGA repeats the ninth glyph
        // column; choosing a 640-wide VBE mode makes the direct scanout reject
        // that frame and leaves the freshly cleared OSD surface black. In the
        // usual VBE catalogue this selects 800x600, while still avoiding the
        // needless traffic of a 1024x768 surface on an old uncached LFB.
        self.modes = candidates;
        let selected = self.modes.iter().copied()
            .filter(|m| matches!(m.format, crate::kernel::display::FormatSpec::Packed(_)))
            .filter(|m| m.width >= 720 && m.height >= 480)
            .min_by_key(|m| (
                m.physical_base == 0,
                u32::from(m.pitch) * u32::from(m.height),
            ))
            .or_else(|| self.modes.iter().copied()
                .filter(|m| matches!(m.format, crate::kernel::display::FormatSpec::Packed(_)))
                .min_by_key(|m| (
                    m.physical_base == 0,
                    u32::from(m.pitch) * u32::from(m.height),
                )));

        let selected = selected.map(|mode| {
            crate::kernel::platform::VbeDisplayMode::try_from_bios_mode(mode)
                .unwrap_or_else(|| lib::compact_panic!(
                    "BIOS selected unusable VBE display mode {:#x}", mode.number
                ))
        });
        crate::compact_println!("VBE: {} available modes (* selected)", self.modes.len());
        for mode in &self.modes {
            crate::compact_println!(
                "VBE: {} {:#05x} {}x{}x{} pitch={} format={:?} phys={:#010x} bank={:04x}:{}K/{}K",
                if selected.is_some_and(|selected| selected.mode() == *mode) { '*' } else { ' ' },
                mode.number,
                mode.width,
                mode.height,
                mode.bits_per_pixel,
                mode.pitch,
                mode.format,
                mode.physical_base,
                mode.window_segment,
                mode.window_granularity_kb,
                mode.window_size_kb,
            );
        }
        selected
    }

    fn call_buffer(
        &mut self,
        machine: &mut A,
        bios_display: &crate::kernel::platform::VgaCap,
        regs: &mut Regs,
        mut transfer: BiosTransfer<'_>,
    ) -> Result<(), BiosError> {
        let caller_space = machine.activate(
            core::mem::take(&mut self.bios_vcpu.space),
            &mut self.fx,
            core::ptr::null_mut(),
        );
        let request = *regs;
        crate::kernel::dos::prepare_bios_int10(machine, regs);
        let frame = regs.frame;
        *regs = request;
        regs.frame = frame;
        match &transfer {
            BiosTransfer::Input(address, buffer) => machine.copy_to(*address, buffer),
            BiosTransfer::InOut(address, buffer) => machine.copy_to(*address, buffer),
            BiosTransfer::None | BiosTransfer::Output(..) => {}
        }
        let io = crate::kernel::io_policy::bios_display(bios_display);
        let completed = run_bios_int10(machine, regs, &io);
        if completed.is_ok() {
            match &mut transfer {
                BiosTransfer::Output(address, buffer) | BiosTransfer::InOut(address, buffer) => {
                    machine.copy_from(*address, buffer);
                }
                BiosTransfer::None | BiosTransfer::Input(..) => {}
            }
        }
        self.bios_vcpu.space = machine.activate(
            caller_space,
            &mut self.fx,
            core::ptr::null_mut(),
        );
        completed
    }

    fn read_workspace(&mut self, machine: &mut A, address: usize, output: &mut [u8]) {
        let caller_space = machine.activate(
            core::mem::take(&mut self.bios_vcpu.space),
            &mut self.fx,
            core::ptr::null_mut(),
        );
        machine.copy_from(address, output);
        self.bios_vcpu.space = machine.activate(
            caller_space,
            &mut self.fx,
            core::ptr::null_mut(),
        );
    }

}

/// Physical-display operations require the state-free VGA capability. The
/// BIOS display object owns the active Legacy/VBE state; its optional native
/// workspace is only the isolated real-mode execution engine.
impl crate::kernel::platform::VgaCap {
    fn bios<'a, A: Arch>(
        &self,
        bios: &'a mut BiosDisplayWorkspace<A>,
    ) -> Result<&'a mut NativeBiosWorkspace<A>, BiosError> {
        bios.native.as_mut().ok_or(BiosError::NoNativeBios)
    }

    fn bios_ref<'a, A: Arch>(
        &self,
        bios: &'a BiosDisplayWorkspace<A>,
    ) -> Result<&'a NativeBiosWorkspace<A>, BiosError> {
        bios.native.as_ref().ok_or(BiosError::NoNativeBios)
    }

    pub fn bios_mode<A: Arch>(
        &self,
        bios: &BiosDisplayWorkspace<A>,
        number: u16,
    ) -> Option<crate::kernel::platform::VbeMode> {
        self.bios_ref(bios).ok()?.mode(number)
    }

    pub fn bios_modes<'a, A: Arch>(
        &self,
        bios: &'a BiosDisplayWorkspace<A>,
    ) -> Option<&'a [crate::kernel::platform::VbeMode]> {
        Some(self.bios_ref(bios).ok()?.modes())
    }

    pub(crate) fn bios_checkpoint<A: Arch>(
        &self,
        machine: &mut A,
        bios: &mut BiosDisplayWorkspace<A>,
    ) -> Option<FirmwareCheckpoint> {
        self.bios(bios).ok()?.checkpoint(machine, self)
    }

    pub(crate) fn bios_restore_checkpoint<A: Arch>(
        &self,
        machine: &mut A,
        bios: &mut BiosDisplayWorkspace<A>,
        state: &FirmwareCheckpoint,
    ) {
        self.bios(bios)
            .and_then(|bios| bios.restore_checkpoint(machine, self, state))
            .unwrap_or_else(|error| lib::compact_panic!(
                "native video BIOS failed to restore capture checkpoint: {:?}", error,
            ));
    }

    pub fn bios_set_mode<A: Arch>(
        &mut self,
        machine: &mut A,
        bios: &mut BiosDisplayWorkspace<A>,
        mode: u16,
    ) {
        self.guest_bios_set_mode(machine, bios, mode)
            .unwrap_or_else(|error| lib::compact_panic!("native BIOS mode {:#x} failed: {:?}", mode, error))
    }

    pub fn bios_set_mode_request<A: Arch>(
        &mut self,
        machine: &mut A,
        bios: &mut BiosDisplayWorkspace<A>,
        request: u16,
    ) {
        self.guest_bios_set_mode_request(machine, bios, request)
            .unwrap_or_else(|error| lib::compact_panic!("native BIOS mode request {:#x} failed: {:?}", request, error))
    }

    /// Guest INT 10h mode selection may legitimately be rejected by firmware.
    pub fn guest_bios_set_mode<A: Arch>(
        &mut self,
        machine: &mut A,
        bios: &mut BiosDisplayWorkspace<A>,
        mode: u16,
    ) -> Result<(), BiosError> {
        self.guest_bios_set_mode_request(
            machine, bios, mode | if mode > 0xFF { 0x4000 } else { 0 },
        )
    }

    /// Guest VBE 4F02h preserves the complete request and reports failure in AX.
    pub fn guest_bios_set_mode_request<A: Arch>(
        &mut self,
        machine: &mut A,
        bios: &mut BiosDisplayWorkspace<A>,
        request: u16,
    ) -> Result<(), BiosError> {
        let number = request & 0x3FFF;
        let mode = if number > 0xFF {
            Some(self.bios_ref(bios)?.mode(number).ok_or(BiosError::Rejected(0x014F))?)
        } else { None };
        self.bios(bios)?.set_mode_request(machine, self, request)?;
        if let Some(mode) = mode {
            if matches!(mode.format, crate::kernel::display::FormatSpec::Indexed8)
                || mode.programmable_ramp
            {
                let mut entries = alloc::vec![0; 1024];
                if !vga::VbePalette::new().read(0, &mut entries) {
                    return Err(BiosError::InvalidFrame);
                }
                bios.mark_vbe(mode, request);
                self.bios_indexed_palette_call(machine, bios, 0, 0, &mut entries)?;
            } else {
                bios.mark_vbe(mode, request);
            }
        } else {
            bios.mark_legacy();
        }
        Ok(())
    }

    pub fn bios_set_bank<A: Arch>(
        &mut self,
        machine: &mut A,
        bios: &mut BiosDisplayWorkspace<A>,
        mode: crate::kernel::platform::VbeMode,
        bank: u16,
    ) -> Result<(), BiosError> {
        self.bios(bios)?.set_bank(machine, self, mode, bank)
    }

    pub fn guest_bios_window<A: Arch>(
        &mut self,
        machine: &mut A,
        bios: &mut BiosDisplayWorkspace<A>,
        set: Option<u16>,
    ) -> Result<u16, BiosError> {
        let BiosDisplayWorkspace { active, native } = bios;
        let PhysicalVideoState::Vbe(state) = active else { return Err(BiosError::Rejected(0x014F)); };
        native.as_mut().ok_or(BiosError::NoNativeBios)?.window(machine, self, state, set)
    }

    pub fn guest_bios_display_start<A: Arch>(
        &mut self,
        machine: &mut A,
        bios: &mut BiosDisplayWorkspace<A>,
        caller: &mut Regs,
    ) -> Result<(), BiosError> {
        let BiosDisplayWorkspace { active, native } = bios;
        let PhysicalVideoState::Vbe(state) = active else { return Err(BiosError::Rejected(0x014F)); };
        native.as_mut().ok_or(BiosError::NoNativeBios)?.display_start(machine, self, state, caller)
    }

    pub fn guest_bios_scan_line_length<A: Arch>(
        &mut self,
        machine: &mut A,
        bios: &mut BiosDisplayWorkspace<A>,
        caller: &mut Regs,
    ) -> Result<(), BiosError> {
        let BiosDisplayWorkspace { active, native } = bios;
        let PhysicalVideoState::Vbe(state) = active else { return Err(BiosError::Rejected(0x014F)); };
        native.as_mut().ok_or(BiosError::NoNativeBios)?.scan_line_length(machine, self, state, caller)
    }

    pub(crate) fn bios_indexed_palette_call<A: Arch>(
        &mut self,
        machine: &mut A,
        bios: &mut BiosDisplayWorkspace<A>,
        subfn: u8,
        start: u16,
        entries: &mut [u8],
    ) -> Result<(), BiosError> {
        let BiosDisplayWorkspace { active, native } = bios;
        let PhysicalVideoState::Vbe(state) = active else { return Err(BiosError::Rejected(0x014F)); };
        let physical_dac = state.mode.vga_compatible
            && matches!(state.mode.format, crate::kernel::display::FormatSpec::Indexed8);
        native.as_mut().ok_or(BiosError::NoNativeBios)?.indexed_palette_call(
            machine, self, &mut state.svga.palette, physical_dac, subfn, start, entries,
        )
    }

    pub fn bios_palette_call<A: Arch>(
        &mut self,
        machine: &mut A,
        bios: &mut BiosDisplayWorkspace<A>,
        caller: &mut Regs,
        buffer: Option<&mut [u8]>,
        copy_to_bios: bool,
        offset_in_di: bool,
    ) -> Result<(), BiosError> {
        self.bios(bios)?.palette_call(
            machine, self, caller, buffer, copy_to_bios, offset_in_di,
        )
    }

    pub fn bios_font_call<A: Arch>(
        &mut self,
        machine: &mut A,
        bios: &mut BiosDisplayWorkspace<A>,
        caller: &mut Regs,
        font: Option<&[u8]>,
    ) -> Result<(), BiosError> {
        self.bios(bios)?.font_call(machine, self, caller, font)
    }

    pub fn bios_present<A: Arch>(
        &mut self,
        machine: &mut A,
        bios: &mut BiosDisplayWorkspace<A>,
        mode: crate::kernel::platform::VbeMode,
        current_bank: &mut u16,
        shadow_height: usize,
        shadow: &[u8],
    ) -> Result<usize, BiosError> {
        self.bios(bios)?.present_banked(
            machine, self, mode, current_bank, shadow_height, shadow,
        )
    }

    pub(crate) fn bios_present_packed<A: Arch>(
        &mut self,
        machine: &mut A,
        bios: &mut BiosDisplayWorkspace<A>,
        mode: crate::kernel::platform::VbeMode,
        current_bank: &mut u16,
        source: crate::kernel::display::PackedSource<'_>,
    ) -> Result<usize, BiosError> {
        self.bios(bios)?.present_banked_packed(
            machine, self, mode, current_bank, source,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn bios_present_packed_regions<A: Arch>(
        &mut self,
        machine: &mut A,
        bios: &mut BiosDisplayWorkspace<A>,
        mode: crate::kernel::platform::VbeMode,
        current_bank: &mut u16,
        width: usize,
        height: usize,
        pixels: &[u8],
        regions: &[crate::kernel::gui::Rect],
    ) -> Result<usize, BiosError> {
        self.bios(bios)?.present_banked_packed_regions(
            machine, self, mode, current_bank, width, height, pixels, regions,
        )
    }

    pub fn bios_discover_vbe<A: Arch>(
        &self,
        machine: &mut A,
        bios: &mut BiosDisplayWorkspace<A>,
    ) -> Option<crate::kernel::platform::VbeDisplayMode> {
        self.bios(bios).ok()?.discover_vbe(machine, self)
    }
}

fn run_bios_int10<A: Arch>(
    machine: &mut A,
    regs: &mut Regs,
    io: &arch_abi::IoPolicy,
) -> Result<(), BiosError> {
    run_bios(machine, regs, io, crate::kernel::dos::bios_int10_returned)
}

fn run_bios_until<A: Arch>(
    machine: &mut A,
    regs: &mut Regs,
    return_ip: u32,
    io: &arch_abi::IoPolicy,
) -> Result<(), BiosError> {
    run_bios(machine, regs, io, |regs, event| {
        crate::kernel::dos::bios_thunk_returned(regs, event, return_ip)
    })
}

fn run_bios<A: Arch>(
    machine: &mut A,
    regs: &mut Regs,
    io: &arch_abi::IoPolicy,
    returned: impl Fn(&Regs, &crate::KernelEvent) -> bool,
) -> Result<(), BiosError> {
    loop {
        let event = machine.execute(regs, io);
        if returned(regs, &event) {
            return Ok(());
        }
        match event {
            // A hardware interrupt is merely a scheduling exit. The BIOS call
            // is deliberately non-interruptible at the Rust level.
            crate::KernelEvent::Irq => {}
            crate::KernelEvent::In { port, size } => {
                let (mask, value) = match size {
                    IoSize::Byte => (0xFF, u64::from(machine.inb(port))),
                    IoSize::Word => (0xFFFF, u64::from(machine.inw(port))),
                    IoSize::Dword => (0xFFFF_FFFF, u64::from(machine.inl(port))),
                };
                regs.rax = (regs.rax & !mask) | value;
            }
            crate::KernelEvent::Out { port, size } => match size {
                IoSize::Byte => machine.outb(port, regs.rax as u8),
                IoSize::Word => machine.outw(port, regs.rax as u16),
                IoSize::Dword => machine.outl(port, regs.rax as u32),
            },
            _ => return Err(BiosError::UnexpectedEvent),
        }
    }
}

fn prepare_bank_call<A: Arch>(
    machine: &mut A,
    regs: &mut Regs,
    mode: crate::kernel::platform::VbeMode,
    bank: u16,
) -> u32 {
    let return_ip = if mode.window_function == 0 {
        crate::kernel::dos::prepare_bios_int10(machine, regs);
        // INT 10h; INT 31h occupies two adjacent two-byte vector slots.
        crate::kernel::dos::bios_int10_return_ip()
    } else {
        crate::kernel::dos::prepare_bios_window_call(machine, regs, mode.window_function)
    };
    regs.rax = 0x4F05;
    regs.rbx = 0;
    regs.rdx = u64::from(bank);
    return_ip
}

fn parse_vbe_mode(
    info: &VbeModeInfo,
    number: u16,
) -> Option<crate::kernel::platform::VbeMode> {
    let attributes = info.attributes;
    let memory_model = info.memory_model;
    if attributes & 0x0019 != 0x0019 || !matches!(memory_model, 4 | 6) {
        return None;
    }
    let width = info.width;
    let height = info.height;
    let bpp = info.bits_per_pixel;
    let programmable_ramp = info.direct_color_attributes & 0x01 != 0;
    let physical_base_raw = info.physical_base;
    let linear = attributes & 0x0080 != 0 && physical_base_raw != 0;
    let physical_base = if linear { physical_base_raw } else { 0 };
    let banked_pitch = info.banked_pitch;
    let linear_pitch_raw = info.linear_pitch;
    let linear_pitch = if linear_pitch_raw != 0 { linear_pitch_raw } else { banked_pitch };
    let pitch = if linear { linear_pitch } else { banked_pitch };
    let linear_fields = [
        info.linear_red_position, info.linear_red_mask_size,
        info.linear_green_position, info.linear_green_mask_size,
        info.linear_blue_position, info.linear_blue_mask_size,
    ];
    let legacy_fields = [
        info.red_position, info.red_mask_size,
        info.green_position, info.green_mask_size,
        info.blue_position, info.blue_mask_size,
    ];
    let fields = if linear && linear_fields[1] != 0 { linear_fields } else { legacy_fields };
    let format = if memory_model == 4 && bpp == 8 {
        crate::kernel::display::FormatSpec::Indexed8
    } else {
        let format = crate::kernel::display::PixelFormat::from_rgb(
            bpp.div_ceil(8), fields,
        )?;
        let supported = match bpp {
            15 => crate::kernel::display::PixelFormat::RGB555,
            16 => crate::kernel::display::PixelFormat::RGB565,
            24 => crate::kernel::display::PixelFormat::RGB888,
            32 => crate::kernel::display::PixelFormat::NATIVE,
            _ => return None,
        };
        // The software OSD renderer deliberately implements only these
        // canonical packed layouts. An otherwise valid vendor-specific mask
        // is not a mode RetroOS can faithfully composite.
        if format != supported { return None; }
        crate::kernel::display::FormatSpec::Packed(format)
    };
    let bytes_per_pixel = match format {
        crate::kernel::display::FormatSpec::Packed(format) => format.bytes_per_pixel,
        crate::kernel::display::FormatSpec::Indexed8 => 1,
    };
    let window_segment = info.window_a_segment;
    let window_attributes = info.window_a_attributes;
    let window_granularity_kb = info.window_granularity_kb;
    let window_size_kb = info.window_size_kb;
    let window_function = info.window_function;
    let banked_image_pages = info.banked_image_pages;
    let linear_image_pages = info.linear_image_pages;
    let banked_bytes = u32::from(banked_pitch)
        .checked_mul(u32::from(height))?
        .checked_mul(u32::from(banked_image_pages) + 1)?;
    let linear_bytes = u32::from(linear_pitch)
        .checked_mul(u32::from(height))?
        .checked_mul(u32::from(linear_image_pages) + 1)?;
    let framebuffer_bytes = banked_bytes.max(linear_bytes);
    if width == 0 || height == 0 || (physical_base == 0 && window_segment == 0)
        || (physical_base == 0
            && (window_attributes & 0x05 != 0x05
                || window_granularity_kb == 0 || window_size_kb == 0))
        || usize::from(banked_pitch) < usize::from(width) * usize::from(bytes_per_pixel)
        || usize::from(linear_pitch) < usize::from(width) * usize::from(bytes_per_pixel)
        || framebuffer_bytes as usize > 16 * 1024 * 1024
    {
        return None;
    }
    Some(crate::kernel::platform::VbeMode {
        number, vga_compatible: attributes & 0x0020 == 0,
        physical_base, width, height, pitch, banked_pitch, linear_pitch,
        bits_per_pixel: bpp, format, programmable_ramp,
        window_segment,
        window_granularity_kb,
        window_size_kb,
        banked_image_pages,
        linear_image_pages,
        framebuffer_bytes,
        window_function,
    })
}
