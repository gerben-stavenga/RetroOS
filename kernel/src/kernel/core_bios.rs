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

/// Opaque controller state produced by VBE 4F04h. Its layout belongs to the
/// machine's video BIOS; the kernel only carries it between ownership turns.
#[derive(Clone)]
pub struct VbeState(Vec<u8>);

/// Software VGA state owned by the core INT 10h/video-BIOS driver.
pub struct EmulatedVga {
    pub state: alloc::boxed::Box<vga::VgaState>,
    /// Opaque controller state saved by native video firmware.
    pub(crate) firmware_state: Option<VbeState>,
    /// Guest pages backing the substitute-VBE aperture.
    pub svga_pages: usize,
    /// Firmware transition needed when returning to native VGA ownership.
    pub(crate) resume_vbe: Option<VbeResume>,
    /// Physical framebuffer whose aliases target `SVGA_LFB_BASE` while this
    /// VGA is detached from the adapter.
    pub(crate) physical_lfb: Option<u32>,
    /// Legacy BIOS mode whose persistent BDA state must be re-established
    /// before restoring direct-register state. Meaningful when `resume_vbe`
    /// is absent.
    pub(crate) resume_legacy_mode: u8,
}

#[derive(Clone, Copy)]
pub(crate) struct VbeResume {
    pub(crate) request: u16,
    pub(crate) bank: Option<u16>,
}

/// A VGA paired with an output target. Native VGA intrinsically owns physical
/// scanout; an emulated VGA targets a real, composited, hosted, or headless
/// display.
pub enum DisplayedVga {
    Native(crate::kernel::platform::NativeVga),
    Emulated(EmulatedVga, crate::kernel::display::Display),
}

impl EmulatedVga {
    /// Construct the conventional initial PC text display image without
    /// publishing it into any particular guest address space.
    pub fn initial_mode3() -> Self {
        Self {
            state: vga::VgaState::new_mode3_boxed(),
            firmware_state: None,
            svga_pages: 0,
            resume_vbe: None,
            physical_lfb: None,
            resume_legacy_mode: 3,
        }
    }

    pub(crate) fn clone_for_fork(&self) -> Self {
        Self {
            state: alloc::boxed::Box::new((*self.state).clone()),
            firmware_state: self.firmware_state.clone(),
            svga_pages: self.svga_pages,
            resume_vbe: self.resume_vbe,
            physical_lfb: self.physical_lfb,
            resume_legacy_mode: self.resume_legacy_mode,
        }
    }
}

/// Runtime native-video firmware service. The object is always present so it
/// can flow through backend-independent scheduling code; only a native-BIOS
/// platform has an execution workspace inside it. The interior is deliberately
/// private and can only be opened by a [`VgaCap`](crate::kernel::platform::VgaCap).
pub struct BiosDisplayWorkspace<A: Arch>(Option<NativeBiosWorkspace<A>>);

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
        Self(native)
    }

    /// Backend paths which deliberately bypass platform probing (the hosted
    /// bare-ELF runner) have no native video firmware.
    pub(crate) fn absent() -> Self { Self(None) }
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
        self.with_bios_workspace(
            machine,
            display,
            &mut regs,
            |_, regs| {
                regs.rax = 0x4F04;
                regs.rcx = Self::STATE_COMPONENTS;
                regs.rdx = 0;
            },
            |_, regs| {
                if regs.rax as u16 != 0x004F { return None; }
                let bytes = usize::from(regs.rbx as u16).checked_mul(64)?;
                (bytes != 0 && bytes <= Self::MAX_STATE_BYTES).then_some(bytes)
            },
        ).ok().flatten()
    }

    /// Save all firmware-visible controller state. Failure means the caller
    /// should retain its direct-register fallback; it is not a fatal display
    /// error because many plain VGA BIOSes predate VBE.
    fn save_state(
        &mut self,
        machine: &mut A,
        display: &crate::kernel::platform::VgaCap,
    ) -> Option<VbeState> {
        if !self.state_probed {
            self.state_bytes = self.probe_state_size(machine, display);
            self.state_probed = true;
        }
        let bytes = self.state_bytes?;
        let mut regs = Regs::empty();
        self.with_bios_workspace(
            machine,
            display,
            &mut regs,
            |machine, regs| {
                machine.copy_to(Self::STATE_BUFFER, &alloc::vec![0; bytes]);
                regs.rax = 0x4F04;
                regs.rcx = Self::STATE_COMPONENTS;
                regs.rdx = 1;
                regs.es = (Self::STATE_BUFFER >> 4) as u64;
                regs.rbx = (Self::STATE_BUFFER & 0xF) as u64;
            },
            |machine, regs| {
                if regs.rax as u16 != 0x004F { return None; }
                let mut state = alloc::vec![0; bytes];
                machine.copy_from(Self::STATE_BUFFER, &mut state);
                Some(VbeState(state))
            },
        ).ok().flatten()
    }

    /// Restore a blob returned by [`save_state`](Self::save_state).
    /// Call this after restoring framebuffer memory: VBE state includes the
    /// exact hidden VGA/SVGA sequencing state that direct memory access would
    /// otherwise disturb.
    fn restore_state(
        &mut self,
        machine: &mut A,
        display: &crate::kernel::platform::VgaCap,
        state: &VbeState,
    ) -> Result<(), BiosError> {
        if state.0.is_empty() || state.0.len() > Self::MAX_STATE_BYTES {
            return Err(BiosError::InvalidStateSize);
        }
        let mut regs = self.bios_vcpu.regs;
        self.with_bios_workspace(
            machine,
            display,
            &mut regs,
            |machine, regs| {
                machine.copy_to(Self::STATE_BUFFER, &state.0);
                regs.rax = 0x4F04;
                regs.rcx = Self::STATE_COMPONENTS;
                regs.rdx = 2;
                regs.es = (Self::STATE_BUFFER >> 4) as u64;
                regs.rbx = (Self::STATE_BUFFER & 0xF) as u64;
            },
            |_, _| (),
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
    fn set_mode(
        &mut self,
        machine: &mut A,
        bios_display: &mut crate::kernel::platform::VgaCap,
        mode: u16,
    ) -> Result<(), BiosError> {
        self.set_mode_request(machine, bios_display, mode | if mode > 0xFF { 0x4000 } else { 0 })
    }

    /// Execute a guest-requested native mode set. `request` retains VBE's LFB
    /// bit. The persistent firmware workspace remains the authority for the
    /// resulting current mode.
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
            let mut regs = self.bios_vcpu.regs;
            self.with_bios_workspace(machine, bios_display, &mut regs, |_, regs| {
                regs.rax = u64::from(number);
            }, |_, _| ())?;
            return Ok(());
        }
        let Some(_) = self.mode(number) else {
            return Err(BiosError::Rejected(0x014F));
        };
        let mut regs = self.bios_vcpu.regs;
        self.with_bios_workspace(machine, bios_display, &mut regs, |_, regs| {
            regs.rax = 0x4F02;
            regs.rbx = u64::from(request);
        }, |_, _| ())?;
        let status = regs.rax as u16;
        if status == 0x004F { Ok(()) } else {
            Err(BiosError::Rejected(status))
        }
    }

    /// Ask the persistent firmware instance which VBE mode currently owns the
    /// adapter. Legacy modes return `None`; VBE returns its descriptor and the
    /// LFB bit reported by 4F03h.
    fn current_vbe_mode(
        &mut self,
        machine: &mut A,
        display: &crate::kernel::platform::VgaCap,
    ) -> Result<Option<(crate::kernel::platform::VbeMode, bool)>, BiosError> {
        let mut regs = self.bios_vcpu.regs;
        self.with_bios_workspace(machine, display, &mut regs, |_, regs| {
            regs.rax = 0x4F03;
        }, |_, _| ())?;
        let status = regs.rax as u16;
        if status != 0x004F {
            return Err(BiosError::Rejected(status));
        }
        let request = regs.rbx as u16;
        let number = request & 0x3FFF;
        if number <= 0xFF {
            return Ok(None);
        }
        let mode = self.mode(number).ok_or(BiosError::Rejected(0x014F))?;
        Ok(Some((mode, request & 0x4000 != 0)))
    }

    fn current_legacy_mode(
        &mut self,
        machine: &mut A,
        display: &crate::kernel::platform::VgaCap,
    ) -> Result<u8, BiosError> {
        let mut regs = self.bios_vcpu.regs;
        self.with_bios_workspace(machine, display, &mut regs, |_, regs| {
            regs.rax = 0x0F00;
        }, |_, _| ())?;
        Ok(regs.rax as u8)
    }

    /// Forward VBE 4F05h to the same persistent firmware instance. This is
    /// authoritative even when a program used a firmware window-function
    /// entry rather than the substitute BIOS path.
    fn window(
        &mut self,
        machine: &mut A,
        display: &crate::kernel::platform::VgaCap,
        set: Option<u16>,
    ) -> Result<u16, BiosError> {
        let mut regs = self.bios_vcpu.regs;
        self.with_bios_workspace(machine, display, &mut regs, |_, regs| {
            regs.rax = 0x4F05;
            regs.rbx = if set.is_some() { 0 } else { 0x0100 };
            regs.rdx = u64::from(set.unwrap_or(0));
        }, |_, _| ())?;
        let status = regs.rax as u16;
        if status == 0x004F { Ok(regs.rdx as u16) } else { Err(BiosError::Rejected(status)) }
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
        let input_data = if copy_to_bios {
            buffer.as_ref().map(|b| b.to_vec())
        } else {
            None
        };
        let mut regs = self.bios_vcpu.regs;
        let output = self.with_bios_workspace(
            machine,
            display,
            &mut regs,
            |machine, regs| {
                regs.rax = input[0];
                regs.rbx = input[1];
                regs.rcx = input[2];
                regs.rdx = input[3];
                if len != 0 {
                    if let Some(data) = input_data.as_deref() {
                        machine.copy_to(Self::STATE_BUFFER, data);
                    }
                    regs.es = (Self::STATE_BUFFER >> 4) as u64;
                    if offset_in_di {
                        regs.rdi = (Self::STATE_BUFFER & 0xF) as u64;
                    } else {
                        regs.rdx = (Self::STATE_BUFFER & 0xF) as u64;
                    }
                }
            },
            |machine, _| {
                let mut data = alloc::vec![0; len];
                if len != 0 && !copy_to_bios {
                    machine.copy_from(Self::STATE_BUFFER, &mut data);
                }
                data
            },
        )?;

        // VBE reports status in AX. Legacy AH=10h/AL=15h additionally returns
        // one DAC entry in DH/CH/CL. Do not leak the bounce-buffer offset back
        // through DX/DI for pointer-bearing calls.
        caller.rax = regs.rax;
        if input[0] as u16 == 0x1015 {
            caller.rcx = regs.rcx;
            caller.rdx = regs.rdx;
        }
        if let Some(dst) = buffer
            && !copy_to_bios
        {
            dst.copy_from_slice(&output);
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
        let data = font.map(<[u8]>::to_vec);
        let mut regs = self.bios_vcpu.regs;
        self.with_bios_workspace(
            machine,
            display,
            &mut regs,
            |machine, regs| {
                regs.rax = input[0];
                regs.rbx = input[1];
                regs.rcx = input[2];
                regs.rdx = input[3];
                if let Some(data) = data.as_deref() {
                    machine.copy_to(Self::STATE_BUFFER, data);
                    regs.es = (Self::STATE_BUFFER >> 4) as u64;
                    regs.rbp = (Self::STATE_BUFFER & 0xF) as u64;
                }
            },
            |_, _| (),
        )?;
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
        let crate::kernel::display::FormatSpec::Packed(rgb) = mode.format else {
            return Err(BiosError::InvalidFrame);
        };
        let (shadow_width, _) = crate::kernel::display::fit_vga(
            usize::from(mode.width), usize::from(mode.height),
        );
        let step = usize::from(rgb.bytes_per_pixel);
        let row_bytes = shadow_width.checked_mul(step).ok_or(BiosError::InvalidFrame)?;
        let needed = row_bytes.checked_mul(shadow_height).ok_or(BiosError::InvalidFrame)?;
        let panel_w = usize::from(mode.width);
        let panel_h = usize::from(mode.height);
        let pitch = usize::from(mode.pitch);
        let granularity = usize::from(mode.window_granularity_kb) * 1024;
        let window_size = usize::from(mode.window_size_kb) * 1024;
        if shadow_height == 0 || shadow.len() < needed
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
            let (out_w, out_h) = crate::kernel::display::fit_vga(panel_w, panel_h);
            if shadow_width != out_w { return Err(BiosError::InvalidFrame); }
            let bx = (panel_w - out_w) / 2;
            let by = (panel_h - out_h) / 2;
            let (ybase, yrem) = (out_h / shadow_height, out_h % shadow_height);
            let aperture = usize::from(mode.window_segment) * 16;
            let mut current_bank = None;
            let mut oy = 0usize;
            let mut yerr = 0usize;

            for sy in 0..shadow_height {
                yerr += yrem;
                let carry = usize::from(yerr >= shadow_height);
                let rows = ybase + carry;
                yerr -= carry * shadow_height;
                let src = &shadow[sy * row_bytes..(sy + 1) * row_bytes];
                for _ in 0..rows {
                    let mut source = src;
                    let mut offset = (by + oy) * pitch + bx * step;
                    while !source.is_empty() {
                        let window_base = offset / window_size * window_size;
                        let bank_usize = window_base / granularity;
                        let bank = u16::try_from(bank_usize).map_err(|_| BiosError::InvalidFrame)?;
                        if current_bank != Some(bank) {
                            let mut regs = self.bios_vcpu.regs;
                            let return_ip = prepare_bank_call(machine, &mut regs, mode, bank);
                            run_bios_until(machine, &mut regs, return_ip, &io)?;
                            let status = regs.rax as u16;
                            if status != 0x004F { return Err(BiosError::Rejected(status)); }
                            *bank_state = bank;
                            current_bank = Some(bank);
                        }
                        let inside = offset - window_base;
                        let count = source.len().min(window_size - inside);
                        machine.copy_to(aperture + inside, &source[..count]);
                        source = &source[count..];
                        offset += count;
                    }
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
            crate::println!("VGA: VBE 4F04 state save/restore ({} bytes) — exact ownership handoff", bytes);
        } else if crate::kernel::platform::get().vga_readback {
            crate::println!("VGA: VBE 4F04 unavailable — using Cirrus CR22/24/26 readbacks");
        } else {
            crate::println!("VGA: WARNING no VBE state service or Cirrus readbacks — full process VGA restore NOT supported");
        }
        const INFO: usize = 0x9000;
        const MODE_INFO: usize = 0x9200;

        let mut regs = Regs::empty();
        let modes = self.with_bios_workspace(
            machine,
            bios_display,
            &mut regs,
            |machine, regs| {
                machine.copy_to(INFO, &[0; 512]);
                machine.copy_to(INFO, b"VBE2");
                regs.rax = 0x4F00;
                regs.es = (INFO >> 4) as u64;
                regs.rdi = (INFO & 0xF) as u64;
            },
            |machine, regs| {
                if regs.rax as u16 != 0x004F {
                    return Vec::new();
                }
                let far = machine.read::<u32>(INFO + 14);
                let list = usize::from((far >> 16) as u16) * 16 + usize::from(far as u16);
                let mut modes = Vec::new();
                for i in 0..512 {
                    let mode = machine.read::<u16>(list + i * 2);
                    if mode == 0xFFFF { break; }
                    modes.push(mode);
                }
                modes
            },
        ).ok()?;

        let mut candidates = Vec::new();
        for number in modes {
            let mut regs = Regs::empty();
            let mode = self.with_bios_workspace(
                machine,
                bios_display,
                &mut regs,
                |machine, regs| {
                    machine.copy_to(MODE_INFO, &[0; 256]);
                    regs.rax = 0x4F01;
                    regs.rcx = u64::from(number);
                    regs.es = (MODE_INFO >> 4) as u64;
                    regs.rdi = (MODE_INFO & 0xF) as u64;
                },
                |machine, regs| {
                    if regs.rax as u16 != 0x004F { return None; }
                    parse_vbe_mode(machine, MODE_INFO, number)
                },
            ).ok().flatten();
            if let Some(mode) = mode {
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
                .unwrap_or_else(|| panic!(
                    "BIOS selected unusable VBE display mode {:#x}", mode.number
                ))
        });
        crate::println!("VBE: {} available modes (* selected)", self.modes.len());
        for mode in &self.modes {
            crate::println!(
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

    fn with_bios_workspace<T, F, G>(
        &mut self,
        machine: &mut A,
        bios_display: &crate::kernel::platform::VgaCap,
        regs: &mut Regs,
        configure: F,
        collect: G,
    ) -> Result<T, BiosError>
    where
        F: FnOnce(&mut A, &mut Regs),
        G: FnOnce(&mut A, &Regs) -> T,
    {
        // The ROM owns one persistent private real-mode workspace, just as it
        // does on a physical PC. It is isolated from every guest address space,
        // but BIOS scratch/BDA state intentionally survives between calls.
        // Keeping that workspace parked here also makes high-frequency VBE
        // operations (notably 4F05h bank switching) ordinary BIOS executions
        // instead of a COW fork + full page-table teardown per bank.
        let caller_space = machine.activate(
            core::mem::take(&mut self.bios_vcpu.space),
            &mut self.fx,
            core::ptr::null_mut(),
        );

        crate::kernel::dos::prepare_bios_int10(machine, regs);
        configure(machine, regs);
        let io = crate::kernel::io_policy::bios_display(bios_display);
        let completed = run_bios_int10(machine, regs, &io);

        let result = completed.map(|()| collect(machine, regs));

        // `self.fx` contains the caller's displaced FPU image. Restore both
        // caller resources and park the BIOS workspace/FPU state for next time.
        self.bios_vcpu.space = machine.activate(
            caller_space,
            &mut self.fx,
            core::ptr::null_mut(),
        );
        result
    }
}

/// Native video-ROM operations are methods on the physical VGA capability:
/// the receiver proves that the caller owns the adapter, while the workspace
/// is only the isolated real-mode execution engine.
impl crate::kernel::platform::VgaCap {
    fn bios<'a, A: Arch>(
        &self,
        bios: &'a mut BiosDisplayWorkspace<A>,
    ) -> Result<&'a mut NativeBiosWorkspace<A>, BiosError> {
        bios.0.as_mut().ok_or(BiosError::NoNativeBios)
    }

    fn bios_ref<'a, A: Arch>(
        &self,
        bios: &'a BiosDisplayWorkspace<A>,
    ) -> Result<&'a NativeBiosWorkspace<A>, BiosError> {
        bios.0.as_ref().ok_or(BiosError::NoNativeBios)
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

    pub fn bios_save_state<A: Arch>(
        &self,
        machine: &mut A,
        bios: &mut BiosDisplayWorkspace<A>,
    ) -> Option<VbeState> {
        self.bios(bios).ok()?.save_state(machine, self)
    }

    pub fn bios_restore_state<A: Arch>(
        &self,
        machine: &mut A,
        bios: &mut BiosDisplayWorkspace<A>,
        state: &VbeState,
    ) -> Result<(), BiosError> {
        self.bios(bios)?.restore_state(machine, self, state)
    }

    pub fn bios_set_mode<A: Arch>(
        &mut self,
        machine: &mut A,
        bios: &mut BiosDisplayWorkspace<A>,
        mode: u16,
    ) {
        self.guest_bios_set_mode(machine, bios, mode)
            .unwrap_or_else(|error| panic!("native BIOS mode {:#x} failed: {:?}", mode, error))
    }

    pub fn bios_set_mode_request<A: Arch>(
        &mut self,
        machine: &mut A,
        bios: &mut BiosDisplayWorkspace<A>,
        request: u16,
    ) {
        self.guest_bios_set_mode_request(machine, bios, request)
            .unwrap_or_else(|error| panic!("native BIOS mode request {:#x} failed: {:?}", request, error))
    }

    /// Guest INT 10h mode selection may legitimately be rejected by firmware.
    pub fn guest_bios_set_mode<A: Arch>(
        &mut self,
        machine: &mut A,
        bios: &mut BiosDisplayWorkspace<A>,
        mode: u16,
    ) -> Result<(), BiosError> {
        self.bios(bios)?.set_mode(machine, self, mode)
    }

    /// Guest VBE 4F02h preserves the complete request and reports failure in AX.
    pub fn guest_bios_set_mode_request<A: Arch>(
        &mut self,
        machine: &mut A,
        bios: &mut BiosDisplayWorkspace<A>,
        request: u16,
    ) -> Result<(), BiosError> {
        self.bios(bios)?.set_mode_request(machine, self, request)
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

    pub fn bios_current_vbe_mode<A: Arch>(
        &self,
        machine: &mut A,
        bios: &mut BiosDisplayWorkspace<A>,
    ) -> Result<Option<(crate::kernel::platform::VbeMode, bool)>, BiosError> {
        self.bios(bios)?.current_vbe_mode(machine, self)
    }

    pub fn bios_current_legacy_mode<A: Arch>(
        &self,
        machine: &mut A,
        bios: &mut BiosDisplayWorkspace<A>,
    ) -> Result<u8, BiosError> {
        self.bios(bios)?.current_legacy_mode(machine, self)
    }

    pub fn guest_bios_window<A: Arch>(
        &self,
        machine: &mut A,
        bios: &mut BiosDisplayWorkspace<A>,
        set: Option<u16>,
    ) -> Result<u16, BiosError> {
        self.bios(bios)?.window(machine, self, set)
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

fn parse_vbe_mode<A: Arch>(
    machine: &A,
    address: usize,
    number: u16,
) -> Option<crate::kernel::platform::VbeMode> {
    let attributes = machine.read::<u16>(address);
    let memory_model = machine.read::<u8>(address + 0x1B);
    if attributes & 0x0019 != 0x0019 || !matches!(memory_model, 4 | 6) {
        return None;
    }
    let width = machine.read::<u16>(address + 0x12);
    let height = machine.read::<u16>(address + 0x14);
    let bpp = machine.read::<u8>(address + 0x19);
    let physical_base_raw = machine.read::<u32>(address + 0x28);
    let linear = attributes & 0x0080 != 0 && physical_base_raw != 0;
    let physical_base = if linear { physical_base_raw } else { 0 };
    let linear_pitch = machine.read::<u16>(address + 0x32);
    let pitch = if linear && linear_pitch != 0 {
        linear_pitch
    } else {
        machine.read::<u16>(address + 0x10)
    };
    let linear_fields = [
        machine.read::<u8>(address + 0x37), machine.read::<u8>(address + 0x36),
        machine.read::<u8>(address + 0x39), machine.read::<u8>(address + 0x38),
        machine.read::<u8>(address + 0x3B), machine.read::<u8>(address + 0x3A),
    ];
    let legacy_fields = [
        machine.read::<u8>(address + 0x20), machine.read::<u8>(address + 0x1F),
        machine.read::<u8>(address + 0x22), machine.read::<u8>(address + 0x21),
        machine.read::<u8>(address + 0x24), machine.read::<u8>(address + 0x23),
    ];
    let fields = if linear && linear_fields[1] != 0 { linear_fields } else { legacy_fields };
    let format = if memory_model == 4 && bpp == 8 {
        crate::kernel::display::FormatSpec::Indexed8
    } else {
        crate::kernel::display::FormatSpec::Packed(
            crate::kernel::display::PixelFormat::from_rgb(bpp.div_ceil(8), fields)?
        )
    };
    let bytes_per_pixel = match format {
        crate::kernel::display::FormatSpec::Packed(format) => format.bytes_per_pixel,
        crate::kernel::display::FormatSpec::Indexed8 => 1,
    };
    let window_segment = machine.read::<u16>(address + 0x08);
    let window_attributes = machine.read::<u8>(address + 0x02);
    let window_granularity_kb = machine.read::<u16>(address + 0x04);
    let window_size_kb = machine.read::<u16>(address + 0x06);
    let window_function = machine.read::<u32>(address + 0x0C);
    if width == 0 || height == 0 || (physical_base == 0 && window_segment == 0)
        || (physical_base == 0
            && (window_attributes & 0x05 != 0x05
                || window_granularity_kb == 0 || window_size_kb == 0))
        || usize::from(pitch) < usize::from(width) * usize::from(bytes_per_pixel)
    {
        return None;
    }
    Some(crate::kernel::platform::VbeMode {
        number, physical_base, width, height, pitch, bits_per_pixel: bpp, format,
        window_segment,
        window_granularity_kb,
        window_size_kb,
        window_function,
    })
}
