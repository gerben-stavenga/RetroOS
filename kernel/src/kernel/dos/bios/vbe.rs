//! VESA VBE services: INT 10h AH=4Fh and the bank-window entry.
use crate::Regs;
use crate::kernel::dos::{dos, dpmi, machine, seg_offset, DosState};

// ============================================================================
// VESA VBE (INT 10h AH=4Fh)
// ============================================================================

/// The banked SVGA modes we expose: (VBE mode#, width, height, bpp). Presented
/// through the emulated framebuffer sink, integer-scaled/centred to the panel.
/// 8bpp goes through the DAC palette; 15/16/24 are direct colour. Substitute
/// path only — the native/SeaBIOS path has the card's own VBE.
const VBE_MODES: &[(u16, u16, u16, u8)] = &[
    (0x101, 640, 480, 8),
    (0x103, 800, 600, 8),
    (0x110, 640, 480, 15),
    (0x111, 640, 480, 16),
    (0x112, 640, 480, 24),
];

fn substitute_vbe_mode(number: u16) -> Option<crate::kernel::platform::VbeMode> {
    let &(_, width, height, bits_per_pixel) =
        VBE_MODES.iter().find(|&&(candidate, ..)| candidate == number)?;
    let format = if bits_per_pixel == 8 {
        crate::kernel::display::FormatSpec::Indexed8
    } else {
        let packed = match bits_per_pixel {
            15 => crate::kernel::display::PixelFormat::RGB555,
            16 => crate::kernel::display::PixelFormat::RGB565,
            24 => crate::kernel::display::PixelFormat::RGB888,
            _ => return None,
        };
        crate::kernel::display::FormatSpec::Packed(packed)
    };
    let pitch = width * u16::from(bits_per_pixel.div_ceil(8));
    let image_bytes = usize::from(pitch) * usize::from(height);
    let image_count = (machine::vga::SVGA_LFB_MAX_BYTES / image_bytes)
        .clamp(1, 256);
    let image_pages = (image_count - 1) as u8;
    Some(crate::kernel::platform::VbeMode {
        number,
        // This is an implementation detail of the RAM-backed substitute mode;
        // its public ModeInfo still deliberately says not VGA compatible.
        vga_compatible: false,
        physical_base: machine::vga::svga_lfb_base(),
        width,
        height,
        pitch,
        banked_pitch: pitch,
        linear_pitch: pitch,
        bits_per_pixel,
        format,
        // The RAM-backed substitute surface has no independent output
        // RAMDAC; Voodoo applies its CLUT while rendering into the host sink.
        programmable_ramp: false,
        window_segment: 0xA000,
        window_granularity_kb: 64,
        window_size_kb: 64,
        banked_image_pages: image_pages,
        linear_image_pages: image_pages,
        framebuffer_bytes: (image_count * image_bytes) as u32,
    })
}

pub(super) fn vbe<A: crate::Arch>(
    machine: &mut A,
    bios_display: &mut crate::kernel::bios_display::BiosDisplayWorkspace<A>,
    dos: &mut DosState<A>,
    regs: &mut Regs,
) {
    // Every VBE call returns AL=4Fh ("supported"); AH=00h success, 01h failed.
    let al = regs.rax as u8;
    let done = |regs: &mut Regs, ok: bool| {
        regs.rax = (regs.rax & !0xFFFF) | if ok { 0x004F } else { 0x014F };
    };
    match al {
        0x00 => {
            let native_modes = bios_display.curated_modes();
            vbe_controller_info(machine, dos, regs, native_modes);
            done(regs, true);
        }
        0x01 => {
            let native_mode = bios_display.curated_mode(regs.rcx as u16 & 0x3FFF);
            let ok = synthetic_vbe_mode_info(machine, dos, regs, native_mode);
            done(regs, ok);
        }
        0x02 => {
            let ok = vbe_set_mode(machine, bios_display, dos, regs);
            done(regs, ok);
        }
        0x03 => {
            let cur = if let Some(_display) = dos.pc.vga.native() {
                bios_display.vbe_state().map_or(0, |state| state.svga.mode_value())
            } else {
                dos.pc.vga.emulated().and_then(|dev| dev.state.svga())
                    .map_or(0, |svga| svga.mode_value())
            };
            regs.rbx = (regs.rbx & !0xFFFF) | cur as u64;
            done(regs, true);
        }
        0x05 => {
            let ok = vbe_window(machine, bios_display, dos, regs);
            done(regs, ok);
        }
        0x06 => {
            let ok = vbe_scan_line(machine, bios_display, dos, regs);
            done(regs, ok);
        }
        0x07 => {
            let ok = if let Some(display) = dos.pc.vga.native_mut() {
                display.cap_mut().guest_bios_display_start(
                    machine, bios_display, regs,
                ).is_ok()
            } else {
                emulated_vbe_display_start(&mut dos.pc, regs)
            };
            done(regs, ok);
        }
        0x08 => {
            let ok = vbe_dac_format(bios_display, dos, regs);
            done(regs, ok);
        }
        0x09 => {
            let ok = vbe_palette(machine, bios_display, dos, regs);
            done(regs, ok);
        }
        // The native 4F0Ah result is executable code in the isolated BIOS
        // workspace. Returning its ES:DI would hand the guest a pointer into a
        // different address space. Report the standard failure so clients use
        // their INT 10h fallback (including Build's 4F05h/4F07h paths).
        0x0A => done(regs, false),
        _ => done(regs, false),
    }
}

/// VBE 4F08h — Set/Get DAC palette format. Changing the exposed width never
/// rewrites the canonical eight-bit palette/ramp.
fn vbe_dac_format<A: crate::Arch>(
    bios: &mut crate::kernel::bios_display::BiosDisplayWorkspace<A>,
    dos: &mut DosState<A>,
    regs: &mut Regs,
) -> bool {
    let palette = if dos.pc.vga.native().is_some() {
        bios.vbe_state_mut().and_then(|state| {
            (matches!(state.mode.format, crate::kernel::display::FormatSpec::Indexed8)
                || state.mode.programmable_ramp)
                .then_some(&mut state.svga.palette)
        })
    } else {
        dos.pc.vga.emulated_mut().and_then(|dev| {
            let svga = dev.vbe_state_mut()?;
            svga.config.palette_capable.then_some(&mut svga.palette)
        })
    };
    let Some(palette) = palette else { return false };
    match regs.rbx as u8 {
        0 => {
            if !palette.set_width((regs.rbx >> 8) as u8) { return false; }
        }
        1 => {}
        _ => return false,
    }
    regs.rbx = (regs.rbx & !0xFF00) | (u64::from(palette.width) << 8);
    true
}

/// VBE 4F09h — Set/Get Palette Data. CX entries from index DX at ES:DI, each 4
/// bytes (Blue, Green, Red, align), in the width selected through 4F08h.
/// Native modes retain their shadow in the BIOS display service; detached
/// modes retain a complete private copy in `EmulatedVga`.
fn vbe_palette<A: crate::Arch>(
    machine: &mut A,
    bios_display: &mut crate::kernel::bios_display::BiosDisplayWorkspace<A>,
    dos: &mut DosState<A>,
    regs: &mut Regs,
) -> bool {
    let has_palette = if let Some(display) = dos.pc.vga.native() {
        let _ = display;
        bios_display.vbe_state().is_some_and(|state| {
            matches!(state.mode.format, crate::kernel::display::FormatSpec::Indexed8)
                || state.mode.programmable_ramp
        })
    } else {
        dos.pc.vga.emulated().and_then(|dev| dev.state.svga())
            .is_some_and(|svga| svga.config.palette_capable)
    };
    if !has_palette { return false; }
    let count = regs.rcx as u16 as usize;
    let start = regs.rdx as u16;
    if start >= 256 || count > 256 - usize::from(start) { return false; }
    let tbl = seg_offset(dos, regs, regs.es as u16, regs.rdi as u32) as usize;
    if let Some(display) = dos.pc.vga.native_mut() {
        let mut data = alloc::vec![0; count * 4];
        let subfn = regs.rbx as u8;
        if matches!(subfn, 0 | 0x80) { machine.copy_from(tbl, &mut data); }
        let ok = display.cap_mut().bios_indexed_palette_call(
            machine, bios_display, subfn, start, &mut data,
        ).is_ok();
        if ok && subfn == 1 { machine.copy_to(tbl, &data); }
        return ok;
    }
    let Some(dev) = dos.pc.vga.emulated_mut() else { return false };
    match regs.rbx as u8 {
        0x00 | 0x80 => {
            // Set (00h) / set-during-retrace (80h): update the VBE
            // indexed-colour state directly. Raw VGA DAC ports are a
            // different interface and are absent in the non-VGA-compatible
            // modes exposed by RetroOS.
            for i in 0..count {
                let e = tbl + i * 4;
                let (b, g, r): (u8, u8, u8) = (machine.read(e), machine.read(e + 1), machine.read(e + 2));
                let entry = [b, g, r, 0];
                let Some(svga) = dev.state.svga_mut() else { return false };
                if !svga.palette.write((usize::from(start) + i) as u16, &entry) {
                    return false;
                }
            }
            true
        }
        0x01 => {
            // Get: read the VBE palette shadow back into the caller's table.
            for i in 0..count {
                let mut entry = [0; 4];
                let Some(svga) = dev.state.svga() else { return false };
                if !svga.palette.read((usize::from(start) + i) as u16, &mut entry) {
                    return false;
                }
                let e = tbl + i * 4;
                machine.write::<u8>(e, entry[0]);
                machine.write::<u8>(e + 1, entry[1]);
                machine.write::<u8>(e + 2, entry[2]);
                machine.write::<u8>(e + 3, 0);
            }
            true
        }
        _ => false, // 02h secondary palette: unsupported
    }
}

/// VBE 4F00h — controller info into ES:DI, with VideoModePtr naming stable
/// personality-owned low memory. The list must outlive and not alias this
/// output block: clients routinely reuse the block for subsequent 4F01h calls.
fn vbe_controller_info<A: crate::Arch>(
    machine: &mut A,
    dos: &DosState<A>,
    regs: &mut Regs,
    native_modes: Option<&[crate::kernel::platform::VbeMode]>,
) {
    let lin = seg_offset(dos, regs, regs.es as u16, regs.rdi as u32) as usize;
    for i in (0..256).step_by(4) {
        machine.write::<u32>(lin + i, 0);
    }
    machine.write::<u8>(lin, b'V');
    machine.write::<u8>(lin + 1, b'E');
    machine.write::<u8>(lin + 2, b'S');
    machine.write::<u8>(lin + 3, b'A');
    machine.write::<u16>(lin + 0x04, 0x0200); // VBE 2.0
    // Bit 0: the RetroOS VBE boundary supports switching between six- and
    // eight-bit DAC components; storage remains canonical eight-bit.
    machine.write::<u32>(lin + 0x0A, 1);
    let list = dos::vbe_mode_list_addr() as usize;
    // Far pointer 0000:list. The fixed LowMem target is below 64 KiB.
    machine.write::<u32>(lin + 0x0E, list as u32);
    machine.write::<u16>(lin + 0x12, 0x100); // generic adapter memory: 16 MB
    let mut p = list;
    let remaining = dos::VBE_MODE_LIST_CAPACITY - 1;
    if let Some(modes) = native_modes {
        for mode in modes.iter().take(remaining) {
            machine.write::<u16>(p, mode.number);
            p += 2;
        }
    } else {
        for &(num, ..) in VBE_MODES.iter().take(remaining) {
            machine.write::<u16>(p, num);
            p += 2;
        }
    }
    machine.write::<u16>(p, 0xFFFF); // list terminator
}

/// Generic RetroOS VBE 4F01h — mode info for CX into ES:DI. Curated native
/// modes retain only validated geometry, pitch, pixel format and apertures;
/// vendor identity, executable pointers and private controller fields never
/// cross out of the firmware workspace.
fn synthetic_vbe_mode_info<A: crate::Arch>(
    machine: &mut A,
    dos: &DosState<A>,
    regs: &mut Regs,
    native_mode: Option<crate::kernel::platform::VbeMode>,
) -> bool {
    let want = regs.rcx as u16 & 0x1FF;
    let mode = native_mode.or_else(|| substitute_vbe_mode(want));
    let (w, h, bpp, banked_pitch, linear_pitch, format,
        banked_pages, linear_pages, linear, banked) = if let Some(mode) = mode {
        (mode.width, mode.height, mode.bits_per_pixel, mode.banked_pitch,
            mode.linear_pitch,
            mode.format,
            mode.banked_image_pages, mode.linear_image_pages,
            mode.physical_base != 0, mode.window_segment != 0)
    } else {
        return false;
    };
    let lin = seg_offset(dos, regs, regs.es as u16, regs.rdi as u32) as usize;
    for i in (0..256).step_by(4) {
        machine.write::<u32>(lin + i, 0);
    }
    let direct = matches!(format, crate::kernel::display::FormatSpec::Packed(_));
    // ModeAttributes: supported|reserved|colour|graphics, plus LFB only when
    // the curated hardware mode actually has one. The substitute modes have
    // both apertures; a native banked-only mode must not entice a client into
    // sending an unsupported 4F02h request with bit 14 set.
    machine.write::<u16>(lin, 0x003B | if linear { 0x0080 } else { 0 });
    machine.write::<u8>(lin + 0x02, if banked { 0x07 } else { 0 });
    machine.write::<u8>(lin + 0x03, 0x00); // win B: not present
    machine.write::<u16>(lin + 0x04, if banked { 64 } else { 0 });
    machine.write::<u16>(lin + 0x06, if banked { 64 } else { 0 });
    machine.write::<u16>(lin + 0x08, if banked { 0xA000 } else { 0 });
    machine.write::<u32>(
        lin + 0x0C,
        if banked { dos::vbe_window_ptr() } else { 0 },
    );
    machine.write::<u16>(lin + 0x10, banked_pitch); // banked bytes per scanline
    machine.write::<u16>(lin + 0x12, w);
    machine.write::<u16>(lin + 0x14, h);
    machine.write::<u8>(lin + 0x16, 8); // char width
    machine.write::<u8>(lin + 0x17, 16); // char height
    machine.write::<u8>(lin + 0x18, 1); // planes
    machine.write::<u8>(lin + 0x19, bpp);
    machine.write::<u8>(lin + 0x1A, 1); // banks
    machine.write::<u8>(lin + 0x1B, if direct { 6 } else { 4 }); // direct vs packed
    machine.write::<u8>(lin + 0x1C, if banked { 64 } else { 0 });
    machine.write::<u8>(lin + 0x1D, banked_pages);
    machine.write::<u8>(lin + 0x1E, 1); // reserved (must be 1)
    if direct {
        // (red, grn, blu, rsv) as (mask_size, field_position) at 0x1F..0x26.
        let crate::kernel::display::FormatSpec::Packed(pixel) = format else {
            return false;
        };
        let used = pixel.red_size + pixel.green_size + pixel.blue_size;
        let masks: [(u8, u8); 4] = [
            (pixel.red_size, pixel.red_pos),
            (pixel.green_size, pixel.green_pos),
            (pixel.blue_size, pixel.blue_pos),
            (bpp.saturating_sub(used), used),
        ];
        for (i, &(sz, pos)) in masks.iter().enumerate() {
            machine.write::<u8>(lin + 0x1F + i * 2, sz);
            machine.write::<u8>(lin + 0x20 + i * 2, pos);
            // VBE 3.0's linear-framebuffer mask fields. The curated model
            // exposes one canonical pixel encoding for both access paths.
            machine.write::<u8>(lin + 0x36 + i * 2, sz);
            machine.write::<u8>(lin + 0x37 + i * 2, pos);
        }
        machine.write::<u8>(lin + 0x27, 1); // direct-colour mode information
    }
    // PhysBasePtr is RetroOS's stable guest-linear aperture, but only a mode
    // backed by a genuine physical or emulated LFB has one. A native banked
    // card remains banked all the way through; paging cannot make its moving
    // 64 KiB window into a simultaneous linear framebuffer.
    machine.write::<u32>(
        lin + 0x28,
        if linear { machine::vga::svga_lfb_base() } else { 0 },
    );
    machine.write::<u16>(lin + 0x32, linear_pitch);
    machine.write::<u8>(lin + 0x35, linear_pages);
    true
}

/// VBE 4F07h over the detached process framebuffer, including every image the
/// curated mode advertised. The active start is process state, not firmware
/// state, and therefore survives OSD/background execution exactly.
fn emulated_vbe_display_start(pc: &mut machine::PcMachine, regs: &mut Regs) -> bool {
    let Some(dev) = pc.vga.emulated_mut() else { return false };
    if dev.state.svga().is_none() {
        return regs.rbx as u8 == 0x01 && {
            regs.rcx &= !0xFFFF;
            regs.rdx &= !0xFFFF;
            true
        };
    }
    let Some(svga) = dev.state.svga_mut() else { return false };
    match regs.rbx as u8 {
        0x00 | 0x80 => {
            svga.display_start(Some((regs.rcx as u16, regs.rdx as u16))).is_some()
        }
        0x01 => {
            let Some((x, y)) = svga.display_start(None) else { return false };
            regs.rcx = (regs.rcx & !0xFFFF) | u64::from(x);
            regs.rdx = (regs.rdx & !0xFFFF) | u64::from(y);
            true
        }
        _ => false,
    }
}

fn vbe_scan_line<A: crate::Arch>(
    machine: &mut A,
    bios: &mut crate::kernel::bios_display::BiosDisplayWorkspace<A>,
    dos: &mut DosState<A>,
    regs: &mut Regs,
) -> bool {
    if let Some(display) = dos.pc.vga.native_mut() {
        return display.cap_mut().guest_bios_scan_line_length(machine, bios, regs).is_ok();
    }
    let Some(dev) = dos.pc.vga.emulated_mut() else { return false };
    let Some(svga) = dev.state.svga_mut() else { return false };
    let set = match regs.rbx as u8 {
        0 => Some((regs.rcx as u16, false)),
        2 => Some((regs.rcx as u16, true)),
        1 | 3 => None,
        _ => return false,
    };
    let Some(result) = svga.scan_line(set) else { return false };
    regs.rbx = (regs.rbx & !0xFFFF) | u64::from(result.bytes);
    regs.rcx = (regs.rcx & !0xFFFF) | u64::from(result.pixels);
    regs.rdx = (regs.rdx & !0xFFFF) | u64::from(result.lines);
    true
}

/// VBE 4F02h — set mode (BX). The substitute exposes both the bank window and
/// its RAM-backed PhysBasePtr; native firmware receives the request unchanged.
fn vbe_set_mode<A: crate::Arch>(
    machine: &mut A,
    bios_display: &mut crate::kernel::bios_display::BiosDisplayWorkspace<A>,
    dos: &mut DosState<A>,
    regs: &mut Regs,
) -> bool {
    if let Some(display) = dos.pc.as_mut().vga.native_mut() {
        let success = match display.cap_mut()
            .guest_bios_set_mode_request(machine, bios_display, regs.rbx as u16)
        {
            Ok(()) => true,
            Err(error) => {
                crate::compact_println!("VBE: mode request {:#x} failed: {:?}", regs.rbx as u16, error);
                false
            }
        };
        if success
            && let Some(state) = bios_display.vbe_state().copied()
        {
            machine::vga::select_native_svga_aperture(
                machine, state.mode, state.svga.access);
            dpmi::refresh_physical_mappings(machine, dos);
        }
        return success;
    }
    let want = regs.rbx as u16 & 0x3FFF;
    let Some(mode) = bios_display.curated_mode(want).or_else(|| substitute_vbe_mode(want)) else {
        return false;
    };
    machine::vga::svga_set_curated_mode(
        machine, &mut dos.pc, mode, regs.rbx as u16,
    );
    dpmi::refresh_physical_mappings(machine, dos);
    true
}

/// VBE 4F05h — window control. BH=0 set / 1 get; BL=window (we only do A); DX=bank.
pub(in crate::kernel::dos) fn vbe_window<A: crate::Arch>(
    machine: &mut A,
    bios_display: &mut crate::kernel::bios_display::BiosDisplayWorkspace<A>,
    dos: &mut DosState<A>,
    regs: &mut Regs,
) -> bool {
    if let Some(display) = dos.pc.as_mut().vga.native_mut() {
        let set = ((regs.rbx >> 8) as u8 == 0).then_some(regs.rdx as u16);
        return match display.cap_mut().guest_bios_window(machine, bios_display, set) {
            Ok(bank) => {
                regs.rdx = (regs.rdx & !0xFFFF) | u64::from(bank);
                true
            }
            Err(_) => false,
        };
    }
    let Some(dev) = dos.pc.vga.emulated() else { return false };
    if dev.state.svga().is_some_and(|svga| matches!(svga.access, vga::SvgaAccess::Linear))
    {
        return false;
    }
    if (regs.rbx >> 8) as u8 == 0 {
        machine::vga::svga_set_bank(machine, &mut dos.pc, regs.rdx as u16);
    } else {
        let Some(dev) = dos.pc.vga.emulated() else { return false };
        let Some(svga) = dev.state.svga() else { return false };
        let Some(bank) = svga.bank() else { return false };
        regs.rdx = (regs.rdx & !0xFFFF) | bank as u64;
    }
    true
}
