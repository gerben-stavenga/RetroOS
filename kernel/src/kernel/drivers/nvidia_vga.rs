//! Native NVIDIA video-BIOS workarounds. These operate only while the caller
//! owns VgaCap; GOP and the software VGA/VBE implementation never enter here.
//!
//! Legacy mode reconstruction is inspired by EGAFIX 0.08 by Gael Cathelin
//! (egafix.asm in EGAFIX08.zip). Its working-mode substitutions and register
//! settings repair incomplete CGA/EGA support in NVIDIA video BIOSes.
//!
//! Extended CRTC handling is adapted from NEWAX by Marco Pistella:
//! https://github.com/Marco-Pistella/NEWAX (MIT; see THIRD_PARTY_LICENSES.md).
//! In particular, CR13/3B encode pitch and CR0D/0C/35/34 encode display start.

use crate::kernel::{platform::VgaCap, portio::{inb, outb, outw}};

/// Require one unambiguous I/O-enabled VGA adapter. A secondary NVIDIA GPU
/// must never make us program NVIDIA registers on the primary Intel/AMD VGA.
pub(crate) fn primary_nvidia<A: crate::Arch>(machine: &mut A) -> bool {
    use crate::kernel::pci::read32;
    let mut vendor = None;
    for bus in 0..=255 {
        for dev in 0..32 {
            for func in 0..8 {
                let id = read32(machine, bus, dev, func, 0);
                if id as u16 == 0xFFFF {
                    if func == 0 { break; }
                    continue;
                }
                if read32(machine, bus, dev, func, 8) >> 16 == 0x0300
                    && read32(machine, bus, dev, func, 4) & 1 != 0
                {
                    if vendor.is_some() { return false; }
                    vendor = Some(id as u16);
                }
                if func == 0 && read32(machine, bus, dev, func, 0x0C) & 0x0080_0000 == 0 { break; }
            }
        }
    }
    vendor == Some(0x10DE)
}

pub(crate) fn crtc_port(_cap: &VgaCap) -> u16 {
    if inb(0x3CC) & 1 != 0 { 0x3D4 } else { 0x3B4 }
}

pub(crate) fn read(_cap: &VgaCap, port: u16, index: u8) -> u8 {
    outb(port, index);
    inb(port + 1)
}

pub(crate) fn write(_cap: &VgaCap, port: u16, index: u8, value: u8) {
    outw(port, u16::from(index) | (u16::from(value) << 8));
}

/// EGAFIX starts with firmware modes known to work, then reconstructs the
/// requested mode. Keep the no-clear bit on the temporary firmware request.
pub(crate) fn legacy_base(request: u8) -> Option<u8> {
    let base = match request & 0x7F {
        0..=2 => 3,
        4..=6 | 0x0D | 0x0E => 0x13,
        0x0F | 0x10 => 0x12,
        _ => return None,
    };
    Some(base | (request & 0x80))
}

fn words(port: u16, values: &[u16]) {
    for &value in values { outw(port, value); }
}

fn attributes(values: &[u16]) {
    let _ = inb(0x3DA);
    super::vga_hw::track_ac_reset();
    for &value in values {
        for byte in value.to_le_bytes() {
            outb(0x3C0, byte);
            super::vga_hw::track_ac_write(byte);
        }
    }
    outb(0x3C0, 0x20);
    super::vga_hw::track_ac_write(0x20);
}

const CRTC_320: &[u16] = &[0x2D00, 0x2701, 0x2802, 0x9003, 0x2B04, 0x1413];
const ATTR_EGA: &[u16] = &[
    0x1406, 0x3808, 0x3909, 0x3A0A, 0x3B0B, 0x3C0C, 0x3D0D, 0x3E0E, 0x3F0F, 0x0110,
];

/// EGAFIX 0.08 register recipes. RetroOS already supplies its own BDA, font,
/// TTY, palette services and VRAM clearing; those TSR services aren't copied.
pub(crate) fn finish_legacy(_cap: &VgaCap, request: u8) {
    let mode = request & 0x7F;
    match mode {
        0 | 1 => {
            words(0x3C4, &[0x0801]);
            words(0x3D4, &[0x0E11, 0xA005]);
            words(0x3D4, CRTC_320);
        }
        2 => {} // EGAFIX substitutes colour text for monochrome text.
        4 | 5 => {
            words(0x3C4, &[0x0901, 0x0302, 0x0204]);
            words(0x3CE, &[0x3005, 0x0F06, 0x0007]);
            words(0x3D4, &[0x0E11, 0xC109, 0x0014, 0xA217]);
            words(0x3D4, CRTC_320);
            attributes(&[0x1301, 0x1502, 0x1703, 0x0110, 0x0312]);
        }
        6 => {
            words(0x3C4, &[0x0102, 0x0604]);
            words(0x3CE, &[0x0005, 0x0D06, 0x0007]);
            words(0x3D4, &[0x0E11, 0xC109, 0x0014, 0xC217]);
            attributes(&[0x1701, 0x0110, 0x0112]);
        }
        0x0D | 0x0E => {
            if mode == 0x0D { words(0x3C4, &[0x0901]); }
            words(0x3C4, &[0x0604]);
            words(0x3CE, &[0x0005]);
            words(0x3D4, &[0x0E11, 0xC009, 0x0014, 0xE317]);
            if mode == 0x0D { words(0x3D4, CRTC_320); }
            attributes(ATTR_EGA);
        }
        0x0F | 0x10 => {
            outb(0x3C2, 0xA3);
            words(0x3D4, &[0x0511, 0xBF06, 0x1F07, 0x8310, 0x5D12, 0x0F14, 0x6315, 0xBA16]);
        }
        _ => return,
    }
    if matches!(mode, 4..=6 | 0x0D | 0x0E) {
        // EGAFIX's repeated RGBI palette agrees with our software VGA palette.
        outb(0x3C8, 0);
        for &value in &vga::ega_200line_dac()[..64 * 3] { outb(0x3C9, value); }
    }
}

/// NEWAX's G80+ extended start bits must not leak into the next legacy mode.
pub(crate) fn reset_start(cap: &VgaCap) {
    let port = crtc_port(cap);
    let lock = read(cap, port, 0x3F);
    write(cap, port, 0x3F, 0x57);
    write(cap, port, 0x35, 0);
    write(cap, port, 0x34, 0);
    write(cap, port, 0x3F, lock);
}

/// Packed-pixel VBE pitch is in eight-byte units on NEWAX-compatible NVIDIA
/// hardware. Round up so the programmed pitch never truncates the request.
pub(crate) fn aligned_pitch(bytes: u16) -> Option<u16> {
    u16::try_from(u32::from(bytes).div_ceil(8) * 8).ok().filter(|&v| v != 0)
}

pub(crate) fn set_pitch(cap: &VgaCap, bytes: u16) {
    let port = crtc_port(cap);
    let lock = read(cap, port, 0x3F);
    write(cap, port, 0x3F, 0x57);
    let offset = bytes / 8;
    write(cap, port, 0x13, offset as u8);
    write(cap, port, 0x3B, (offset >> 8) as u8);
    write(cap, port, 0x3F, lock);
}

/// NEWAX packed-pixel start addresses use dword units plus AC fine panning.
/// RetroOS's native VBE catalogue currently exposes packed/indexed modes only.
pub(crate) fn start_registers(offset: u32) -> Option<([u8; 4], u8)> {
    let address = offset / 4;
    (address < 1 << 30).then_some(([
        address as u8, (address >> 8) as u8, (address >> 16) as u8,
        ((address >> 24) & 0x3F) as u8,
    ], ((offset & 3) * 2) as u8))
}

pub(crate) fn set_start(cap: &VgaCap, offset: u32, retrace: bool) -> bool {
    let Some((address, pan)) = start_registers(offset) else { return false };
    let port = crtc_port(cap);
    if retrace {
        // Unlike NEWAX's unbounded loops, a missing/stuck retrace signal must
        // return failure rather than hang the entire kernel.
        for desired in [false, true] {
            let mut seen = false;
            for _ in 0..1_000_000 {
                let value = inb(port + 6);
                super::vga_hw::track_ac_reset();
                if (value & 8 != 0) == desired { seen = true; break; }
            }
            if !seen { return false; }
        }
    }
    let lock = read(cap, port, 0x3F);
    write(cap, port, 0x3F, 0x57);
    for (index, value) in [0x0D, 0x0C, 0x35, 0x34].into_iter().zip(address) {
        write(cap, port, index, value);
    }
    write(cap, port, 0x3F, lock);
    attributes(&[u16::from(pan) << 8 | 0x13]);
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn legacy_substitutions_preserve_no_clear() {
        for (mode, base) in [(0, 3), (1, 3), (2, 3), (4, 0x13), (5, 0x13),
            (6, 0x13), (0x0D, 0x13), (0x0E, 0x13), (0x0F, 0x12), (0x10, 0x12)] {
            assert_eq!(legacy_base(mode), Some(base));
            assert_eq!(legacy_base(mode | 0x80), Some(base | 0x80));
        }
        for mode in [3, 7, 0x11, 0x12, 0x13] { assert_eq!(legacy_base(mode), None); }
    }

    #[test]
    fn pitch_and_start_cross_extended_register_boundaries() {
        assert_eq!(aligned_pitch(641), Some(648));
        assert_eq!(aligned_pitch(0), None);
        assert_eq!(aligned_pitch(65535), None);
        assert_eq!(start_registers(0x0404_0007), Some(([1, 0, 1, 1], 6)));
        assert_eq!(start_registers(640 * 480), Some(([0, 0x2C, 1, 0], 0)));
    }
}
