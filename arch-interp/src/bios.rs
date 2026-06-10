//! Load the C-compiled BIOS firmware (`arch-interp/bios/bios.c`, built by our own
//! in-OS Turbo C) at segment 0xF000 and wire the IVT to its handlers.
//!
//! The blob is a Turbo C tiny-model `.COM`. We never EXECUTE it: its C0 startup
//! does DOS calls (INT 21h) that would fault at firmware time, so that code is
//! inert. Instead we scan the blob for a self-describing signature table
//! (`0xF00D 0xB105` followed by `(vector, handler-offset)` pairs) and point each
//! IVT entry at `F000:offset`. The handlers are DS-independent (far pointers to
//! the BDA / video memory only), so they run correctly as ISRs without the C
//! runtime ever initialising anything.
//!
//! To rebuild after editing bios.c (offsets are re-scanned, so they need not be
//! known here):
//!   retroos-host --host DIR --cmd "boot/TC/TCC.EXE -mt -lt BIOS.C" --cwd host/ image_min.bin
//! then copy DIR/BIOS.COM to arch-interp/bios/bios.bin.

const BIOS_COM: &[u8] = include_bytes!("../bios/bios.bin");
const BIOS_SEG: u16 = 0xF000;
const BIOS_ORG: usize = 0x100; // .COM load offset (file byte 0 == segment 0x100)

/// Place the BIOS at F000, wire the IVT from its signature table, seed the BDA.
pub fn install() {
    let m = crate::vcpu::mem();
    let base = (BIOS_SEG as usize) << 4;
    m.write_bytes(base + BIOS_ORG, BIOS_COM);

    // Signature 0xF00D 0xB105 (little-endian), then (vector, offset) u16 pairs
    // terminated by vector 0. Offsets are absolute within the F000 segment.
    // Pseudo-vectors >= 0x100 carry the default stubs (see bios.c): 0x100 =
    // IRET for every vector, 0x101/0x102 = master/slave-PIC EOI for the HW IRQ
    // ranges. Defaults are written first so the explicit entries override —
    // a real BIOS leaves no IVT entry null (SB IRQ autodetect chains through
    // "old" vectors; a null one executes the IVT itself).
    const SIG: [u8; 4] = [0x0D, 0xF0, 0x05, 0xB1];
    if let Some(p) = BIOS_COM.windows(4).position(|w| w == SIG) {
        let mut entries = Vec::new();
        let (mut iret, mut eoi_m, mut eoi_s) = (None, None, None);
        let mut o = p + 4;
        while o + 4 <= BIOS_COM.len() {
            let vec = u16::from_le_bytes([BIOS_COM[o], BIOS_COM[o + 1]]);
            let off = u16::from_le_bytes([BIOS_COM[o + 2], BIOS_COM[o + 3]]);
            o += 4;
            match vec {
                0 => break,
                0x100 => iret = Some(off),
                0x101 => eoi_m = Some(off),
                0x102 => eoi_s = Some(off),
                _ => entries.push((vec, off)),
            }
        }
        let wire = |vec: usize, off: u16| {
            m.write::<u16>(vec * 4, off);
            m.write::<u16>(vec * 4 + 2, BIOS_SEG);
        };
        if let Some(off) = iret {
            for vec in 0..256 {
                wire(vec, off);
            }
        }
        if let Some(off) = eoi_m {
            for vec in 0x08..0x10 {
                wire(vec, off);
            }
        }
        if let Some(off) = eoi_s {
            for vec in 0x70..0x78 {
                wire(vec, off);
            }
        }
        for (vec, off) in entries {
            wire(vec as usize, off);
        }
    }

    seed_bda(m);
}

/// Seed the BDA fields the (never-run) `main()` would have set. Guest segment
/// 0x40 == linear 0x400.
fn seed_bda(m: crate::vcpu::GuestMem) {
    m.write::<u8>(0x449, 3); // video mode 3 (80x25 colour)
    m.write::<u16>(0x44A, 80); // columns
    m.write::<u16>(0x463, 0x03D4); // CRTC base port (colour)
    m.write::<u8>(0x484, 24); // rows - 1
    m.write::<u16>(0x485, 16); // character cell height
    // Equipment word: bits 4-5 = 00 means "EGA/VGA with its own BIOS" — games'
    // adapter detection (e.g. SkyRoads) checks this alongside INT 10h AX=1A00.
    m.write::<u16>(0x410, 0x0001);
    // Keyboard ring buffer: empty (head == tail), buffer 0x1E..0x3D.
    m.write::<u16>(0x41A, 0x1E); // head
    m.write::<u16>(0x41C, 0x1E); // tail
    m.write::<u16>(0x480, 0x1E); // ring start
    m.write::<u16>(0x482, 0x3E); // ring end
}
