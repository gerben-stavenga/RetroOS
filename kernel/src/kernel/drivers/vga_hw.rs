//! The real VGA card: saving its live state and putting it back.
//!
//! A machine has one VGA, and more than one thing wants the screen — a DOS
//! program, a Linux program, the kernel console. Whoever is not holding the
//! card keeps its screen as a *model* ([`VgaState`], a passive register file
//! and four plane images that belongs to the machine model, not here), and the
//! two functions below are the only code that moves state between that model
//! and the silicon. `save` reads the card into a model; `restore` programs a
//! model into the card.
//!
//! This is a driver, not personality code: `platform` calls it on a display
//! handover and `linux` calls it when a graphical thread suspends, exactly as
//! DOS does. It lived inside `dos/machine/vga.rs` for a long time, which had
//! a Linux thread reaching through the DOS personality to touch the CRTC.
//!
//! What is NOT here: mode classification, the planar write logic, rendering,
//! and the emulated port model. Those are the machine's model of a VGA and
//! run with no card present at all.

use vga::{AcState, VgaState};

/// The real card's Attribute-Controller flip-flop and latched index.
///
/// The flip-flop phase is not port-readable, so it must be tracked. The
/// latched address (including PAS) is readable only on some VGA-compatible
/// hardware. Because both belong to the *card*, the tracker is global rather
/// than per-thread (a thread's own AC state lives in its `VgaState`).
/// The guest's own 0x3C0 writes reach it through [`track_ac_write`] when the
/// port is passed through to a native card.
static mut AC: AcState = AcState::new();

/// Note a guest write to 0x3C0 that went through to the real card, keeping
/// the tracker in step with the flip-flop it cannot read back.
pub fn track_ac_write(val: u8) {
    unsafe {
        if !AC.pending_data {
            // Index write — latch the full byte, PAS bit included.
            AC.index = val;
        }
        AC.pending_data = !AC.pending_data;
    }
}

/// Note the flip-flop reset that reading 0x3DA performs on the real card.
pub fn track_ac_reset() {
    unsafe { AC.pending_data = false; }
}

/// Read only the register subset that determines the current VGA mode. Index
/// latches are restored, no sequencer reset is asserted, and VRAM/DAC/AC are
/// untouched, so COMMAND.COM can decide whether a mode-3 BIOS call is needed
/// without disturbing a child's implicit text-screen return value.
pub fn read_mode_regs() -> vga::Regs {
    use crate::kernel::portio::{inb, outb};
    let seq_index = inb(0x3C4);
    let gc_index = inb(0x3CE);
    let misc = inb(0x3CC);
    let crtc_port = if misc & 1 != 0 { 0x3D4 } else { 0x3B4 };
    let crtc_index = inb(crtc_port);
    let mut seq = [0u8; 5];
    let mut gc = [0u8; 9];
    let mut crtc = [0u8; 25];
    for i in 0..5u8 {
        outb(0x3C4, i);
        seq[i as usize] = inb(0x3C5);
    }
    for i in 0..9u8 {
        outb(0x3CE, i);
        gc[i as usize] = inb(0x3CF);
    }
    for i in 0..25u8 {
        outb(crtc_port, i);
        crtc[i as usize] = inb(crtc_port + 1);
    }
    outb(0x3C4, seq_index);
    outb(0x3CE, gc_index);
    outb(crtc_port, crtc_index);
    vga::Regs { crtc, seq, gc, misc }
}

pub fn is_standard_text_mode(_cap: &crate::kernel::platform::VgaCap) -> bool {
    vga::is_standard_text(&read_mode_regs())
}

/// Read the live card's whole register file, DAC and plane memory into
/// `state`. Called when a thread stops owning the physical display and its
/// screen must survive as a model (`NativeVga -> EmulatedVga`).
pub fn save(cap: &crate::kernel::platform::VgaCap, state: &mut VgaState) {
    use crate::kernel::portio::{inb, outb};
    if state.planes.is_empty() {
        state.planes = alloc::vec![0u8; 4 * 65536];
    }
    // Capture the AC sequencing state, then reset the flipflop to a
    // known index state. With 0x3C0/0x3DA granted to the guest
    // (io_policy's `DisplayedVga::Native` arm), the VGA_AC_STATE tracker never saw
    // its writes — the card is the only source of truth, and it must be
    // read BEFORE the 0x3DA reset below destroys the phase.
    let plat = crate::kernel::platform::get();
    let index = inb(0x3C0); // address-register readback (incl. PAS)
    let pending_data = if plat.vga_readback {
        let crtc_index = inb(0x3D4);
        outb(0x3D4, 0x24); // Cirrus CR24: bit 7 = flip-flop phase
        let phase = inb(0x3D5) & 0x80 != 0;
        outb(0x3D4, crtc_index);
        phase
    } else {
        // Phase not readable on this card — assume index state (the boot
        // warning declared full restore unsupported here).
        false
    };
    state.ac_state = AcState { index, pending_data };
    let _ = inb(0x3DA);

    // Capture index registers BEFORE the save loops overwrite them.
    state.seq_index = inb(0x3C4);
    state.crtc_index = inb(0x3D4);
    state.gc_index = inb(0x3CE);

    // Save all registers
    state.misc_output = inb(0x3CC);
    state.feature_ctl = inb(0x3CA);
    for i in 0..5u8 { outb(0x3C4, i); state.seq[i as usize] = inb(0x3C5); }
    for i in 0..25u8 { outb(0x3D4, i); state.crtc[i as usize] = inb(0x3D5); }
    for i in 0..9u8 { outb(0x3CE, i); state.gc[i as usize] = inb(0x3CF); }

    // Data latches, via Cirrus CR22 (latch selected by GC4 read-map).
    // Must happen before the plane copy below — every VRAM read reloads
    // them. Without the readback the latches stay unrecoverable (see the
    // gap comment further down).
    if plat.vga_readback {
        for plane in 0..4u8 {
            outb(0x3CE, 4); outb(0x3CF, plane);
            outb(0x3D4, 0x22);
            state.latches[plane as usize] = inb(0x3D5);
        }
        outb(0x3CE, 4); outb(0x3CF, state.gc[4]);
    }
    save_dac(cap, state);

    // Attribute Controller — must reset flipflop EACH iteration.
    // inb(0x3C1) reads the register but does NOT toggle the flipflop,
    // so without a reset the next outb(0x3C0, i) would be a data write.
    for i in 0..21u8 {
        let _ = inb(0x3DA);
        outb(0x3C0, i);
        state.ac[i as usize] = inb(0x3C1);
    }

    // Restore hardware AC to the program's tracked state. Always write the
    // latched index byte (carries the PAS bit, which the save loop above
    // clobbered to 0). Then, if the program is in index state, do one more
    // 0x3DA read to put the flipflop back.
    let _ = inb(0x3DA);
    outb(0x3C0, state.ac_state.index);
    if !state.ac_state.pending_data {
        let _ = inb(0x3DA);
    }

    crate::dbg_println!("VGA save: seq4={:02X} gc5={:02X} gc6={:02X} crtc14={:02X} crtc17={:02X} ac10={:02X} misc={:02X} start={:04X} dacmask={:02X}",
        state.seq[4], state.gc[5], state.gc[6], state.crtc[0x14], state.crtc[0x17], state.ac[0x10], state.misc_output,
        (state.crtc[0x0C] as u16) << 8 | state.crtc[0x0D] as u16,
        state.dac_mask);

    // Chain-4 has the same boundary problem in mode 13h: once chain-4 is
    // disabled, the A0000 aperture no longer presents the guest's linear
    // pixel stream. Preserve that stream before changing SEQ[4], then use
    // it to normalize the four plane images after the flat capture.
    let native_chain4 = if matches!(
        state.classify_mode(),
        Some(vga::VgaMode::Mode13h)
    ) {
        let mut chained = alloc::vec![0u8; 0x10000];
        let graphics_window = (crate::LOW_MEM_BASE + 0xA0000) as *const u8;
        for (i, dst) in chained.iter_mut().enumerate() {
            *dst = unsafe { core::ptr::read_volatile(graphics_window.add(i)) };
        }
        Some(chained)
    } else {
        None
    };
    // Preserve the CPU-visible text aperture before flattening odd/even. The
    // linear B8000 view is identical across implementations and therefore
    // provides the unambiguous representation at this hardware boundary.
    let native_text = if matches!(
        state.classify_mode(),
        Some(vga::VgaMode::Text { .. })
    ) {
        let mut text = alloc::vec![0u8; 0x8000];
        let text_window = (crate::LOW_MEM_BASE + 0xB8000) as *const u8;
        unsafe { core::ptr::copy_nonoverlapping(text_window, text.as_mut_ptr(), text.len()); }
        Some(text)
    } else {
        None
    };

    // Blank the display for the rest of the save. The flat-planar
    // overrides below mis-interpret the current framebuffer if the
    // guest was in chain-4 / chain-2 / odd-even, so without screen-off
    // the user sees a brief frame of scrambled pixels.
    // SEQ Index 1 bit 5 = "Screen Off" — DAC output forced to 0
    // without touching any other register. Restored at the bottom.
    outb(0x3C4, 1); outb(0x3C5, state.seq[1] | 0x20);

    // Force flat planar mode for reading planes:
    // SEQ mem mode = sequential access (no chain-4, no odd/even)
    // GC mode = read mode 0, write mode 0
    // GC misc = graphics mode, A0000/64K window, no chain odd/even
    outb(0x3C4, 4); outb(0x3C5, 0x06);
    outb(0x3CE, 5); outb(0x3CF, 0x00);
    outb(0x3CE, 6); outb(0x3CF, 0x05);

    // GAP (plain VGA only): GC read latches (4 bytes loaded by the most
    // recent VGA memory read) are not preserved across save/restore —
    // the bulk reads below clobber them, and stock VGA exposes no port
    // to read them without a destructive VRAM access. With Cirrus
    // readbacks (`platform::vga_readback`) they were already captured
    // via CR22 above and are reloaded by `restore`.
    //
    // Symptom without readbacks: a mode-X latch blit preempted between
    // its source read and destination write produces 4 wrong bytes when
    // the program resumes:
    //     mov al, [esi]   ; loads latches with src plane bytes
    //     <-- preempt here -->
    //     mov [edi], al   ; write mode 1: writes (wrong) latches to dst
    // The affected window is 1–2 instructions wide, so a lost latch
    // normally appears as one bad 4-byte stripe in one frame.
    // Read planes through the kernel-side low-memory mapping
    // (LOW_MEM_BASE + 0xA0000) so this works regardless of which
    // personality's user pages are currently mapped — Linux threads
    // don't have a 0xA0000 identity mapping at all, so a bare access
    // would fault when suspending shell.elf.
    let vga_window = (crate::LOW_MEM_BASE + 0xA0000) as *const u8;
    let layout = state.layout();
    let mut plane_bytes = alloc::vec![0u8; 65536];
    for plane in 0..4u8 {
        outb(0x3CE, 4); outb(0x3CF, plane);
        unsafe {
            core::ptr::copy_nonoverlapping(vga_window, plane_bytes.as_mut_ptr(), 65536);
        }
        for (offset, &byte) in plane_bytes.iter().enumerate() {
            state.planes[layout.index(plane as usize, offset)] = byte;
        }
    }
    if let Some(chained) = native_chain4.as_deref() {
        for (address, &byte) in chained.iter().enumerate() {
            state.planes[layout.index(address & 3, address >> 2)] = byte;
        }
    }
    if let Some(text) = native_text.as_deref() {
        for (address, &byte) in text.iter().enumerate() {
            state.planes[layout.index(address & 1, address >> 1)] = byte;
        }
    }
    // Registers were captured first, so the forced-flat read and repairs write
    // directly into the ordering implied by this exact saved VGA state.

    // Restore registers we temporarily changed (incl. SEQ[1] to unblank)
    outb(0x3C4, 1); outb(0x3C5, state.seq[1]);
    outb(0x3C4, 4); outb(0x3C5, state.seq[4]);
    outb(0x3CE, 4); outb(0x3CF, state.gc[4]);
    outb(0x3CE, 5); outb(0x3CF, state.gc[5]);
    outb(0x3CE, 6); outb(0x3CF, state.gc[6]);
    // Restore the program's tracked index registers
    outb(0x3C4, state.seq_index);
    outb(0x3D4, state.crtc_index);
    outb(0x3CE, state.gc_index);

    // SeaVGABIOS traffic can bypass the trapped-port AC tracker, leaving its
    // PAS bit stale even though the outgoing owner was visibly scanning out.
    // The save boundary must be observational: a fork hands this still-live
    // adapter directly to its child, so repair QEMU's palette-enable latch
    // without touching registers, VRAM, palette or mode.
    if crate::kernel::platform::get().host == crate::kernel::platform::Host::Qemu {
        enable_palette_output(cap, state);
    }
}

/// Capture only the palette state shared by legacy VGA and indexed VBE.
/// Unlike [`save`], this never touches sequencer, CRTC, graphics-controller or
/// aperture state, so it is safe while a firmware VBE mode is scanning out.
pub fn save_dac(_cap: &crate::kernel::platform::VgaCap, state: &mut VgaState) {
    use crate::kernel::portio::{inb, outb};
    let dac_mask = inb(0x3C6);
    // QEMU's legacy VGA returns zero for the standard PEL-mask read even when
    // scanout is using the normal all-bits mask. Replaying that fabricated
    // zero during a display handoff makes every indexed VBE pixel select DAC
    // entry zero. A zero mask is therefore unknowable on this backend.
    state.dac_mask = if crate::kernel::platform::get().host
        == crate::kernel::platform::Host::Qemu
        && dac_mask == 0
    {
        0xFF
    } else {
        dac_mask
    };
    state.dac_index = inb(0x3C8);
    state.dac_state = inb(0x3C7);
    outb(0x3C7, 0);
    for i in 0..768 { state.dac[i] = inb(0x3C9); }
}

/// Program `state` back into the live card: registers, DAC, and plane
/// memory. Called while acquiring the physical lease, or when repainting an
/// owner that already holds it.
pub fn restore(_cap: &crate::kernel::platform::VgaCap, state: &VgaState) {
    if state.planes.is_empty() { return; }
    use crate::kernel::portio::{inb, outb};

    // Reset AC flipflop to known (index) state before any VGA register work.
    let _ = inb(0x3DA);

    // Blank the display for the entire mode-set so the user doesn't see
    // intermediate state — the prior mode's CRTC/AC/DAC settings vs. the
    // new mode's plane data is a parade of garbage otherwise. SEQ Index 1
    // bit 5 = "Screen Off" forces DAC output to 0 without touching any
    // other state. The full-mode SEQ restore below intentionally OR-s bit
    // 5 back in (so the rest of CRTC/GC/AC/DAC reprogramming stays dark);
    // an explicit final write of SEQ[1] unblanks once everything is set.
    outb(0x3C4, 1);
    outb(0x3C5, inb(0x3C5) | 0x20);

    // Step 1: Write planes in forced flat planar mode.
    // Need misc_output for clock source, but force sequential planar access.
    outb(0x3C4, 0); outb(0x3C5, 0x01); // sync reset
    outb(0x3C2, state.misc_output);
    outb(0x3C4, 2); outb(0x3C5, 0x0F); // map mask: all planes
    outb(0x3C4, 4); outb(0x3C5, 0x06); // mem mode: sequential, no chain-4
    outb(0x3C4, 0); outb(0x3C5, 0x03); // release reset
    outb(0x3CE, 5); outb(0x3CF, 0x00); // GC mode: write mode 0
    outb(0x3CE, 6); outb(0x3CF, 0x05); // GC misc: graphics, A0000/64K

    // Write planes through the kernel-side low-memory mapping (see
    // `save` for the rationale).
    let vga_window = (crate::LOW_MEM_BASE + 0xA0000) as *mut u8;
    let mut plane_bytes = alloc::vec![0u8; 65536];
    for plane in 0..4u8 {
        outb(0x3C4, 2); outb(0x3C5, 1 << plane);
        for (offset, byte) in plane_bytes.iter_mut().enumerate() {
            *byte = state.planes[state.layout().index(plane as usize, offset)];
        }
        unsafe { core::ptr::copy_nonoverlapping(plane_bytes.as_ptr(), vga_window, 65536); }
    }

    // Reload the guest's data latches (captured via Cirrus CR22 in
    // `save`): stage the four bytes at offset 0, one read
    // pulls all four into the latches, then put the real content back.
    // Writes never load latches and everything below Step 2 is port
    // I/O only, so the guest resumes with its blit state intact. Still
    // in forced flat-planar write mode 0 here, so the staging writes
    // land verbatim.
    {
        let plat = crate::kernel::platform::get();
        if plat.vga_readback {
            for plane in 0..4u8 {
                outb(0x3C4, 2); outb(0x3C5, 1 << plane);
                unsafe { core::ptr::write_volatile(vga_window, state.latches[plane as usize]); }
            }
            unsafe { let _ = core::ptr::read_volatile(vga_window as *const u8); }
            for plane in 0..4u8 {
                outb(0x3C4, 2); outb(0x3C5, 1 << plane);
                unsafe {
                    core::ptr::write_volatile(
                        vga_window,
                        state.planes[state.layout().index(plane as usize, 0)],
                    );
                }
            }
        }
    }

    // Step 2: Set target mode registers.
    // Bracket SEQ writes with sync reset so a dot-clock change in
    // misc_output/seq[1] doesn't glitch the sequencer mid-cycle.
    // Reverse iteration so SEQ[0] = state.seq[0] is the last write
    // and naturally acts as the release.
    outb(0x3C4, 0); outb(0x3C5, 0x01); // assert sync reset
    outb(0x3C2, state.misc_output);
    outb(0x3DA, state.feature_ctl); // FCR (color mode write port)
    // SEQ restore: hold screen-off (bit 5) through SEQ[1] so the CRTC/AC/DAC
    // reprogramming below stays dark. The final explicit SEQ[1] write at
    // the end of this function unblanks.
    for i in (0..5u8).rev() {
        let v = if i == 1 { state.seq[1] | 0x20 } else { state.seq[i as usize] };
        outb(0x3C4, i); outb(0x3C5, v);
    }

    // CRTC — unlock first (clear protect bit in reg 0x11)
    outb(0x3D4, 0x11); outb(0x3D5, state.crtc[0x11] & 0x7F);
    for i in 0..25u8 { outb(0x3D4, i); outb(0x3D5, state.crtc[i as usize]); }
    // Graphics Controller
    for i in 0..9u8 { outb(0x3CE, i); outb(0x3CF, state.gc[i as usize]); }

    // For chain-4, finish by replaying the linear CPU aperture
    // through the target mode itstate. The flat pass above preserves the
    // whole 4x64K VGA store, but strict implementations can expose a
    // different address interpretation while that pass is active. A
    // chained write makes the card perform the definitive n&3 / n>>2
    // routing for the visible 64K image. Keep the screen blank and force
    // an unmodified write-mode-0 transfer, then restore the guest's exact
    // write registers.
    if matches!(state.classify_mode(), Some(vga::VgaMode::Mode13h)) {
        let mut chained = alloc::vec![0u8; 0x10000];
        for (address, byte) in chained.iter_mut().enumerate() {
            *byte = state.planes[state.layout().index(address & 3, address >> 2)];
        }

        outb(0x3C4, 2); outb(0x3C5, 0x0F); // all chain-selected planes enabled
        outb(0x3CE, 1); outb(0x3CF, 0x00); // disable set/reset
        outb(0x3CE, 3); outb(0x3CF, 0x00); // no rotate/ALU operation
        outb(0x3CE, 5); outb(0x3CF, state.gc[5] & !0x03); // write mode 0
        outb(0x3CE, 8); outb(0x3CF, 0xFF); // pass every CPU data bit

        let chained_window = (crate::LOW_MEM_BASE + 0xA0000) as *mut u8;
        for (i, &src) in chained.iter().enumerate() {
            unsafe { core::ptr::write_volatile(chained_window.add(i), src); }
        }

        outb(0x3C4, 2); outb(0x3C5, state.seq[2]);
        for i in [1u8, 3, 5, 8] {
            outb(0x3CE, i); outb(0x3CF, state.gc[i as usize]);
        }
    }

    // Text mode needs the same treatment, and for the same reason: odd/even
    // is a different address interpretation, so the flat planar pass above
    // writes plane bytes without exercising the target odd/even address
    // routing. Replay the visible page through the target mode and let the
    // card perform the definitive A0 plane selection itself.
    //
    // Without this, a text-mode program that follows a mode-13h one sees
    // every cell smeared across four bytes (`00 00 char attr`): Dark Forces
    // launched after Duke3D rendered its screen as two column-interleaved
    // streams, while B8000 row 0 — written after the mode set — was clean.
    if matches!(state.classify_mode(), Some(vga::VgaMode::Text { .. })) {
        let mut text = alloc::vec![0u8; 0x8000];
        for (address, byte) in text.iter_mut().enumerate() {
            *byte = state.planes[
                state.layout().index(address & 1, address >> 1)
            ];
        }

        outb(0x3C4, 2); outb(0x3C5, 0x03); // char plane 0 + attribute plane 1
        outb(0x3CE, 1); outb(0x3CF, 0x00); // disable set/reset
        outb(0x3CE, 3); outb(0x3CF, 0x00); // no rotate/ALU operation
        outb(0x3CE, 5); outb(0x3CF, state.gc[5] & !0x03); // write mode 0
        outb(0x3CE, 8); outb(0x3CF, 0xFF); // pass every CPU data bit

        let text_window = (crate::LOW_MEM_BASE + 0xB8000) as *mut u8;
        for (i, &src) in text.iter().enumerate() {
            unsafe { core::ptr::write_volatile(text_window.add(i), src); }
        }

        outb(0x3C4, 2); outb(0x3C5, state.seq[2]);
        for i in [1u8, 3, 5, 8] {
            outb(0x3CE, i); outb(0x3CF, state.gc[i as usize]);
        }
    }
    // Attribute Controller — write all 21 registers
    let _ = inb(0x3DA);
    for i in 0..21u8 { outb(0x3C0, i); outb(0x3C0, state.ac[i as usize]); }
    // Restore the program's AC state. Same pattern as `save`.
    let _ = inb(0x3DA);
    outb(0x3C0, state.ac_state.index);
    if !state.ac_state.pending_data {
        let _ = inb(0x3DA);
    }
    unsafe { AC = state.ac_state; }
    // DAC
    outb(0x3C6, state.dac_mask);
    outb(0x3C8, 0);
    for i in 0..768 { outb(0x3C9, state.dac[i]); }
    // Restore the program's DAC index latch + read/write mode.
    // dac_state bits[1:0]: 0x03 = read-mode (set via 0x3C7),
    //                      0x00 = write-mode (set via 0x3C8).
    if state.dac_state & 3 == 3 {
        outb(0x3C7, state.dac_index);
    } else {
        outb(0x3C8, state.dac_index);
    }
    // Unblank: rewrite SEQ[1] with the saved (bit-5-cleared) value now
    // that CRTC/GC/AC/DAC are all loaded. Has to happen before the index
    // restore below, which sets SEQ index to whatever the program had.
    outb(0x3C4, 1); outb(0x3C5, state.seq[1]);

    // Restore index registers
    outb(0x3C4, state.seq_index);
    outb(0x3D4, state.crtc_index);
    outb(0x3CE, state.gc_index);
}

/// Re-enable Attribute Controller palette output after a broken firmware
/// state restore. SeaVGABIOS/QEMU restores the AC address latch with PAS clear
/// even though the saved display was visible. The register contents and
/// flip-flop phase remain those of `state`; only the display-enable bit is
/// normalized at this ownership boundary.
pub fn enable_palette_output(
    _cap: &crate::kernel::platform::VgaCap,
    state: &VgaState,
) {
    use crate::kernel::portio::{inb, outb};
    let ac_state = AcState {
        index: state.ac_state.index | 0x20,
        pending_data: state.ac_state.pending_data,
    };
    let _ = inb(0x3DA);
    outb(0x3C0, ac_state.index);
    if !ac_state.pending_data {
        let _ = inb(0x3DA);
    }
    unsafe { AC = ac_state; }
}

/// Restore only the DAC portion of a detached VBE display. Replaying the
/// legacy sequencer/CRTC register file after a firmware VBE mode set would
/// destroy that mode, but indexed VBE scanout still depends on this
/// palette and PEL mask.
pub fn restore_dac(_cap: &crate::kernel::platform::VgaCap, state: &VgaState) {
    use crate::kernel::portio::outb;
    outb(0x3C6, state.dac_mask);
    outb(0x3C8, 0);
    for &component in &state.dac {
        outb(0x3C9, component);
    }
    if state.dac_state & 3 == 3 {
        outb(0x3C7, state.dac_index);
    } else {
        outb(0x3C8, state.dac_index);
    }
}
