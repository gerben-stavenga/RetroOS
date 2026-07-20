//! GUSTEST — Gravis UltraSound (GF1) emulation probe.
//!
//! Exercises the emulated GUS the way real drivers do, one phase per marker
//! (a `FAIL-*` line stops the run):
//!
//! - `GDRAM-OK`  — chip reset, then the standard detection poke/peek: distinct
//!   bytes at DRAM 0x00000 and 0xFFFFF both read back (full 1 MB board, no
//!   aliasing inside the 20-bit window).
//! - `GREG-OK`   — GF1 register-file write/readback through the voice-select /
//!   register-select / data-low/high scheme: a 16-bit voice register
//!   (frequency control) and the global active-voices register (readback sets
//!   the top two bits).
//! - `GTIMER-OK` — timer 1 (80 µs units) through the AdLib-shaped 2X8/2X9
//!   window + reg 0x45 IRQ enable + reset-reg master enable actually raises
//!   the ULTRASND IRQ, and the handler sees the T1 bit in the 2X6 status.
//! - `GDMA-OK`   — a 256-byte sample upload through the virtual 8237 + GF1
//!   regs 0x42/0x41 lands in DRAM byte-exact, raises the TC IRQ, and reading
//!   0x41 (bit 6 set) acks it.
//! - `GVOICE-OK` — the uploaded block programmed as a looping voice actually
//!   plays: the live current-address register moves.
//!
//! The wiring comes from `ULTRASND` in the environment — base, play DMA and
//! GF1 IRQ — the same string the kernel configures the emulated card from.
//! Nothing here is hardcoded, so the probe follows whatever the image ships
//! and cannot drift out of step with CONFIG.SYS. Both PIC halves are handled:
//! an IRQ above 7 vectors through 0x70+, unmasks on the slave, needs master
//! IR2 (the cascade) open, and EOIs both chips.
//!
//! A dosrt app: 32-bit protected mode under the DPMI host, so it still
//! exercises the DOS personality's port I/O, IRQ delivery and virtual 8237.
//!
//! CI: `test/hosted_games.sh` runs this and asserts every marker.

#![no_std]
#![no_main]

use dosrt::io::{inb, outb};
use dosrt::{dos, puts};

/// Card wiring, read from `ULTRASND=<base>,<playdma>,<recdma>,<gf1irq>,<midiirq>`
/// — base hex, the rest decimal, which is what every driver and setup writes.
#[derive(Clone, Copy)]
struct Wiring {
    base: u16,
    dma: u8,
    irq: u8,
}

impl Wiring {
    /// Every field is required and must parse. There is deliberately NO
    /// default anywhere in here: a probe that quietly substitutes a guess
    /// asserts nothing, and would pass while testing the wrong card — the
    /// exact failure that let a broken env read ship once already.
    fn from_env() -> Wiring {
        let Some(s) = dos::env_get(b"ULTRASND") else {
            fail("ULTRASND not in environment")
        };
        let mut it = s.split(|&b| b == b',');
        let base = field(&mut it, 16, "base");
        let dma = field(&mut it, 10, "playdma");
        let _rec = field(&mut it, 10, "recdma"); // parsed to validate; not modelled
        let irq = field(&mut it, 10, "gf1irq");
        Wiring { base: base as u16, dma: dma as u8, irq: irq as u8 }
    }

    // GF1 block sits at base + 0x100.
    fn voice(&self) -> u16 { self.base + 0x102 }   // voice select (page)
    fn reg(&self) -> u16 { self.base + 0x103 }     // register select
    fn datlo(&self) -> u16 { self.base + 0x104 }   // data low (16-bit regs)
    fn dathi(&self) -> u16 { self.base + 0x105 }   // data high / 8-bit data
    fn dram(&self) -> u16 { self.base + 0x107 }    // DRAM peek/poke
    fn irqstat(&self) -> u16 { self.base + 0x006 } // GF1 IRQ status
    fn timer(&self) -> u16 { self.base + 0x008 }   // AdLib-shaped timer window

    /// 8237 channel 0..3: address/count are ch*2 and ch*2+1, but the page
    /// register is not contiguous — hence the table.
    fn dma_regs(&self) -> (u16, u16, u16) {
        const PAGES: [u16; 4] = [0x87, 0x83, 0x81, 0x82];
        let ch = (self.dma & 3) as u16;
        (ch * 2, ch * 2 + 1, PAGES[ch as usize])
    }

    /// Real-mode vector, PIC mask port + bit, and whether this line is on the
    /// slave. IRQs 0..7 land at 0x08+n on the master; 8..15 at 0x70+(n-8) on
    /// the slave, which also needs master IR2 (the cascade) open.
    fn irq_wiring(&self) -> (u8, u16, u8, bool) {
        if self.irq < 8 {
            (0x08 + self.irq, 0x21, 1 << self.irq, false)
        } else {
            (0x70 + (self.irq - 8), 0xA1, 1 << (self.irq - 8), true)
        }
    }
}

/// A required ULTRASND field. Missing or malformed is fatal, never defaulted.
fn field<'a>(it: &mut impl Iterator<Item = &'a [u8]>, radix: u32, what: &str) -> u32 {
    match it.next().and_then(|t| parse(t, radix)) {
        Some(v) => v,
        None => {
            puts("FAIL-GENV: ULTRASND field '");
            puts(what);
            puts("' missing or malformed\r\n");
            park(1)
        }
    }
}

fn fail(why: &str) -> ! {
    puts("FAIL-GENV: ");
    puts(why);
    puts("\r\n");
    park(1)
}

fn parse(s: &[u8], radix: u32) -> Option<u32> {
    let mut v: u32 = 0;
    let mut any = false;
    for &c in s {
        let d = (c as char).to_digit(radix)?;
        v = v.wrapping_mul(radix).wrapping_add(d);
        any = true;
    }
    if any { Some(v) } else { None }
}

// ── GF1 register access ─────────────────────────────────────────────────────

/// Placeholder only — overwritten by `from_env()` before any use. Deliberately
/// not a plausible wiring: if it ever reaches the card, the run must break
/// loudly rather than quietly probe a default port.
static mut W: Wiring = Wiring { base: 0, dma: 0xFF, irq: 0xFF };

fn w() -> Wiring {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(W)) }
}

fn selreg(r: u8) { outb(w().reg(), r); }
fn wr8(v: u8) { outb(w().dathi(), v); }
fn rd8() -> u8 { inb(w().dathi()) }

fn wr16(v: u16) {
    let p = w().datlo();
    outb(p, v as u8);
    outb(p + 1, (v >> 8) as u8);
}

fn rd16() -> u16 {
    let p = w().datlo();
    inb(p) as u16 | ((inb(p + 1) as u16) << 8)
}

/// DRAM I/O address: reg 0x43 = bits 15:0, reg 0x44 = bits 19:16.
fn set_dram_addr(lo16: u16, hi4: u8) {
    selreg(0x43);
    wr16(lo16);
    selreg(0x44);
    wr8(hi4);
}

fn dram_peek(lo16: u16, hi4: u8) -> u8 {
    set_dram_addr(lo16, hi4);
    inb(w().dram())
}

fn dram_poke(lo16: u16, hi4: u8, v: u8) {
    set_dram_addr(lo16, hi4);
    outb(w().dram(), v);
}

// ── interrupt ───────────────────────────────────────────────────────────────

static mut IRQ_SEEN: bool = false;
static mut DMA_SEEN: bool = false;

unsafe extern "C" fn gus_isr() {
    let wi = w();
    let st = inb(wi.irqstat());
    if st & 0x04 != 0 {
        // timer 1
        unsafe { core::ptr::write_volatile(core::ptr::addr_of_mut!(IRQ_SEEN), true) };
        outb(wi.timer(), 0x04); // index 4 = timer control
        outb(wi.timer() + 1, 0x80); //   clear the expiry flags
        outb(wi.timer() + 1, 0x00); //   ...and stop both
    } else if st & 0x80 != 0 {
        // DMA terminal count — reading 0x41 acks it
        selreg(0x41);
        let _ = rd8();
        unsafe { core::ptr::write_volatile(core::ptr::addr_of_mut!(DMA_SEEN), true) };
    }
    let (_, _, _, slave) = wi.irq_wiring();
    if slave {
        outb(0xA0, 0x20);
    }
    outb(0x20, 0x20);
}

/// BIOS tick counter at 0040:006C, 18.2 Hz.
fn ticks() -> u32 {
    unsafe { core::ptr::read_volatile(dosrt::conv_flat_ptr(0x40).add(0x6C) as *const u32) }
}

/// Wait for a flag, up to ~2 s of REAL time. Not an instruction-count loop:
/// KVM runs the guest at native speed, where a counted loop expires in
/// milliseconds — before any IRQ could arrive.
fn wait_flag(flag: *const bool) -> bool {
    let start = ticks();
    loop {
        if unsafe { core::ptr::read_volatile(flag) } {
            return true;
        }
        if ticks().wrapping_sub(start) >= 36 {
            return false;
        }
    }
}

/// Park on a keypress (INT 16h AH=00) before leaving.
///
/// The harness snapshots the screen at 1 Hz and treats a guest that exits
/// early as a failure, so the verdict has to stay on screen until it is
/// caught — the same reason the asm version ended on INT 16h.
fn park(code: u8) -> ! {
    let mut r = dosrt::dpmi::Rmcs::default();
    r.eax = 0x0000;
    dosrt::dpmi::sim_int(0x16, &mut r);
    dos::exit(code)
}

fn die(marker: &str) -> ! {
    puts(marker);
    puts("\r\n");
    park(1)
}

#[unsafe(no_mangle)]
pub fn app_main(_argc: usize, _argv: &[&[u8]]) {
    unsafe { core::ptr::write_volatile(core::ptr::addr_of_mut!(W), Wiring::from_env()) };
    let wi = w();

    // chip reset: reg 0x4C bit 0 low, settle, then high
    selreg(0x4C);
    wr8(0x00);
    for _ in 0..100 {
        core::hint::spin_loop();
    }
    selreg(0x4C);
    wr8(0x01);

    // ── phase 1: DRAM poke/peek at both ends of the 1 MB window ──
    dram_poke(0x0000, 0x00, 0x55);
    dram_poke(0xFFFF, 0x0F, 0xAA);
    if dram_peek(0xFFFF, 0x0F) != 0xAA {
        die("FAIL-GDRAM");
    }
    if dram_peek(0x0000, 0x00) != 0x55 {
        die("FAIL-GDRAM"); // byte 0 unmolested — no alias
    }
    puts("GDRAM-OK\r\n");

    // ── phase 2: register write/readback ──
    outb(wi.voice(), 3);
    selreg(0x01);
    wr16(0x2345); // frequency control
    selreg(0x81);
    if rd16() != 0x2345 {
        die("FAIL-GREG");
    }
    selreg(0x0E);
    wr8(0x1F); // active voices = 32
    selreg(0x8E);
    if rd8() != 0xDF {
        die("FAIL-GREG"); // hardware sets the top two bits
    }
    puts("GREG-OK\r\n");

    // ── phase 3: timer 1 → the ULTRASND IRQ ──
    let (vec, mask_port, mask_bit, slave) = wi.irq_wiring();
    // Distinct marker: an install failure and a timer timeout are different
    // faults and must not share a name.
    if let Err(e) = dosrt::dpmi::install_handler(vec, gus_isr) {
        puts("FAIL-GINSTALL vec=");
        dosrt::puthex8(vec);
        puts(" err=");
        dosrt::puthex32(e as u32);
        puts("\r\n");
        park(1)
    }
    outb(mask_port, inb(mask_port) & !mask_bit);
    if slave {
        // Master IR2 is the cascade the slave hangs off; masked, an IRQ
        // above 7 never reaches the CPU at all.
        outb(0x21, inb(0x21) & !0x04);
    }

    selreg(0x4C);
    wr8(0x07); // run + DAC + master IRQ enable
    selreg(0x46);
    wr8(156); // T1 count: (256-156)*80us = 8 ms period
    selreg(0x45);
    wr8(0x04); // enable the T1 IRQ
    outb(wi.timer(), 0x04);
    outb(wi.timer() + 1, 0x01); // start T1
    if !wait_flag(core::ptr::addr_of!(IRQ_SEEN)) {
        die("FAIL-GTIMER");
    }
    puts("GTIMER-OK\r\n");

    // ── phase 4: DMA sample upload + TC IRQ ──
    // The buffer must be conventional memory the 8237 can address, so take it
    // from DOS rather than our own PM heap.
    let Some((seg, _sel)) = dosrt::dpmi::alloc_dos_mem(16) else {
        die("FAIL-GDMA");
    };
    let buf = dosrt::conv_flat_ptr(seg);
    for i in 0..256usize {
        unsafe { core::ptr::write_volatile(buf.add(i), (i as u8) ^ 0x5A) };
    }
    let phys = (seg as u32) << 4;

    let (addr_port, cnt_port, page_port) = wi.dma_regs();
    outb(0x0A, 0x04 | wi.dma); // mask
    outb(0x0B, 0x48 | wi.dma); // single, read (mem -> card)
    outb(0x0C, 0x00); // clear flip-flop
    outb(addr_port, phys as u8);
    outb(addr_port, (phys >> 8) as u8);
    outb(page_port, (phys >> 16) as u8);
    outb(cnt_port, 255); // count - 1
    outb(cnt_port, 0);
    outb(0x0A, wi.dma); // unmask

    selreg(0x42);
    wr16(0x0000); // DMA start: DRAM 0 (units of 16)
    selreg(0x41);
    wr8(0x21); // enable upload + TC IRQ (bits 0,5)
    if !wait_flag(core::ptr::addr_of!(DMA_SEEN)) {
        die("FAIL-GDMA");
    }
    if dram_peek(0x0000, 0x00) != 0x5A {
        die("FAIL-GDMA"); // 0 ^ 0x5A
    }
    if dram_peek(0x00FF, 0x00) != 0xA5 {
        die("FAIL-GDMA"); // 255 ^ 0x5A
    }
    puts("GDMA-OK\r\n");

    // ── phase 5: the uploaded block as a looping, audible voice ──
    outb(wi.voice(), 0);
    selreg(0x01);
    wr16(0x0400); // 1.0 frames/sample
    selreg(0x02);
    wr16(0x0000); // start = 0
    selreg(0x03);
    wr16(0x0000);
    selreg(0x04);
    wr16(0x0002); // end = frame 256 (combined = 256 << 9)
    selreg(0x05);
    wr16(0x0000);
    selreg(0x0A);
    wr16(0x0000); // current address = 0
    selreg(0x0B);
    wr16(0x0000);
    selreg(0x09);
    wr16(0xFFF0); // current volume: near unity
    selreg(0x0C);
    wr8(7); // pan center
    selreg(0x00);
    wr8(0x08); // voice control: 8-bit forward loop, start

    selreg(0x8B); // live current-address low
    let watch = rd16();
    let start = ticks();
    loop {
        selreg(0x8B);
        if rd16() != watch {
            break; // it moved: the voice is playing
        }
        if ticks().wrapping_sub(start) >= 36 {
            die("FAIL-GVOICE");
        }
    }
    puts("GVOICE-OK\r\n");
    park(0)
}
