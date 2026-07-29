//! The machine, probed once, as types.
//!
//! Everything the kernel needs to know about the hardware/host it landed on
//! is detected EAGERLY here, at one fixed point early in startup, and frozen
//! into [`Platform`] — an immutable, write-once description. Policy code
//! (VGA passthrough vs emulation, native vs substitute BIOS, console
//! routing, per-personality I/O bitmaps) derives from these types with
//! exhaustive matches; nothing downstream probes hardware lazily or keeps a
//! private `static` verdict. Adding an enum variant breaks every policy
//! site at compile time — deliberately.

use crate::println;

pub struct Platform {
    pub host: Host,
    pub display: Display,
    /// What sound hardware answered (probe fact).
    pub audio_hw: AudioHw,
    /// The real Sound Blaster's own report, when one answered: base,
    /// generation, and (SB16 only) its strapped IRQ/DMA.
    pub sb_card: Option<crate::kernel::drivers::sb16::SbCard>,
    /// The physical card's wiring: read from an SB16's mixer, or declared
    /// for an early card (`SB_AUDIO=native <irq> <dma>`). This is the HOST
    /// side — which line the PIC delivers and which 8237 channels we
    /// reprogram. The guest's own IRQ/DMA are labels it picks in BLASTER;
    /// the relay and the DMA remap translate between them.
    pub sb_wiring: Option<crate::kernel::drivers::sb16::SbWiring>,
    pub firmware: Firmware,
    pub audio: Audio,
    /// The real card exposes Cirrus-style save/restore readbacks (CR22
    /// latches, CR24 AC flip-flop, CR26 AC index). With them, task
    /// save/restore is exact without trapping 0x3C0/0x3DA; without them the
    /// snapshot is best-effort (warned at boot). Always false off VgaCard.
    pub vga_readback: bool,
    /// A host filesystem transport answered — the native backend punch-through
    /// (hosted) or the COM1 client (metal / the Python bridge). Whether it ends
    /// up as `/host`, as the root, or unused is `startup`'s mount policy.
    pub hostfs: bool,
    pub debug: DebugSink,
}

/// What is running the kernel.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Host {
    /// QEMU (the loader saw fw_cfg): synthetic-retrace fabrication etc.
    Qemu,
    /// Real hardware — or an emulator without fw_cfg (Bochs), which earns
    /// real-hardware treatment: trust the devices.
    Metal,
    /// The hosted interpreter backend (arch-interp as a host process).
    Interp,
}

/// The display path. Exactly one of these is true, decided here — not
/// re-derived piecemeal by render/console/IOPB code.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Display {
    /// A real VGA card drives the panel, scanning out its own memory: metal
    /// that booted in text mode with no framebuffer handed over. Guests
    /// program the hardware directly (passthrough port window); console = VGA
    /// text; the ROM's video services are authoritative (see [`Firmware`]).
    VgaCard,
    /// No card, but the loader handed over a linear framebuffer (UEFI/GOP) —
    /// or a hosted window supplied one. The emulated VGA blits into it; the
    /// descriptor travels with the verdict, so nothing has to call back to
    /// find out where the pixels go.
    Framebuffer,
    /// No card or framebuffer, but a host window installed a present sink
    /// (retroos-play): the emulated VGA renders into the window.
    HostWindow,
    /// Nothing to display on (headless interp run): the emulated VGA still
    /// models state — screendumps and --screenshot remain possible.
    Headless,
}

/// The unique authority to make the selected display visible. Unlike
/// [`Display`], this is a moved resource, never stored in the global platform
/// facts.
pub enum DisplayToken {
    VgaCard,
    Framebuffer(crate::kernel::display::Framebuffer),
    HostWindow,
    Headless,
}

impl DisplayToken {
    pub fn kind(&self) -> Display {
        match self {
            Self::VgaCard => Display::VgaCard,
            Self::Framebuffer(_) => Display::Framebuffer,
            Self::HostWindow => Display::HostWindow,
            Self::Headless => Display::Headless,
        }
    }
}

pub struct ProbedPlatform {
    pub facts: &'static Platform,
    pub display: DisplayToken,
}

/// Kernel console state while it is the visible display owner.
pub struct VisibleScreen {
    writer: crate::vga::Screen,
    display: DisplayToken,
}

/// Kernel console state while another owner is visible. It intentionally does
/// not implement `fmt::Write`.
pub struct HiddenScreen {
    writer: crate::vga::Screen,
    native_vga: Option<crate::kernel::dos::VgaState>,
}

impl VisibleScreen {
    pub fn new(writer: crate::vga::Screen, display: DisplayToken) -> Self {
        Self { writer, display }
    }

    pub fn suspend<A: crate::Arch>(self, _machine: &mut A) -> (HiddenScreen, DisplayToken) {
        let native_vga = if matches!(self.display, DisplayToken::VgaCard) {
            let mut vga = crate::kernel::dos::VgaState::new();
            vga.save_from_hardware();
            Some(vga)
        } else {
            None
        };
        (HiddenScreen { writer: self.writer, native_vga }, self.display)
    }
}

impl HiddenScreen {
    pub fn resume<A: crate::Arch>(
        self,
        _machine: &mut A,
        display: DisplayToken,
    ) -> VisibleScreen {
        if matches!(display, DisplayToken::VgaCard) {
            self.native_vga
                .as_ref()
                .expect("native screen lost VGA state")
                .restore_to_hardware();
        }
        VisibleScreen { writer: self.writer, display }
    }
}

impl core::fmt::Write for VisibleScreen {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        core::fmt::Write::write_str(&mut self.writer, s)
    }
}

/// Real-mode firmware at the legacy ROM window.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Firmware {
    /// A legacy BIOS owns F000 (far-JMP at the reset vector): DOS threads
    /// use the real ROM services.
    NativeBios,
    /// No ROM (UEFI metal, interp's zeroed RAM): the DOS personality
    /// installs its substitute Rust BIOS (`dos/bios.rs`).
    Substitute,
}

/// What sound hardware answered — pure probe fact, no policy. Which of
/// these the guest may drive itself, and what the kernel does with the rest,
/// is [`Audio`], decided later from the boot config.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum AudioHw {
    /// A real Sound Blaster answered a DSP reset with 0xAA.
    Sb,
    /// An Intel HD Audio controller on PCI (class 04:03).
    Hda,
    /// An AC'97 codec on PCI.
    Ac97,
    /// A backend installed a sink behind the canonical port window (hosted).
    PortWindow,
    /// Nothing answered.
    None,
}

impl AudioHw {
    /// The default verdict for this hardware, before config policy: a real
    /// SB is the guest's (only card a DOS program can drive; the cheapest
    /// thing a slow machine can do), everything else is the kernel's to
    /// emulate through.
    fn default_verdict(self) -> Audio {
        match self {
            AudioHw::Sb => Audio::NativeSb,
            AudioHw::Hda => Audio::EmulatedHda,
            AudioHw::Ac97 => Audio::EmulatedAc97,
            AudioHw::PortWindow => Audio::EmulatedPortWindow,
            AudioHw::None => Audio::EmulatedSilent,
        }
    }
}

/// The audio path — who owns the sound hardware and what renders through
/// it. Derived from [`AudioHw`] plus the boot config's `SB_AUDIO=` policy
/// (`apply_audio_mode`), never probed directly.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Audio {
    /// A real Sound Blaster answered on a LEGACY machine (real VGA scanout —
    /// the 386/486/Pentium class, and QEMU's BIOS path with `-device sb16`):
    /// the guest owns the card NATIVELY. DSP traffic forwards straight to the
    /// hardware, guest 8237 programming is remapped onto the real chip, the
    /// card's IRQ reaches the guest vPIC — zero kernel mixing, no kernel
    /// sink, and no GM bank ROM is burned. Old hardware cannot afford the
    /// emulated stack and does not need it: the machine IS the sound card the
    /// games were written for.
    NativeSb,
    /// A real Sound Blaster on a BIOS machine that the owner chose to run
    /// EMULATED (`audio=mixed`): the software SB/GUS/GM are emulated as usual
    /// and their canonical PCM renders out the real card as the kernel `sound`
    /// sink (`drivers::sb16`, 16-bit auto-init DMA on channel 5, IRQ 5). Buys
    /// GUS/GM music on a machine that only has an SB — DOOM with wavetable
    /// MIDI on a fast Pentium — at the cost of mixing every source in
    /// software. Not a probe verdict: one card has one owner, so this is a
    /// judgment about CPU budget that only the machine's owner can make.
    SbSink,
    /// No card; the software SB16 renders through the kernel sound API into an
    /// Intel HD Audio controller found on PCI (QEMU `intel-hda`, modern metal).
    EmulatedHda,
    /// No card; the software SB16 renders through the kernel sound API into
    /// the AC'97 codec found on PCI (UEFI-class metal).
    EmulatedAc97,
    /// No card or codec; rendering goes to the canonical audio port window
    /// (the interpreter's WAV sink answered the signature probe).
    EmulatedPortWindow,
    /// Nothing answers. Emulation still satisfies device detection (games
    /// configure and run); playback is dropped.
    EmulatedSilent,
}

impl Audio {
    /// Guest SB programming reaches the real card directly (native playback),
    /// vs the software DSP. Phase A always emulates — even with a real SB16
    /// present it is a kernel sink, not guest-owned — so this is always false.
    /// Phase B makes it dynamic (true while a DOS program drives the card).
    /// The guest owns the Sound Blaster: its DSP/mixer ports are granted
    /// through the IOPB and its DMA is remapped onto the real 8237.
    pub fn sb_passthrough(self) -> bool {
        matches!(self, Audio::NativeSb)
    }
}

/// Where dbg_println bytes go. Installed by the backend long before startup
/// (boot prints need it); recorded here so policy can reason about it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum DebugSink {
    /// Port 0xE9 debugcon (QEMU/Bochs `-debugcon`; harmlessly absent on
    /// real metal).
    Debugcon,
    /// The host process's stdout (hosted backend).
    HostStdout,
}

impl Display {
    /// Guest VGA port programming reaches the real card (vs the VgaState
    /// register model).
    pub fn vga_passthrough(self) -> bool {
        matches!(self, Display::VgaCard)
    }


}

impl Platform {
    /// The focused DOS thread owns 0x3C0/0x3DA directly — no AC-tracking
    /// traps. True on a real card everywhere except QEMU, whose 0x3DA
    /// retrace is fabricated (the trap is load-bearing there). Save/restore
    /// then recovers AC sequencing state from the card: exactly via the
    /// Cirrus readbacks when `vga_readback`, best-effort otherwise.
    pub fn vga_ports_direct(&self) -> bool {
        self.display.vga_passthrough() && self.host != Host::Qemu
    }
}

/// Environment facts only the ENTRY crate knows — injected before `probe`
/// instead of selected by `cfg`. Metal installs `{ metal, Debugcon,
/// fbcon::active }`; the hosted entry installs `{ interp, HostStdout,
/// || false }`. The default (never installed) describes a bare headless
/// substitute machine, so a `probe` without an entry is coherent, not UB.
#[derive(Clone, Copy)]
pub struct HostEnv {
    /// The framebuffer this backend presents into, if any: a GOP framebuffer
    /// on metal, a window-sized buffer on hosted. Probed once — the kernel
    /// writes into it directly rather than through a present callback.
    pub framebuffer: fn() -> Option<crate::kernel::display::Framebuffer>,
    /// Where boot debug bytes were routed (recorded for policy).
    pub debug: DebugSink,
    /// True on the bare-metal backend (chooses Metal/Qemu vs Interp for host).
    pub is_metal: bool,
}

impl HostEnv {
    fn host(&self, is_qemu: bool) -> Host {
        if !self.is_metal {
            Host::Interp
        } else if is_qemu {
            Host::Qemu
        } else {
            Host::Metal
        }
    }
}

static mut HOST_ENV: HostEnv = HostEnv {
    framebuffer: || None,
    debug: DebugSink::HostStdout,
    is_metal: false,
};

/// Install the entry's environment facts. Boot-time single-threaded; call
/// before `probe`.
pub fn set_host_env(env: HostEnv) {
    unsafe { HOST_ENV = env };
}

fn host_env() -> HostEnv {
    unsafe { HOST_ENV }
}

static mut PLATFORM: Option<Platform> = None;

/// Probe the machine and freeze the result. Called exactly once, early in
/// `startup` — after the heap, before threading (still single-threaded, so
/// the write-once static needs no lock).
pub fn probe<A: crate::Arch>(
    machine: &mut A,
    boot: &crate::BootConfig,
) -> ProbedPlatform {
    let mut sb_card = None;
    let audio_hw = probe_audio(machine, &mut sb_card);
    // A native host backend (hosted "punch-through") means /host is available
    // without COM1 — take it as hostfs-present and skip the serial probe.
    // Otherwise fall back to the COM1 transport (metal, or the Python bridge).
    let hostfs = crate::kernel::fs::hostfs::host_backend_installed()
        || crate::kernel::fs::hostfs::init();

    // Metal: ask the hardware. Hosted: the answers are properties of the
    // backend itself — the interp port bus has no VGA device and its zeroed
    // guest RAM never contains a ROM — and its guest address space doesn't
    // even exist yet this early, so there is nothing to probe.
    let env = host_env();
    let p = {
        // Display resolution, unified across backends by precedence:
        //   fbcon → present-sink → metal ⇒ VGA card, else headless.
        //
        // A GOP linear framebuffer (fbcon active) wins: even when a legacy VGA
        // card also answers its I/O ports, the framebuffer — not the dead
        // legacy register file — drives the panel (a UEFI laptop mislabelled
        // `VgaCard` painted blank). `fbcon::init` panics rather than declining
        // a linear framebuffer it cannot render into, so reaching this point
        // with no framebuffer means none was OFFERED, not that one was
        // rejected: the loader left us in VGA text mode.
        //
        // Which then makes the last step a fact about the backend, not a probe.
        // Metal with no framebuffer and no present sink is a legacy PC that
        // booted in text mode — it HAS a VGA card, by construction. The old
        // `vga_card_answers()` (write the SEQ index, read it back) only ever
        // confirmed what `is_metal` already implied: the hosted port bus has no
        // VGA device to answer, and a metal machine that boots this way does.
        let (display, display_token) = if let Some(fb) = (env.framebuffer)() {
            (Display::Framebuffer, DisplayToken::Framebuffer(fb))
        } else if crate::kernel::display::host_present_sink_installed() {
            (Display::HostWindow, DisplayToken::HostWindow)
        } else if env.is_metal {
            (Display::VgaCard, DisplayToken::VgaCard)
        } else {
            (Display::Headless, DisplayToken::Headless)
        };

        // Who owns the IVT follows from WHO DRIVES THE DISPLAY — not from a
        // probe of the ROM. A real VGA card scanning out its own memory IS the
        // legacy PC: such a machine has a ROM, and its video services are
        // authoritative precisely because the card the ROM programs is the
        // panel. That is also why we need it — the ROM drives the modes.
        //
        // Every other display path needs the substitute BIOS, and `install`
        // is all-or-nothing (all 256 IVT slots), so this is one verdict:
        //   * Framebuffer / HostWindow — the panel is OURS to paint from the
        //     emulated `VgaState`. A ROM INT 10h here would faithfully mode-set
        //     a card that is not the display and write VRAM nothing renders
        //     from: the guest sees a frozen screen. The ROM must not own 10h,
        //     hence not the IVT.
        //   * Headless — the hosted backend, whose zeroed guest RAM has no ROM
        //     to call in the first place.
        //
        // This replaced sniffing for the far-JMP (0xEA) at the reset vector
        // F000:FFF0. That inferred "a ROM exists", which is neither what the
        // consumer needs nor reliable: it is one opcode byte against arbitrary
        // firmware code (OVMF has `0F 20 C0 A8 01` there), and it answered
        // wrongly for a legacy-booted machine handed a framebuffer — real ROM
        // present, but its video services still not authoritative.
        let firmware = if matches!(display, Display::VgaCard) {
            Firmware::NativeBios
        } else {
            Firmware::Substitute
        };

        let vga_readback = matches!(display, Display::VgaCard) && vga_readback_answers();

        (Platform {
            host: env.host(boot.is_qemu),
            display,
            firmware,
            vga_readback,
            audio_hw,
            sb_card,
            // Filled by `apply_audio_mode`, which also sees the owner's
            // declaration for cards that cannot report their straps.
            sb_wiring: sb_card.and_then(|c| c.wiring),
            // Policy comes later, when CONFIG.SYS is readable
            // (`apply_audio_mode`); until then, the hardware's default.
            audio: audio_hw.default_verdict(),
            hostfs,
            debug: env.debug,
        }, display_token)
    };

    let (p, display_token) = p;
    unsafe {
        PLATFORM = Some(p);
    }
    let p = get();
    println!(
        "Platform: host={:?} display={:?} firmware={:?} audio={:?} hostfs={} debug={:?}",
        p.host, p.display, p.firmware, p.audio, p.hostfs, p.debug
    );
    if p.vga_ports_direct() {
        if p.vga_readback {
            println!("VGA: Cirrus readbacks (CR22/24/26) — AC ports direct, exact save/restore");
        } else {
            println!("VGA: WARNING no readback extensions — AC ports direct, full process VGA restore NOT supported (flip-flop/latches unrecoverable)");
        }
    }
    ProbedPlatform { facts: p, display: display_token }
}

/// The frozen platform description. Panics if `probe` has not run — an init
/// ordering bug that should be loud.
/// Apply the boot config's sound-mode policy to the frozen probe. Called
/// exactly once by `startup`, after the mounts make CONFIG.SYS readable and
/// before anything reads `audio` (io_policy's IOPB build, the bank burn, the
/// first guest).
///
/// The probe reports which card answered; this decides who owns it. Only a
/// real Sound Blaster is guest-drivable, so only there is there a choice —
/// HDA/AC'97 are PCI codecs no DOS program can address and are always
/// emulated. `mixed` costs a software mix of every source plus the ~5 MB GM
/// bank, and buys GUS/GM wavetable music on an SB-only machine; `native`
/// hands the card over and costs the kernel nothing, which is what a 386/486
/// (and the 86Box/Bochs emulations of one) can afford.
pub fn apply_audio_mode(
    mixed: bool,
    declared: Option<crate::kernel::drivers::sb16::SbWiring>,
) {
    let p = unsafe { (&raw mut PLATFORM).as_mut().unwrap().as_mut() }
        .expect("platform::apply_audio_mode before probe");
    p.audio = match (p.audio_hw, mixed) {
        (AudioHw::Sb, true) => Audio::SbSink,
        (hw, _) => hw.default_verdict(),
    };
    // An SB16 reports its own straps; anything older needs the owner's.
    p.sb_wiring = p.sb_card.and_then(|c| c.wiring).or(declared);
    crate::println!("Audio: {:?} ({})", p.audio,
        if mixed { "SB_AUDIO=mixed" } else { "SB_AUDIO=native" });
}

/// Update the acting SB wiring after a restrap (startup's native-mode
/// BLASTER reconciliation). `sb_card` keeps the probe-time snapshot — this
/// is the wiring the relay/remap act on.
pub fn set_sb_wiring(w: crate::kernel::drivers::sb16::SbWiring) {
    let p = unsafe { (&raw mut PLATFORM).as_mut().unwrap().as_mut() }
        .expect("platform::set_sb_wiring before probe");
    p.sb_wiring = Some(w);
}

pub fn get() -> &'static Platform {
    unsafe {
        (&raw const PLATFORM)
            .as_ref()
            .unwrap()
            .as_ref()
            .expect("platform::get before platform::probe")
    }
}

/// Whether `probe` has run. The full disk-boot / windowed paths always probe;
/// the minimal bare-ELF dev path (`host_run_elf`) does not. Lets the few
/// pieces reachable from that path (console-VGA snapshot on thread exit) pick a
/// sane default instead of tripping `get`'s panic-if-unprobed invariant.
pub fn probed() -> bool {
    unsafe { (&raw const PLATFORM).as_ref().unwrap().is_some() }
}

/// The audio probe is uniform across backends: an absent ISA device reads
/// 0xFF (so no-SB is the same answer on the interpreter's port bus and on
/// card-less metal), PCI config reads are 0xFFFFFFFF where there is no PCI,
/// and the canonical port window answers its signature only where a backend
/// installed a sink. Card presence is machine-wide, so the probe uses the
/// canonical SB base 0x220 (a per-thread BLASTER override relocates the
/// guest-visible base, not the card).
fn probe_audio<A: crate::Arch>(machine: &mut A, card: &mut Option<crate::kernel::drivers::sb16::SbCard>) -> AudioHw {
    *card = crate::kernel::drivers::sb16::scan(machine);
    if card.is_some() {
        return AudioHw::Sb;
    }
    if crate::kernel::drivers::hda::scan(machine).is_some() {
        return AudioHw::Hda;
    }
    if crate::kernel::drivers::ac97::scan(machine).is_some() {
        return AudioHw::Ac97;
    }
    if crate::kernel::sound::window_present(machine) {
        return AudioHw::PortWindow;
    }
    AudioHw::None
}






/// Cirrus-style save/restore readbacks: CR22 (data latches), CR24 (AC
/// flip-flop), CR26 (AC index). Probed FUNCTIONALLY — toggle the AC
/// flip-flop and watch CR24 bit 7 follow — because the capability, not a
/// vendor ID, is what save/restore consumes. Runs at boot while the kernel
/// owns the card, and leaves the AC in a defined state (index phase,
/// address register restored).
fn vga_readback_answers() -> bool {
    use crate::kernel::portio::{inb, outb};
    let crtc_index = inb(0x3D4);
    let _ = inb(0x3DA); // flip-flop → index phase
    outb(0x3D4, 0x24);
    let at_index = inb(0x3D5) & 0x80;
    let ac_addr = inb(0x3C0); // address register readback (incl. PAS)
    outb(0x3C0, ac_addr); // re-latch it: flip-flop → data phase
    let at_data = inb(0x3D5) & 0x80;
    let _ = inb(0x3DA); // back to index phase
    outb(0x3C0, ac_addr); // leave the index latched...
    let _ = inb(0x3DA); // ...and the flip-flop at index phase
    outb(0x3D4, crtc_index);
    at_index == 0 && at_data != 0
}
