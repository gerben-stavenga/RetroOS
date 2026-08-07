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

/// The VBE mode/bank descriptions a firmware probe fills in. Plain data
/// about pixels, so they live with the card state in `//lib:vga`.
pub use vga::{VbeBank, VbeMode};

use crate::println;

pub struct Platform {
    pub host: Host,
    pub display: Display,
    /// What sound hardware answered (probe fact).
    ///
    /// A *fact*, not a capability: that a Sound Blaster answered is frozen
    /// here, but the card itself is a move-only value with one owner
    /// (`sb16::SbCard`), and `Platform` hands out `&'static`. It used to be
    /// mirrored here as `sb_card` + `sb_wiring`, which is how every DOS
    /// thread came to mint its own copy of the machine's one card.
    pub audio_hw: AudioHw,
    pub firmware: Firmware,
    /// Preferred packed linear mode advertised by the native video BIOS.
    /// Discovered once at boot; selecting/mapping it still requires ownership
    /// of the `BiosDisplay` capability.
    pub vbe_mode: Option<VbeMode>,
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
    /// QEMU (the loader saw fw_cfg). Not a VGA reference: its VGA device
    /// model gets planes, text odd/even, the PEL mask and the retrace bit
    /// wrong, and the kernel no longer carries compensations for any of it —
    /// run QEMU with `--firmware uefi`, where the guest never touches a
    /// legacy card. Kept as a fact because a few genuinely QEMU-shaped
    /// decisions remain (the deliberately misaligned sb16 strap).
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
    /// The loader handed over a linear framebuffer (UEFI/GOP or BIOS/VBE) —
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
    BiosDisplay(BiosDisplay),
    LfbDisplay(crate::kernel::display::LfbDisplay),
    HostWindow,
    Headless,
}

/// The unique firmware-controlled physical display. The enum is deliberately
/// neither `Copy` nor `Clone`: moving it transfers both card authority and the
/// state required to reconstruct what the firmware established.
#[derive(Debug)]
pub enum BiosDisplay {
    /// Register-based VGA mode. The physical card is the live state; a detach
    /// snapshots its register file, DAC and legacy aperture.
    Legacy,
    /// VBE mode. Its descriptor identifies the LFB; bank selection is tracked
    /// because it cannot be recovered from the legacy VGA register file.
    Vesa {
        mode: VbeMode,
        bank: Option<VbeBank>,
    },
}


impl BiosDisplay {
    fn new() -> Self { Self::Legacy }

    pub(crate) fn vbe_mode(&self) -> Option<VbeMode> {
        match self {
            Self::Legacy => None,
            Self::Vesa { mode, .. } => Some(*mode),
        }
    }

    pub(crate) fn set_legacy(&mut self) { *self = Self::Legacy; }

    pub(crate) fn set_vesa(&mut self, mode: VbeMode, linear: bool) {
        let bank = (!linear).then_some(VbeBank {
            current: 0,
            window_segment: mode.window_segment,
            granularity_kb: mode.window_granularity_kb,
            window_size_kb: mode.window_size_kb,
        });
        *self = Self::Vesa { mode, bank };
    }

    pub(crate) fn set_bank(&mut self, current: u16) {
        if let Self::Vesa { bank: Some(bank), .. } = self {
            bank.current = current;
        }
    }
}

pub struct ProbedPlatform {
    pub facts: &'static Platform,
    pub display: DisplayToken,
    pub audio: AudioToken,
}

/// The initialized kernel-owned audio capability discovered at boot. Like the
/// display token, this is deliberately kept out of the frozen fact table: it
/// is unique mutable authority, carried once into its runtime owner.
pub enum AudioToken {
    Hda(&'static mut crate::kernel::drivers::hda::Hda),
    Ac97(&'static mut crate::kernel::drivers::ac97::Ac97),
    None,
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
        // Whether a card answers, not which emulator we are on. QEMU was
        // excluded because its 0x3DA was fabricated for the guest, so the
        // ports had to trap; that fabrication is gone.
        self.display.vga_passthrough()
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
    pub framebuffer: fn() -> Option<crate::kernel::display::LfbDisplay>,
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
    let (audio_hw, audio_token) = probe_audio(machine);
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
            (Display::Framebuffer, DisplayToken::LfbDisplay(fb))
        } else if crate::kernel::display::host_present_sink_installed() {
            (Display::HostWindow, DisplayToken::HostWindow)
        } else if env.is_metal {
            (Display::VgaCard, DisplayToken::BiosDisplay(BiosDisplay::new()))
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
            vbe_mode: None,
            vga_readback,
            audio_hw,
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
    ProbedPlatform { facts: p, display: display_token, audio: audio_token }
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
/// This is also where the machine's Sound Blaster is MINTED, because it is the
/// first moment its wiring can be known: an SB16 reports its own straps, but a
/// pre-SB16 card's are physical jumpers that only `SB_AUDIO=native <irq> <dma>`
/// can describe. The capability is returned to the caller to give to an owner;
/// `None` means no card anyone can drive, whatever the mode says.
pub fn apply_audio_mode<A: crate::Arch>(
    machine: &mut A,
    mixed: bool,
    declared: Option<crate::kernel::drivers::sb16::SbWiring>,
) -> Option<crate::kernel::drivers::sb16::SbCard> {
    let p = unsafe { (&raw mut PLATFORM).as_mut().unwrap().as_mut() }
        .expect("platform::apply_audio_mode before probe");
    let card = (p.audio_hw == AudioHw::Sb)
        .then(|| crate::kernel::drivers::sb16::scan(machine, declared))
        .flatten();
    // The mode is a choice only where there is a card to choose about, and
    // `mixed` additionally needs a card that can BE the sink: the kernel mixer
    // drives 16-bit signed-stereo auto-init, which an SB Pro cannot do at all.
    // Refuse it loudly rather than programming 16-bit commands into a card
    // that has no 16-bit channel and calling the resulting silence a mode.
    p.audio = match (&card, mixed) {
        (Some(c), true) if c.dma16.is_some() => Audio::SbSink,
        (Some(_), true) => {
            crate::println!(
                "Audio: SB_AUDIO=mixed needs a 16-bit DMA channel and this card has none — \
                 running the card natively instead"
            );
            Audio::NativeSb
        }
        (Some(_), false) => Audio::NativeSb,
        // No card: whatever else the machine has (or silence).
        (None, _) => match p.audio_hw {
            AudioHw::Sb => Audio::EmulatedSilent,
            hw => hw.default_verdict(),
        },
    };
    crate::println!("Audio: {:?} ({})", p.audio,
        if mixed { "SB_AUDIO=mixed" } else { "SB_AUDIO=native" });
    card
}

/// Complete boot-time display discovery after the pristine BIOS environment
/// exists. This records a descriptor only; it neither sets the mode nor maps
/// the framebuffer.
pub fn set_vbe_mode(mode: Option<VbeMode>) {
    let p = unsafe { (&raw mut PLATFORM).as_mut().unwrap().as_mut() }
        .expect("platform::set_vbe_mode before probe");
    p.vbe_mode = mode;
    match mode {
        Some(m) => crate::println!(
            "VBE: preferred mode {:#x} {}x{} pitch={} phys={:#x}",
            m.number, m.width, m.height, m.pitch, m.physical_base
        ),
        None if p.display == Display::VgaCard => {
            crate::println!("VBE: no usable packed linear mode; OSD will use mode 13h")
        }
        None => {}
    }
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

/// Probe audio once. PCI drivers return their initialized capability together
/// with the fact recorded in `Platform`; SB presence is separate because its
/// wiring and ownership policy cannot be settled until CONFIG.SYS is mounted.
fn probe_audio<A: crate::Arch>(machine: &mut A) -> (AudioHw, AudioToken) {
    // Presence only. Minting the card needs its wiring, and a pre-SB16 card's
    // wiring comes from CONFIG.SYS — unreadable this early — so the capability
    // is minted later, in `apply_audio_mode`.
    if crate::kernel::drivers::sb16::answers(machine) {
        return (AudioHw::Sb, AudioToken::None);
    }
    if let Some(device) = crate::kernel::drivers::hda::probe(machine) {
        return (AudioHw::Hda, AudioToken::Hda(device));
    }
    if let Some(device) = crate::kernel::drivers::ac97::probe(machine) {
        return (AudioHw::Ac97, AudioToken::Ac97(device));
    }
    if crate::kernel::sound::window_present(machine) {
        return (AudioHw::PortWindow, AudioToken::None);
    }
    (AudioHw::None, AudioToken::None)
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
