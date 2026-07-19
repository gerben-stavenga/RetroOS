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
    pub firmware: Firmware,
    pub audio: Audio,
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
    /// A real VGA card answered the SEQ-register probe: guests program the
    /// hardware directly (passthrough port window); console = VGA text.
    VgaCard,
    /// No card, but the loader handed over a linear framebuffer (UEFI/GOP) —
    /// or a hosted window supplied one. The emulated VGA blits into it; the
    /// descriptor travels with the verdict, so nothing has to call back to
    /// find out where the pixels go.
    Framebuffer(crate::kernel::display::Framebuffer),
    /// No card or framebuffer, but a host window installed a present sink
    /// (retroos-play): the emulated VGA renders into the window.
    HostWindow,
    /// Nothing to display on (headless interp run): the emulated VGA still
    /// models state — screendumps and --screenshot remain possible.
    Headless,
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

/// The audio path — exactly one of these is true, decided here. Replaces
/// three lazy probes: vsb's `ensure_mode` (SB card), ac97's PRESENT atomic,
/// and sound's port-window signature cache.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Audio {
    /// A real Sound Blaster answered the DSP-status probe (legacy metal,
    /// QEMU `sb16`): guest DSP/mixer traffic forwards to the card and only
    /// the 8237 stays virtual. Implies a real OPL — the 0x388 window is
    /// part of the DOS io_policy template, not a runtime grant.
    SbPassthrough,
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
    /// Guest SB programming reaches a real card (vs the software DSP).
    pub fn sb_passthrough(self) -> bool {
        matches!(self, Audio::SbPassthrough)
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
pub fn probe<A: crate::Arch>(machine: &mut A, boot: &crate::BootConfig) -> &'static Platform {
    let audio = probe_audio(machine);
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
        //   fbcon → present-sink → VGA card → headless.
        // Each predicate is false on the backends it can't apply to (a hosted
        // run's `fbcon_active` hook returns false and no real VGA card answers
        // its port bus; a metal run installs no window present sink), so one
        // ordered chain covers both. A GOP linear framebuffer (fbcon active)
        // wins unconditionally — even when a legacy VGA card also answers its
        // I/O ports, the GOP framebuffer, not the dead legacy register file,
        // drives the panel (a UEFI laptop mislabelled `VgaCard` painted blank).
        let display = if let Some(fb) = (env.framebuffer)() {
            Display::Framebuffer(fb)
        } else if lib::vga_render::present_sink_installed() {
            Display::HostWindow
        } else if vga_card_answers() {
            Display::VgaCard
        } else {
            Display::Headless
        };

        // Every legacy BIOS has a far-JMP (0xEA) at the reset vector
        // F000:FFF0. Only metal can probe it: `LOW_MEM_BASE` is a real
        // kernel-mapped window there, but on the hosted backend it is a GUEST
        // linear address — dereferencing it as a host pointer would SIGSEGV.
        // A hosted run has no legacy ROM anyway, so it is always Substitute.
        let firmware = if env.is_metal {
            let reset_vector =
                unsafe { core::ptr::read_volatile((crate::LOW_MEM_BASE + 0xFFFF0) as *const u8) };
            if reset_vector == 0xEA { Firmware::NativeBios } else { Firmware::Substitute }
        } else {
            Firmware::Substitute
        };

        Platform {
            host: env.host(boot.is_qemu),
            display,
            firmware,
            audio,
            hostfs,
            debug: env.debug,
        }
    };

    unsafe {
        PLATFORM = Some(p);
    }
    let p = get();
    println!(
        "Platform: host={:?} display={:?} firmware={:?} audio={:?} hostfs={} debug={:?}",
        p.host, p.display, p.firmware, p.audio, p.hostfs, p.debug
    );
    p
}

/// The frozen platform description. Panics if `probe` has not run — an init
/// ordering bug that should be loud.
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
fn probe_audio<A: crate::Arch>(machine: &mut A) -> Audio {
    let sb_absent = machine.inb(0x22C) == 0xFF && machine.inb(0x22E) == 0xFF;
    if !sb_absent {
        return Audio::SbPassthrough;
    }
    if crate::kernel::drivers::hda::scan(machine).is_some() {
        return Audio::EmulatedHda;
    }
    if crate::kernel::drivers::ac97::scan(machine).is_some() {
        return Audio::EmulatedAc97;
    }
    if crate::kernel::sound::window_present(machine) {
        return Audio::EmulatedPortWindow;
    }
    Audio::EmulatedSilent
}






/// Is a real VGA card on the bus? Write the SEQ index register and read it
/// back — an absent ISA-bus port reads 0xFF (so a hosted run, whose port bus
/// has no VGA card, answers false and falls through to Headless/HostWindow).
fn vga_card_answers() -> bool {
    use crate::kernel::portio::{inb, outb};
    let saved = inb(0x3C4);
    outb(0x3C4, 0x02);
    let present = inb(0x3C4) == 0x02;
    if present {
        outb(0x3C4, saved);
    }
    present
}
