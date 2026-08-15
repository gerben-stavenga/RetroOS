//! The F12 host monitor: an on-screen menu overlaid on the running guest.
//!
//! One host hotkey, F12, opens a small panel; every key then drives the panel
//! (nothing reaches the guest) until Esc/F12 closes it. The guest keeps
//! RUNNING behind the panel — so a volume change is heard at once and the frame
//! under the menu keeps updating. This replaces the old one-key-per-action
//! debug/switch hotkeys: one discoverable door.
//!
//! Actions fold into machinery that already exists — Switch opens a task picker
//! that targets the focus-switch request, Trace the shared DOS/DPMI/Linux
//! syscall-trace gate, Profile the profile-dump toggle, Dump the register/VGA
//! dump, Disk lists the CD images shipped in `C:\CD`, Kill the ordinary exit path (a pending flag the event loop turns into
//! `Exit` for the focused thread, exactly as the SEGV path does). Volume is the
//! one new knob: a runtime master gain multiplied into the single mix-out clip.
//!
//! State is a handful of single-threaded atomics. Input handling ([`key`]) lives here but is
//! called from [`console`](crate::kernel::console), which has the `machine`/
//! `regs`/`DosState` the Dump action needs; painting ([`paint`]) is called from
//! the DOS display tick, the one place both backends hold a finished frame.

use core::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};

use vga::{self, PixelFormat};

use crate::Regs;
use crate::kernel::thread;

/// Output exclusively owned by the kernel monitor while it is open. For a
/// legacy machine the contained display carries the physical `VgaCap`; the
/// focused personality has already been reduced to headless `EmulatedVga`.
pub struct OsdDisplay {
    display: crate::kernel::display::Display,
}

impl OsdDisplay {
    pub fn new(display: crate::kernel::display::Display) -> Self { Self { display } }
    pub fn into_inner(self) -> crate::kernel::display::Display { self.display }
}

static mut OSD_DISPLAY: Option<OsdDisplay> = None;

pub fn with_display<R>(f: impl FnOnce(Option<&mut crate::kernel::display::Display>) -> R) -> R {
    unsafe { f((&raw mut OSD_DISPLAY).as_mut().and_then(Option::as_mut).map(|o| &mut o.display)) }
}

pub fn take_display() -> Option<OsdDisplay> {
    unsafe { (&raw mut OSD_DISPLAY).as_mut().and_then(Option::take) }
}

// ── Menu model ───────────────────────────────────────────────────────────────

const TAB_SYSTEM: usize = 0;
const TAB_SOUND: usize = 1;
const TAB_DISK: usize = 2;
const TAB_DEBUG: usize = 3;
const NUM_TABS: usize = 4;

const SYSTEM_ITEM_KILL: usize = 0;
const SYSTEM_ITEM_SWITCH: usize = 1;
const SYSTEM_NUM_ITEMS: usize = 2;

const SOUND_ITEM_VOLUME: usize = 0;
const SOUND_ITEM_LATENCY: usize = 1;
const SOUND_ITEM_RATE: usize = 2;
const SOUND_ITEM_HDA_OUTPUT: usize = 3;
const SOUND_NUM_ITEMS_BASE: usize = 3;
const SOUND_NUM_ITEMS_WITH_HDA_OUTPUT: usize = 4;

const DEBUG_ITEM_TRACE: usize = 0;
const DEBUG_ITEM_PROFILE: usize = 1;
const DEBUG_ITEM_DUMP: usize = 2;
const DEBUG_NUM_ITEMS: usize = 3;

/// Master volume step, adjusted by ◄/► on the Volume row. The displayed
/// percentage selects a perceptual gain step; 100 is unity.
const VOL_MAX: u32 = 100;
const VOL_STEP: u32 = 10;
const DEFAULT_VOLUME_PCT: u32 = 50;
const VOLUME_GAIN_Q16: [i32; 11] = [
    0, 1039, 1646, 2609, 4135, 6554,
    10387, 16462, 26090, 41350, 65536,
];
const LATENCY_MIN_MS: u32 = 10;
const LATENCY_MAX_MS: u32 = 80;
const LATENCY_STEP_MS: u32 = 5;

static OPEN: AtomicBool = AtomicBool::new(false);
static REPAINT: AtomicBool = AtomicBool::new(false);
static ACTIVE_TAB: AtomicUsize = AtomicUsize::new(TAB_SOUND);
static SYSTEM_SEL: AtomicUsize = AtomicUsize::new(0);
static SOUND_SEL: AtomicUsize = AtomicUsize::new(0);
static DISK_SEL: AtomicUsize = AtomicUsize::new(0);
/// Which media device the Disk tab is showing: 0=A:, 1=B:, 2=CD (◄/►).
static DISK_DEV: AtomicUsize = AtomicUsize::new(0);
/// First visible row of the Disk tab's scroller.
static DISK_SCROLL: AtomicUsize = AtomicUsize::new(0);
static DEBUG_SEL: AtomicUsize = AtomicUsize::new(0);
static VOL_PCT: AtomicU32 = AtomicU32::new(DEFAULT_VOLUME_PCT);
static LATENCY_MS: AtomicU32 = AtomicU32::new(30);
static KILL_REQ: AtomicBool = AtomicBool::new(false);

/// Is the monitor panel currently open?
pub fn is_open() -> bool {
    OPEN.load(Ordering::Relaxed)
}

/// Open the panel (F12 while closed). Selection starts at the top, menu mode.
pub fn open(display: OsdDisplay) {
    crate::kernel::fs::cdrom::refresh_catalog();
    crate::kernel::fs::floppy::refresh_catalog();
    unsafe { OSD_DISPLAY = Some(display); }
    ACTIVE_TAB.store(TAB_SOUND, Ordering::Relaxed);
    SYSTEM_SEL.store(0, Ordering::Relaxed);
    SOUND_SEL.store(SOUND_ITEM_VOLUME, Ordering::Relaxed);
    DISK_SEL.store(0, Ordering::Relaxed);
    DISK_SCROLL.store(0, Ordering::Relaxed);
    DEBUG_SEL.store(0, Ordering::Relaxed);
    PICKER.store(false, Ordering::Relaxed);
    REPAINT.store(true, Ordering::Relaxed);
    OPEN.store(true, Ordering::Relaxed);
}

/// Consume an immediate repaint request. Native VGA uses this to make menu
/// input responsive without continuously rebuilding the live background.
pub fn take_repaint_request() -> bool {
    REPAINT.swap(false, Ordering::Relaxed)
}

fn close() {
    PICKER.store(false, Ordering::Relaxed);
    OPEN.store(false, Ordering::Relaxed);
}

/// Close the monitor without interpreting another key. Used when the focused
/// owner is exiting: its display must first be returned from the OSD.
pub fn dismiss() {
    close();
}

/// The master output gain in Q16, read by the mixer pump. Unity (65536) at
/// 100%; scales the summed mix just before its single clip.
pub fn master_gain_q16() -> i32 {
    volume_gain_q16(VOL_PCT.load(Ordering::Relaxed))
}

fn volume_gain_q16(percent: u32) -> i32 {
    let index = (percent / VOL_STEP) as usize;
    VOLUME_GAIN_Q16[index.min(VOLUME_GAIN_Q16.len() - 1)]
}

fn parse_volume_percent(raw: &[u8]) -> Option<u32> {
    let mut value = 0u32;
    if raw.is_empty() {
        return None;
    }
    for &byte in raw {
        if !byte.is_ascii_digit() {
            return None;
        }
        value = value.checked_mul(10)?.checked_add(u32::from(byte - b'0'))?;
    }
    (value <= VOL_MAX && value.is_multiple_of(VOL_STEP)).then_some(value)
}

pub fn configure_master_volume(raw: Option<&[u8]>) {
    let value = match raw {
        None => DEFAULT_VOLUME_PCT,
        Some(raw) => match parse_volume_percent(raw) {
            Some(value) => value,
            None => {
                crate::println!(
                    "audio: invalid AUDIO_VOLUME={}",
                    core::str::from_utf8(raw).unwrap_or("<non-UTF8>")
                );
                DEFAULT_VOLUME_PCT
            }
        },
    };
    VOL_PCT.store(value, Ordering::Relaxed);
}

/// Requested physical output latency. The sink rounds this up to its active
/// device's block granularity and caps it to the safe half of that device's
/// DMA ring.
pub fn audio_latency_ms() -> u32 {
    LATENCY_MS.load(Ordering::Relaxed)
}

fn active_tab() -> usize {
    ACTIVE_TAB.load(Ordering::Relaxed).min(NUM_TABS - 1)
}

fn set_active_tab(tab: usize) {
    ACTIVE_TAB.store(tab.min(NUM_TABS - 1), Ordering::Relaxed);
}

fn active_sel(tab: usize) -> usize {
    match tab {
        TAB_SOUND => SOUND_SEL.load(Ordering::Relaxed),
        TAB_DISK => DISK_SEL.load(Ordering::Relaxed),
        TAB_DEBUG => DEBUG_SEL.load(Ordering::Relaxed),
        _ => SYSTEM_SEL.load(Ordering::Relaxed),
    }
}

fn set_active_sel(tab: usize, sel: usize) {
    match tab {
        TAB_SOUND => SOUND_SEL.store(sel.min(sound_item_count() - 1), Ordering::Relaxed),
        TAB_DISK => DISK_SEL.store(sel.min(disk_item_count() - 1), Ordering::Relaxed),
        TAB_DEBUG => DEBUG_SEL.store(sel.min(DEBUG_NUM_ITEMS - 1), Ordering::Relaxed),
        _ => SYSTEM_SEL.store(sel.min(SYSTEM_NUM_ITEMS - 1), Ordering::Relaxed),
    }
}

fn active_item_count(tab: usize) -> usize {
    match tab {
        TAB_SOUND => sound_item_count(),
        TAB_DISK => disk_item_count(),
        TAB_DEBUG => DEBUG_NUM_ITEMS,
        _ => SYSTEM_NUM_ITEMS,
    }
}

fn sound_item_count_for(audio: crate::kernel::platform::Audio) -> usize {
    match audio {
        crate::kernel::platform::Audio::EmulatedHda => SOUND_NUM_ITEMS_WITH_HDA_OUTPUT,
        _ => SOUND_NUM_ITEMS_BASE,
    }
}

fn sound_item_count() -> usize {
    sound_item_count_for(crate::kernel::platform::get().audio)
}

/// The Disk tab shows ONE device at a time — A:, B:, or CD, cycled with
/// ◄/► — as a scrolling list that always fits the panel (the old
/// all-devices-at-once list outgrew a 200-line mode and the whole OSD
/// vanished). An empty device lists its catalogue (insert on Enter); a
/// loaded device lists "Eject <name>" first, then the OTHER images as swap
/// targets — the in-use image is not offered.
const DISK_DEVICES: usize = 3;
/// Rows of the Disk scroller visible at once — derived from the panel's
/// character budget (see `MAX_ROWS`): everything but title, tab bar,
/// device sub-tabs, and footer.
const DISK_VISIBLE: usize = MAX_ROWS - 4;

fn disk_device() -> usize {
    DISK_DEV.load(Ordering::Relaxed)
}

fn disk_device_label(dev: usize) -> &'static [u8] {
    match dev {
        0 => b"A:",
        1 => b"B:",
        _ => b"CD",
    }
}

fn disk_catalog_count(dev: usize) -> usize {
    if dev == 2 {
        crate::kernel::fs::cdrom::catalog_count()
    } else {
        crate::kernel::fs::floppy::catalog_count()
    }
}

fn disk_inserted(dev: usize) -> bool {
    if dev == 2 {
        crate::kernel::fs::cdrom::is_inserted()
    } else {
        crate::kernel::fs::floppy::is_inserted(dev)
    }
}

fn disk_entry_in_use(dev: usize, index: usize) -> bool {
    if dev == 2 {
        crate::kernel::fs::cdrom::selected(index)
    } else {
        crate::kernel::fs::floppy::selected(dev, index)
    }
}

fn disk_catalog_name(dev: usize, index: usize, out: &mut [u8]) -> usize {
    if dev == 2 {
        crate::kernel::fs::cdrom::catalog_name(index, out)
    } else {
        crate::kernel::fs::floppy::catalog_name(index, out)
    }
}

fn disk_label(dev: usize, out: &mut [u8]) -> usize {
    if dev == 2 {
        crate::kernel::fs::cdrom::label(out)
    } else {
        crate::kernel::fs::floppy::label(dev, out)
    }
}

/// One row of the current device's list.
#[derive(Clone, Copy)]
enum DiskRow {
    /// "Eject <name>" — only when media is inserted, always row 0.
    Eject,
    /// Insert/swap to this catalogue index.
    Insert(usize),
    /// "(no images)" placeholder for an empty device + empty catalogue.
    NoImages,
}

fn disk_row(item: usize) -> DiskRow {
    let dev = disk_device();
    let inserted = disk_inserted(dev);
    if inserted && item == 0 {
        return DiskRow::Eject;
    }
    let want = if inserted { item - 1 } else { item };
    let mut seen = 0;
    for i in 0..disk_catalog_count(dev) {
        if inserted && disk_entry_in_use(dev, i) {
            continue; // the in-use image is not a swap target
        }
        if seen == want {
            return DiskRow::Insert(i);
        }
        seen += 1;
    }
    DiskRow::NoImages
}

fn disk_item_count() -> usize {
    let dev = disk_device();
    let catalog = disk_catalog_count(dev);
    if disk_inserted(dev) {
        1 + catalog.saturating_sub(1) // Eject + swap targets
    } else {
        catalog.max(1) // list, or the "(no images)" row
    }
}

/// Keep the Disk selection visible: slide the scroll window after any
/// selection or device change.
fn disk_follow_scroll() {
    let sel = DISK_SEL.load(Ordering::Relaxed);
    let mut scroll = DISK_SCROLL.load(Ordering::Relaxed);
    let count = disk_item_count();
    let max_scroll = count.saturating_sub(DISK_VISIBLE);
    if scroll > max_scroll {
        scroll = max_scroll;
    }
    if sel < scroll {
        scroll = sel;
    } else if sel >= scroll + DISK_VISIBLE {
        scroll = sel + 1 - DISK_VISIBLE;
    }
    DISK_SCROLL.store(scroll, Ordering::Relaxed);
}

fn active_tab_name(tab: usize) -> &'static [u8] {
    match tab {
        TAB_SOUND => b"Sound",
        TAB_DISK => b"Disk",
        TAB_DEBUG => b"Debug",
        _ => b"System",
    }
}

/// Consume a pending "kill the focused task" request. The event loop calls this
/// each iteration and, when set, exits the focused thread down the ordinary
/// teardown path.
pub fn take_kill_request() -> bool {
    KILL_REQ.swap(false, Ordering::Relaxed)
}

// ── Process list (the Switch picker) ─────────────────────────────────────────

/// Max tasks the picker lists — RetroOS runs a handful, not hundreds.
const MAX_LIST: usize = 12;

#[derive(Clone, Copy)]
struct Proc {
    tid: u16,
    /// One-glyph state: 'R'unning / 'r'eady / 'B'locked.
    state: u8,
    focused: bool,
    name: [u8; 16],
    name_len: u8,
}

impl Proc {
    const EMPTY: Proc = Proc { tid: 0, state: 0, focused: false, name: [0; 16], name_len: 0 };
}

/// The picker's snapshot, rebuilt once per timer tick while the monitor is
/// open — at the event-loop point where the whole thread table is borrowable.
/// Single-threaded cooperative kernel, so a plain `static mut` behind
/// accessors, the same discipline as the flags above.
static mut PROCS: [Proc; MAX_LIST] = [Proc::EMPTY; MAX_LIST];
static PROC_COUNT: AtomicUsize = AtomicUsize::new(0);
static PICK_SEL: AtomicUsize = AtomicUsize::new(0);
static PICKER: AtomicBool = AtomicBool::new(false);

/// Rebuild the process list from the thread table. Mirrors `cycle_next`'s
/// active-thread filter (skip tid 0 and Unused/Zombie); `focused` marks the
/// current console owner.
pub fn refresh_processes<A: crate::Arch>(threads: &[thread::Thread<A>], focused: usize) {
    let mut count = 0;
    for (i, t) in threads.iter().enumerate().skip(1) {
        if count >= MAX_LIST {
            break;
        }
        let k = &t.kernel;
        let state = match k.state {
            thread::ThreadState::Running => b'R',
            thread::ThreadState::Ready => b'r',
            thread::ThreadState::Blocked => b'B',
            _ => continue, // Unused / Zombie: not a switch target
        };
        let name: &[u8] = match &threads[i].personality {
            thread::Personality::Linux(l) => thread::basename(l.exec_path_str()),
            thread::Personality::Dos(_) => {
                let c = k.comm_str();
                if c.is_empty() { b"DOS" } else { c }
            }
        };
        let n = name.len().min(16);
        // SAFETY: single-threaded cooperative kernel; no concurrent access.
        unsafe {
            let p = &mut (*core::ptr::addr_of_mut!(PROCS))[count];
            p.tid = i as u16;
            p.state = state;
            p.focused = i == focused;
            p.name = [0; 16];
            p.name[..n].copy_from_slice(&name[..n]);
            p.name_len = n as u8;
        }
        count += 1;
    }
    PROC_COUNT.store(count, Ordering::Relaxed);
    if PICK_SEL.load(Ordering::Relaxed) >= count {
        PICK_SEL.store(count.saturating_sub(1), Ordering::Relaxed);
    }
}

fn proc_at(idx: usize) -> Proc {
    // SAFETY: single-threaded; idx bounded by the caller against PROC_COUNT.
    unsafe { (*core::ptr::addr_of!(PROCS))[idx] }
}

// ── Input ────────────────────────────────────────────────────────────────────

// Bare PC set-1 make codes, matching what both the SDL harness and the stdin
// pump post for these keys (extended keys arrive un-prefixed; a stray 0xE0 is
// simply an unmapped code we swallow while open).
const K_ESC: u8 = 0x01;
const K_ENTER: u8 = 0x1C;
const K_TAB: u8 = 0x0F;
const K_UP: u8 = 0x48;
const K_DOWN: u8 = 0x50;
const K_LEFT: u8 = 0x4B;
const K_RIGHT: u8 = 0x4D;
const K_F12: u8 = 0x58;

/// Drive the panel from one key event. Only called while [`is_open`]; releases
/// (bit 7) are swallowed so no break code leaks to the guest. `machine`/`regs`/
/// `dos` are threaded through only for the Dump action.
pub fn key<A: crate::Arch>(machine: &mut A, regs: &mut Regs, sc: u8, dos: Option<&thread::DosState<A>>) {
    if sc & 0x80 != 0 {
        return; // release: swallowed, no action
    }
    REPAINT.store(true, Ordering::Relaxed);
    if PICKER.load(Ordering::Relaxed) {
        pick_key(sc);
        return;
    }
    match sc {
        K_F12 | K_ESC => close(),
        K_TAB => cycle_tab(),
        K_UP => move_sel(true),
        K_DOWN => move_sel(false),
        K_LEFT => adjust(false),
        K_RIGHT => adjust(true),
        K_ENTER => activate(machine, regs, dos),
        _ => {} // any other key: swallowed while open
    }
}

/// Drive the Switch picker submode. Esc/◄ backs out to the menu; Enter/► picks.
fn pick_key(sc: u8) {
    match sc {
        K_F12 => close(),
        K_ESC | K_LEFT => PICKER.store(false, Ordering::Relaxed), // back to the menu
        K_UP => pick_move(true),
        K_DOWN => pick_move(false),
        K_ENTER | K_RIGHT => pick_select(),
        _ => {}
    }
}

fn pick_move(up: bool) {
    let count = PROC_COUNT.load(Ordering::Relaxed);
    if count == 0 {
        return;
    }
    let cur = PICK_SEL.load(Ordering::Relaxed);
    let sel = if up { (cur + count - 1) % count } else { (cur + 1) % count };
    PICK_SEL.store(sel, Ordering::Relaxed);
}

fn pick_select() {
    let sel = PICK_SEL.load(Ordering::Relaxed);
    if sel < PROC_COUNT.load(Ordering::Relaxed) {
        thread::request_switch_to(proc_at(sel).tid as usize);
    }
    close();
}

fn cycle_tab() {
    let next = (active_tab() + 1) % NUM_TABS;
    set_active_tab(next);
    REPAINT.store(true, Ordering::Relaxed);
}

fn move_sel(up: bool) {
    let tab = active_tab();
    let count = active_item_count(tab);
    if count == 0 {
        return;
    }
    let cur = active_sel(tab);
    let sel = if up {
        (cur + count - 1) % count
    } else {
        (cur + 1) % count
    };
    set_active_sel(tab, sel);
    if tab == TAB_DISK {
        disk_follow_scroll();
    }
}

/// ◄/► adjust the selected continuous setting — and on the Disk tab,
/// cycle the device sub-tab (A: / B: / CD).
fn adjust(up: bool) {
    if active_tab() == TAB_DISK {
        let cur = DISK_DEV.load(Ordering::Relaxed);
        let next = if up { (cur + 1) % DISK_DEVICES } else { (cur + DISK_DEVICES - 1) % DISK_DEVICES };
        DISK_DEV.store(next, Ordering::Relaxed);
        DISK_SEL.store(0, Ordering::Relaxed);
        DISK_SCROLL.store(0, Ordering::Relaxed);
        return;
    }
    if active_tab() != TAB_SOUND {
        return;
    }
    match active_sel(TAB_SOUND) {
        SOUND_ITEM_VOLUME => {
            let cur = VOL_PCT.load(Ordering::Relaxed);
            let next = if up {
                (cur + VOL_STEP).min(VOL_MAX)
            } else {
                cur.saturating_sub(VOL_STEP)
            };
            VOL_PCT.store(next, Ordering::Relaxed);
        }
        SOUND_ITEM_LATENCY => {
            let cur = LATENCY_MS.load(Ordering::Relaxed);
            let next = if up {
                (cur + LATENCY_STEP_MS).min(LATENCY_MAX_MS)
            } else {
                cur.saturating_sub(LATENCY_STEP_MS).max(LATENCY_MIN_MS)
            };
            LATENCY_MS.store(next, Ordering::Relaxed);
        }
        SOUND_ITEM_HDA_OUTPUT => crate::kernel::drivers::hda::cycle_output_route(up),
        _ => {}
    }
}

fn activate<A: crate::Arch>(machine: &mut A, regs: &mut Regs, dos: Option<&thread::DosState<A>>) {
    match active_tab() {
        // Continuous settings are adjusted with ◄/►; Enter does nothing.
        TAB_SOUND => {}
        TAB_DISK => {
            let dev = disk_device();
            match disk_row(active_sel(TAB_DISK)) {
                DiskRow::Eject => {
                    if dev == 2 {
                        crate::kernel::fs::cdrom::eject();
                    } else {
                        crate::kernel::fs::floppy::eject(dev);
                    }
                }
                DiskRow::Insert(index) => {
                    if dev == 2 {
                        if let Err(error) = crate::kernel::fs::cdrom::insert(index) {
                            crate::println!("CD-ROM: insert failed: {:?}", error);
                        }
                    } else if let Err(error) = crate::kernel::fs::floppy::insert(dev, index) {
                        crate::println!("Floppy: insert failed: {:?}", error);
                    }
                }
                DiskRow::NoImages => {}
            }
            // Eject/insert changes the row model: re-clamp selection + scroll.
            set_active_sel(TAB_DISK, active_sel(TAB_DISK));
            disk_follow_scroll();
        }
        TAB_DEBUG => match active_sel(TAB_DEBUG) {
            // Toggle each diagnostic and stay open so the new state shows on the row.
            DEBUG_ITEM_TRACE => crate::kernel::startup::toggle_trace(),
            DEBUG_ITEM_PROFILE => crate::kernel::startup::toggle_profile(),
            DEBUG_ITEM_DUMP => {
                crate::kernel::startup::dump_interrupted_thread(machine, regs, dos);
                close();
            }
            _ => {}
        },
        _ => match active_sel(TAB_SYSTEM) {
            SYSTEM_ITEM_KILL => {
                KILL_REQ.store(true, Ordering::Relaxed);
                close();
            }
            // Open the task picker (a submode of the still-open monitor).
            SYSTEM_ITEM_SWITCH => {
                PICK_SEL.store(0, Ordering::Relaxed);
                PICKER.store(true, Ordering::Relaxed);
            }
            _ => {}
        },
    }
}

// ── Painting ─────────────────────────────────────────────────────────────────

const PANEL_BG: u32 = 0x0010_1830;
const TITLE_BG: u32 = 0x0028_50B0;
const TITLE_FG: u32 = 0x00FF_FFFF;
const ITEM_FG: u32 = 0x00C8_D0DC;
const SEL_BG: u32 = 0x00F0_B000;
const SEL_FG: u32 = 0x0020_1000;
const FOOT_FG: u32 = 0x0078_88A0;

// The panel is a FIXED character grid sized to fit the smallest mode
// (320x200) at scale 1; larger shadows scale the whole grid uniformly
// (see `paint_scales`). The font is 8x8: in a 200-line mode with 1.2:1
// pixel aspect an 8x16 text-mode glyph displays ~1:2.4 tall-and-narrow —
// low-res-era UIs used 8x8 for exactly this reason.
const COLS: usize = 30;
const MAX_ROWS: usize = 16;
const PAD: usize = 8;
const CELL_W: usize = 8;
const CELL_H: usize = 8;
const _: () = assert!(COLS * CELL_W + 2 * PAD <= 320, "panel wider than the smallest mode");
const _: () = assert!(MAX_ROWS * CELL_H + 2 * PAD <= 200, "panel taller than the smallest mode");

/// Two glyph scales with distinct meanings. `sy` carries the sink's
/// mandatory vertical enlargement (a Mode 13h sink later downsamples rows,
/// so glyphs must be pre-stretched vertically on the 320-wide shadow) TIMES
/// the readability factor; `sx` carries the readability factor alone. On a
/// panel-sized shadow both equal the same uniform factor — scaling only
/// vertically there made the panel 8px-narrow with N·16-tall glyphs.
#[allow(clippy::too_many_arguments)]
fn paint_text(
    out: &mut [u8], stride: usize, w: usize, h: usize,
    logical_w: usize, x: usize, y: usize, sx: usize, sy: usize,
    s: &[u8], fg: u32, bg: u32,
    fmt: PixelFormat,
) {
    if logical_w == 0 { return; }
    let fgp = fmt.encode(fg).to_le_bytes();
    let bgp = fmt.encode(bg).to_le_bytes();
    let bytes = fmt.bytes_per_pixel as usize;
    let font = &lib::vga_fonts::FONT_8X8;
    for (i, &ch) in s.iter().enumerate() {
        let cx = x + i * CELL_W * sx;
        if cx + CELL_W * sx > logical_w { break; }
        let glyph = &font[ch as usize * CELL_H..(ch as usize + 1) * CELL_H];
        for (gy, &bits) in glyph.iter().enumerate() {
            for repeat in 0..sy {
                let py = y + gy * sy + repeat;
                if py >= h { break; }
                for gx in 0..CELL_W {
                    let pixel = if bits & (0x80 >> gx) != 0 { &fgp } else { &bgp };
                    for sub in 0..sx {
                        let lx = cx + gx * sx + sub;
                        let x0 = lx.saturating_mul(w) / logical_w;
                        let x1 = (lx + 1).saturating_mul(w) / logical_w;
                        for xx in x0..x1.min(w) {
                            let offset = py * stride + xx * bytes;
                            if offset + bytes <= out.len() {
                                out[offset..offset + bytes].copy_from_slice(&pixel[..bytes]);
                            }
                        }
                    }
                }
            }
        }
    }
}

/// Split the paint scales: `sink_y` is the display's mandatory vertical
/// factor; the uniform readability factor grows the panel on BOTH axes as
/// far as the shadow allows, capped so the panel stays a monitor overlay
/// (~80% of screen height with the 11-row grid) rather than a full-screen
/// takeover on large text-mode shadows. Returns `(sx, sy)`.
fn paint_scales(
    sink_y: usize, logical_w: usize, h: usize, base_w: usize, base_h: usize,
) -> (usize, usize) {
    let sink_y = sink_y.max(1);
    let uniform = (h / (base_h * sink_y))
        .min(logical_w / base_w)
        .min((h / (240 * sink_y)).max(1))
        .max(1);
    (uniform, sink_y * uniform)
}

/// Composite the panel into a completed packed shadow. `scale_y` is an
/// integer because a Mode 13h output may consume several source rows per
/// physical row; glyph rows are repeated, never fractionally resampled.
pub fn paint(
    out: &mut [u8],
    stride: usize,
    w: usize,
    h: usize,
    logical_w: usize,
    scale_y: usize,
    fmt: PixelFormat,
) {
    if PICKER.load(Ordering::Relaxed) {
        paint_picker(out, stride, w, h, logical_w, scale_y, fmt);
        return;
    }
    let tab = active_tab();
    let count = active_item_count(tab);
    // The Disk tab is a fixed-height scroller (device sub-tab row + window);
    // other tabs list all their items.
    let (visible, scroll) = if tab == TAB_DISK {
        (count.min(DISK_VISIBLE), DISK_SCROLL.load(Ordering::Relaxed))
    } else {
        (count, 0)
    };
    let subtab_rows = usize::from(tab == TAB_DISK);
    // Title + tab bar + (device sub-tabs) + items + footer.
    let rows = visible + subtab_rows + 3;
    let base_panel_w = COLS * CELL_W + PAD * 2;
    let base_panel_h = rows * CELL_H + PAD * 2;
    let (sx, sy) = paint_scales(scale_y, logical_w, h, base_panel_w, base_panel_h);
    let panel_w = base_panel_w * sx;
    let panel_h = base_panel_h * sy;
    if logical_w < panel_w || h < panel_h {
        return;
    }
    let x0 = (logical_w - panel_w) / 2;
    let y0 = (h - panel_h) / 2;
    let (pad_x, pad_y) = (PAD * sx, PAD * sy);

    vga::overlay_fill_xscaled(
        out, stride, w, h, logical_w, x0, y0, panel_w, panel_h, PANEL_BG, fmt,
    );
    vga::overlay_fill_xscaled(
        out, stride, w, h, logical_w, x0, y0, panel_w,
        CELL_H * sy + pad_y, TITLE_BG, fmt,
    );

    let tx = x0 + pad_x;
    let mut ty = y0 + pad_y;
    let mut title = Line::new();
    title.put(b"RetroOS Monitor  ");
    title.put(active_tab_name(tab));
    paint_text(
        out, stride, w, h, logical_w, tx, ty, sx, sy,
        title.as_bytes(), TITLE_FG, TITLE_BG, fmt,
    );
    ty += CELL_H * sy;

    paint_tabs(out, stride, w, h, logical_w, tx, ty, tab, sx, sy, fmt);
    ty += CELL_H * sy;

    if tab == TAB_DISK {
        paint_disk_subtabs(out, stride, w, h, logical_w, tx, ty, sx, sy, fmt);
        ty += CELL_H * sy;
    }

    let sel = active_sel(tab);
    for row in 0..visible {
        let item = scroll + row;
        let mut line = Line::new();
        item_line(tab, item, &mut line);
        let selected = item == sel;
        if selected {
            vga::overlay_fill_xscaled(
                out, stride, w, h, logical_w, x0 + pad_x / 2, ty,
                panel_w - pad_x, CELL_H * sy, SEL_BG, fmt,
            );
        }
        let (fg, bg) = if selected { (SEL_FG, SEL_BG) } else { (ITEM_FG, PANEL_BG) };
        paint_text(
            out, stride, w, h, logical_w, tx, ty, sx, sy,
            line.as_bytes(), fg, bg, fmt,
        );
        // Scroller continuation markers in the rightmost column.
        let marker_x = x0 + panel_w - pad_x - CELL_W * sx;
        if row == 0 && scroll > 0 {
            paint_text(out, stride, w, h, logical_w, marker_x, ty, sx, sy,
                b"\x18", FOOT_FG, if selected { SEL_BG } else { PANEL_BG }, fmt);
        }
        if row + 1 == visible && scroll + visible < count {
            paint_text(out, stride, w, h, logical_w, marker_x, ty, sx, sy,
                b"\x19", FOOT_FG, if selected { SEL_BG } else { PANEL_BG }, fmt);
        }
        ty += CELL_H * sy;
    }

    paint_text(
        out, stride, w, h, logical_w, tx, ty, sx, sy,
        b"Up/Dn Enter <>adjust Tab Esc", FOOT_FG, PANEL_BG, fmt,
    );
}

/// The Disk tab's device row: `A:  B:  CD`, current device highlighted,
/// switched with ◄/►.
#[allow(clippy::too_many_arguments)]
fn paint_disk_subtabs(
    out: &mut [u8],
    stride: usize,
    w: usize,
    h: usize,
    logical_w: usize,
    tx: usize,
    ty: usize,
    sx: usize,
    sy: usize,
    fmt: PixelFormat,
) {
    let active = disk_device();
    let mut x = tx + CELL_W * sx;
    for dev in 0..DISK_DEVICES {
        let label = disk_device_label(dev);
        let label_w = (label.len() + 1) * CELL_W * sx;
        let selected = dev == active;
        if selected {
            vga::overlay_fill_xscaled(
                out, stride, w, h, logical_w, x, ty, label_w, CELL_H * sy, SEL_BG, fmt,
            );
        }
        let (fg, bg) = if selected { (SEL_FG, SEL_BG) } else { (ITEM_FG, PANEL_BG) };
        paint_text(
            out, stride, w, h, logical_w, x + (CELL_W * sx) / 2, ty, sx, sy,
            label, fg, bg, fmt,
        );
        x += label_w + CELL_W * sx;
    }
}

#[allow(clippy::too_many_arguments)]
fn paint_tabs(
    out: &mut [u8],
    stride: usize,
    w: usize,
    h: usize,
    logical_w: usize,
    tx: usize,
    ty: usize,
    active: usize,
    sx: usize,
    sy: usize,
    fmt: PixelFormat,
) {
    let mut x = tx;
    for &(tab, label) in &[
        (TAB_SYSTEM, b"System" as &[u8]),
        (TAB_SOUND, b"Sound" as &[u8]),
        (TAB_DISK, b"Disk" as &[u8]),
        (TAB_DEBUG, b"Debug" as &[u8]),
    ] {
        let selected = tab == active;
        let label_w = (label.len() + 1) * CELL_W * sx;
        if selected {
            vga::overlay_fill_xscaled(
                out, stride, w, h, logical_w, x, ty,
                label_w, CELL_H * sy, SEL_BG, fmt,
            );
        }
        let (fg, bg) = if selected { (SEL_FG, SEL_BG) } else { (ITEM_FG, PANEL_BG) };
        paint_text(
            out, stride, w, h, logical_w, x + (CELL_W * sx) / 2, ty,
            sx, sy, label, fg, bg, fmt,
        );
        x += label_w + CELL_W * sx;
    }
}

/// Paint the Switch picker: one row per active task, `tid: name  S *`.
fn paint_picker(
    out: &mut [u8],
    stride: usize,
    w: usize,
    h: usize,
    logical_w: usize,
    scale_y: usize,
    fmt: PixelFormat,
) {
    let count = PROC_COUNT.load(Ordering::Relaxed);
    // Character budget: the list shares MAX_ROWS with title + footer.
    let visible = count.clamp(1, MAX_ROWS - 2);
    let rows = visible + 2;
    let base_panel_w = COLS * CELL_W + PAD * 2;
    let base_panel_h = rows * CELL_H + PAD * 2;
    let (sx, sy) = paint_scales(scale_y, logical_w, h, base_panel_w, base_panel_h);
    let panel_w = base_panel_w * sx;
    let panel_h = base_panel_h * sy;
    if logical_w < panel_w || h < panel_h {
        return;
    }
    let x0 = (logical_w - panel_w) / 2;
    let y0 = (h - panel_h) / 2;
    let (pad_x, pad_y) = (PAD * sx, PAD * sy);

    vga::overlay_fill_xscaled(
        out, stride, w, h, logical_w, x0, y0, panel_w, panel_h, PANEL_BG, fmt,
    );
    vga::overlay_fill_xscaled(
        out, stride, w, h, logical_w, x0, y0, panel_w,
        CELL_H * sy + pad_y, TITLE_BG, fmt,
    );

    let tx = x0 + pad_x;
    let mut ty = y0 + pad_y;
    paint_text(
        out, stride, w, h, logical_w, tx, ty, sx, sy,
        b"Switch to task", TITLE_FG, TITLE_BG, fmt,
    );
    ty += CELL_H * sy;

    let sel = PICK_SEL.load(Ordering::Relaxed);
    if count == 0 {
        paint_text(
            out, stride, w, h, logical_w, tx, ty, sx, sy,
            b"(no tasks)", ITEM_FG, PANEL_BG, fmt,
        );
        ty += CELL_H * sy;
    } else {
        // Window follows the selection so it stays visible.
        let start = sel.saturating_sub(visible - 1).min(count - visible);
        for idx in start..start + visible {
            let mut line = Line::new();
            proc_line(idx, &mut line);
            let selected = idx == sel;
            if selected {
                vga::overlay_fill_xscaled(
                    out, stride, w, h, logical_w, x0 + pad_x / 2, ty,
                    panel_w - pad_x, CELL_H * sy, SEL_BG, fmt,
                );
            }
            let (fg, bg) = if selected { (SEL_FG, SEL_BG) } else { (ITEM_FG, PANEL_BG) };
            paint_text(
                out, stride, w, h, logical_w, tx, ty, sx, sy,
                line.as_bytes(), fg, bg, fmt,
            );
            ty += CELL_H * sy;
        }
    }

    paint_text(
        out, stride, w, h, logical_w, tx, ty, sx, sy,
        b"Up/Dn  Enter  Esc back", FOOT_FG, PANEL_BG, fmt,
    );
}

/// One picker row: `tid: name` padded to a column, then state glyph and a `*`
/// for the current console owner.
fn proc_line(idx: usize, line: &mut Line) {
    let p = proc_at(idx);
    line.put_num(p.tid as u32);
    line.put(b": ");
    line.put(&p.name[..p.name_len as usize]);
    while line.len < 22 {
        line.put(b" ");
    }
    line.put(&[p.state]);
    if p.focused {
        line.put(b" *");
    }
}

/// Compose one tab row's text into `line`.
fn item_line(tab: usize, item: usize, line: &mut Line) {
    match tab {
        TAB_SOUND => match item {
            SOUND_ITEM_VOLUME => {
                let pct = VOL_PCT.load(Ordering::Relaxed);
                line.put(b"Volume   [");
                let filled = (pct / VOL_STEP) as usize; // 0..=10 bars
                for i in 0..10 {
                    line.put(if i < filled { b"#" } else { b"-" });
                }
                line.put(b"] ");
                line.put_num(pct);
                line.put(b"%");
            }
            SOUND_ITEM_LATENCY => {
                line.put(b"Latency  ");
                line.put_num(LATENCY_MS.load(Ordering::Relaxed));
                line.put(b" ms");
            }
            SOUND_ITEM_RATE => {
                line.put(b"Mix rate ");
                line.put_rate_q16(crate::kernel::sound::mixing_rate_q16());
            }
            SOUND_ITEM_HDA_OUTPUT => {
                line.put(b"HDA out  ");
                line.put(crate::kernel::drivers::hda::output_route_label());
            }
            _ => {}
        },
        TAB_DISK => match disk_row(item) {
            DiskRow::Eject => {
                let dev = disk_device();
                line.put(b"Eject ");
                let mut name = [0_u8; 24];
                let len = disk_label(dev, &mut name);
                line.put(&name[..len]);
            }
            DiskRow::Insert(index) => {
                let mut name = [0_u8; 28];
                let len = disk_catalog_name(disk_device(), index, &mut name);
                line.put(&name[..len]);
            }
            DiskRow::NoImages => line.put(b"(no images)"),
        },
        TAB_DEBUG => match item {
            DEBUG_ITEM_TRACE => {
                line.put(b"Trace    ");
                line.put(if crate::kernel::startup::trace_enabled() { b"ON" } else { b"off" });
            }
            DEBUG_ITEM_PROFILE => {
                line.put(b"Profile  ");
                line.put(if crate::kernel::startup::profile_enabled() { b"ON" } else { b"off" });
            }
            DEBUG_ITEM_DUMP => line.put(b"Dump state"),
            _ => {}
        },
        _ => match item {
            SYSTEM_ITEM_KILL => line.put(b"Kill task"),
            SYSTEM_ITEM_SWITCH => line.put(b"Switch task"),
            _ => {}
        },
    }
}

/// A tiny fixed-capacity line builder — no allocation in the present path.
struct Line {
    buf: [u8; 48],
    len: usize,
}

impl Line {
    fn new() -> Line {
        Line { buf: [b' '; 48], len: 0 }
    }
    fn put(&mut self, s: &[u8]) {
        for &b in s {
            if self.len < self.buf.len() {
                self.buf[self.len] = b;
                self.len += 1;
            }
        }
    }
    fn put_num(&mut self, mut n: u32) {
        if n == 0 {
            self.put(b"0");
            return;
        }
        let mut tmp = [0u8; 10];
        let mut i = 0;
        while n > 0 && i < tmp.len() {
            tmp[i] = b'0' + (n % 10) as u8;
            n /= 10;
            i += 1;
        }
        while i > 0 {
            i -= 1;
            if self.len < self.buf.len() {
                self.buf[self.len] = tmp[i];
                self.len += 1;
            }
        }
    }

    fn put_3digits(&mut self, n: u32) {
        let n = n.min(999);
        let digits = [
            b'0' + ((n / 100) % 10) as u8,
            b'0' + ((n / 10) % 10) as u8,
            b'0' + (n % 10) as u8,
        ];
        self.put(&digits);
    }

    fn put_rate_q16(&mut self, rate_q16: u64) {
        let whole = (rate_q16 >> crate::kernel::sound::RATE_FP_SHIFT) as u32;
        let frac = (((rate_q16 & ((1u64 << crate::kernel::sound::RATE_FP_SHIFT) - 1))
            as u128 * 1_000u128)
            >> crate::kernel::sound::RATE_FP_SHIFT) as u32;
        self.put_num(whole);
        self.put(b".");
        self.put_3digits(frac);
        self.put(b" Hz");
    }
    fn as_bytes(&self) -> &[u8] {
        &self.buf[..self.len]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sound_item_count_is_conditional_on_hda() {
        use crate::kernel::platform::Audio;

        assert_eq!(sound_item_count_for(Audio::EmulatedHda), 4);
        assert_eq!(sound_item_count_for(Audio::NativeSb), 3);
        assert_eq!(sound_item_count_for(Audio::SbSink), 3);
        assert_eq!(sound_item_count_for(Audio::EmulatedAc97), 3);
        assert_eq!(sound_item_count_for(Audio::EmulatedPortWindow), 3);
        assert_eq!(sound_item_count_for(Audio::EmulatedSilent), 3);
    }

    #[test]
    fn volume_gain_uses_the_perceptual_table() {
        assert_eq!(DEFAULT_VOLUME_PCT, 50);
        for (index, &gain) in VOLUME_GAIN_Q16.iter().enumerate() {
            assert_eq!(volume_gain_q16((index as u32) * VOL_STEP), gain);
        }
        assert_eq!(volume_gain_q16(0), 0);
        assert_eq!(volume_gain_q16(100), 65_536);
        assert_eq!(volume_gain_q16(101), 65_536);
        for pair in VOLUME_GAIN_Q16.windows(2) {
            assert!(pair[0] < pair[1]);
        }
    }

    #[test]
    fn volume_parser_accepts_only_displayed_steps() {
        for (text, value) in [
            (b"0".as_slice(), 0),
            (b"10".as_slice(), 10),
            (b"20".as_slice(), 20),
            (b"30".as_slice(), 30),
            (b"40".as_slice(), 40),
            (b"50".as_slice(), 50),
            (b"60".as_slice(), 60),
            (b"70".as_slice(), 70),
            (b"80".as_slice(), 80),
            (b"90".as_slice(), 90),
            (b"100".as_slice(), 100),
        ] {
            assert_eq!(parse_volume_percent(text), Some(value));
        }
        assert_eq!(parse_volume_percent(b"00"), Some(0));
        assert_eq!(parse_volume_percent(b"050"), Some(50));
        assert_eq!(parse_volume_percent(b"0100"), Some(100));
        for value in [
            b"".as_slice(), b"+50", b"-50", b" 50", b"50 ", b"50%", b"55", b"110",
            b"abc", b"999999999999999999999999999999",
        ] {
            assert_eq!(parse_volume_percent(value), None);
        }
    }
}
