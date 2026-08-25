//! The F12 host monitor: an on-screen menu overlaid on the running guest.
//!
//! One host hotkey, F12, opens a small panel; every key then drives the panel
//! (nothing reaches the guest) until Esc/F12 closes it. The guest keeps
//! RUNNING behind the panel — so a volume change is heard at once and the frame
//! under the menu keeps updating. This replaces the old one-key-per-action
//! debug/switch hotkeys: one discoverable door.
//!
//! The Windows tab selects windows, toggles the focused window between its
//! retained fullscreen/windowed modes, and can terminate its task. Trace toggles the shared DOS/DPMI/Linux
//! syscall-trace gate, Profile the profile-dump toggle, Dump the register/VGA
//! dump, and Disk lists the CD images shipped in `C:\CD`. Kill uses the ordinary exit path (a pending flag the event loop turns into
//! `Exit` for the focused thread, exactly as the SEGV path does). Volume is the
//! one new knob: a runtime master gain multiplied into the single mix-out clip.
//!
//! State is a handful of single-threaded atomics. Input handling ([`key`]) lives here but is
//! called from [`console`](crate::kernel::console), which has the `machine`/
//! `regs`/`DosState` the Dump action needs; painting ([`paint`]) happens at the
//! shared display publication boundary after a personality has rendered.

use core::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};

use vga::{self, PixelFormat};

use crate::Regs;
use crate::kernel::thread;

// ── Menu model ───────────────────────────────────────────────────────────────

const TAB_WINDOWS: usize = 0;
const TAB_SOUND: usize = 1;
const TAB_DISK: usize = 2;
const TAB_DEBUG: usize = 3;
const NUM_TABS: usize = 4;

const WINDOWS_ITEM_SELECT: usize = 0;
const WINDOWS_ITEM_PRESENTATION: usize = 1;
const WINDOWS_ITEM_KILL: usize = 2;
const WINDOWS_NUM_ITEMS: usize = 3;

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
/// True only when opening the OSD revoked a DOS fullscreen scanout lease.
/// Desktop OSD sessions already have the compositor and require no restore.
static BORROWED_FULLSCREEN: AtomicBool = AtomicBool::new(false);
static REPAINT: AtomicBool = AtomicBool::new(false);
static ACTIVE_TAB: AtomicUsize = AtomicUsize::new(TAB_SOUND);
static WINDOWS_SEL: AtomicUsize = AtomicUsize::new(0);
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
static PRESENTATION_REQ: AtomicBool = AtomicBool::new(false);
static CURRENT_FULLSCREEN: AtomicBool = AtomicBool::new(false);

/// Is the monitor panel currently open?
pub fn is_open() -> bool {
    OPEN.load(Ordering::Relaxed)
}

/// Open the panel (F12 while closed). Selection starts at the top, menu mode.
pub fn open(borrowed_fullscreen: bool) {
    crate::kernel::fs::cdrom::refresh_catalog();
    crate::kernel::fs::floppy::refresh_catalog();
    ACTIVE_TAB.store(TAB_SOUND, Ordering::Relaxed);
    WINDOWS_SEL.store(0, Ordering::Relaxed);
    SOUND_SEL.store(SOUND_ITEM_VOLUME, Ordering::Relaxed);
    DISK_SEL.store(0, Ordering::Relaxed);
    DISK_SCROLL.store(0, Ordering::Relaxed);
    DEBUG_SEL.store(0, Ordering::Relaxed);
    PICKER.store(false, Ordering::Relaxed);
    PRESENTATION_REQ.store(false, Ordering::Relaxed);
    CURRENT_FULLSCREEN.store(borrowed_fullscreen, Ordering::Relaxed);
    BORROWED_FULLSCREEN.store(borrowed_fullscreen, Ordering::Relaxed);
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
    REPAINT.store(true, Ordering::Relaxed);
}

/// Close the monitor without interpreting another key. Used when the focused
/// owner is exiting: its display must first be returned from the OSD.
pub fn dismiss() {
    close();
}

/// Consume the fullscreen lease marker when an ordinary OSD close must return
/// the display capability to DOS direct scanout.
pub fn take_fullscreen_lease() -> bool {
    BORROWED_FULLSCREEN.swap(false, Ordering::Relaxed)
}

/// Close after a window selection or explicit presentation change. The event
/// loop now owns the display token and will apply the destination's retained
/// mode, so the OSD must not restore the mode from which it was opened.
pub fn finish_presentation_change() {
    BORROWED_FULLSCREEN.store(false, Ordering::Relaxed);
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
        _ => WINDOWS_SEL.load(Ordering::Relaxed),
    }
}

fn set_active_sel(tab: usize, sel: usize) {
    match tab {
        TAB_SOUND => SOUND_SEL.store(sel.min(sound_item_count() - 1), Ordering::Relaxed),
        TAB_DISK => DISK_SEL.store(sel.min(disk_item_count() - 1), Ordering::Relaxed),
        TAB_DEBUG => DEBUG_SEL.store(sel.min(DEBUG_NUM_ITEMS - 1), Ordering::Relaxed),
        _ => WINDOWS_SEL.store(sel.min(WINDOWS_NUM_ITEMS - 1), Ordering::Relaxed),
    }
}

fn active_item_count(tab: usize) -> usize {
    match tab {
        TAB_SOUND => sound_item_count(),
        TAB_DISK => disk_item_count(),
        TAB_DEBUG => DEBUG_NUM_ITEMS,
        _ => WINDOWS_NUM_ITEMS,
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
    /// Runtime CD-ROM transfer-speed control, always row 0 on the CD tab.
    Speed,
    /// "Eject <name>" — first media row when media is inserted.
    Eject,
    /// Insert/swap to this catalogue index.
    Insert(usize),
    /// "(no images)" placeholder for an empty device + empty catalogue.
    NoImages,
}

fn disk_row(item: usize) -> DiskRow {
    let dev = disk_device();
    if dev == 2 && item == 0 {
        return DiskRow::Speed;
    }
    let item = item - usize::from(dev == 2);
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
    let media_rows = if disk_inserted(dev) {
        1 + catalog.saturating_sub(1) // Eject + swap targets
    } else {
        catalog.max(1) // list, or the "(no images)" row
    };
    media_rows + usize::from(dev == 2) // CD also has its speed row
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
        _ => b"Windows",
    }
}

/// Consume a pending "kill the focused task" request. The event loop calls this
/// each iteration and, when set, exits the focused thread down the ordinary
/// teardown path.
pub fn take_kill_request() -> bool {
    KILL_REQ.swap(false, Ordering::Relaxed)
}

pub fn take_presentation_request() -> bool {
    PRESENTATION_REQ.swap(false, Ordering::Relaxed)
}

// ── Primary-window list ──────────────────────────────────────────────────────

/// Max primary windows the picker lists in this first endpoint-backed model.
const MAX_LIST: usize = 12;

#[derive(Clone, Copy)]
struct WindowEntry {
    tid: u16,
    focused: bool,
    name: [u8; 16],
    name_len: u8,
}

impl WindowEntry {
    const EMPTY: WindowEntry = WindowEntry { tid: 0, focused: false, name: [0; 16], name_len: 0 };
}

/// The picker's snapshot, rebuilt once per timer tick while the monitor is
/// open — at the event-loop point where the whole thread table is borrowable.
/// Single-threaded cooperative kernel, so a plain `static mut` behind
/// accessors, the same discipline as the flags above.
static mut WINDOWS: [WindowEntry; MAX_LIST] = [WindowEntry::EMPTY; MAX_LIST];
static WINDOW_COUNT: AtomicUsize = AtomicUsize::new(0);
static PICK_SEL: AtomicUsize = AtomicUsize::new(0);
static PICKER: AtomicBool = AtomicBool::new(false);
static WINDOW_REQUEST: AtomicUsize = AtomicUsize::new(usize::MAX);

/// Rebuild the primary-window list from live personality endpoints. Native
/// Windows/OS2 adapters can replace this snapshot with multiple WindowIds.
pub fn refresh_windows<A: crate::Arch>(
    threads: &[thread::Thread<A>],
    focused: usize,
    fullscreen: bool,
) {
    let mut count = 0;
    for (i, t) in threads.iter().enumerate().skip(1) {
        if count >= MAX_LIST {
            break;
        }
        let k = &t.kernel;
        match k.state {
            thread::ThreadState::Running
            | thread::ThreadState::Ready
            | thread::ThreadState::Blocked => {}
            _ => continue, // Unused / Zombie: not a switch target
        }
        let name: &[u8] = match &threads[i].personality {
            thread::Personality::Linux(l) => thread::basename(l.exec_path_str()),
            thread::Personality::Os2(o) => thread::basename(o.exec_path_str()),
            thread::Personality::Windows(w) => thread::basename(w.exec_path_str()),
            thread::Personality::Dos(_) => {
                let c = k.comm_str();
                if c.is_empty() { b"DOS" } else { c }
            }
        };
        let n = name.len().min(16);
        // SAFETY: single-threaded cooperative kernel; no concurrent access.
        unsafe {
            let p = &mut (*core::ptr::addr_of_mut!(WINDOWS))[count];
            p.tid = i as u16;
            p.focused = i == focused;
            p.name = [0; 16];
            p.name[..n].copy_from_slice(&name[..n]);
            p.name_len = n as u8;
        }
        count += 1;
    }
    WINDOW_COUNT.store(count, Ordering::Relaxed);
    CURRENT_FULLSCREEN.store(fullscreen, Ordering::Relaxed);
    if PICK_SEL.load(Ordering::Relaxed) >= count {
        PICK_SEL.store(count.saturating_sub(1), Ordering::Relaxed);
    }
}

fn window_at(idx: usize) -> WindowEntry {
    // SAFETY: single-threaded; idx bounded by the caller against WINDOW_COUNT.
    unsafe { (*core::ptr::addr_of!(WINDOWS))[idx] }
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

/// Drive the window picker submode. Esc/◄ backs out to the menu; Enter/► picks.
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
    let count = WINDOW_COUNT.load(Ordering::Relaxed);
    if count == 0 {
        return;
    }
    let cur = PICK_SEL.load(Ordering::Relaxed);
    let sel = if up { (cur + count - 1) % count } else { (cur + 1) % count };
    PICK_SEL.store(sel, Ordering::Relaxed);
}

fn pick_select() {
    let sel = PICK_SEL.load(Ordering::Relaxed);
    if sel < WINDOW_COUNT.load(Ordering::Relaxed) {
        WINDOW_REQUEST.store(window_at(sel).tid as usize, Ordering::Relaxed);
    }
    // Stay open until the event loop consumes the request atomically with the
    // destination presentation transition.
    REPAINT.store(true, Ordering::Relaxed);
}

pub fn take_window_request() -> Option<usize> {
    let tid = WINDOW_REQUEST.swap(usize::MAX, Ordering::Relaxed);
    (tid != usize::MAX).then_some(tid)
}

/// After a switch the focused-window marker in the picker is stale until the
/// event loop's next snapshot; nudge a repaint so it corrects promptly.
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
        if disk_device() == 2 && matches!(disk_row(active_sel(TAB_DISK)), DiskRow::Speed) {
            crate::kernel::fs::cdrom::cycle_speed(up);
            return;
        }
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
                DiskRow::Speed => {}
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
        _ => match active_sel(TAB_WINDOWS) {
            // Open the primary-window list. Personalities can later contribute
            // multiple native top-level windows without changing selection.
            WINDOWS_ITEM_SELECT => {
                PICK_SEL.store(0, Ordering::Relaxed);
                PICKER.store(true, Ordering::Relaxed);
            }
            WINDOWS_ITEM_PRESENTATION => {
                PRESENTATION_REQ.store(true, Ordering::Relaxed);
            }
            WINDOWS_ITEM_KILL => {
                KILL_REQ.store(true, Ordering::Relaxed);
                close();
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
const COLS: usize = 28;
const MAX_ROWS: usize = 16;
const PAD: usize = 8;
const CELL_W: usize = 8;
const CELL_H: usize = 8;
const _: () = assert!(COLS * CELL_W + 2 * PAD <= 320, "panel wider than the smallest mode");
const _: () = assert!(MAX_ROWS * CELL_H + 2 * PAD <= 200, "panel taller than the smallest mode");

/// The two axes are scaled differently on purpose. VERTICAL is coarse:
/// `sy` shadow rows per glyph row, and the present step multiplies by its
/// own stretch afterward — we only get to pick from `8·sy` row steps. An
/// even `sy` upgrades to the 8x16 font at half row scale (real
/// letterforms). HORIZONTAL is fine-grained: the shadow is already at
/// output width, so the cell width `cw` is free in PIXELS — glyph columns
/// are distributed over `cw` Bresenham-style, letting the cell take the
/// font's natural aspect at whatever height the vertical quantization
/// produced instead of snapping to multiples of 8.
#[allow(clippy::too_many_arguments)]
fn paint_text(
    out: &mut [u8], stride: usize, w: usize, h: usize,
    logical_w: usize, x: usize, y: usize, cw: usize, sy: usize,
    s: &[u8], fg: u32, bg: u32,
    fmt: PixelFormat,
) {
    if logical_w == 0 || cw == 0 { return; }
    let fgp = fmt.encode(fg).to_le_bytes();
    let bgp = fmt.encode(bg).to_le_bytes();
    let bytes = fmt.bytes_per_pixel as usize;
    let (font, rows, row_scale): (&[u8], usize, usize) = if sy.is_multiple_of(2) {
        (&lib::vga_fonts::FONT_8X16, 16, sy / 2)
    } else {
        (&lib::vga_fonts::FONT_8X8, 8, sy)
    };
    for (i, &ch) in s.iter().enumerate() {
        let cx = x + i * cw;
        if cx + cw > logical_w { break; }
        let glyph = &font[ch as usize * rows..(ch as usize + 1) * rows];
        for (gy, &bits) in glyph.iter().enumerate() {
            for repeat in 0..row_scale {
                let py = y + gy * row_scale + repeat;
                if py >= h { break; }
                for gx in 0..CELL_W {
                    let pixel = if bits & (0x80 >> gx) != 0 { &fgp } else { &bgp };
                    // Column gx spans its share of the cw-wide cell.
                    let lx0 = cx + gx * cw / CELL_W;
                    let lx1 = cx + (gx + 1) * cw / CELL_W;
                    for lx in lx0..lx1 {
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

/// Choose the cell geometry `(cw, sy)` — VERTICAL FIRST, because that is
/// the coarse axis. The shadow is wide-and-short: rows are already
/// stretched to output width, but the mode's ROW COUNT is kept and the
/// present step expands rows by `stretch_y` AFTERWARD (a 320x200 game on
/// a 480-line output is a 640x200 shadow stretched x2.4 after we paint),
/// so cell heights only exist in steps of `8·stretch_y` screen pixels.
///
/// - VERTICAL: `sy` targets ~26 text lines of the shadow's row space
///   (`round(rows/208)`), snapped down until the panel's rows fit. Even
///   `sy` renders the 8x16 font.
/// - HORIZONTAL: fine-grained — the cell width `cw` (in pixels, any
///   value) takes the chosen font's natural aspect at the realized
///   screen height: 8x16 → half the height, 8x8 → equal. Clamped to fit.
///
/// `rows_needed` is the panel's total character rows.
fn paint_scales(
    stretch_y: usize, logical_w: usize, h: usize, rows_needed: usize,
) -> (usize, usize) {
    let stretch_y = stretch_y.max(1);
    let mut sy = ((h + 104) / 208).max(1);
    while sy > 1 && rows_needed * CELL_H * sy + 2 * PAD > h {
        sy -= 1;
    }
    // Prefer the detailed 8x16 font whenever the rows allow it: an odd
    // sy > 1 (e.g. 3 on an 800x600 shadow) would fall back to chunky 8x8
    // when one step down buys real letterforms at a slightly smaller cell.
    if sy > 1 && sy % 2 == 1 {
        sy -= 1;
    }
    let screen_cell_h = CELL_H * sy * stretch_y;
    let natural = if sy.is_multiple_of(2) { screen_cell_h / 2 } else { screen_cell_h };
    // The font-natural width, BOUNDED by a width budget: ~60% of the
    // screen for the 30 columns. Without the bound the square 8x8 aspect
    // blows the panel to full width exactly when a big vertical stretch
    // denies the tall font (sy=1 over a 320x200 game on a large panel);
    // with it, cells there get mildly narrow glyphs instead — the same
    // trade every 40-column-era UI made. The 8px floor keeps genuine
    // low-res modes at their authentic full-density fit.
    let budget = (logical_w * 3 / 5) / COLS.max(1);
    let cw = natural
        .min(budget)
        .clamp(CELL_W, ((logical_w.saturating_sub(2 * PAD)) / COLS.max(1)).max(CELL_W));
    (cw, sy)
}

fn panel_rows() -> usize {
    if PICKER.load(Ordering::Relaxed) {
        WINDOW_COUNT.load(Ordering::Relaxed).clamp(1, MAX_ROWS - 2) + 2
    } else {
        let tab = active_tab();
        let count = active_item_count(tab);
        let visible = if tab == TAB_DISK { count.min(DISK_VISIBLE) } else { count };
        visible + usize::from(tab == TAB_DISK) + 3
    }
}

/// Size of the opaque system window containing the monitor panel.
pub fn window_size(
    canvas_width: usize,
    canvas_height: usize,
    scale_y: usize,
) -> Option<(usize, usize)> {
    let rows = panel_rows();
    let (cw, sy) = paint_scales(scale_y, canvas_width, canvas_height, rows);
    let (pad_x, pad_y) = ((cw / 4).max(1), 2 * sy);
    let width = COLS * cw + pad_x * 2;
    let height = rows * CELL_H * sy + pad_y * 2;
    (canvas_width >= width && canvas_height >= height).then_some((width, height))
}

/// Composite the panel into a completed packed shadow. `scale_y` is an
/// integer because a Mode 13h output may consume several source rows per
/// physical row; glyph rows are repeated, never fractionally resampled.
pub fn paint(
    out: &mut [u8],
    stride: usize,
    w: usize,
    h: usize,
    canvas_width: usize,
    canvas_height: usize,
    scale_y: usize,
    fmt: PixelFormat,
) {
    if PICKER.load(Ordering::Relaxed) {
        paint_picker(out, stride, w, h, canvas_width, canvas_height, scale_y, fmt);
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
    let (cw, sy) = paint_scales(scale_y, canvas_width, canvas_height, rows);
    // Tight box: a two-glyph-pixel margin, just enough to keep strokes
    // off the panel edge (a glyph pixel is cw/8 wide, sy rows tall).
    let (pad_x, pad_y) = ((cw / 4).max(1), 2 * sy);
    let panel_w = COLS * cw + pad_x * 2;
    let panel_h = rows * CELL_H * sy + pad_y * 2;
    if w < panel_w || h < panel_h {
        return;
    }
    let logical_w = w;
    let x0 = (w - panel_w) / 2;
    let y0 = (h - panel_h) / 2;

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
        out, stride, w, h, logical_w, tx, ty, cw, sy,
        title.as_bytes(), TITLE_FG, TITLE_BG, fmt,
    );
    ty += CELL_H * sy;

    paint_tabs(out, stride, w, h, logical_w, tx, ty, tab, cw, sy, fmt);
    ty += CELL_H * sy;

    if tab == TAB_DISK {
        paint_disk_subtabs(out, stride, w, h, logical_w, tx, ty, cw, sy, fmt);
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
            out, stride, w, h, logical_w, tx, ty, cw, sy,
            line.as_bytes(), fg, bg, fmt,
        );
        // Scroller continuation markers in the rightmost column.
        let marker_x = x0 + panel_w - pad_x - cw;
        if row == 0 && scroll > 0 {
            paint_text(out, stride, w, h, logical_w, marker_x, ty, cw, sy,
                b"\x18", FOOT_FG, if selected { SEL_BG } else { PANEL_BG }, fmt);
        }
        if row + 1 == visible && scroll + visible < count {
            paint_text(out, stride, w, h, logical_w, marker_x, ty, cw, sy,
                b"\x19", FOOT_FG, if selected { SEL_BG } else { PANEL_BG }, fmt);
        }
        ty += CELL_H * sy;
    }

    paint_text(
        out, stride, w, h, logical_w, tx, ty, cw, sy,
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
    cw: usize,
    sy: usize,
    fmt: PixelFormat,
) {
    let active = disk_device();
    let mut x = tx + cw;
    for dev in 0..DISK_DEVICES {
        let label = disk_device_label(dev);
        let label_w = (label.len() + 1) * cw;
        let selected = dev == active;
        if selected {
            vga::overlay_fill_xscaled(
                out, stride, w, h, logical_w, x, ty, label_w, CELL_H * sy, SEL_BG, fmt,
            );
        }
        let (fg, bg) = if selected { (SEL_FG, SEL_BG) } else { (ITEM_FG, PANEL_BG) };
        paint_text(
            out, stride, w, h, logical_w, x + cw / 2, ty, cw, sy,
            label, fg, bg, fmt,
        );
        x += label_w + cw;
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
    cw: usize,
    sy: usize,
    fmt: PixelFormat,
) {
    let mut x = tx;
    for &(tab, label) in &[
        (TAB_WINDOWS, b"Windows" as &[u8]),
        (TAB_SOUND, b"Sound" as &[u8]),
        (TAB_DISK, b"Disk" as &[u8]),
        (TAB_DEBUG, b"Debug" as &[u8]),
    ] {
        let selected = tab == active;
        let label_w = (label.len() + 1) * cw;
        if selected {
            vga::overlay_fill_xscaled(
                out, stride, w, h, logical_w, x, ty,
                label_w, CELL_H * sy, SEL_BG, fmt,
            );
        }
        let (fg, bg) = if selected { (SEL_FG, SEL_BG) } else { (ITEM_FG, PANEL_BG) };
        paint_text(
            out, stride, w, h, logical_w, x + cw / 2, ty,
            cw, sy, label, fg, bg, fmt,
        );
        x += label_w + cw;
    }
}

/// Paint the window picker: currently one primary window per active endpoint.
fn paint_picker(
    out: &mut [u8],
    stride: usize,
    w: usize,
    h: usize,
    canvas_width: usize,
    canvas_height: usize,
    scale_y: usize,
    fmt: PixelFormat,
) {
    let count = WINDOW_COUNT.load(Ordering::Relaxed);
    // Character budget: the list shares MAX_ROWS with title + footer.
    let visible = count.clamp(1, MAX_ROWS - 2);
    let rows = visible + 2;
    let (cw, sy) = paint_scales(scale_y, canvas_width, canvas_height, rows);
    let (pad_x, pad_y) = ((cw / 4).max(1), 2 * sy);
    let panel_w = COLS * cw + pad_x * 2;
    let panel_h = rows * CELL_H * sy + pad_y * 2;
    if w < panel_w || h < panel_h {
        return;
    }
    let logical_w = w;
    let x0 = (w - panel_w) / 2;
    let y0 = (h - panel_h) / 2;

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
        out, stride, w, h, logical_w, tx, ty, cw, sy,
        b"Select window", TITLE_FG, TITLE_BG, fmt,
    );
    ty += CELL_H * sy;

    let sel = PICK_SEL.load(Ordering::Relaxed);
    if count == 0 {
        paint_text(
            out, stride, w, h, logical_w, tx, ty, cw, sy,
            b"(no windows)", ITEM_FG, PANEL_BG, fmt,
        );
        ty += CELL_H * sy;
    } else {
        // Window follows the selection so it stays visible.
        let start = sel.saturating_sub(visible - 1).min(count - visible);
        for idx in start..start + visible {
            let mut line = Line::new();
            window_line(idx, &mut line);
            let selected = idx == sel;
            if selected {
                vga::overlay_fill_xscaled(
                    out, stride, w, h, logical_w, x0 + pad_x / 2, ty,
                    panel_w - pad_x, CELL_H * sy, SEL_BG, fmt,
                );
            }
            let (fg, bg) = if selected { (SEL_FG, SEL_BG) } else { (ITEM_FG, PANEL_BG) };
            paint_text(
                out, stride, w, h, logical_w, tx, ty, cw, sy,
                line.as_bytes(), fg, bg, fmt,
            );
            ty += CELL_H * sy;
        }
    }

    paint_text(
        out, stride, w, h, logical_w, tx, ty, cw, sy,
        b"Up/Dn  Enter  Esc back", FOOT_FG, PANEL_BG, fmt,
    );
}

/// One primary-window row, with a `*` for keyboard focus.
fn window_line(idx: usize, line: &mut Line) {
    let p = window_at(idx);
    line.put(&p.name[..p.name_len as usize]);
    while line.len < 24 {
        line.put(b" ");
    }
    if p.focused {
        line.put(b"*");
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
            DiskRow::Speed => {
                line.put(b"Speed    ");
                line.put(crate::kernel::fs::cdrom::speed_label());
            }
            DiskRow::Eject => {
                let dev = disk_device();
                line.put(b"Eject ");
                let mut name = [0_u8; 22];
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
            WINDOWS_ITEM_SELECT => line.put(b"Select window"),
            WINDOWS_ITEM_PRESENTATION => {
                line.put(if CURRENT_FULLSCREEN.load(Ordering::Relaxed) {
                    b"Make window"
                } else {
                    b"Make fullscreen"
                });
            }
            WINDOWS_ITEM_KILL => line.put(b"Kill task"),
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
