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
//! dump, Kill the ordinary exit path (a pending flag the event loop turns into
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

// ── Menu model ───────────────────────────────────────────────────────────────

const TAB_SYSTEM: usize = 0;
const TAB_SOUND: usize = 1;
const TAB_DEBUG: usize = 2;
const NUM_TABS: usize = 3;

const SYSTEM_ITEM_KILL: usize = 0;
const SYSTEM_ITEM_SWITCH: usize = 1;
const SYSTEM_NUM_ITEMS: usize = 2;

const SOUND_ITEM_VOLUME: usize = 0;
const SOUND_ITEM_LATENCY: usize = 1;
const SOUND_ITEM_RATE: usize = 2;
const SOUND_NUM_ITEMS: usize = 3;

const DEBUG_ITEM_TRACE: usize = 0;
const DEBUG_ITEM_PROFILE: usize = 1;
const DEBUG_ITEM_DUMP: usize = 2;
const DEBUG_NUM_ITEMS: usize = 3;

/// Master volume as a percentage of unity, adjusted by ◄/► on the Volume row.
/// 100 = unity (the level the per-source scales already balance to); attenuate
/// only — a boost above unity would just clip against the mix-out rail.
const VOL_MAX: u32 = 100;
const VOL_STEP: u32 = 10;
const LATENCY_MIN_MS: u32 = 10;
const LATENCY_MAX_MS: u32 = 80;
const LATENCY_STEP_MS: u32 = 5;

static OPEN: AtomicBool = AtomicBool::new(false);
static REPAINT: AtomicBool = AtomicBool::new(false);
static ACTIVE_TAB: AtomicUsize = AtomicUsize::new(TAB_SOUND);
static SYSTEM_SEL: AtomicUsize = AtomicUsize::new(0);
static SOUND_SEL: AtomicUsize = AtomicUsize::new(0);
static DEBUG_SEL: AtomicUsize = AtomicUsize::new(0);
static VOL_PCT: AtomicU32 = AtomicU32::new(100);
static LATENCY_MS: AtomicU32 = AtomicU32::new(30);
static KILL_REQ: AtomicBool = AtomicBool::new(false);

/// Is the monitor panel currently open?
pub fn is_open() -> bool {
    OPEN.load(Ordering::Relaxed)
}

/// Open the panel (F12 while closed). Selection starts at the top, menu mode.
pub fn open() {
    ACTIVE_TAB.store(TAB_SOUND, Ordering::Relaxed);
    SYSTEM_SEL.store(0, Ordering::Relaxed);
    SOUND_SEL.store(SOUND_ITEM_VOLUME, Ordering::Relaxed);
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
    (VOL_PCT.load(Ordering::Relaxed) as i32 * 65536 / 100).max(0)
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
        TAB_DEBUG => DEBUG_SEL.load(Ordering::Relaxed),
        _ => SYSTEM_SEL.load(Ordering::Relaxed),
    }
}

fn set_active_sel(tab: usize, sel: usize) {
    match tab {
        TAB_SOUND => SOUND_SEL.store(sel.min(SOUND_NUM_ITEMS - 1), Ordering::Relaxed),
        TAB_DEBUG => DEBUG_SEL.store(sel.min(DEBUG_NUM_ITEMS - 1), Ordering::Relaxed),
        _ => SYSTEM_SEL.store(sel.min(SYSTEM_NUM_ITEMS - 1), Ordering::Relaxed),
    }
}

fn active_item_count(tab: usize) -> usize {
    match tab {
        TAB_SOUND => SOUND_NUM_ITEMS,
        TAB_DEBUG => DEBUG_NUM_ITEMS,
        _ => SYSTEM_NUM_ITEMS,
    }
}

fn active_tab_name(tab: usize) -> &'static [u8] {
    match tab {
        TAB_SOUND => b"Sound",
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
}

/// ◄/► adjust the selected continuous setting.
fn adjust(up: bool) {
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
        _ => {}
    }
}

fn activate<A: crate::Arch>(machine: &mut A, regs: &mut Regs, dos: Option<&thread::DosState<A>>) {
    match active_tab() {
        // Continuous settings are adjusted with ◄/►; Enter does nothing.
        TAB_SOUND => {}
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

const COLS: usize = 30;
const PAD: usize = 8;
const CELL_W: usize = vga::OVERLAY_CELL_W;
const CELL_H: usize = vga::OVERLAY_CELL_H;

#[allow(clippy::too_many_arguments)]
fn paint_text(
    out: &mut [u8], stride: usize, w: usize, h: usize,
    logical_w: usize, x: usize, y: usize, scale_y: usize,
    s: &[u8], fg: u32, bg: u32,
    fmt: PixelFormat,
) {
    if logical_w == 0 { return; }
    let fgp = fmt.encode(fg).to_le_bytes();
    let bgp = fmt.encode(bg).to_le_bytes();
    let bytes = fmt.bytes_per_pixel as usize;
    let font = &lib::vga_fonts::FONT_8X16;
    for (i, &ch) in s.iter().enumerate() {
        let cx = x + i * CELL_W;
        if cx + CELL_W > logical_w { break; }
        let glyph = &font[ch as usize * CELL_H..(ch as usize + 1) * CELL_H];
        for (gy, &bits) in glyph.iter().enumerate() {
            for repeat in 0..scale_y {
                let py = y + gy * scale_y + repeat;
                if py >= h { break; }
                for gx in 0..CELL_W {
                    let pixel = if bits & (0x80 >> gx) != 0 { &fgp } else { &bgp };
                    let lx = cx + gx;
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
    let scale_y = scale_y.max(1);
    if PICKER.load(Ordering::Relaxed) {
        paint_picker(out, stride, w, h, logical_w, scale_y, fmt);
        return;
    }
    let tab = active_tab();
    let count = active_item_count(tab);
    // Title + tab bar + items + footer.
    let rows = count + 3;
    let panel_w = COLS * CELL_W + PAD * 2;
    let base_panel_h = rows * CELL_H + PAD * 2;
    let scale_y = scale_y.min(h / base_panel_h).max(1);
    let panel_h = base_panel_h * scale_y;
    if logical_w < panel_w || h < panel_h {
        return;
    }
    let x0 = (logical_w - panel_w) / 2;
    let y0 = (h - panel_h) / 2;

    vga::overlay_fill_xscaled(
        out, stride, w, h, logical_w, x0, y0, panel_w, panel_h, PANEL_BG, fmt,
    );
    vga::overlay_fill_xscaled(
        out, stride, w, h, logical_w, x0, y0, panel_w,
        (CELL_H + PAD) * scale_y, TITLE_BG, fmt,
    );

    let tx = x0 + PAD;
    let mut ty = y0 + PAD * scale_y;
    let mut title = Line::new();
    title.put(b"RetroOS Monitor  ");
    title.put(active_tab_name(tab));
    paint_text(
        out, stride, w, h, logical_w, tx, ty, scale_y,
        title.as_bytes(), TITLE_FG, TITLE_BG, fmt,
    );
    ty += CELL_H * scale_y;

    paint_tabs(out, stride, w, h, logical_w, tx, ty, tab, scale_y, fmt);
    ty += CELL_H * scale_y;

    let sel = active_sel(tab);
    for item in 0..count {
        let mut line = Line::new();
        item_line(tab, item, &mut line);
        let selected = item == sel;
        if selected {
            vga::overlay_fill_xscaled(
                out, stride, w, h, logical_w, x0 + PAD / 2, ty,
                panel_w - PAD, CELL_H * scale_y, SEL_BG, fmt,
            );
        }
        let (fg, bg) = if selected { (SEL_FG, SEL_BG) } else { (ITEM_FG, PANEL_BG) };
        paint_text(
            out, stride, w, h, logical_w, tx, ty, scale_y,
            line.as_bytes(), fg, bg, fmt,
        );
        ty += CELL_H * scale_y;
    }

    paint_text(
        out, stride, w, h, logical_w, tx, ty, scale_y,
        b"Up/Dn Enter <>adjust Tab Esc", FOOT_FG, PANEL_BG, fmt,
    );
}

fn paint_tabs(
    out: &mut [u8],
    stride: usize,
    w: usize,
    h: usize,
    logical_w: usize,
    tx: usize,
    ty: usize,
    active: usize,
    scale_y: usize,
    fmt: PixelFormat,
) {
    let mut x = tx;
    for &(tab, label) in &[
        (TAB_SYSTEM, b"System" as &[u8]),
        (TAB_SOUND, b"Sound" as &[u8]),
        (TAB_DEBUG, b"Debug" as &[u8]),
    ] {
        let selected = tab == active;
        let label_w = label.len() * CELL_W + CELL_W;
        if selected {
            vga::overlay_fill_xscaled(
                out, stride, w, h, logical_w, x, ty,
                label_w, CELL_H * scale_y, SEL_BG, fmt,
            );
        }
        let (fg, bg) = if selected { (SEL_FG, SEL_BG) } else { (ITEM_FG, PANEL_BG) };
        paint_text(
            out, stride, w, h, logical_w, x + CELL_W / 2, ty,
            scale_y, label, fg, bg, fmt,
        );
        x += label_w + CELL_W;
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
    let rows = count.max(1) + 2; // title + list (≥1 line) + footer
    let panel_w = COLS * CELL_W + PAD * 2;
    let base_panel_h = rows * CELL_H + PAD * 2;
    let scale_y = scale_y.min(h / base_panel_h).max(1);
    let panel_h = base_panel_h * scale_y;
    if logical_w < panel_w || h < panel_h {
        return;
    }
    let x0 = (logical_w - panel_w) / 2;
    let y0 = (h - panel_h) / 2;

    vga::overlay_fill_xscaled(
        out, stride, w, h, logical_w, x0, y0, panel_w, panel_h, PANEL_BG, fmt,
    );
    vga::overlay_fill_xscaled(
        out, stride, w, h, logical_w, x0, y0, panel_w,
        (CELL_H + PAD) * scale_y, TITLE_BG, fmt,
    );

    let tx = x0 + PAD;
    let mut ty = y0 + PAD * scale_y;
    paint_text(
        out, stride, w, h, logical_w, tx, ty, scale_y,
        b"Switch to task", TITLE_FG, TITLE_BG, fmt,
    );
    ty += CELL_H * scale_y;

    let sel = PICK_SEL.load(Ordering::Relaxed);
    if count == 0 {
        paint_text(
            out, stride, w, h, logical_w, tx, ty, scale_y,
            b"(no tasks)", ITEM_FG, PANEL_BG, fmt,
        );
        ty += CELL_H * scale_y;
    } else {
        for idx in 0..count {
            let mut line = Line::new();
            proc_line(idx, &mut line);
            let selected = idx == sel;
            if selected {
                vga::overlay_fill_xscaled(
                    out, stride, w, h, logical_w, x0 + PAD / 2, ty,
                    panel_w - PAD, CELL_H * scale_y, SEL_BG, fmt,
                );
            }
            let (fg, bg) = if selected { (SEL_FG, SEL_BG) } else { (ITEM_FG, PANEL_BG) };
            paint_text(
                out, stride, w, h, logical_w, tx, ty, scale_y,
                line.as_bytes(), fg, bg, fmt,
            );
            ty += CELL_H * scale_y;
        }
    }

    paint_text(
        out, stride, w, h, logical_w, tx, ty, scale_y,
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
            _ => {}
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
        let frac = ((rate_q16 & ((1u64 << crate::kernel::sound::RATE_FP_SHIFT) - 1))
            as u128 * 1_000u128
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
