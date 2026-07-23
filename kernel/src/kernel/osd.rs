//! The F12 host monitor: an on-screen menu overlaid on the running guest.
//!
//! One host hotkey, F12, opens a small panel; every key then drives the panel
//! (nothing reaches the guest) until Esc/F12 closes it. The guest keeps
//! RUNNING behind the panel — so a volume change is heard at once and the frame
//! under the menu keeps updating. This replaces the old one-key-per-action
//! chords (F10 profile / F11 switch / F12 dump): one discoverable door.
//!
//! Actions fold into machinery that already exists — Switch opens a task picker
//! that targets the focus-switch request, Trace the shared DOS/DPMI/Linux
//! syscall-trace gate, Profile the profile-dump toggle, Dump the register/VGA
//! dump, Kill the ordinary exit path (a pending flag the event loop turns into
//! `Exit` for the focused thread, exactly as the SEGV path does). Volume is the
//! one new knob: a runtime master gain multiplied into the single mix-out clip.
//!
//! State is a handful of single-threaded atomics — the same volatile-flag shape
//! as [`thread::request_switch`]. Input handling ([`key`]) lives here but is
//! called from [`console`](crate::kernel::console), which has the `machine`/
//! `regs`/`DosState` the Dump action needs; painting ([`paint`]) is called from
//! the DOS display tick, the one place both backends hold a finished frame.

use core::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};

use lib::vga_render::{self, PixelFormat};

use crate::Regs;
use crate::kernel::thread;

// ── Menu model ───────────────────────────────────────────────────────────────

const ITEM_KILL: usize = 0;
const ITEM_SWITCH: usize = 1;
const ITEM_VOLUME: usize = 2;
const ITEM_TRACE: usize = 3;
const ITEM_PROFILE: usize = 4;
const ITEM_DUMP: usize = 5;
const NUM_ITEMS: usize = 6;

/// Master volume as a percentage of unity, adjusted by ◄/► on the Volume row.
/// 100 = unity (the level the per-source scales already balance to); attenuate
/// only — a boost above unity would just clip against the mix-out rail.
const VOL_MIN: u32 = 0;
const VOL_MAX: u32 = 100;
const VOL_STEP: u32 = 10;

static OPEN: AtomicBool = AtomicBool::new(false);
static SEL: AtomicUsize = AtomicUsize::new(0);
static VOL_PCT: AtomicU32 = AtomicU32::new(100);
static KILL_REQ: AtomicBool = AtomicBool::new(false);

/// Is the monitor panel currently open?
pub fn is_open() -> bool {
    OPEN.load(Ordering::Relaxed)
}

/// Open the panel (F12 while closed). Selection starts at the top, menu mode.
pub fn open() {
    SEL.store(0, Ordering::Relaxed);
    PICKER.store(false, Ordering::Relaxed);
    OPEN.store(true, Ordering::Relaxed);
}

fn close() {
    PICKER.store(false, Ordering::Relaxed);
    OPEN.store(false, Ordering::Relaxed);
}

/// The master output gain in Q16, read by the mixer pump. Unity (65536) at
/// 100%; scales the summed mix just before its single clip.
pub fn master_gain_q16() -> i32 {
    (VOL_PCT.load(Ordering::Relaxed) as i32 * 65536 / 100).max(0)
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

/// The picker's snapshot, rebuilt each event-loop iteration while the monitor is
/// open — that's the one place the whole thread table is in scope. Single-
/// threaded cooperative kernel, so a plain `static mut` behind accessors, the
/// same discipline as the flags above.
static mut PROCS: [Proc; MAX_LIST] = [Proc::EMPTY; MAX_LIST];
static PROC_COUNT: AtomicUsize = AtomicUsize::new(0);
static PICK_SEL: AtomicUsize = AtomicUsize::new(0);
static PICKER: AtomicBool = AtomicBool::new(false);

/// Rebuild the process list from the thread table. Mirrors `cycle_next`'s
/// active-thread filter (skip tid 0 and Unused/Zombie); `focused` marks the
/// current console owner.
pub fn refresh_processes<A: crate::Arch>(threads: &[thread::Thread<A>], focused: usize) {
    let mut count = 0;
    for i in 1..threads.len() {
        if count >= MAX_LIST {
            break;
        }
        let k = &threads[i].kernel;
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
    if PICKER.load(Ordering::Relaxed) {
        pick_key(sc);
        return;
    }
    match sc {
        K_F12 | K_ESC => close(),
        K_UP => move_sel(NUM_ITEMS - 1), // -1 mod NUM_ITEMS
        K_DOWN => move_sel(1),
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

fn move_sel(delta: usize) {
    let sel = (SEL.load(Ordering::Relaxed) + delta) % NUM_ITEMS;
    SEL.store(sel, Ordering::Relaxed);
}

/// ◄/► adjust the Volume row; a no-op on every other row.
fn adjust(up: bool) {
    if SEL.load(Ordering::Relaxed) != ITEM_VOLUME {
        return;
    }
    let cur = VOL_PCT.load(Ordering::Relaxed);
    let next = if up {
        (cur + VOL_STEP).min(VOL_MAX)
    } else {
        cur.saturating_sub(VOL_STEP).max(VOL_MIN)
    };
    VOL_PCT.store(next, Ordering::Relaxed);
}

fn activate<A: crate::Arch>(machine: &mut A, regs: &mut Regs, dos: Option<&thread::DosState<A>>) {
    match SEL.load(Ordering::Relaxed) {
        ITEM_KILL => {
            KILL_REQ.store(true, Ordering::Relaxed);
            close();
        }
        // Open the task picker (a submode of the still-open monitor).
        ITEM_SWITCH => {
            PICK_SEL.store(0, Ordering::Relaxed);
            PICKER.store(true, Ordering::Relaxed);
        }
        // Volume is adjusted with ◄/►; Enter on it does nothing.
        ITEM_VOLUME => {}
        // Toggle each diagnostic and stay open so the new state shows on the row.
        ITEM_TRACE => crate::kernel::startup::toggle_trace(),
        ITEM_PROFILE => crate::kernel::startup::toggle_profile(),
        ITEM_DUMP => {
            crate::kernel::startup::dump_interrupted_thread(machine, regs, dos);
            close();
        }
        _ => {}
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
const CELL_W: usize = vga_render::OVERLAY_CELL_W;
const CELL_H: usize = vga_render::OVERLAY_CELL_H;

/// Composite the panel onto a finished frame. `out` is pitched by `stride`,
/// with `w`×`h` visible pixels in `fmt` (native for the hosted `present_fb`,
/// `fb.format` for the GOP framebuffer). A no-op if the frame can't hold it.
pub fn paint(out: &mut [u32], stride: usize, w: usize, h: usize, fmt: PixelFormat) {
    if PICKER.load(Ordering::Relaxed) {
        paint_picker(out, stride, w, h, fmt);
        return;
    }
    // Title + 6 items + footer = 8 rows.
    let rows = NUM_ITEMS + 2;
    let panel_w = COLS * CELL_W + PAD * 2;
    let panel_h = rows * CELL_H + PAD * 2;
    if w < panel_w || h < panel_h {
        return;
    }
    let x0 = (w - panel_w) / 2;
    let y0 = (h - panel_h) / 2;

    vga_render::overlay_fill(out, stride, w, h, x0, y0, panel_w, panel_h, PANEL_BG, fmt);
    vga_render::overlay_fill(out, stride, w, h, x0, y0, panel_w, CELL_H + PAD, TITLE_BG, fmt);

    let tx = x0 + PAD;
    let mut ty = y0 + PAD;
    vga_render::overlay_text(out, stride, w, h, tx, ty, b"RetroOS Monitor", TITLE_FG, TITLE_BG, fmt);
    ty += CELL_H;

    let sel = SEL.load(Ordering::Relaxed);
    for item in 0..NUM_ITEMS {
        let mut line = Line::new();
        item_line(item, &mut line);
        let selected = item == sel;
        if selected {
            vga_render::overlay_fill(out, stride, w, h, x0 + PAD / 2, ty, panel_w - PAD, CELL_H, SEL_BG, fmt);
        }
        let (fg, bg) = if selected { (SEL_FG, SEL_BG) } else { (ITEM_FG, PANEL_BG) };
        vga_render::overlay_text(out, stride, w, h, tx, ty, line.as_bytes(), fg, bg, fmt);
        ty += CELL_H;
    }

    vga_render::overlay_text(out, stride, w, h, tx, ty, b"Up/Dn  Enter  <> vol  Esc", FOOT_FG, PANEL_BG, fmt);
}

/// Paint the Switch picker: one row per active task, `tid: name  S *`.
fn paint_picker(out: &mut [u32], stride: usize, w: usize, h: usize, fmt: PixelFormat) {
    let count = PROC_COUNT.load(Ordering::Relaxed);
    let rows = count.max(1) + 2; // title + list (≥1 line) + footer
    let panel_w = COLS * CELL_W + PAD * 2;
    let panel_h = rows * CELL_H + PAD * 2;
    if w < panel_w || h < panel_h {
        return;
    }
    let x0 = (w - panel_w) / 2;
    let y0 = (h - panel_h) / 2;

    vga_render::overlay_fill(out, stride, w, h, x0, y0, panel_w, panel_h, PANEL_BG, fmt);
    vga_render::overlay_fill(out, stride, w, h, x0, y0, panel_w, CELL_H + PAD, TITLE_BG, fmt);

    let tx = x0 + PAD;
    let mut ty = y0 + PAD;
    vga_render::overlay_text(out, stride, w, h, tx, ty, b"Switch to task", TITLE_FG, TITLE_BG, fmt);
    ty += CELL_H;

    let sel = PICK_SEL.load(Ordering::Relaxed);
    if count == 0 {
        vga_render::overlay_text(out, stride, w, h, tx, ty, b"(no tasks)", ITEM_FG, PANEL_BG, fmt);
        ty += CELL_H;
    } else {
        for idx in 0..count {
            let mut line = Line::new();
            proc_line(idx, &mut line);
            let selected = idx == sel;
            if selected {
                vga_render::overlay_fill(out, stride, w, h, x0 + PAD / 2, ty, panel_w - PAD, CELL_H, SEL_BG, fmt);
            }
            let (fg, bg) = if selected { (SEL_FG, SEL_BG) } else { (ITEM_FG, PANEL_BG) };
            vga_render::overlay_text(out, stride, w, h, tx, ty, line.as_bytes(), fg, bg, fmt);
            ty += CELL_H;
        }
    }

    vga_render::overlay_text(out, stride, w, h, tx, ty, b"Up/Dn  Enter  Esc back", FOOT_FG, PANEL_BG, fmt);
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

/// Compose one menu row's text into `line`. Volume, Trace and Profile are dynamic.
fn item_line(item: usize, line: &mut Line) {
    match item {
        ITEM_KILL => line.put(b"Kill task"),
        ITEM_SWITCH => line.put(b"Switch task"),
        ITEM_VOLUME => {
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
        ITEM_TRACE => {
            line.put(b"Trace    ");
            line.put(if crate::kernel::startup::trace_enabled() { b"ON" } else { b"off" });
        }
        ITEM_PROFILE => {
            line.put(b"Profile  ");
            line.put(if crate::kernel::startup::profile_enabled() { b"ON" } else { b"off" });
        }
        ITEM_DUMP => line.put(b"Dump state"),
        _ => {}
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
    fn as_bytes(&self) -> &[u8] {
        &self.buf[..self.len]
    }
}
