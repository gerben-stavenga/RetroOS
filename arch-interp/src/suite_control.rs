//! Opt-in synchronous control for game regression tests. Ordinary hosted
//! execution never takes the gate or changes its clock.
use std::sync::{Condvar, Mutex};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::atomic::AtomicI32;

static ENABLED: AtomicBool = AtomicBool::new(false);
static TIME: AtomicU64 = AtomicU64::new(0);
static SPEED: AtomicU64 = AtomicU64::new(6000);
static CPU_MODEL: AtomicI32 = AtomicI32::new(-1);
pub fn set_cpu_model(name: &str) -> bool {
    // Values of Unicorn 2.1's X86CpuModel::{Model_486, PENTIUM}. Keeping
    // this control module independent of Unicorn lets KVM reject the mode
    // cleanly and allows the standalone gate test to compile without a CPU.
    let value = match name { "486" => 7, "pentium" => 8, _ => return false };
    CPU_MODEL.store(value, Ordering::Relaxed);
    true
}
#[cfg(feature = "tcg")]
pub(crate) fn cpu_model() -> Option<i32> {
    let model = CPU_MODEL.load(Ordering::Relaxed);
    (model >= 0).then_some(model)
}
static CLOCK_REMAINDER: Mutex<u64> = Mutex::new(0);
struct State { until: u64, paused: bool, snapshot: bool }
static STATE: Mutex<State> = Mutex::new(State { until: 0, paused: false, snapshot: false });
static CHANGED: Condvar = Condvar::new();

pub fn enable() {
    if !cfg!(feature = "tcg") {
        eprintln!("--suite-control requires the TCG engine (retired-instruction clock)");
        std::process::exit(2);
    }
    ENABLED.store(true, Ordering::SeqCst);
}
pub fn enabled() -> bool { ENABLED.load(Ordering::Relaxed) }
/// Release a stopped CPU when the controller disconnects.
pub fn disable() {
    ENABLED.store(false, Ordering::Relaxed);
    let mut state = STATE.lock().unwrap();
    state.until = u64::MAX;
    CHANGED.notify_all();
}
pub fn now() -> u64 { TIME.load(Ordering::Relaxed) }
pub fn cycles(value: u64) {
    assert!(value > 0);
    SPEED.store(value, Ordering::Relaxed);
    *CLOCK_REMAINDER.lock().unwrap() = 0;
}
pub fn advance(instructions: u64) {
    if !enabled() { return; }
    let speed = SPEED.load(Ordering::Relaxed);
    let mut remainder = CLOCK_REMAINDER.lock().unwrap();
    let numerator = u128::from(instructions) * 1_000_000 + u128::from(*remainder);
    TIME.fetch_add((numerator / u128::from(speed)) as u64, Ordering::Relaxed);
    *remainder = (numerator % u128::from(speed)) as u64;
}
/// Called on the CPU thread between kernel event-loop iterations.
pub fn gate() {
    if !enabled() { return; }
    let mut state = STATE.lock().unwrap();
    while now() >= state.until {
        if state.snapshot {
            drop(state);
            crate::screendump::request();
            crate::screendump::maybe_dump();
            state = STATE.lock().unwrap();
            state.snapshot = false;
        }
        state.paused = true;
        CHANGED.notify_all();
        state = CHANGED.wait(state).unwrap();
    }
    state.paused = false;
}
pub fn snapshot() {
    let mut state = STATE.lock().unwrap();
    while !state.paused { state = CHANGED.wait(state).unwrap(); }
    state.snapshot = true;
    CHANGED.notify_all();
    while state.snapshot { state = CHANGED.wait(state).unwrap(); }
}
pub fn wait_paused() {
    let mut state = STATE.lock().unwrap();
    while !state.paused { state = CHANGED.wait(state).unwrap(); }
}
/// Run from a stopped frontier and wait for the next stopped frontier.
pub fn run(milliseconds: u64) {
    if milliseconds == 0 { wait_paused(); return; }
    let mut state = STATE.lock().unwrap();
    while !state.paused { state = CHANGED.wait(state).unwrap(); }
    state.until = now().saturating_add(milliseconds.saturating_mul(1_000_000));
    state.paused = false;
    CHANGED.notify_all();
    while !state.paused { state = CHANGED.wait(state).unwrap(); }
}
