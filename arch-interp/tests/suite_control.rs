//! Standalone clock/gate proof: no emulator or guest assets required.
#[path = "../src/suite_control.rs"]
mod suite_control;
mod screendump {
    pub fn request() {}
    pub fn maybe_dump() {}
}

#[test]
fn guest_time_stops_at_the_gate_and_remains_monotonic_when_speed_changes() {
    use std::sync::{Arc, atomic::{AtomicBool, Ordering}};
    suite_control::enable();
    let stopped = Arc::new(AtomicBool::new(false));
    let cpu_stopped = stopped.clone();
    let cpu = std::thread::spawn(move || {
        while !cpu_stopped.load(Ordering::Relaxed) {
            suite_control::gate();
            if !cpu_stopped.load(Ordering::Relaxed) {
                suite_control::advance(300);
            }
        }
    });
    suite_control::wait_paused();
    assert_eq!(suite_control::now(), 0);
    suite_control::cycles(300);
    suite_control::run(10);
    assert_eq!(suite_control::now(), 10_000_000);
    suite_control::snapshot();
    assert_eq!(suite_control::now(), 10_000_000, "capture must not advance guest time");
    suite_control::cycles(600);
    suite_control::run(10);
    assert_eq!(suite_control::now(), 20_000_000, "speed changes must not rescale elapsed time");
    assert!(suite_control::set_cpu_model("486"));
    assert_eq!(suite_control::cpu_model(), Some(7));
    assert!(suite_control::set_cpu_model("pentium"));
    assert_eq!(suite_control::cpu_model(), Some(8));
    assert!(!suite_control::set_cpu_model("386"));
    stopped.store(true, Ordering::Relaxed);
    suite_control::disable();
    cpu.join().unwrap();
}
