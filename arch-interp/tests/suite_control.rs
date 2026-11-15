//! Standalone gate proof: execution pauses, the host clock keeps advancing.
#[path = "../src/suite_control.rs"]
mod suite_control;
mod screendump {
    pub fn request() {}
    pub fn maybe_dump() {}
}

mod machine {
    pub fn now() -> u64 {
        static EPOCH: std::sync::OnceLock<std::time::Instant> = std::sync::OnceLock::new();
        EPOCH.get_or_init(std::time::Instant::now).elapsed().as_nanos() as u64
    }
}

#[test]
fn gate_pauses_execution_without_stopping_or_rescaling_host_time() {
    use std::sync::{Arc, atomic::{AtomicBool, Ordering}};
    suite_control::enable();
    let stopped = Arc::new(AtomicBool::new(false));
    let cpu_stopped = stopped.clone();
    let cpu = std::thread::spawn(move || {
        while !cpu_stopped.load(Ordering::Relaxed) {
            suite_control::gate();

        }
    });
    suite_control::wait_paused();
    let start = suite_control::now();
    suite_control::run(10);
    assert!(suite_control::now() >= start + 10_000_000);
    suite_control::snapshot();
    let paused = suite_control::now();
    std::thread::sleep(std::time::Duration::from_millis(2));
    assert!(suite_control::now() >= paused + 2_000_000, "host clock continues while execution is paused");
    let start = suite_control::now();
    suite_control::run(10);
    assert!(suite_control::now() >= start + 10_000_000);
    assert!(suite_control::set_cpu_model("486"));
    assert_eq!(suite_control::cpu_model(), Some(7));
    assert!(suite_control::set_cpu_model("pentium"));
    assert_eq!(suite_control::cpu_model(), Some(8));
    assert!(!suite_control::set_cpu_model("386"));
    stopped.store(true, Ordering::Relaxed);
    suite_control::disable();
    cpu.join().unwrap();
}
