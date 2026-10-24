use std::cell::{Cell, UnsafeCell};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Barrier, Mutex};

thread_local! {
    static LINE: UnsafeCell<lib::log::LineBuffer> = const { UnsafeCell::new(lib::log::LineBuffer::new()) };
    static CORE: Cell<u32> = const { Cell::new(0) };
}
static OUTPUT: Mutex<Vec<u8>> = Mutex::new(Vec::new());
static CALLBACK: AtomicBool = AtomicBool::new(false);
fn context() -> *mut lib::log::LineBuffer {
    LINE.with(|line| line.get())
}
fn core_id() -> u32 {
    CORE.with(Cell::get)
}
fn sink(byte: u8) {
    OUTPUT.lock().unwrap().push(byte);
}
fn callback() {
    if !CALLBACK.swap(true, Ordering::Relaxed) {
        lib::compact_println!("callback");
    }
}

#[test]
fn concurrent_lines_readers_and_early_buffer_promotion() {
    unsafe {
        lib::log::set_line_context(context);
    }
    lib::log::set_core_id_source(core_id);
    lib::log::set_debug_sink(sink);
    lib::log::set_line_sink(callback);
    klog::init(Box::leak(vec![0; 8192].into_boxed_slice()));
    lib::compact_println!("early");
    klog::init(Box::leak(vec![0; 1024 * 1024].into_boxed_slice()));
    let barrier = Arc::new(Barrier::new(9));
    let finished = Arc::new(AtomicBool::new(false));
    let read_done = finished.clone();
    let reader = std::thread::spawn(move || {
        let mut bytes = vec![0; 1024 * 1024];
        while !read_done.load(Ordering::Acquire) {
            let (_, count) = klog::read_since(0, &mut bytes);
            assert!(count == 0 || bytes[count - 1] == b'\n');
            let text = std::str::from_utf8(&bytes[..count]).unwrap();
            assert!(text.lines().all(|line| line.starts_with("core ")));
            std::thread::yield_now();
        }
    });
    let mut writers = Vec::new();
    for id in 1..=8u32 {
        let barrier = barrier.clone();
        writers.push(std::thread::spawn(move || {
            CORE.with(|core| core.set(id));
            barrier.wait();
            for sequence in 0..200u32 {
                lib::print!("writer {} ", id);
                std::thread::yield_now();
                lib::compact_println!("sequence {}", sequence);
            }
        }));
    }
    barrier.wait();
    for writer in writers {
        writer.join().unwrap();
    }
    finished.store(true, Ordering::Release);
    reader.join().unwrap();
    let output = OUTPUT.lock().unwrap().clone();
    let mut retained = vec![0; output.len()];
    assert_eq!(klog::read(0, &mut retained), output.len());
    assert_eq!(retained, output);
    let text = std::str::from_utf8(&output).unwrap();
    assert!(text.starts_with("core 0: early\ncore 0: callback\n"));
    assert_eq!(text.lines().count(), 1602);
    for id in 1..=8 {
        for sequence in 0..200 {
            let expected = format!("core {id}: writer {id} sequence {sequence}");
            assert_eq!(text.lines().filter(|line| *line == expected).count(), 1);
        }
    }
    // Oversized records are bounded and explicitly marked, never split/interleaved.
    let long_line = "x".repeat(700);
    lib::compact_println!("{}", long_line.as_str());
    let output = OUTPUT.lock().unwrap();
    let last = output.split_inclusive(|&b| b == b'\n').last().unwrap();
    assert_eq!(last.len(), 513);
    assert!(last.starts_with(b"core 0: ") && last.ends_with(b"...\n"));
}
