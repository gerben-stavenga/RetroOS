#![feature(thread_local)]
extern crate alloc;
#[path = "../src/kernel/media.rs"]
pub(crate) mod media;
mod kernel {
    pub(crate) use super::media;
}
#[allow(dead_code)]
#[path = "../src/kernel/dos/machine/vvoodoo.rs"]
mod vvoodoo;

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
static GRAPHICS_STARTED: AtomicBool = AtomicBool::new(false);
static AUDIO_RAN: AtomicBool = AtomicBool::new(false);
static REFRESHES: AtomicUsize = AtomicUsize::new(0);
static WORKER_ALLOCATIONS: AtomicUsize = AtomicUsize::new(0);
std::thread_local! { static ON_WORKER: std::cell::Cell<bool> = const { std::cell::Cell::new(false) }; }
struct AuditedAllocator;
unsafe impl std::alloc::GlobalAlloc for AuditedAllocator {
    unsafe fn alloc(&self, layout: std::alloc::Layout) -> *mut u8 {
        if ON_WORKER.try_with(|flag| flag.get()).unwrap_or(false) {
            WORKER_ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
        }
        unsafe { std::alloc::System.alloc(layout) }
    }
    unsafe fn dealloc(&self, pointer: *mut u8, layout: std::alloc::Layout) {
        if ON_WORKER.try_with(|flag| flag.get()).unwrap_or(false) {
            WORKER_ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
        }
        unsafe {
            std::alloc::System.dealloc(pointer, layout);
        }
    }
}
#[global_allocator]
static ALLOCATOR: AuditedAllocator = AuditedAllocator;

fn voodoo_frame() -> Vec<u8> {
    use voodoo::regs::*;
    let mut card = vvoodoo::VVoodoo::new();
    card.config_write(0x40, 1);
    let write = |card: &mut vvoodoo::VVoodoo, reg: usize, data: u32| {
        for (i, byte) in data.to_le_bytes().into_iter().enumerate() {
            card.write8((reg * 4 + i) as u32, byte);
        }
    };
    // More than two complete command-ring wraps, followed by the checked
    // framebuffer operation below. All register writes must retain order.
    for value in 0..600 { write(&mut card, color1, value); }
    for (reg, value) in [
        (fbiInit1, 10 << 4),
        (fbiInit2, 150 << 11),
        (hSync, 1),
        (vSync, 1),
        (videoDimensions, (479 << 16) | 639),
        (clipLeftRight, 640),
        (clipLowYHighY, 480),
        (color1, 0xf8fc08),
        (fbzMode, (1 << 9) | (1 << 14)),
        (fastfillCMD, 0),
        (swapbufferCMD, 0),
    ] {
        write(&mut card, reg, value);
    }
    // Stop submitting work. The device service must reach the final mode
    // without any guest tick, scanout call, fence, or graphics-job kick.
    let output = card.output();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while output.dimensions() != (640, 480) {
        assert!(std::time::Instant::now() < deadline, "Voodoo needs a producer kick");
        std::thread::yield_now();
    }
    // Read-after-render and swap must fence the preceding asynchronous clear.
    let _ = card.read8(0);
    let mut pixels = vec![0; 640 * 480 * 4];
    card.scanout(&mut pixels, 640 * 4, &voodoo::Dac::native());
    assert!(pixels.iter().any(|&pixel| pixel != 0));
    pixels
}

#[test]
fn two_core_priority_handoff_and_drop_fences() {
    // No AP: identical jobs execute inline.

    let mut inline = media::Graphics::new(3usize);
    unsafe {
        inline.start(|value| *value *= 2);
    }
    assert_eq!(*inline.get(), 6);
    let expected_pixels = voodoo_frame();

    std::thread::spawn(|| {
        ON_WORKER.with(|flag| flag.set(true));
        unsafe {
            media::worker(|| {
                REFRESHES.fetch_add(1, Ordering::Relaxed);
            })
        }
    });
    while !media::enabled() {
        std::thread::yield_now();
    }
    let mut drawing = media::Graphics::new(0usize);
    unsafe {
        drawing.start(|value| {
            GRAPHICS_STARTED.store(true, Ordering::Release);
            while !AUDIO_RAN.load(Ordering::Acquire) {
                media::checkpoint();
            }
            *value = 42;
        });
    }
    while !GRAPHICS_STARTED.load(Ordering::Acquire) {
        std::thread::yield_now();
    }
    // Queue another graphics command while the first is running. Audio must
    // still run INSIDE the first command, not behind either graphics job.
    let mut queued = media::Graphics::new(0usize);
    unsafe {
        queued.start(|value| *value = 91);
    }
    static POLLS: AtomicUsize = AtomicUsize::new(0);
    static DUE: AtomicBool = AtomicBool::new(false);
    static HOLD_AUDIO: AtomicBool = AtomicBool::new(false);
    static AUDIO_HELD: AtomicBool = AtomicBool::new(false);
    let service = unsafe { media::AudioService::new((), || DUE.load(Ordering::Acquire), |_| {
        POLLS.fetch_add(1, Ordering::Relaxed);
        AUDIO_RAN.store(true, Ordering::Release);
        if HOLD_AUDIO.load(Ordering::Acquire) {
            AUDIO_HELD.store(true, Ordering::Release);
            while HOLD_AUDIO.load(Ordering::Acquire) { core::hint::spin_loop(); }
        }
    }) };
    let refreshes = REFRESHES.load(Ordering::Acquire);
    for _ in 0..100 { std::thread::yield_now(); }
    assert_eq!(POLLS.load(Ordering::Acquire), 0);
    assert_eq!(REFRESHES.load(Ordering::Acquire), refreshes,
        "an audio checkpoint before the deadline must not refresh mappings");
    DUE.store(true, Ordering::Release);
    // No mix submission or guest tick is required: the service continues to
    // run while the producer does unrelated work.
    while POLLS.load(Ordering::Acquire) < 100 { std::thread::yield_now(); }
    static BLOCKED: AtomicBool = AtomicBool::new(false);
    static RELEASE: AtomicBool = AtomicBool::new(false);
    let mut blocker = media::Graphics::new(());
    unsafe { blocker.start(|_| {
        BLOCKED.store(true, Ordering::Release);
        while !RELEASE.load(Ordering::Acquire) { core::hint::spin_loop(); }
    }); }
    while !BLOCKED.load(Ordering::Acquire) { std::thread::yield_now(); }
    let before = POLLS.load(Ordering::Acquire);
    for _ in 0..100 { media::checkpoint(); }
    assert_eq!(POLLS.load(Ordering::Acquire), before, "core 0 must not execute audio checkpoints");
    RELEASE.store(true, Ordering::Release);
    blocker.wait();
    HOLD_AUDIO.store(true, Ordering::Release);
    while !AUDIO_HELD.load(Ordering::Acquire) { std::thread::yield_now(); }
    assert!(service.try_lock().is_none(), "UI status must not wait for the mixer");
    HOLD_AUDIO.store(false, Ordering::Release);

    // A video read deferred by the guest must not strand that guest while
    // the next worker pass starts an unrelated audio mix.
    DUE.store(false, Ordering::Release);
    unsafe { media::graphics(|| ()); }
    AUDIO_HELD.store(false, Ordering::Release);
    HOLD_AUDIO.store(true, Ordering::Release);
    static SAMPLE_REQUESTED: AtomicBool = AtomicBool::new(false);
    media::GUEST_MEMORY.enter();
    let pending_video = unsafe { media::VideoService::new((),
        || !SAMPLE_REQUESTED.load(Ordering::Acquire), |_| {
            assert!(media::GUEST_MEMORY.try_read().is_none());
            SAMPLE_REQUESTED.store(true, Ordering::Release);
            DUE.store(true, Ordering::Release);
        }) };
    pending_video.activate();
    while !AUDIO_HELD.load(Ordering::Acquire) { std::thread::yield_now(); }
    media::GUEST_MEMORY.leave();
    let guest_released = std::sync::Arc::new(AtomicBool::new(false));
    let released = guest_released.clone();
    let guest = std::thread::spawn(move || {
        media::GUEST_MEMORY.yield_to_reader();
        released.store(true, Ordering::Release);
    });
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(1);
    while !guest_released.load(Ordering::Acquire) && std::time::Instant::now() < deadline {
        std::thread::yield_now();
    }
    let released_during_mix = guest_released.load(Ordering::Acquire);
    HOLD_AUDIO.store(false, Ordering::Release);
    guest.join().unwrap();
    drop(pending_video);
    assert!(released_during_mix, "guest waited for audio after a deferred video sample");
    drop(service);
    let stopped = POLLS.load(Ordering::Acquire);
    for _ in 0..100 { std::thread::yield_now(); }
    assert_eq!(POLLS.load(Ordering::Acquire), stopped);
    // Once the guest yields for a deferred audio read, keep that offer until
    // the reader actually acquires memory, including across worker retries.
    static READ_DUE: AtomicBool = AtomicBool::new(true);
    static ATTEMPTS: AtomicUsize = AtomicUsize::new(0);
    static RETRY_STARTED: AtomicBool = AtomicBool::new(false);
    static ALLOW_READ: AtomicBool = AtomicBool::new(false);
    static COPIED: AtomicBool = AtomicBool::new(false);
    media::GUEST_MEMORY.enter();
    let reader = unsafe { media::AudioService::new((), || READ_DUE.load(Ordering::Acquire), |_| {
        if ATTEMPTS.fetch_add(1, Ordering::Relaxed) == 0 {
            assert!(media::GUEST_MEMORY.try_read().is_none());
            return;
        }
        RETRY_STARTED.store(true, Ordering::Release);
        while !ALLOW_READ.load(Ordering::Acquire) { core::hint::spin_loop(); }
        let _read = media::GUEST_MEMORY.try_read().expect("guest offered memory for audio");
        COPIED.store(true, Ordering::Release);
        READ_DUE.store(false, Ordering::Release);
    }) };
    while !RETRY_STARTED.load(Ordering::Acquire) { std::thread::yield_now(); }
    media::GUEST_MEMORY.leave();
    let resumed = std::sync::Arc::new(AtomicBool::new(false));
    let guest_resumed = resumed.clone();
    let guest = std::thread::spawn(move || {
        media::GUEST_MEMORY.yield_to_reader();
        guest_resumed.store(true, Ordering::Release);
    });
    std::thread::sleep(std::time::Duration::from_millis(50));
    let resumed_before_read = resumed.load(Ordering::Acquire);
    ALLOW_READ.store(true, Ordering::Release);
    guest.join().unwrap();
    drop(reader);
    assert!(!resumed_before_read, "audio cancelled its request before acquiring guest memory");
    assert!(COPIED.load(Ordering::Acquire));
    assert_eq!(*drawing.get(), 42);
    assert_eq!(*queued.get_mut(), 91);

    let mut pixels = vec![0usize; 4096];
    for sequence in 1..128 {
        let sum = unsafe {
            media::graphics(|| {
                pixels.fill(sequence);
                pixels.iter().sum::<usize>()
            })
        };
        assert_eq!(sum, sequence * pixels.len());
    }
    static DROPPED: AtomicBool = AtomicBool::new(false);
    struct DropCheck;
    impl Drop for DropCheck {
        fn drop(&mut self) {
            DROPPED.store(true, Ordering::Release);
        }
    }
    let mut last = media::Graphics::new(DropCheck);
    unsafe {
        last.start(|_| assert!(!DROPPED.load(Ordering::Acquire)));
    }
    drop(last);
    assert!(DROPPED.load(Ordering::Acquire));
    assert!(REFRESHES.load(Ordering::Relaxed) >= 131);
    assert_eq!(voodoo_frame(), expected_pixels);
    static VIDEO_TICKS: AtomicUsize = AtomicUsize::new(0);
    static HOLD_VIDEO: AtomicBool = AtomicBool::new(true);
    static VIDEO_STARTED: AtomicBool = AtomicBool::new(false);
    let old_video = unsafe { media::VideoService::new((), || true, |_| {
        VIDEO_STARTED.store(true, Ordering::Release);
        while HOLD_VIDEO.load(Ordering::Acquire) { media::checkpoint(); }
        VIDEO_TICKS.fetch_add(1, Ordering::Release);
    }) };
    old_video.activate();
    while !VIDEO_STARTED.load(Ordering::Acquire) { std::thread::yield_now(); }
    assert!(old_video.try_lock().is_none(), "publication must skip a running frame, never join it");
    assert!(old_video.try_publish().is_none(), "scene publication must not join the running frame");
    HOLD_VIDEO.store(false, Ordering::Release);
    // A completed graphics job proves the worker finished its previous frame
    // and returned through its poll loop. It must leave the next video turn
    // available to the deferred publisher instead of rendering repeatedly.
    unsafe { media::graphics(|| ()); }
    assert_eq!(VIDEO_TICKS.load(Ordering::Acquire), 1);
    let publication = old_video.try_publish().expect("deferred publisher gets the next turn");
    assert_eq!(VIDEO_TICKS.load(Ordering::Acquire), 1);
    drop(publication);
    while VIDEO_TICKS.load(Ordering::Acquire) < 10 { std::thread::yield_now(); }
    let video = unsafe { media::VideoService::new((), || true, |_| {
        VIDEO_TICKS.fetch_add(1, Ordering::Release);
    }) };
    video.activate();
    drop(old_video); // Retiring an old display must not unregister its successor.
    let before = VIDEO_TICKS.load(Ordering::Acquire);
    while VIDEO_TICKS.load(Ordering::Acquire) == before { std::thread::yield_now(); }
    video.pause();
    let stopped = VIDEO_TICKS.load(Ordering::Acquire);
    for _ in 0..100 { std::thread::yield_now(); }
    assert_eq!(VIDEO_TICKS.load(Ordering::Acquire), stopped);
    video.activate();
    while VIDEO_TICKS.load(Ordering::Acquire) == stopped { std::thread::yield_now(); }
    drop(video);
    assert_eq!(WORKER_ALLOCATIONS.load(Ordering::Relaxed), 0);
}
