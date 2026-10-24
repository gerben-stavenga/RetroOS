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
    assert_eq!(unsafe { media::audio(|| 17) }, 17);
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
    unsafe {
        media::audio(|| AUDIO_RAN.store(true, Ordering::Release));
    }
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
    assert_eq!(WORKER_ALLOCATIONS.load(Ordering::Relaxed), 0);
}
