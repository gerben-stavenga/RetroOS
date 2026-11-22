//! One media worker, shared by audio and graphics. The BSP remains the only
//! allocator and owner of guest mappings. Audio reads permanent ISA channel
//! buffers directly; graphics also operates on resident kernel storage.
//! Publishing storage refreshes the worker's kernel mappings and TLB.
//! Audio runs as an independent service, including at graphics checkpoints.

#![forbid(unsafe_code)]

use alloc::{boxed::Box, collections::VecDeque, sync::Arc};
use core::sync::atomic::{AtomicBool, Ordering};
use lib::worker_queue::WorkerQueue;

static GRAPHICS: WorkerQueue<Arc<dyn GraphicsJob>> = WorkerQueue::new();
static ENABLED: AtomicBool = AtomicBool::new(false);
#[thread_local]
static ON_WORKER: core::cell::Cell<bool> = const { core::cell::Cell::new(false) };
static REFRESH: spin::Once<fn()> = spin::Once::new();

fn refresh_mappings() { (REFRESH.get().expect("media worker not initialized"))(); }

pub fn enabled() -> bool {
    ENABLED.load(Ordering::Acquire)
}

/// Start exactly one consumer, after platform initialization. Never returns.
///
/// `refresh` synchronizes kernel
/// mappings and invalidate translations before accessing handed-off storage;
/// it may be empty when the host OS maintains shared process mappings.
pub fn worker(refresh: fn()) -> ! {
    ON_WORKER.set(true);
    let mut started = false;
    REFRESH.call_once(|| { started = true; refresh });
    assert!(started, "media worker already initialized");
    ENABLED.store(true, Ordering::Release);
    loop {
        audio_checkpoint();
        video_checkpoint();
        device_checkpoint();
        if !GRAPHICS.poll(refresh_mappings, |job| job.run()) {
            core::hint::spin_loop();
        }
    }
}

/// Graphics callbacks invoke this between bounded row batches. Worker only.
/// Inline fallback never consumes the worker mailbox.
fn audio_checkpoint() {
    if let Some(slot) = AUDIO_SERVICE.try_lock()
        && let Some(service) = slot.as_ref()
        && (service.due)()
    {
        refresh_mappings();
        (service.poll)();
    }
}

/// Join a graphics calculation borrowing resident source/destination buffers.
/// The callback works on resident kernel storage without allocating.
pub fn graphics<F: FnOnce() -> R + Send, R: Send>(function: F) -> R {
    if !enabled() || ON_WORKER.get() { function() }
    else { GRAPHICS.join(function) }
}

trait GraphicsJob: Send + Sync {
    fn run(&self);
}

struct State<T> {
    work: spin::Mutex<(T, Option<fn(&mut T)>)>,
}

impl<T: Send> GraphicsJob for State<T> {
    fn run(&self) {
        let mut work = self.work.lock();
        let run = work.1.take().expect("graphics job missing callback");
        run(&mut work.0);
    }
}

/// Stable, exclusively owned graphics state. Access and destruction join any
/// outstanding work; the mailbox owns a reference until the job completes.
pub struct Graphics<T: Send + 'static> {
    state: Arc<State<T>>,
}

impl<T: Send + 'static> Graphics<T> {
    pub fn new(value: T) -> Self {
        Self { state: Arc::new(State { work: spin::Mutex::new((value, None)) }) }
    }

    pub fn wait(&self) {
        while Arc::strong_count(&self.state) != 1 {
            core::hint::spin_loop();
        }
    }

    fn owned_state(&mut self) -> &mut (T, Option<fn(&mut T)>) {
        self.wait();
        Arc::get_mut(&mut self.state).expect("graphics state still shared").work.get_mut()
    }

    pub fn get_mut(&mut self) -> &mut T { &mut self.owned_state().0 }

    /// Hand the entire state to the graphics worker. Access and drop join it.
    /// The callback uses resident storage, runs without allocating, and can
    /// checkpoint audio between bounded batches.
    pub fn start(&mut self, run: fn(&mut T)) {
        if !enabled() {
            run(self.get_mut());
            return;
        }
        assert!(!ON_WORKER.get(), "the media worker cannot submit graphics to itself");
        self.owned_state().1 = Some(run);
        GRAPHICS.send(self.state.clone());
    }
}

impl<T: Send + 'static> Drop for Graphics<T> {
    fn drop(&mut self) { self.wait(); }
}

/// A checkpoint installed in graphics libraries. Inline execution has no
/// competing worker and therefore nothing to service.
pub fn checkpoint() {
    if ON_WORKER.get() {
        audio_checkpoint();
    }
}

/// Kernel-context ownership lock. Interrupt handlers must not acquire it.
/// The media core never allocates while holding this lock.
pub struct Shared<T>(spin::Mutex<T>);
pub type Guard<'a, T> = spin::MutexGuard<'a, T>;

impl<T> Shared<T> {
    pub const fn new(value: T) -> Self { Self(spin::Mutex::new(value)) }
    pub fn with<R>(&self, read: impl FnOnce(&T) -> R) -> R { read(&self.lock()) }
    pub fn lock(&self) -> Guard<'_, T> { self.0.lock() }
    pub fn try_lock(&self) -> Option<Guard<'_, T>> { self.0.try_lock() }
}

// Registration is held while polling. Unregistering therefore also joins the
// last poll, before the owning core can release the service's storage.
struct AudioPoll {
    due: fn() -> bool,
    poll: Box<dyn Fn() + Send + Sync>,
}
static AUDIO_SERVICE: Shared<Option<AudioPoll>> = Shared::new(None);

/// One independently polled audio service. Register and retire it on the BSP.
/// The callback runs on the media core without allocating. The deadline check
/// reads permanent storage before the worker refreshes its mappings.
pub struct AudioService<T: Send + 'static> {
    state: Arc<Shared<T>>,
    registered: bool,
}

impl<T: Send + 'static> AudioService<T> {
    pub fn new(value: T, due: fn() -> bool, poll: fn(&mut T)) -> Self {
        let state = Arc::new(Shared::new(value));
        let registered = enabled();
        if registered {
            let mut slot = AUDIO_SERVICE.lock();
            assert!(slot.is_none(), "only one audio service may own the sink");
            let shared = state.clone();
            *slot = Some(AudioPoll {
                due,
                poll: Box::new(move || {
                    if let Some(mut state) = shared.try_lock() { poll(&mut state); }
                }),
            });
        }
        Self { state, registered }
    }

    pub fn lock(&self) -> Guard<'_, T> { self.state.lock() }
    pub fn try_lock(&self) -> Option<Guard<'_, T>> { self.state.try_lock() }
}

impl<T: Send + 'static> Drop for AudioService<T> {
    fn drop(&mut self) {
        if self.registered {
            let old = AUDIO_SERVICE.lock().take();
            drop(old);
        }
    }
}

struct VideoPoll {
    state: Arc<dyn VideoJob>,
    owner: usize,
    due: fn() -> bool,
    deadline: fn(u64) -> u64,
}
static VIDEO_SERVICE: Shared<Option<VideoPoll>> = Shared::new(None);
static VIDEO_OWNER: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);

/// Resident display state. The active display is polled independently of the
/// guest loop. Inactive displays retain their storage until their owner drops.
pub struct VideoService<T: Send + 'static> {
    state: Arc<VideoState<T>>,
    due: fn() -> bool,
    deadline: fn(u64) -> u64,
}

trait VideoJob: Send + Sync {
    fn render(&self);
}

struct VideoState<T> {
    value: Shared<T>,
    publication_pending: AtomicBool,
    poll: fn(&mut T),
}

impl<T: Send> VideoJob for VideoState<T> {
    fn render(&self) {
        if self.publication_pending.load(Ordering::Acquire) { return; }
        if let Some(mut state) = self.value.try_lock() { (self.poll)(&mut state); }
    }
}

impl<T: Send + 'static> VideoService<T> {
    /// The callback uses resident storage and runs without allocating.
    /// The deadline check reads permanent boot storage.
    pub fn new(value: T, due: fn() -> bool, deadline: fn(u64) -> u64, poll: fn(&mut T)) -> Self {
        Self { state: Arc::new(VideoState {
            value: Shared::new(value), publication_pending: AtomicBool::new(false), poll,
        }), due, deadline }
    }

    pub fn try_lock(&self) -> Option<Guard<'_, T>> { self.state.value.try_lock() }

    /// Defer the next frame until the BSP retries a busy scene publication.
    /// The current frame may finish; the producer never waits for it.
    /// A failed attempt must be retried, or cancelled with `pause`.
    pub fn try_publish(&self) -> Option<Guard<'_, T>> {
        self.state.publication_pending.store(true, Ordering::Release);
        let guard = self.state.value.try_lock()?;
        self.state.publication_pending.store(false, Ordering::Release);
        Some(guard)
    }

    pub fn activate(&self) {
        let owner = Arc::as_ptr(&self.state) as usize;
        if VIDEO_OWNER.load(Ordering::Acquire) == owner {
            kernel_entry();
            return;
        }
        let mut slot = VIDEO_SERVICE.lock();
        let old = slot.replace(VideoPoll { state: self.state.clone(), owner, due: self.due, deadline: self.deadline });
        VIDEO_OWNER.store(owner, Ordering::Release);
        drop(slot);
        drop(old);
        kernel_entry();
    }

    /// Fence scanout before changing the physical mode or releasing mappings.
    pub fn pause(&self) {
        let owner = Arc::as_ptr(&self.state) as usize;
        let mut slot = VIDEO_SERVICE.lock();
        let old = if slot.as_ref().is_some_and(|slot| slot.owner == owner) {
            VIDEO_OWNER.store(0, Ordering::Release);
            slot.take()
        } else { None };
        self.state.publication_pending.store(false, Ordering::Release);
        drop(slot);
        drop(old);
    }
}

impl<T: Send + 'static> Drop for VideoService<T> {
    fn drop(&mut self) { self.pause(); }
}

/// The synchronous driver consumes precisely the same device phases as the
/// media worker. Call before dispatching a guest event that can change VGA.
pub(crate) fn kernel_entry() {
    if !enabled() { video_checkpoint(); }
}

/// Without a media core, scanout owns a logical alarm just like other devices.
/// Native instruction shortcuts need no renderer checks or special exits.
pub(crate) fn inline_video_deadline(now: u64) -> Option<u64> {
    if enabled() { return None; }
    VIDEO_SERVICE.lock().as_ref().map(|service| (service.deadline)(now))
}
fn video_checkpoint() {
    if let Some(slot) = VIDEO_SERVICE.try_lock()
        && let Some(service) = slot.as_ref()
        && (service.due)()
    {
        if enabled() { refresh_mappings(); }
        service.state.render();
    }
}

/// Persistent devices are polled independently of guest exits and display
/// refresh. Registration changes fence callbacks; only the BSP allocates.
trait DeviceJob: Send + Sync {
    fn ready(&self) -> bool;
    fn poll(&self);
}

struct DevicePoll {
    state: Arc<dyn DeviceJob>,
    owner: usize,
}
static DEVICES: Shared<alloc::vec::Vec<DevicePoll>> = Shared::new(alloc::vec::Vec::new());
static DEVICE_REVISION: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);

struct DeviceState<T> { value: T, ready: fn(&T) -> bool, poll: fn(&T) }

impl<T: Send + Sync> DeviceJob for DeviceState<T> {
    fn ready(&self) -> bool { (self.ready)(&self.value) }
    fn poll(&self) { (self.poll)(&self.value); }
}

pub struct DeviceService<T: Send + Sync + 'static> {
    state: Arc<DeviceState<T>>,
    registered: bool,
}

impl<T: Send + Sync + 'static> DeviceService<T> {
    /// Readiness uses resident storage. Polling is bounded, allocation-free
    /// work and does not register or recursively poll other services.
    pub fn new(value: T, ready: fn(&T) -> bool, poll: fn(&T)) -> Self {
        let state = Arc::new(DeviceState { value, ready, poll });
        let registered = enabled();
        if registered {
            let mut devices = DEVICES.lock();
            devices.push(DevicePoll { state: state.clone(), owner: Arc::as_ptr(&state) as usize });
            DEVICE_REVISION.fetch_add(1, Ordering::Release);
        }
        Self { state, registered }
    }

    pub fn poll_inline(&self) {
        if !self.registered && self.state.ready() { self.state.poll(); }
    }
}

impl<T: Send + Sync + 'static> Drop for DeviceService<T> {
    fn drop(&mut self) {
        if self.registered {
            let owner = Arc::as_ptr(&self.state) as usize;
            DEVICES.lock().retain(|device| device.owner != owner);
            DEVICE_REVISION.fetch_add(1, Ordering::Release);
        }
    }
}

fn device_checkpoint() {
    // Refresh before dereferencing newly registered heap storage.
    static SEEN: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);
    let Some(devices) = DEVICES.try_lock() else { return };
    let revision = DEVICE_REVISION.load(Ordering::Acquire);
    if SEEN.load(Ordering::Relaxed) != revision {
        refresh_mappings();
        SEEN.store(revision, Ordering::Relaxed);
    }
    for device in devices.iter() {
        if device.state.ready() {
            refresh_mappings();
            device.state.poll();
        }
    }
}

/// Fixed-capacity command ring. Storage is committed on construction.
/// The lock only protects queue metadata and a single command transfer.
pub struct Commands<T, const N: usize> {
    queue: spin::Mutex<VecDeque<T>>,
    pending: AtomicBool,
}

impl<T, const N: usize> Commands<T, N> {
    pub fn new() -> Self {
        assert!(N != 0);
        Self {
            queue: spin::Mutex::new(VecDeque::with_capacity(N)),
            pending: AtomicBool::new(false),
        }
    }

    pub fn pending(&self) -> bool { self.pending.load(Ordering::Acquire) }

    pub fn push(&self, command: T) -> bool {
        let mut queue = self.queue.lock();
        if queue.len() == N { return false; }
        queue.push_back(command);
        self.pending.store(true, Ordering::Release);
        true
    }

    pub fn pop(&self) -> Option<T> {
        let mut queue = self.queue.lock();
        let next = queue.pop_front();
        if queue.is_empty() { self.pending.store(false, Ordering::Release); }
        next
    }
}

#[cfg(test)]
#[test]
fn inline_video_entries_do_not_require_a_worker_refresh_callback() {
    assert!(!enabled());
    assert!(REFRESH.get().is_none());
    assert_eq!(inline_video_deadline(100), None);
    let service = VideoService::new(0usize, || true, |now| now + 123, |calls| *calls += 1);
    service.activate();
    assert_eq!(inline_video_deadline(100), Some(223));
    kernel_entry();
    assert_eq!(*service.try_lock().unwrap(), 2);
    service.pause();
    assert_eq!(inline_video_deadline(100), None);
    kernel_entry();
    assert_eq!(*service.try_lock().unwrap(), 2);
    service.activate();
    assert_eq!(*service.try_lock().unwrap(), 3);
}
