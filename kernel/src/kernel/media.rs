//! One media worker, shared by audio and graphics. The BSP remains the only
//! allocator and owner of guest mappings. Guarded DMA reads borrow an arch
//! read view; jobs otherwise operate on resident kernel
//! buffers; an ownership handoff refreshes the worker's mappings and TLB.
//! Audio runs as an independent service, including at graphics checkpoints.

use alloc::boxed::Box;
use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicBool, Ordering};

#[derive(Clone, Copy)]
struct Command {
    run: unsafe fn(usize),
    argument: usize,
}
struct Mailbox {
    ready: AtomicBool,
    command: UnsafeCell<Option<Command>>,
}
// Single BSP producer, single worker consumer; Release/Acquire transfers the
// command. The consumer copies it before allowing the producer to reuse it.
unsafe impl Sync for Mailbox {}
impl Mailbox {
    const fn new() -> Self {
        Self {
            ready: AtomicBool::new(false),
            command: UnsafeCell::new(None),
        }
    }
    fn send(&self, command: Command) {
        while self.ready.load(Ordering::Acquire) {
            core::hint::spin_loop();
        }
        unsafe {
            *self.command.get() = Some(command);
        }
        self.ready.store(true, Ordering::Release);
    }
    fn take(&self) -> Option<Command> {
        if !self.ready.load(Ordering::Acquire) {
            return None;
        }
        let command = unsafe { (*self.command.get()).take() };
        self.ready.store(false, Ordering::Release);
        command
    }
}
static GRAPHICS: Mailbox = Mailbox::new();
static ENABLED: AtomicBool = AtomicBool::new(false);
#[thread_local]
static mut ON_WORKER: bool = false;
#[thread_local]
static mut IN_CHECKPOINT: bool = false;
#[thread_local]
static mut READ_DEFERRED: bool = false;
#[thread_local]
static mut AUDIO_READ_PENDING: bool = false;
static REFRESH: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);

/// Guest execution and brief media reads share this gate. The guest yields
/// only at an event-loop boundary, where it holds no service/device locks.
/// A failed media read requests that next boundary; it never waits inside a
/// callback. Reads release the handoff before rendering or mixing begins.
pub(crate) struct GuestMemoryGate {
    held: AtomicBool,
    requested: AtomicBool,
}
pub(crate) static GUEST_MEMORY: GuestMemoryGate = GuestMemoryGate::new();
impl GuestMemoryGate {
    const fn new() -> Self {
        Self { held: AtomicBool::new(false), requested: AtomicBool::new(false) }
    }
    pub(crate) fn enter(&self) {
        loop {
            while self.held.load(Ordering::Relaxed) { core::hint::spin_loop(); }
            if self.held.compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed).is_ok() { return; }
        }
    }
    pub(crate) fn leave(&self) { self.held.store(false, Ordering::Release); }
    pub(crate) fn try_read(&self) -> Option<GuestMemoryRead<'_>> {
        if self.held.load(Ordering::Relaxed)
            || self.held.compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed).is_err()
        {
            // A checkpoint resumes an unfinished graphics operation. It
            // must not leave the guest waiting for the next row batch.
            if !unsafe { IN_CHECKPOINT } {
                self.requested.store(true, Ordering::Release);
                unsafe { READ_DEFERRED = true; }
            }
            return None;
        }
        Some(GuestMemoryRead(self))
    }
    fn cancel_request(&self) {
        self.requested.store(false, Ordering::Release);
        unsafe { AUDIO_READ_PENDING = false; }
    }
    /// Guest core only, outside all guest-memory and device/service guards.
    pub(crate) fn yield_to_reader(&self) {
        while self.requested.load(Ordering::Acquire) { core::hint::spin_loop(); }
    }
    /// A service may be deactivated after requesting a read. A completed
    /// worker pass must also acknowledge that cancelled request.
    fn finish_turn(&self) {
        if !self.held.load(Ordering::Acquire) && !unsafe { AUDIO_READ_PENDING } {
            self.cancel_request();
        }
    }
}
pub(crate) struct GuestMemoryRead<'a>(&'a GuestMemoryGate);
impl Drop for GuestMemoryRead<'_> {
    fn drop(&mut self) {
        self.0.requested.store(false, Ordering::Release);
        self.0.leave();
    }
}

pub fn enabled() -> bool {
    ENABLED.load(Ordering::Acquire)
}

/// Start exactly one consumer, after platform initialization. Never returns.
///
/// # Safety
/// Only this CPU may consume mailboxes. `refresh` must synchronize kernel
/// mappings and invalidate translations before accessing handed-off storage.
#[allow(dead_code)] // Hosted entry deliberately uses the inline path.
pub unsafe fn worker(refresh: fn()) -> ! {
    unsafe { ON_WORKER = true; }
    REFRESH.store(refresh as usize, Ordering::Relaxed);
    ENABLED.store(true, Ordering::Release);
    loop {
        // Retry a DMA read deferred by this poll before starting a frame.
        // A video read requested last pass must still get its own retry.
        if !audio_checkpoint() { video_checkpoint(); }
        device_checkpoint();
        GUEST_MEMORY.finish_turn();
        if let Some(command) = GRAPHICS.take() {
            // The guest may be joining this job while holding guest memory.
            // Let it run; checkpoints may read opportunistically but cannot
            // hold the guest at a boundary while graphics work continues.
            GUEST_MEMORY.cancel_request();
            unsafe {
                execute(command);
            }
        } else {
            core::hint::spin_loop();
        }
    }
}

unsafe fn execute(command: Command) {
    let refresh: fn() = unsafe { core::mem::transmute(REFRESH.load(Ordering::Relaxed)) };
    refresh();
    unsafe {
        (command.run)(command.argument);
    }
}

/// Graphics callbacks invoke this between bounded row batches. Worker only.
/// Inline fallback never consumes the worker mailbox.
fn audio_checkpoint() -> bool {
    if let Some(service) = AUDIO_SERVICE.try_lock()
        && let Some(command) = *service
    {
        let due: fn() -> bool = unsafe { core::mem::transmute(AUDIO_DUE.load(Ordering::Relaxed)) };
        if due() {
            // A video sample may have requested the guest at the end of the
            // previous pass. Do not hold it there while this poll mixes.
            // Preserve an audio request across retries: cancelling it before
            // try_read lets the guest reclaim memory ahead of the DMA copy.
            if !unsafe { AUDIO_READ_PENDING } { GUEST_MEMORY.cancel_request(); }
            unsafe { READ_DEFERRED = false; execute(command); }
            unsafe { AUDIO_READ_PENDING = READ_DEFERRED; }
            return unsafe { READ_DEFERRED };
        }
    }
    // Deactivation or a deadline change cancels an outstanding audio read.
    if unsafe { AUDIO_READ_PENDING } { GUEST_MEMORY.cancel_request(); }
    false
}

struct Scoped<F, R> {
    function: Option<F>,
    result: Option<R>,
    done: AtomicBool,
}

/// Join a graphics calculation borrowing resident source/destination buffers.
/// # Safety
/// BSP only. No allocation/free, guest mappings, shared mutable globals, or
/// recursive submissions. Referenced storage must remain resident and mapped.
pub unsafe fn graphics<F: FnOnce() -> R + Send, R: Send>(function: F) -> R {
    unsafe { scoped(&GRAPHICS, function) }
}

unsafe fn scoped<F: FnOnce() -> R + Send, R: Send>(mailbox: &Mailbox, function: F) -> R {
    if !enabled() {
        return function();
    }
    unsafe fn invoke<F: FnOnce() -> R, R>(argument: usize) {
        let work = argument as *mut Scoped<F, R>;
        let function = unsafe { (*work).function.take().unwrap() };
        unsafe {
            (*work).result = Some(function());
        }
        unsafe {
            (*work).done.store(true, Ordering::Release);
        }
    }
    let work = UnsafeCell::new(Scoped {
        function: Some(function),
        result: None,
        done: AtomicBool::new(false),
    });
    mailbox.send(Command {
        run: invoke::<F, R>,
        argument: work.get() as usize,
    });
    while !unsafe { (*work.get()).done.load(Ordering::Acquire) } {
        core::hint::spin_loop();
    }
    unsafe { (*work.get()).result.take().unwrap() }
}

struct State<T> {
    busy: AtomicBool,
    value: UnsafeCell<T>,
    run: UnsafeCell<Option<fn(&mut T)>>,
}

/// Stable, exclusively owned graphics state. Access and destruction join any
/// outstanding work; forgetting a job only leaks storage, never dangling it.
pub struct Graphics<T: Send + 'static> {
    state: Box<State<T>>,
}
impl<T: Send + 'static> Graphics<T> {
    pub fn new(value: T) -> Self {
        Self {
            state: Box::new(State {
                busy: AtomicBool::new(false),
                value: UnsafeCell::new(value),
                run: UnsafeCell::new(None),
            }),
        }
    }
    pub fn wait(&self) {
        while self.state.busy.load(Ordering::Acquire) {
            core::hint::spin_loop();
        }
    }
    #[cfg(test)]
    pub fn get(&self) -> &T {
        self.wait();
        unsafe { &*self.state.value.get() }
    }
    pub fn get_mut(&mut self) -> &mut T {
        self.wait();
        unsafe { &mut *self.state.value.get() }
    }

    /// Hand the entire state to the graphics worker. A subsequent get/drop
    /// waits; unrelated guest execution may continue while the worker runs.
    ///
    /// # Safety
    /// BSP only; callback must satisfy the resident, allocation-free contract
    /// of `graphics`. It should service `audio_checkpoint` between bounded batches
    /// when `enabled()`, and must not retain pointers after returning.
    pub unsafe fn start(&mut self, run: fn(&mut T)) {
        self.wait();
        if !enabled() {
            run(self.get_mut());
            return;
        }
        unsafe fn invoke<T>(argument: usize) {
            let state = unsafe { &*(argument as *const State<T>) };
            unsafe {
                ((*state.run.get()).unwrap())(&mut *state.value.get());
            }
            state.busy.store(false, Ordering::Release);
        }
        unsafe {
            *self.state.run.get() = Some(run);
        }
        self.state.busy.store(true, Ordering::Relaxed);
        GRAPHICS.send(Command {
            run: invoke::<T>,
            argument: &*self.state as *const State<T> as usize,
        });
    }
}
impl<T: Send + 'static> Drop for Graphics<T> {
    fn drop(&mut self) {
        self.wait();
    }
}

/// A checkpoint installed in graphics libraries. Inline execution has no
/// competing worker and therefore nothing to service.
pub fn checkpoint() {
    if unsafe { ON_WORKER } {
        let previous = unsafe { IN_CHECKPOINT };
        unsafe { IN_CHECKPOINT = true; }
        audio_checkpoint();
        unsafe { IN_CHECKPOINT = previous; }
    }
}

/// Kernel-context ownership lock. Interrupt handlers must not acquire it.
/// The media core never allocates while holding this lock.
pub struct Shared<T> {
    held: AtomicBool,
    value: UnsafeCell<T>,
}
unsafe impl<T: Send> Sync for Shared<T> {}
impl<T> Shared<T> {
    pub const fn new(value: T) -> Self {
        Self { held: AtomicBool::new(false), value: UnsafeCell::new(value) }
    }
    pub fn with<R>(&self, read: impl FnOnce(&T) -> R) -> R { read(&self.lock()) }
    pub fn lock(&self) -> Guard<'_, T> {
        loop {
            if let Some(guard) = self.try_lock() { return guard; }
            core::hint::spin_loop();
        }
    }
    pub fn try_lock(&self) -> Option<Guard<'_, T>> {
        self.held.compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .ok().map(|_| Guard { owner: self })
    }
}
pub struct Guard<'a, T> { owner: &'a Shared<T> }
impl<T> core::ops::Deref for Guard<'_, T> {
    type Target = T;
    fn deref(&self) -> &T { unsafe { &*self.owner.value.get() } }
}
impl<T> core::ops::DerefMut for Guard<'_, T> {
    fn deref_mut(&mut self) -> &mut T { unsafe { &mut *self.owner.value.get() } }
}
impl<T> Drop for Guard<'_, T> {
    fn drop(&mut self) { self.owner.held.store(false, Ordering::Release); }
}

// Registration is held while polling. Unregistering therefore also joins the
// last poll, before the owning core can release the service's storage.
static AUDIO_SERVICE: Shared<Option<Command>> = Shared::new(None);

/// One independently polled audio service. Register/drop on the BSP only.
pub struct AudioService<T: Send + 'static> {
    state: Box<Shared<T>>,
    registered: bool,
}
impl<T: Send + 'static> AudioService<T> {
    /// # Safety
    /// `poll` runs on the media core and must obey the resident/no-allocation
    /// contract. It must not recursively access this service or submit jobs.
    /// `due` runs before refreshing mappings: it may only read permanent boot
    /// storage and must not access allocations published by the BSP.
    pub unsafe fn new(value: T, due: fn() -> bool, poll: fn(&mut T)) -> Self {
        // Stable resident storage; the registration owns the callback until
        // Drop fences the final poll before freeing the state.
        let state = Box::new(Shared::new(value));
        let registered = enabled();
        let service = Self { state, registered };
        if registered {
            unsafe fn invoke<T>(arg: usize) {
                let state = unsafe { &*(arg as *const Shared<T>) };
                if let Some(mut state) = state.try_lock() {
                    let poll: fn(&mut T) = unsafe {
                        core::mem::transmute(AUDIO_POLL.load(Ordering::Relaxed))
                    };
                    poll(&mut state);
                }
            }
            let mut slot = AUDIO_SERVICE.lock();
            assert!(slot.is_none(), "only one audio service may own the sink");
            AUDIO_POLL.store(poll as usize, Ordering::Relaxed);
            AUDIO_DUE.store(due as usize, Ordering::Relaxed);
            *slot = Some(Command { run: invoke::<T>, argument: &*service.state as *const _ as usize });
        }
        service
    }
    pub fn lock(&self) -> Guard<'_, T> { self.state.lock() }
    pub fn try_lock(&self) -> Option<Guard<'_, T>> { self.state.try_lock() }
}
static AUDIO_DUE: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);
static AUDIO_POLL: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);
impl<T: Send + 'static> Drop for AudioService<T> {
    fn drop(&mut self) {
        if self.registered { *AUDIO_SERVICE.lock() = None; }
    }
}

#[derive(Clone, Copy)]
struct VideoPoll {
    command: Command,
    due: fn() -> bool,
}
static VIDEO_SERVICE: Shared<Option<VideoPoll>> = Shared::new(None);
static VIDEO_OWNER: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);

/// Resident display state. The active display is polled independently of the
/// guest loop. Inactive displays retain their storage until their owner drops.
pub struct VideoService<T: Send + 'static> {
    state: Box<Shared<T>>,
    due: fn() -> bool,
    poll: fn(&mut T),
}
impl<T: Send + 'static> VideoService<T> {
    /// # Safety
    /// Same resident/no-allocation contract as AudioService. `due` only reads
    /// permanent storage. Registration, updates and destruction are BSP-only.
    pub unsafe fn new(value: T, due: fn() -> bool, poll: fn(&mut T)) -> Self {
        Self { state: Box::new(Shared::new(value)), due, poll }
    }
    pub fn try_lock(&self) -> Option<Guard<'_, T>> { self.state.try_lock() }
    pub fn activate(&self) {
        if !enabled() {
            if (self.due)() && let Some(mut state) = self.state.try_lock() {
                (self.poll)(&mut state);
            }
            return;
        }

        let argument = &*self.state as *const Shared<T> as usize;
        if VIDEO_OWNER.load(Ordering::Acquire) == argument { return; }
        unsafe fn invoke<T>(argument: usize) {
            let state = unsafe { &*(argument as *const Shared<T>) };
            if let Some(mut state) = state.try_lock() {
                let poll: fn(&mut T) = unsafe { core::mem::transmute(VIDEO_POLL.load(Ordering::Relaxed)) };
                poll(&mut state);
            }
        }
        let mut slot = VIDEO_SERVICE.lock();
        VIDEO_POLL.store(self.poll as usize, Ordering::Relaxed);
        *slot = Some(VideoPoll { command: Command { run: invoke::<T>, argument }, due: self.due });
        VIDEO_OWNER.store(argument, Ordering::Release);
    }
    /// Fence scanout before changing the physical mode or releasing mappings.
    pub fn pause(&self) {
        let argument = &*self.state as *const Shared<T> as usize;
        let mut slot = VIDEO_SERVICE.lock();
        if slot.as_ref().is_some_and(|slot| slot.command.argument == argument) {
            *slot = None;
            VIDEO_OWNER.store(0, Ordering::Release);
        }
    }
}
static VIDEO_POLL: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);
impl<T: Send + 'static> Drop for VideoService<T> {
    fn drop(&mut self) { self.pause(); }
}
fn video_checkpoint() {
    if let Some(service) = VIDEO_SERVICE.try_lock()
        && let Some(service) = *service
        && (service.due)()
    {
        unsafe { execute(service.command); }
    }
}


/// Persistent devices are polled independently of guest exits and display
/// refresh. Registration changes fence callbacks; only the BSP allocates.
struct DevicePoll { command: Command, ready: unsafe fn(usize) -> bool }
static DEVICES: Shared<alloc::vec::Vec<DevicePoll>> = Shared::new(alloc::vec::Vec::new());
static DEVICE_REVISION: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);
struct DeviceState<T> { value: T, ready: fn(&T) -> bool, poll: fn(&T) }
pub struct DeviceService<T: Send + Sync + 'static> {
    state: Box<DeviceState<T>>,
    registered: bool,
}
impl<T: Send + Sync + 'static> DeviceService<T> {
    /// # Safety
    /// `ready` only reads storage resident at registration. `poll` obeys the
    /// same allocation-free callback contract as AudioService, runs a bounded
    /// batch and must not register/drop services or recursively poll devices.
    pub unsafe fn new(value: T, ready: fn(&T) -> bool, poll: fn(&T)) -> Self {
        let state = Box::new(DeviceState { value, ready, poll });
        let registered = enabled();
        if registered {
            unsafe fn ready<T>(arg: usize) -> bool {
                let state = unsafe { &*(arg as *const DeviceState<T>) };
                (state.ready)(&state.value)
            }
            unsafe fn invoke<T>(arg: usize) {
                let state = unsafe { &*(arg as *const DeviceState<T>) };
                (state.poll)(&state.value);
            }
            let mut devices = DEVICES.lock();
            devices.push(DevicePoll { command: Command { run: invoke::<T>,
                argument: &*state as *const _ as usize }, ready: ready::<T> });
            DEVICE_REVISION.fetch_add(1, Ordering::Release);
        }
        Self { state, registered }
    }
    pub fn poll_inline(&self) {
        if !self.registered && (self.state.ready)(&self.state.value) {
            (self.state.poll)(&self.state.value);
        }
    }
}
impl<T: Send + Sync + 'static> Drop for DeviceService<T> {
    fn drop(&mut self) {
        if self.registered {
            let argument = &*self.state as *const _ as usize;
            DEVICES.lock().retain(|device| device.command.argument != argument);
            DEVICE_REVISION.fetch_add(1, Ordering::Release);
        }
    }
}
fn device_checkpoint() {
    // Worker only. Refresh before dereferencing newly registered heap storage.
    static SEEN: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);
    let Some(devices) = DEVICES.try_lock() else { return };
    let revision = DEVICE_REVISION.load(Ordering::Acquire);
    if SEEN.load(Ordering::Relaxed) != revision {
        let refresh: fn() = unsafe { core::mem::transmute(REFRESH.load(Ordering::Relaxed)) };
        refresh();
        SEEN.store(revision, Ordering::Relaxed);
    }
    for device in devices.iter() {
        if unsafe { (device.ready)(device.command.argument) } {
            // A guest-side command fence must be able to finish before the
            // guest can offer its memory. Do not leave a read request behind
            // while executing a potentially expensive rendering command.
            GUEST_MEMORY.cancel_request();
            unsafe { execute(device.command); }
        }
    }
}

/// Fixed-capacity SPSC command ring. One guest core publishes, one media core
/// consumes. Storage is committed on construction; neither end allocates.
pub struct Commands<T: Copy, const N: usize> {
    head: core::sync::atomic::AtomicUsize,
    tail: core::sync::atomic::AtomicUsize,
    entries: UnsafeCell<[core::mem::MaybeUninit<T>; N]>,
}
unsafe impl<T: Copy + Send, const N: usize> Sync for Commands<T, N> {}
impl<T: Copy, const N: usize> Commands<T, N> {
    pub fn new() -> Self {
        assert!(N.is_power_of_two());
        Self { head: core::sync::atomic::AtomicUsize::new(0),
            tail: core::sync::atomic::AtomicUsize::new(0),
            entries: UnsafeCell::new([core::mem::MaybeUninit::uninit(); N]) }
    }
    pub fn pending(&self) -> bool { self.head.load(Ordering::Acquire) != self.tail.load(Ordering::Acquire) }
    /// # Safety
    /// Only the single producer may call this method.
    pub unsafe fn push(&self, command: T) -> bool {
        let head = self.head.load(Ordering::Relaxed);
        if head.wrapping_sub(self.tail.load(Ordering::Acquire)) == N { return false; }
        unsafe { (*self.entries.get())[head % N].write(command); }
        self.head.store(head.wrapping_add(1), Ordering::Release);
        true
    }
    /// # Safety
    /// Only the single consumer may call this method.
    pub unsafe fn pop(&self) -> Option<T> {
        let tail = self.tail.load(Ordering::Relaxed);
        if tail == self.head.load(Ordering::Acquire) { return None; }
        let command = unsafe { (*self.entries.get())[tail % N].assume_init_read() };
        self.tail.store(tail.wrapping_add(1), Ordering::Release);
        Some(command)
    }
}

#[cfg(test)]
mod guest_memory_tests {
    use super::*;

    #[test]
    fn failed_read_reserves_next_guest_boundary_until_copy_finishes() {
        let gate = GuestMemoryGate::new();
        gate.enter();
        assert!(gate.try_read().is_none());
        gate.finish_turn();
        assert!(gate.requested.load(Ordering::Acquire));
        gate.leave();
        // The next guest slice must yield; the worker owns the next read.
        assert!(gate.requested.load(Ordering::Acquire));
        let read = gate.try_read().unwrap();
        assert!(gate.held.load(Ordering::Acquire));
        drop(read);
        // Rendering/mixing after the copy cannot keep the guest waiting.
        gate.yield_to_reader();
        gate.enter();
        gate.leave();
    }

    #[test]
    fn graphics_checkpoint_cannot_request_a_future_guest_stall() {
        let gate = GuestMemoryGate::new();
        gate.enter();
        unsafe { IN_CHECKPOINT = true; }
        assert!(gate.try_read().is_none());
        unsafe { IN_CHECKPOINT = false; }
        assert!(!gate.requested.load(Ordering::Acquire));
        gate.leave();
        // Once the worker returns to its main loop, the usual fair handoff
        // remains available; this must not bring back reader starvation.
        gate.enter();
        assert!(gate.try_read().is_none());
        assert!(gate.requested.load(Ordering::Acquire));
        gate.leave();
        drop(gate.try_read().unwrap());
        gate.yield_to_reader();
    }

    #[test]
    fn cancelled_service_does_not_strand_guest_at_boundary() {
        let gate = GuestMemoryGate::new();
        gate.enter();
        assert!(gate.try_read().is_none());
        gate.leave();
        // No callback remains to consume the requested read.
        gate.finish_turn();
        gate.yield_to_reader();
        gate.enter();
        gate.leave();
    }
}
