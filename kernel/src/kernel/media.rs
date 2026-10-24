//! One media worker, shared by audio and graphics. The BSP remains the only
//! allocator and owner of guest mappings. Jobs operate on resident kernel
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
static REFRESH: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);

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
    REFRESH.store(refresh as usize, Ordering::Relaxed);
    ENABLED.store(true, Ordering::Release);
    loop {
        audio_checkpoint();
        video_checkpoint();
        if let Some(command) = GRAPHICS.take() {
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
pub fn audio_checkpoint() {
    if let Some(service) = AUDIO_SERVICE.try_lock()
        && let Some(command) = *service
    {
        let due: fn() -> bool = unsafe { core::mem::transmute(AUDIO_DUE.load(Ordering::Relaxed)) };
        if due() { unsafe { execute(command); } }
    }

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
    pub fn is_busy(&self) -> bool { self.state.busy.load(Ordering::Acquire) }
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
    if enabled() {
        audio_checkpoint();
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
