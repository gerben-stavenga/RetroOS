//! One media worker, shared by audio and graphics. The BSP remains the only
//! allocator and owner of guest mappings. Jobs operate on resident kernel
//! buffers; an ownership handoff refreshes the worker's mappings and TLB.
//! Audio has a separate mailbox and may run at graphics checkpoints.

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
static AUDIO: Mailbox = Mailbox::new();
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
    // Called only by audited graphics jobs or the worker loop, never by the
    // BSP while the worker is enabled.
    if let Some(command) = AUDIO.take() {
        unsafe {
            execute(command);
        }
    }
}

struct Scoped<F, R> {
    function: Option<F>,
    result: Option<R>,
    done: AtomicBool,
}

/// Execute a finite audio quantum and join before returning to guest state.
///
/// # Safety
/// BSP only. The closure must not allocate/free, access guest mappings or
/// shared mutable globals, or submit more jobs. All referenced memory must
/// already be resident, remain mapped, and be exclusively borrowed as needed.
pub unsafe fn audio<F: FnOnce() -> R + Send, R: Send>(function: F) -> R {
    unsafe { scoped(&AUDIO, function) }
}

/// Join a graphics calculation borrowing resident source/destination buffers.
/// # Safety
/// Same contract as `audio`; this call must originate on the BSP.
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
    /// of `audio`. It should service `audio_checkpoint` between bounded batches
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
