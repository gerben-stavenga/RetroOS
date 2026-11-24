//! A one-entry mailbox for a resident worker, with synchronous borrowed work.

use core::sync::atomic::{AtomicBool, Ordering};
use spin::Mutex;

pub struct WorkerQueue<T> {
    ready: AtomicBool,
    entry: Mutex<Option<Entry<T>>>,
}

enum Entry<T> {
    Owned(T),
    Scoped(ScopedJob),
}

struct ScopedJob {
    run: unsafe fn(usize),
    context: usize,
}

impl<T: Send> Default for WorkerQueue<T> {
    fn default() -> Self { Self::new() }
}

impl<T: Send> WorkerQueue<T> {
    pub const fn new() -> Self {
        Self { ready: AtomicBool::new(false), entry: Mutex::new(None) }
    }

    fn submit(&self, entry: Entry<T>) {
        loop {
            if !self.ready.load(Ordering::Acquire) {
                let mut slot = self.entry.lock();
                if slot.is_none() {
                    *slot = Some(entry);
                    self.ready.store(true, Ordering::Release);
                    return;
                }
            }
            core::hint::spin_loop();
        }
    }

    pub fn send(&self, value: T) { self.submit(Entry::Owned(value)); }

    /// Run one queued job, preparing access to its storage before using it.
    pub fn poll(&self, prepare: impl FnOnce(), owned: impl FnOnce(T)) -> bool {
        if !self.ready.load(Ordering::Acquire) { return false; }
        let entry = {
            let mut slot = self.entry.lock();
            let entry = slot.take();
            self.ready.store(false, Ordering::Release);
            entry
        };
        let Some(entry) = entry else { return false };
        prepare();
        match entry {
            Entry::Owned(value) => owned(value),
            Entry::Scoped(job) => {
                // The submitter waits until the callback publishes its result.
                // Removing the entry transfers the sole invocation to this poll.
                unsafe { (job.run)(job.context); }
            }
        }
        true
    }

    /// Submit work that may borrow from the caller. The caller stays in this
    /// scope until the worker has stopped accessing those borrows.
    pub fn join<F, R>(&self, function: F) -> R
    where
        F: FnOnce() -> R + Send,
        R: Send,
    {
        struct Work<F, R> {
            pending: Mutex<Option<F>>,
            result: Mutex<Option<R>>,
            complete: AtomicBool,
        }

        unsafe fn invoke<F: FnOnce() -> R + Send, R: Send>(context: usize) {
            // The caller retains the stack slot until completion is published.
            let work = unsafe { &*(context as *const Work<F, R>) };
            let function = work.pending.lock().take().expect("worker callback reused");
            let result = function();
            *work.result.lock() = Some(result);
            work.complete.store(true, Ordering::Release);
        }

        let work = Work {
            pending: Mutex::new(Some(function)),
            result: Mutex::new(None),
            complete: AtomicBool::new(false),
        };
        self.submit(Entry::Scoped(ScopedJob {
            run: invoke::<F, R>,
            context: &work as *const _ as usize,
        }));

        while !work.complete.load(Ordering::Acquire) {
            core::hint::spin_loop();
        }
        work.result.lock().take().expect("worker did not publish a result")
    }
}
