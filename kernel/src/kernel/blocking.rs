//! Synchronous notifications for operations which may stall the machine.
//!
//! The producer of the operation does not identify its cause. Subscribers
//! only get a chance to prepare immediately before the operation begins.

#[derive(Clone, Copy)]
pub struct BlockingOperationHook {
    callback: Option<fn(*mut ())>,
    context: *mut (),
}

impl BlockingOperationHook {
    pub const fn new(callback: fn(*mut ()), context: *mut ()) -> Self {
        Self { callback: Some(callback), context }
    }

    const fn none() -> Self {
        Self { callback: None, context: core::ptr::null_mut() }
    }
}

static mut HOOK: BlockingOperationHook = BlockingOperationHook::none();

/// Register the process-wide hook used by the kernel's long-lived event loop.
/// The callback context must remain valid until the event loop exits.
pub fn install(hook: BlockingOperationHook) {
    // SAFETY: the hook is installed during single-threaded kernel startup and
    // then only read synchronously by the same kernel execution context.
    unsafe { HOOK = hook; }
}

/// Notify subscribers immediately before a potentially blocking operation.
pub fn before_blocking_operation() {
    // SAFETY: copy the small, immutable registration while interrupts cannot
    // interleave this synchronous kernel transition.
    let hook = unsafe { HOOK };
    if let Some(callback) = hook.callback {
        callback(hook.context);
    }
}
