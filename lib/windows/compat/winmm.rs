//! Multimedia timer callbacks run on a guest worker, independently of USER's
//! message queue. Never hold the timer lock while calling application code.
#![no_std]
#![allow(non_snake_case)]
#![deny(unsafe_op_in_unsafe_fn)]
extern crate alloc;
mod driver;
mod mci;
mod mmio;
mod wave;
#[allow(dead_code)]
#[path = "../user32/runtime.rs"]
mod runtime;
use alloc::vec::Vec;
use core::{
    cell::UnsafeCell,
    sync::atomic::{AtomicBool, Ordering},
};
unsafe extern "system" {
    fn CreateThread(
        a: u32,
        stack: u32,
        entry: unsafe extern "system" fn(u32) -> u32,
        arg: u32,
        flags: u32,
        id: *mut u32,
    ) -> u32;
    fn CloseHandle(handle: u32) -> u32;
}
#[derive(Clone, Copy)]
struct Timer {
    id: u32,
    delay: u32,
    deadline: u32,
    callback: u32,
    user: u32,
    flags: u32,
    cleanup: u32,
    running: bool,
    cancelled: bool,
}
struct State {
    timers: Vec<Timer>,
    next: u32,
    wake: u32,
    worker: u32,
    periods: Vec<u32>,
}
struct Global {
    lock: AtomicBool,
    state: UnsafeCell<State>,
}
unsafe impl Sync for Global {}
static GLOBAL: Global = Global {
    lock: AtomicBool::new(false),
    state: UnsafeCell::new(State {
        timers: Vec::new(),
        next: 1,
        wake: 0,
        worker: 0,
        periods: Vec::new(),
    }),
};
fn with<R>(f: impl FnOnce(&mut State) -> R) -> R {
    while GLOBAL.lock.swap(true, Ordering::Acquire) {
        unsafe {
            runtime::Sleep(0);
        }
    }
    let result = f(unsafe { &mut *GLOBAL.state.get() });
    GLOBAL.lock.store(false, Ordering::Release);
    result
}
fn dispose(timer: Option<Timer>) {
    if let Some(t) = timer {
        if t.cleanup != 0 {
            unsafe {
                core::mem::transmute::<u32, unsafe extern "system" fn(u32)>(t.cleanup)(t.user);
            }
        }
    }
}
unsafe extern "system" fn worker(_: u32) -> u32 {
    loop {
        let now = unsafe { runtime::GetTickCount() };
        let (due, wake, wait) = with(|s| {
            // Service the oldest deadline: a slow periodic callback must not
            // starve later timers just because it is always due again.
            let index = s
                .timers
                .iter()
                .enumerate()
                .filter(|(_, t)| {
                    !t.cancelled && !t.running && now.wrapping_sub(t.deadline) as i32 >= 0
                })
                .max_by_key(|(_, t)| now.wrapping_sub(t.deadline))
                .map(|(i, _)| i);
            if let Some(i) = index {
                let t = &mut s.timers[i];
                t.running = true;
                if t.flags & 1 == 0 {
                    t.cancelled = true;
                } else {
                    // Preserve cadence but coalesce missed ticks instead of a burst.
                    let ticks = now.wrapping_sub(t.deadline) / t.delay + 1;
                    t.deadline = t.deadline.wrapping_add(ticks.wrapping_mul(t.delay));
                }
                (Some(*t), s.wake, 0)
            } else {
                let wait = s
                    .timers
                    .iter()
                    .filter(|t| !t.cancelled)
                    .map(|t| t.deadline.wrapping_sub(now))
                    .min()
                    .unwrap_or(u32::MAX);
                (None, s.wake, wait)
            }
        });
        if let Some(t) = due {
            unsafe {
                if t.flags & 0x10 != 0 {
                    runtime::SetEvent(t.callback);
                } else {
                    core::mem::transmute::<u32, unsafe extern "system" fn(u32, u32, u32, u32, u32)>(
                        t.callback,
                    )(t.id, 0, t.user, 0, 0);
                }
            }
            let removed = with(|s| {
                let i = s.timers.iter().position(|x| x.id == t.id).unwrap();
                s.timers[i].running = false;
                if s.timers[i].cancelled {
                    Some(s.timers.remove(i))
                } else {
                    None
                }
            });
            dispose(removed);
        } else {
            unsafe {
                runtime::WaitForSingleObject(wake, wait);
            }
        }
    }
}
// The private variant transfers ownership of `user` on success. It is released
// exactly once, after cancellation or the final callback has returned.
#[unsafe(no_mangle)]
pub unsafe extern "system" fn RetroTimeSetEvent(
    delay: u32,
    resolution: u32,
    callback: u32,
    user: u32,
    flags: u32,
    cleanup: u32,
) -> u32 {
    // Event-pulse mode requires a real PulseEvent primitive; do not pretend
    // that SetEvent followed by ResetEvent has the same semantics.
    if delay == 0
        || delay > 65535
        || resolution > 65535
        || callback == 0
        || flags & !(1 | 0x10 | 0x100) != 0
    {
        return 0;
    }
    let now = unsafe { runtime::GetTickCount() };
    let (id, wake) = with(|s| {
        if s.wake == 0 {
            s.wake = unsafe { runtime::CreateEventA(0, 0, 0, 0) };
        }
        if s.wake == 0 {
            return (0, 0);
        }
        if s.worker == 0 {
            let mut id = 0;
            let h = unsafe { CreateThread(0, 256 * 1024, worker, 0, 0, &mut id) };
            if h == 0 {
                return (0, 0);
            }
            s.worker = id;
            unsafe {
                CloseHandle(h);
            }
        }
        let mut id = 0;
        for _ in 0..65535 {
            let candidate = s.next;
            s.next = s.next % 65535 + 1;
            if !s.timers.iter().any(|t| t.id == candidate) {
                id = candidate;
                break;
            }
        }
        if id == 0 {
            return (0, 0);
        }
        s.timers.push(Timer {
            id,
            delay,
            deadline: now.wrapping_add(delay),
            callback,
            user,
            flags,
            cleanup,
            running: false,
            cancelled: false,
        });
        (id, s.wake)
    });
    if id != 0 {
        unsafe {
            runtime::SetEvent(wake);
        }
    }
    id
}
#[unsafe(no_mangle)]
pub unsafe extern "system" fn timeSetEvent(
    delay: u32,
    resolution: u32,
    callback: u32,
    user: u32,
    flags: u32,
) -> u32 {
    unsafe { RetroTimeSetEvent(delay, resolution, callback, user, flags, 0) }
}
#[unsafe(no_mangle)]
pub extern "system" fn timeKillEvent(id: u32) -> u32 {
    let result = with(|s| {
        let i = s.timers.iter().position(|t| t.id == id)?;
        let t = &mut s.timers[i];
        t.cancelled = true;
        let synchronous = t.flags & 0x100 != 0 && t.running;
        let removed = if !t.running {
            Some(s.timers.remove(i))
        } else {
            None
        };
        Some((removed, synchronous, s.worker, s.wake))
    });
    let Some((removed, synchronous, worker, wake)) = result else {
        return 11;
    };
    dispose(removed);
    unsafe {
        runtime::SetEvent(wake);
    }
    if synchronous && unsafe { runtime::GetCurrentThreadId() } != worker {
        while with(|s| s.timers.iter().any(|t| t.id == id && t.running)) {
            unsafe {
                runtime::Sleep(1);
            }
        }
    }
    0
}
#[unsafe(no_mangle)]
pub extern "system" fn timeGetTime() -> u32 {
    unsafe { runtime::GetTickCount() }
}
#[unsafe(no_mangle)]
pub extern "system" fn timeBeginPeriod(period: u32) -> u32 {
    if !(1..=65535).contains(&period) {
        return 97;
    }
    with(|s| s.periods.push(period));
    0
}
#[unsafe(no_mangle)]
pub extern "system" fn timeEndPeriod(period: u32) -> u32 {
    with(|s| {
        if let Some(i) = s.periods.iter().position(|p| *p == period) {
            s.periods.remove(i);
            0
        } else {
            97
        }
    })
}
#[unsafe(no_mangle)]
pub unsafe extern "system" fn timeGetDevCaps(out: *mut u32, size: u32) -> u32 {
    if out.is_null() || size < 8 {
        return 11;
    }
    unsafe {
        out.write_unaligned(1);
        out.add(1).write_unaligned(65535);
    }
    0
}
#[unsafe(no_mangle)]
pub unsafe extern "system" fn timeGetSystemTime(out: *mut u32, size: u32) -> u32 {
    if out.is_null() || size < 8 {
        return 11;
    }
    unsafe {
        out.write_unaligned(1);
        out.add(1).write_unaligned(timeGetTime());
    }
    0
}
