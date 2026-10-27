//! Thread queues and timer policy live in guest memory. Kernel input arrives
//! through one transport primitive; blocking reuses KERNEL32 event objects.
use crate::{Message, runtime, state};
use alloc::vec::Vec;

pub struct Queue {
    pub thread: u32,
    pub event: u32,
    pub messages: Vec<Message>,
    pub input: Vec<Message>,
    active: Vec<u64>,
}
pub struct Timer {
    pub thread: u32,
    pub hwnd: u32,
    pub id: u32,
    interval: u32,
    deadline: u32,
    callback: u32,
}
unsafe extern "system" {
    fn RetroReadEvent(out: *mut Message, event: u32) -> u32;
}
fn current() -> u32 {
    unsafe { runtime::GetCurrentThreadId() }
}
fn now() -> u32 {
    unsafe { runtime::GetTickCount() }
}
fn wake(event: u32) {
    unsafe {
        runtime::SetEvent(event);
    }
}

pub fn ensure_queue() -> u32 {
    let thread = current();
    state::with(|s| {
        if let Some(q) = s.queues.iter().find(|q| q.thread == thread) {
            return q.event;
        }
        let event = unsafe { runtime::CreateEventA(0, 0, 0, 0) };
        if event == 0 {
            return 0;
        }
        s.queues.push(Queue {
            thread,
            event,
            messages: Vec::new(),
            input: Vec::new(),
            active: Vec::new(),
        });
        unsafe {
            RetroReadEvent(core::ptr::null_mut(), event);
        }
        event
    })
}
fn pump_input() {
    // Keep draining and routing ordered even if a kernel gate switches threads.
    state::with(|s| {
        let mut message = Message::default();
        while unsafe { RetroReadEvent(&raw mut message, 0) } != 0 {
            crate::keyboard::input(s, &mut message);
            crate::frame::input(s, &mut message);
            if message.message == 0xf {
                crate::paint::record_native(s, message.hwnd);
            }
            let thread = s
                .windows
                .iter()
                .find(|w| w.hwnd == message.hwnd)
                .map(|w| w.thread);
            if let Some(q) = s.queues.iter_mut().find(|q| Some(q.thread) == thread) {
                if message.message != 0xf
                    || !q
                        .input
                        .iter()
                        .any(|m| m.message == 0xf && m.hwnd == message.hwnd)
                {
                    q.input.push(message);
                    wake(q.event);
                }
            }
        }
    });
}
fn matches(s: &state::State, m: &Message, hwnd: u32, min: u32, max: u32) -> bool {
    if m.message == 0x12 {
        return true;
    }
    if (min != 0 || max != 0) && !(min..=max).contains(&m.message) {
        return false;
    }
    if hwnd == 0 {
        return true;
    }
    if hwnd == u32::MAX {
        return m.hwnd == 0;
    }
    let mut h = m.hwnd;
    while h != 0 {
        if h == hwnd {
            return true;
        }
        h = s
            .windows
            .iter()
            .find(|w| w.hwnd == h)
            .map_or(0, |w| w.parent);
    }
    false
}
fn retrieve(thread: u32, hwnd: u32, min: u32, max: u32, remove: bool) -> Option<Message> {
    let time = now();
    state::with(|s| {
        let qi = s.queues.iter().position(|q| q.thread == thread)?;
        let index = s.queues[qi]
            .messages
            .iter()
            .position(|m| matches(s, m, hwnd, min, max));
        if let Some(i) = index {
            return Some(if remove {
                s.queues[qi].messages.remove(i)
            } else {
                s.queues[qi].messages[i]
            });
        }
        // Posted messages precede hardware input; paint is lower priority.
        let index = s.queues[qi]
            .input
            .iter()
            .enumerate()
            .filter(|(_, m)| matches(s, m, hwnd, min, max))
            .min_by_key(|(_, m)| {
                if m.message != 0xf {
                    return (0, 0);
                }
                let mut depth = 0;
                let mut parent = m.hwnd;
                while let Some(w) = s.windows.iter().find(|w| w.hwnd == parent) {
                    if w.parent == 0 {
                        break;
                    }
                    depth += 1;
                    parent = w.parent;
                    if depth >= s.windows.len() {
                        break;
                    }
                }
                // A parent's background can cover its children. Deliver its
                // pending paint before theirs, even when they queued first.
                (1, depth)
            })
            .map(|(i, _)| i);
        if let Some(i) = index {
            return Some(if remove {
                if s.queues[qi].input[i].message == 0xf {
                    s.queues[qi].input[i]
                } else {
                    s.queues[qi].input.remove(i)
                }
            } else {
                s.queues[qi].input[i]
            });
        }
        // Generate only when requested and no queued message matches. Retain a
        // generated PM_NOREMOVE message even if its timer is subsequently killed.
        let ti = s.timers.iter().position(|t| {
            t.thread == thread
                && time.wrapping_sub(t.deadline) as i32 >= 0
                && matches(
                    s,
                    &Message {
                        hwnd: t.hwnd,
                        message: 0x113,
                        ..Message::default()
                    },
                    hwnd,
                    min,
                    max,
                )
        })?;
        let timer = &mut s.timers[ti];
        timer.deadline = time.wrapping_add(timer.interval);
        let m = Message {
            hwnd: timer.hwnd,
            message: 0x113,
            wparam: timer.id,
            lparam: timer.callback,
            time,
            x: 0,
            y: 0,
        };
        if !remove {
            s.queues[qi].messages.push(m);
        }
        Some(m)
    })
}
fn delay(thread: u32, hwnd: u32, min: u32, max: u32) -> u32 {
    let time = now();
    state::with(|s| {
        s.timers
            .iter()
            .filter(|t| {
                t.thread == thread
                    && matches(
                        s,
                        &Message {
                            hwnd: t.hwnd,
                            message: 0x113,
                            ..Message::default()
                        },
                        hwnd,
                        min,
                        max,
                    )
            })
            .map(|t| (t.deadline.wrapping_sub(time) as i32).max(0) as u32)
            .min()
            .unwrap_or(u32::MAX)
    })
}
unsafe fn get(out: *mut Message, hwnd: u32, min: u32, max: u32, remove: bool, wait: bool) -> i32 {
    if out.is_null() {
        state::error(87);
        return if wait { -1 } else { 0 };
    }
    if hwnd != 0 && hwnd != u32::MAX && crate::window::IsWindow(hwnd) == 0 {
        state::error(1400);
        return if wait { -1 } else { 0 };
    }
    let thread = current();
    let event = ensure_queue();
    if event == 0 {
        return if wait { -1 } else { 0 };
    }
    loop {
        dispatch_sent(thread);
        pump_input();
        if let Some(m) = retrieve(thread, hwnd, min, max, remove) {
            unsafe {
                out.write(m);
            }
            return if wait && m.message == 0x12 { 0 } else { 1 };
        }
        if !wait {
            return 0;
        }
        unsafe {
            runtime::WaitForSingleObject(event, delay(thread, hwnd, min, max));
        }
    }
}
macro_rules! get_api {
    ($get:ident, $peek:ident) => {
        #[unsafe(no_mangle)]
        pub unsafe extern "system" fn $get(
            out: *mut Message,
            hwnd: u32,
            min: u32,
            max: u32,
        ) -> i32 {
            unsafe { get(out, hwnd, min, max, true, true) }
        }
        #[unsafe(no_mangle)]
        pub unsafe extern "system" fn $peek(
            out: *mut Message,
            hwnd: u32,
            min: u32,
            max: u32,
            flags: u32,
        ) -> i32 {
            unsafe { get(out, hwnd, min, max, flags & 1 != 0, false) }
        }
    };
}
get_api!(GetMessageA, PeekMessageA);
get_api!(GetMessageW, PeekMessageW);

fn post(thread: u32, hwnd: u32, message: u32, wparam: u32, lparam: u32) -> i32 {
    let time = now();
    state::with(|s| {
        let Some(q) = s.queues.iter_mut().find(|q| q.thread == thread) else {
            return state::error(1444) as i32;
        };
        if q.messages.len() >= 10000 {
            return state::error(1816) as i32;
        }
        q.messages.push(Message {
            hwnd,
            message,
            wparam,
            lparam,
            time,
            x: 0,
            y: 0,
        });
        wake(q.event);
        1
    })
}
#[unsafe(no_mangle)]
pub extern "system" fn PostThreadMessageW(
    thread: u32,
    message: u32,
    wparam: u32,
    lparam: u32,
) -> i32 {
    post(thread, 0, message, wparam, lparam)
}
#[unsafe(no_mangle)]
pub extern "system" fn PostThreadMessageA(
    thread: u32,
    message: u32,
    wparam: u32,
    lparam: u32,
) -> i32 {
    PostThreadMessageW(thread, message, wparam, lparam)
}
#[unsafe(no_mangle)]
pub extern "system" fn PostMessageW(hwnd: u32, message: u32, wparam: u32, lparam: u32) -> i32 {
    if hwnd == 0 {
        ensure_queue();
        return post(current(), 0, message, wparam, lparam);
    }
    if hwnd == 0xffff {
        let windows: Vec<u32> = state::with(|s| {
            s.windows
                .iter()
                .filter(|w| w.parent == 0)
                .map(|w| w.hwnd)
                .collect()
        });
        for h in windows {
            PostMessageW(h, message, wparam, lparam);
        }
        return 1;
    }
    let thread = state::with(|s| s.windows.iter().find(|w| w.hwnd == hwnd).map(|w| w.thread));
    match thread {
        Some(t) => post(t, hwnd, message, wparam, lparam),
        None => state::error(1400) as i32,
    }
}
#[unsafe(no_mangle)]
pub extern "system" fn PostMessageA(hwnd: u32, message: u32, wparam: u32, lparam: u32) -> i32 {
    PostMessageW(hwnd, message, wparam, lparam)
}
#[unsafe(no_mangle)]
pub extern "system" fn PostQuitMessage(code: u32) {
    ensure_queue();
    let thread = current();
    let time = now();
    state::with(|s| {
        if let Some(q) = s.queues.iter_mut().find(|q| q.thread == thread) {
            q.messages.retain(|m| m.message != 0x12);
            q.messages.push(Message {
                message: 0x12,
                wparam: code,
                time,
                ..Message::default()
            });
            wake(q.event);
        }
    });
}
#[unsafe(no_mangle)]
pub extern "system" fn SetTimer(hwnd: u32, id: u32, interval: u32, callback: u32) -> u32 {
    if ensure_queue() == 0 {
        return 0;
    }
    let thread = current();
    let time = now();
    state::with(|s| {
        if hwnd != 0
            && !s
                .windows
                .iter()
                .any(|w| w.hwnd == hwnd && w.thread == thread)
        {
            return state::error(1400);
        }
        let interval = interval.clamp(10, 0x7fff_ffff);
        if let Some(t) = s
            .timers
            .iter_mut()
            .find(|t| t.thread == thread && t.hwnd == hwnd && t.id == id)
        {
            t.interval = interval;
            t.deadline = time.wrapping_add(interval);
            t.callback = callback;
            return t.id;
        }
        let id = if hwnd == 0 {
            // IDs for thread timers are generated; only an existing ID is reused.
            let id = s.next_timer;
            s.next_timer = s.next_timer.wrapping_add(1).max(1);
            id
        } else {
            id
        };
        s.timers.push(Timer {
            thread,
            hwnd,
            id,
            interval,
            deadline: time.wrapping_add(interval),
            callback,
        });
        id
    })
}
#[unsafe(no_mangle)]
pub extern "system" fn KillTimer(hwnd: u32, id: u32) -> i32 {
    let thread = current();
    state::with(|s| {
        let Some(i) = s
            .timers
            .iter()
            .position(|t| t.thread == thread && t.hwnd == hwnd && t.id == id)
        else {
            return 0;
        };
        s.timers.remove(i);
        1
    })
}

pub struct Sent {
    ticket: u64,
    sender: u32,
    receiver: u32,
    message: Message,
    wide: bool,
    started: bool,
    result: Option<i32>,
}
fn reply(ticket: u64, result: i32) -> bool {
    state::with(|s| {
        let Some(sent) = s
            .sent
            .iter_mut()
            .find(|r| r.ticket == ticket && r.result.is_none())
        else {
            return false;
        };
        sent.result = Some(result);
        let sender = sent.sender;
        if let Some(q) = s.queues.iter().find(|q| q.thread == sender) {
            wake(q.event);
        }
        true
    })
}
fn dispatch_sent(thread: u32) {
    loop {
        let next = state::with(|s| {
            let sent = s
                .sent
                .iter_mut()
                .find(|r| r.receiver == thread && !r.started)?;
            sent.started = true;
            let next = (sent.ticket, sent.message, sent.wide);
            s.queues
                .iter_mut()
                .find(|q| q.thread == thread)?
                .active
                .push(sent.ticket);
            Some(next)
        });
        let Some((ticket, m, wide)) = next else {
            return;
        };
        let result = unsafe { crate::invoke(m.hwnd, m.message, m.wparam, m.lparam, wide) };
        state::with(|s| {
            s.queues
                .iter_mut()
                .find(|q| q.thread == thread)
                .unwrap()
                .active
                .pop();
        });
        reply(ticket, result);
    }
}
pub unsafe fn send(hwnd: u32, message: u32, wparam: u32, lparam: u32, wide: bool) -> i32 {
    if hwnd == 0xffff {
        let handles: Vec<u32> = state::with(|s| {
            s.windows
                .iter()
                .filter(|w| w.parent == 0)
                .map(|w| w.hwnd)
                .collect()
        });
        for h in handles {
            unsafe {
                send(h, message, wparam, lparam, wide);
            }
        }
        return 1;
    }
    let sender = current();
    let receiver = state::with(|s| s.windows.iter().find(|w| w.hwnd == hwnd).map(|w| w.thread));
    let Some(receiver) = receiver else {
        return state::error(1400) as i32;
    };
    if sender == receiver {
        return unsafe { crate::invoke(hwnd, message, wparam, lparam, wide) };
    }
    let event = ensure_queue();
    if event == 0 {
        return 0;
    }
    let ticket = state::with(|s| {
        let ticket = s.next_send;
        s.next_send += 1;
        s.sent.push(Sent {
            ticket,
            sender,
            receiver,
            message: Message {
                hwnd,
                message,
                wparam,
                lparam,
                ..Message::default()
            },
            wide,
            started: false,
            result: None,
        });
        if let Some(q) = s.queues.iter().find(|q| q.thread == receiver) {
            wake(q.event);
        }
        ticket
    });
    loop {
        // A blocked sender must service sent messages too: A -> B -> A is legal.
        dispatch_sent(sender);
        let result = state::with(|s| {
            let i = s.sent.iter().position(|r| r.ticket == ticket).unwrap();
            let result = s.sent[i].result?;
            s.sent.remove(i);
            Some(result)
        });
        if let Some(result) = result {
            return result;
        }
        unsafe {
            runtime::WaitForSingleObject(event, u32::MAX);
        }
    }
}
#[unsafe(no_mangle)]
pub extern "system" fn InSendMessage() -> i32 {
    let thread = current();
    state::with(|s| {
        i32::from(
            s.queues
                .iter()
                .any(|q| q.thread == thread && !q.active.is_empty()),
        )
    })
}
#[unsafe(no_mangle)]
pub extern "system" fn ReplyMessage(result: i32) -> i32 {
    let thread = current();
    let ticket = state::with(|s| {
        s.queues
            .iter()
            .find(|q| q.thread == thread)
            .and_then(|q| q.active.last().copied())
    });
    ticket.map_or(0, |ticket| i32::from(reply(ticket, result)))
}

fn queue_bits(q: &Queue) -> u32 {
    let mut bits = if q.messages.is_empty() { 0 } else { 8 | 0x100 };
    for m in &q.input {
        bits |= match m.message {
            0x100..=0x109 => 1,
            0x200 => 2,
            0x201..=0x20e => 4,
            0xf => 0x20,
            _ => 8,
        };
    }
    bits
}
#[unsafe(no_mangle)]
pub extern "system" fn GetQueueStatus(flags: u32) -> u32 {
    ensure_queue();
    pump_input();
    let thread = current();
    state::with(|s| {
        s.queues.iter().find(|q| q.thread == thread).map_or(0, |q| {
            let bits = queue_bits(q) & flags;
            bits | (bits << 16)
        })
    })
}
#[unsafe(no_mangle)]
pub unsafe extern "system" fn MsgWaitForMultipleObjects(
    count: u32,
    handles: *const u32,
    all: u32,
    timeout: u32,
    mask: u32,
) -> u32 {
    if count > 63 || count != 0 && handles.is_null() {
        state::error(87);
        return u32::MAX;
    }
    let event = ensure_queue();
    if event == 0 {
        return u32::MAX;
    }
    let mut waits = alloc::vec![0u32;count as usize+1];
    for i in 0..count as usize {
        waits[i] = unsafe { handles.add(i).read_unaligned() };
    }
    waits[count as usize] = event;
    unsafe extern "system" {
        fn WaitForMultipleObjects(n: u32, handles: *const u32, all: u32, timeout: u32) -> u32;
    }
    let start = now();
    loop {
        pump_input();
        dispatch_sent(current());
        if GetQueueStatus(mask) != 0 {
            if all == 0 || count == 0 {
                return count;
            }
            let r = unsafe { WaitForMultipleObjects(count, waits.as_ptr(), 1, 0) };
            if r == 0 {
                return count;
            }
            if r == u32::MAX {
                return r;
            }
        }
        let elapsed = now().wrapping_sub(start);
        let remaining = if timeout == u32::MAX {
            u32::MAX
        } else {
            timeout.saturating_sub(elapsed)
        };
        let r = unsafe { WaitForMultipleObjects(count + 1, waits.as_ptr(), all, remaining) };
        if r != count {
            return r;
        }
        if timeout != u32::MAX && now().wrapping_sub(start) >= timeout && GetQueueStatus(mask) == 0
        {
            return 258;
        }
    }
}
