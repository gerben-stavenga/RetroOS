//! Per-thread USER timer queues and waitable queue state.
use super::*;
mod keyboard;
use alloc::sync::Arc;
pub(super) use keyboard::enqueue as keyboard_event;
// Checked against Wine headers by the RETROOS.DLL protocol adapter.
const MSG_POSTED: u32 = 6;
struct Timer {
    window: u32,
    id: u64,
    message: u32,
    callback: u64,
    period: u64,
    deadline: u64,
}
#[derive(Default)]
pub(super) struct Foreground {
    tid: u32,
    id: u64,
    offset: u64,
    active: u32,
}
struct Queue {
    tid: u32,
    id: u64,
    offset: u64,
    input_id: u64,
    input_offset: u64,
    event: u32,
    next_timer: u32,
    wake_mask: u32,
    changed_mask: u32,
    wake_bits: u32,
    changed_bits: u32,
    timers: Vec<Timer>,
    keyboard: Vec<keyboard::KeyMessage>,
    posted: Vec<keyboard::Posted>,
    next_key: u32,
    keys: [u8; 256],
    paint: bool,
    foreground: Arc<spin::Mutex<Foreground>>,
    active: u32,
    focus: u32,
    capture: u32,
    menu_owner: u32,
    move_size: u32,
    caret: u32,
    caret_rect: [i32; 4],
    caret_hide: i32,
    caret_state: i32,
}
impl Drop for Queue {
    fn drop(&mut self) {
        let mut fg = self.foreground.lock();
        if fg.id == self.input_id {
            *fg = Foreground::default();
        }
        drop(fg);
        session::release_object(self.offset);
        session::release_object(self.input_offset);
    }
}
pub(super) struct State {
    queues: Vec<Queue>,
    async_keys: [u8; 256],
}
impl Default for State {
    fn default() -> Self {
        Self {
            queues: Vec::new(),
            async_keys: [0; 256],
        }
    }
}
fn refresh(queue: &mut Queue, threads: &mut threads::State, now: u64) {
    let bits = if queue.timers.iter().any(|t| now >= t.deadline) {
        0x10
    } else {
        0
    };
    let bits = bits
        | if queue.keyboard.is_empty() { 0 } else { 1 }
        | if queue.posted.is_empty() { 0 } else { 0x108 };
    let bits = bits | if queue.paint { 0x20 } else { 0 };
    queue.changed_bits |= bits & !queue.wake_bits;
    queue.wake_bits = bits;
    threads::set_signal(
        threads,
        queue.event,
        (bits & queue.wake_mask | queue.changed_bits & queue.changed_mask) != 0,
    );
    let mut shared = [0u8; 28];
    shared[..8].copy_from_slice(&(now / 100).to_le_bytes());
    for (i, value) in [
        queue.wake_mask,
        queue.wake_bits,
        queue.changed_mask,
        queue.changed_bits,
    ]
    .into_iter()
    .enumerate()
    {
        shared[8 + i * 4..12 + i * 4].copy_from_slice(&value.to_le_bytes());
    }
    session::write_object(queue.offset, &shared);
}
pub(super) fn poll<A: crate::Arch>(machine: &mut A, state: &mut WindowsState) {
    let now = machine.now();
    let paints = user_objects::pending_paints(state);
    for queue in &mut state.user_queues.queues {
        queue.paint = paints.iter().any(|p| p.0 == queue.tid);
        refresh(queue, &mut state.threads, now);
    }
}
pub(super) fn set_cursor(state: &mut State, tid: u32, handle: u32, count: i32) {
    if let Some(queue) = state.queues.iter().find(|q| q.tid == tid) {
        let mut data = [0u8; 8];
        data[..4].copy_from_slice(&handle.to_le_bytes());
        data[4..].copy_from_slice(&count.to_le_bytes());
        session::write_object_part(queue.input_offset, 44, &data);
    }
}
pub(super) fn call<A: crate::Arch>(
    machine: &mut A,
    state: &mut WindowsState,
    args: [u32; 3],
) -> u32 {
    let [op, params, out] = args;
    let p: [u32; 10] = core::array::from_fn(|i| machine.read::<u32>(params as usize + i * 4));
    let current_tid = machine.read::<u32>((state.teb_base + 0x24) as usize);
    if op == 7 {
        machine.zero(out as usize, 48);
        if p[0] == 0 {
            if let Some(foreground) = user_objects::foreground(state, current_tid) {
                let fg = foreground.lock();
                machine.write::<u64>(out as usize, fg.id);
                machine.write::<u64>(out as usize + 8, fg.offset);
            }
            return 0;
        }
        if let Some(queue) = state.user_queues.queues.iter().find(|q| q.tid == p[0]) {
            machine.write::<u64>(out as usize, queue.input_id);
            machine.write::<u64>(out as usize + 8, queue.input_offset);
            return 0;
        }
        return if p[0] == current_tid { 0 } else { 0xc000000b };
    }
    if op == 15 {
        let Some(queue) = state.user_queues.queues.iter_mut().find(|q| q.tid == p[0]) else {
            return 0xc000000b;
        };
        queue.posted.push(keyboard::Posted {
            hwnd: p[1],
            message: p[2],
            wparam: p[3] as u64 | ((p[4] as u64) << 32),
            lparam: p[5] as u64 | ((p[6] as u64) << 32),
        });
        queue.changed_bits |= 0x108;
        refresh(queue, &mut state.threads, machine.now());
        return 0;
    }
    let (window, tid) = if matches!(op, 4 | 5) && p[0] != 0 {
        let Some((handle, tid, pid)) = user_objects::window_owner(state, current_tid, p[0]) else {
            return 0xc0000008;
        };
        if tid == 0 || pid != machine.read::<u32>((state.teb_base + 0x20) as usize) {
            return 0xc0000022;
        }
        (handle, tid)
    } else {
        (0, current_tid)
    };
    let window_filter = if op == 6 && p[1] != 0 && p[1] != u32::MAX {
        let Some(windows) = user_objects::window_filter(state, current_tid, p[1]) else {
            return 0xc0010578;
        };
        windows
    } else {
        Vec::new()
    };
    let caret_handle = if matches!(op, 8 | 9 | 11 | 12 | 13) && p[0] != 0 {
        let Some((h, owner, _)) = user_objects::window_owner(state, current_tid, p[0]) else {
            return 0xc0010578;
        };
        if owner != current_tid {
            return 0xc0000022;
        }
        h
    } else {
        0
    };
    let index = if let Some(i) = state.user_queues.queues.iter().position(|q| q.tid == tid) {
        i
    } else {
        let Some(foreground) = user_objects::foreground(state, tid) else {
            return 0xc0000008;
        };
        let id = user_objects::next_id();
        let offset = session::allocate_object(machine, id);
        let input_id = user_objects::next_id();
        let input_offset = session::allocate_object(machine, input_id);
        let event = threads::create_event(state, true, false);
        state.user_queues.queues.push(Queue {
            tid,
            id,
            offset,
            input_id,
            input_offset,
            event,
            next_timer: 0x7fff,
            wake_mask: 0,
            changed_mask: 0,
            wake_bits: 0,
            changed_bits: 0,
            timers: Vec::new(),
            keyboard: Vec::new(),
            posted: Vec::new(),
            next_key: 0,
            keys: [0; 256],
            paint: false,
            foreground,
            active: 0,
            focus: 0,
            capture: 0,
            menu_owner: 0,
            move_size: 0,
            caret: 0,
            caret_rect: [0; 4],
            caret_hide: 1,
            caret_state: 0,
        });
        let (cursor, count) = user_objects::input_cursor(state, tid);
        set_cursor(&mut state.user_queues, tid, cursor, count);
        state.user_queues.queues.len() - 1
    };
    if op == 10 {
        machine.zero(out as usize, 48);
        let Some((_, owner, pid, is_desktop)) =
            user_objects::foreground_window(state, current_tid, p[0])
        else {
            return 0xc0010578;
        };
        if !is_desktop && pid != machine.read::<u32>((state.teb_base + 0x20) as usize) {
            return 0xc00000bb; // Cross-process input queues are not implemented yet.
        }
        let Some(target) = state.user_queues.queues.iter().find(|q| q.tid == owner) else {
            return 0xc0010578;
        };
        let mut fg = target.foreground.lock();
        machine.write::<u32>(out as usize, fg.active);
        machine.write::<u32>(
            out as usize + 4,
            (fg.active != 0 && fg.tid != current_tid) as u32,
        );
        let clear = is_desktop && p[1] == 0;
        if fg.id != target.input_id || clear {
            if fg.id != 0 {
                session::write_object_part(fg.offset, 0, &0u32.to_le_bytes());
            }
            if clear {
                *fg = Foreground::default();
            } else {
                *fg = Foreground {
                    tid: owner,
                    id: target.input_id,
                    offset: target.input_offset,
                    active: target.active,
                };
                session::write_object_part(fg.offset, 0, &1u32.to_le_bytes());
            }
        }
        machine.write::<u32>(out as usize + 8, (fg.tid != current_tid) as u32);
        return 0;
    }
    if op == 6
        && keyboard::read(
            machine,
            &mut state.user_queues.queues[index],
            &p,
            &window_filter,
            out,
        )
    {
        poll(machine, state);
        return 0;
    }
    let paints = user_objects::pending_paints(state);
    if op == 6
        && p[7] == 0
        && (p[0] >> 16 == 0 || p[0] >> 16 & 0x20 != 0)
        && (p[2] == 0 && p[3] == 0 || (p[2]..=p[3]).contains(&0xf))
    {
        if let Some(&(_, hwnd)) = paints
            .iter()
            .find(|&&(t, h)| t == tid && (p[1] == 0 || window_filter.contains(&h)))
        {
            machine.zero(out as usize, 48);
            machine.write::<u32>(out as usize, hwnd);
            machine.write::<u32>(out as usize + 4, 0xf);
            machine.write::<u32>(out as usize + 24, MSG_POSTED);
            if p[0] & 1 != 0 {
                user_objects::consume_internal_paint(state, tid, hwnd);
            }
            poll(machine, state);
            return 0;
        }
    }
    if op == 11 && caret_handle != 0 {
        user_objects::mark_active(state, current_tid, caret_handle);
    }
    let queue = &mut state.user_queues.queues[index];
    queue.paint = paints.iter().any(|p| p.0 == tid);
    let now = machine.now();
    refresh(queue, &mut state.threads, now);
    machine.zero(out as usize, 48);
    let mut status = 0;
    match op {
        14 => {
            if let Some(i) = queue.keyboard.iter().position(|m| m.id == p[0]) {
                let message = queue.keyboard.remove(i);
                queue.keys = message.keys;
                session::write_object_part(queue.input_offset, 52, &queue.keys);
                session::write_object_part(queue.input_offset, 308, &1u32.to_le_bytes());
            }
        }
        16 => {
            let key = p[1] as usize & 255;
            let value = if p[0] != 0 {
                let v = state.user_queues.async_keys[key];
                state.user_queues.async_keys[key] &= !0x40;
                v
            } else {
                queue.keys[key]
            };
            machine.write::<u32>(out as usize, value as u32);
        }
        17 => {
            if p[0] != 0 {
                return 0xc00000bb;
            }
            for (i, key) in queue.keys.iter_mut().enumerate() {
                *key = machine.read::<u8>(p[1] as usize + i);
            }
            session::write_object_part(queue.input_offset, 52, &queue.keys);
            session::write_object_part(queue.input_offset, 308, &1u32.to_le_bytes());
        }
        18 => {
            queue.posted.push(keyboard::Posted {
                hwnd: 0,
                message: 0x12,
                wparam: p[0] as u64,
                lparam: 0,
            });
            queue.changed_bits |= 0x108;
        }

        11 | 12 | 13 => {
            let previous = match op {
                11 => queue.active,
                12 => queue.focus,
                _ => queue.capture,
            };
            if op == 13 && queue.menu_owner != 0 && p[1] & 1 == 0 {
                return 0xc0000022;
            }
            machine.write::<u32>(out as usize, previous);
            match op {
                11 => {
                    queue.active = caret_handle;
                    let mut fg = queue.foreground.lock();
                    if fg.id == queue.input_id {
                        fg.active = caret_handle;
                    }
                }
                12 => queue.focus = caret_handle,
                _ => {
                    queue.capture = caret_handle;
                    queue.menu_owner = if p[1] & 1 != 0 { caret_handle } else { 0 };
                    queue.move_size = if p[1] & 2 != 0 { caret_handle } else { 0 };
                    machine.write::<u32>(out as usize + 4, caret_handle);
                }
            }
            sync_activation(queue);
        }
        8 | 9 => {
            machine.write::<u32>(out as usize, queue.caret);
            for (j, value) in queue.caret_rect.iter().enumerate() {
                machine.write::<i32>(out as usize + 4 + j * 4, *value);
            }
            machine.write::<i32>(out as usize + 20, queue.caret_hide);
            machine.write::<i32>(out as usize + 24, queue.caret_state);
            if op == 8 {
                if caret_handle == 0 || caret_handle != queue.caret {
                    queue.caret_rect = [0; 4];
                }
                queue.caret = caret_handle;
                queue.caret_hide = 1;
                queue.caret_state = 0;
                queue.caret_rect[2] = queue.caret_rect[0].wrapping_add(p[1] as i32);
                queue.caret_rect[3] = queue.caret_rect[1].wrapping_add(p[2] as i32);
            } else {
                if caret_handle != 0 && caret_handle != queue.caret {
                    return 0xc0000022;
                }
                let old = queue.caret_rect;
                if p[1] & 1 != 0 {
                    queue.caret_rect = [
                        p[2] as i32,
                        p[3] as i32,
                        (p[2] as i32).wrapping_add(old[2].wrapping_sub(old[0])),
                        (p[3] as i32).wrapping_add(old[3].wrapping_sub(old[1])),
                    ];
                }
                if p[1] & 2 != 0 {
                    queue.caret_hide = queue.caret_hide.saturating_add(p[4] as i32).max(0);
                }
                if p[1] & 4 != 0 {
                    match p[5] {
                        0 | 1 => queue.caret_state = p[5] as i32,
                        2 => queue.caret_state ^= 1,
                        3 if p[2] as i32 != old[0] || p[3] as i32 != old[1] => {
                            queue.caret_state = 1
                        }
                        _ => (),
                    }
                }
            }
            sync_caret(queue);
        }
        0 => {
            machine.write::<u64>(out as usize, queue.id);
            machine.write::<u64>(out as usize + 8, queue.offset);
        }
        1 => machine.write::<u32>(out as usize, queue.event),
        2 | 3 => {
            machine.write::<u32>(out as usize, queue.wake_bits);
            machine.write::<u32>(out as usize + 4, queue.changed_bits);
            if op == 2 {
                queue.wake_mask = p[0];
                queue.changed_mask = p[1];
            } else {
                queue.changed_bits &= !p[0];
            }
        }
        4 => {
            if !matches!(p[1], 0x113 | 0x118) {
                return 0xc000000d;
            }
            let mut id = p[3] as u64 | ((p[4] as u64) << 32);
            let index = queue
                .timers
                .iter()
                .position(|t| t.window == window && t.id == id && t.message == p[1]);
            if window == 0 && index.is_none() {
                let mut found = false;
                for _ in 0x101..=0x7fff {
                    id = queue.next_timer as u64;
                    queue.next_timer = if queue.next_timer <= 0x101 {
                        0x7fff
                    } else {
                        queue.next_timer - 1
                    };
                    if !queue
                        .timers
                        .iter()
                        .any(|t| t.window == 0 && t.id == id && t.message == p[1])
                    {
                        found = true;
                        break;
                    }
                }
                if !found {
                    return 0xc000009a;
                }
            }
            let period = u64::from(p[2].max(1)) * 1_000_000;
            let timer = Timer {
                window,
                id,
                message: p[1],
                callback: p[5] as u64 | ((p[6] as u64) << 32),
                period,
                deadline: now.saturating_add(period),
            };
            if let Some(i) = index {
                queue.timers[i] = timer;
            } else {
                queue.timers.push(timer);
            }
            machine.write::<u64>(out as usize, id);
        }
        5 => {
            let id = p[3] as u64 | ((p[4] as u64) << 32);
            let Some(i) = queue
                .timers
                .iter()
                .position(|t| t.window == window && t.id == id && t.message == p[1])
            else {
                return 0xc000000d;
            };
            queue.timers.remove(i);
        }
        6 => {
            if p[7] != 0 {
                return 0x103;
            } // driver-internal messages only
            let filter = p[0] >> 16;
            let index = queue.timers.iter().position(|t| {
                now >= t.deadline
                    && (filter == 0 || filter & 0x10 != 0)
                    && (p[1] == 0
                        || (p[1] == u32::MAX && t.window == 0)
                        || window_filter.contains(&t.window))
                    && (p[2] == 0 && p[3] == 0 || (p[2]..=p[3]).contains(&t.message))
            });
            if let Some(i) = index {
                let timer = &mut queue.timers[i];
                machine.write::<u32>(out as usize, timer.window);
                machine.write::<u32>(out as usize + 4, timer.message);
                machine.write::<u64>(out as usize + 8, timer.id);
                machine.write::<u64>(out as usize + 16, timer.callback);
                machine.write::<u32>(out as usize + 24, MSG_POSTED); // MSG_POSTED
                machine.write::<u32>(out as usize + 36, (now / 1_000_000) as u32);
                if p[0] & 1 != 0 {
                    timer.deadline = now.saturating_add(timer.period);
                }
            } else {
                queue.wake_mask = p[5];
                queue.changed_mask = p[6];
                status = 0x103;
            }
            queue.changed_bits &= !0x10;
        }
        _ => return 0xc000000d,
    }
    refresh(queue, &mut state.threads, now);
    if op == 16 && p[0] != 0 {
        user_objects::keyboard_state(state, current_tid, &state.user_queues.async_keys);
    }
    status
}

pub(super) fn remove_windows(state: &mut State, handles: &[u32]) {
    for queue in &mut state.queues {
        queue.timers.retain(|t| !handles.contains(&t.window));
        queue.keyboard.retain(|m| !handles.contains(&m.hwnd));
        queue.posted.retain(|m| !handles.contains(&m.hwnd));
        for h in [
            &mut queue.active,
            &mut queue.focus,
            &mut queue.capture,
            &mut queue.menu_owner,
            &mut queue.move_size,
        ] {
            if handles.contains(h) {
                *h = 0;
            }
        }
        {
            let mut fg = queue.foreground.lock();
            if fg.id == queue.input_id {
                fg.active = queue.active;
            }
        }
        sync_activation(queue);
        if handles.contains(&queue.caret) {
            queue.caret = 0;
            queue.caret_rect = [0; 4];
            queue.caret_hide = 1;
            queue.caret_state = 0;
            sync_caret(queue);
        }
    }
}

fn sync_caret(queue: &Queue) {
    let mut data = [0u8; 20];
    data[..4].copy_from_slice(&queue.caret.to_le_bytes());
    for (i, v) in queue.caret_rect.iter().enumerate() {
        data[4 + i * 4..8 + i * 4].copy_from_slice(&v.to_le_bytes());
    }
    session::write_object_part(queue.input_offset, 24, &data);
}

fn sync_activation(queue: &Queue) {
    let mut data = [0u8; 20];
    for (i, v) in [
        queue.active,
        queue.focus,
        queue.capture,
        queue.menu_owner,
        queue.move_size,
    ]
    .iter()
    .enumerate()
    {
        data[i * 4..i * 4 + 4].copy_from_slice(&v.to_le_bytes());
    }
    session::write_object_part(queue.input_offset, 4, &data);
}
