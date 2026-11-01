//! Physical mouse packets enter the same Wine hardware queue as keyboard input.
//! Wine performs child hit-testing, activation, client conversion and capture.
use super::*;

pub(in crate::kernel::windows) fn enqueue(state: &mut WindowsState, buttons: u8, now: u64) {
    let Some(desktop_tid) = state.user_queues.queues.first().map(|q| q.tid) else {
        return;
    };
    (state.mouse_x, state.mouse_y) =
        user_objects::mouse_position(state, desktop_tid, state.mouse_x, state.mouse_y, now);
    let keys = &mut state.user_queues.async_keys;
    for (bit, vk) in [(1, 1), (2, 2), (4, 4)] {
        if (state.mouse_buttons ^ buttons) & bit != 0 {
            keyboard::update(keys, vk, buttons & bit != 0);
        }
    }
    let keys = *keys;
    let captured = state
        .user_queues
        .queues
        .iter()
        .find(|q| q.capture != 0)
        .map(|q| (q.tid, q.capture));
    let target = captured
        .or_else(|| user_objects::mouse_target(state, desktop_tid, state.mouse_x, state.mouse_y));
    let Some((tid, hwnd)) = target else {
        return;
    };
    let Some(queue) = state.user_queues.queues.iter_mut().find(|q| q.tid == tid) else {
        return;
    };
    let wparam = u32::from(buttons & 1 != 0)
        | (u32::from(buttons & 2 != 0) << 1)
        | (u32::from(buttons & 4 != 0) << 4)
        | (u32::from(keys[0x10] & 0x80 != 0) << 2)
        | (u32::from(keys[0x11] & 0x80 != 0) << 3);
    let mut messages = vec![(0x200, 2)];
    for (bit, down, up) in [(1, 0x201, 0x202), (2, 0x204, 0x205), (4, 0x207, 0x208)] {
        if (state.mouse_buttons ^ buttons) & bit != 0 {
            messages.push((if buttons & bit != 0 { down } else { up }, 4));
        }
    }
    for (message, mask) in messages {
        // Coalesce only adjacent moves, never across a button transition.
        if message == 0x200 && queue.hardware.last().is_some_and(|m| m.message == 0x200) {
            queue.hardware.pop();
        }
        queue.next_key = queue.next_key.wrapping_add(1).max(1);
        queue.hardware.push(keyboard::HardwareMessage {
            id: queue.next_key,
            hwnd,
            message,
            vk: wparam,
            flags: 0,
            time: (now / 1_000_000) as u32,
            keys,
            x: state.mouse_x,
            y: state.mouse_y,
            mask,
        });
        queue.changed_bits |= mask;
    }
    refresh(queue, &mut state.threads, now);
    user_objects::keyboard_state(state, tid, &keys);
}
