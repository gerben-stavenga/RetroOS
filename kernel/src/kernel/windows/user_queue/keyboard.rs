//! Native keyboard delivery to Wine's per-thread hardware queues.
use super::*;

#[derive(Clone)]
pub(super) struct KeyMessage {
    pub id: u32,
    pub hwnd: u32,
    pub message: u32,
    pub vk: u32,
    pub flags: u32,
    pub time: u32,
    pub keys: [u8; 256],
}
#[derive(Clone)]
pub(super) struct Posted {
    pub hwnd: u32,
    pub message: u32,
    pub wparam: u64,
    pub lparam: u64,
}

fn update(keys: &mut [u8; 256], vk: usize, down: bool) {
    if down {
        if keys[vk] & 0x80 == 0 {
            keys[vk] ^= 1;
        }
        keys[vk] |= 0xc0;
    } else {
        keys[vk] &= !0x80;
    }
    for (generic, left, right) in [(0x10, 0xa0, 0xa1), (0x11, 0xa2, 0xa3), (0x12, 0xa4, 0xa5)] {
        if vk == left || vk == right {
            let pressed = (keys[left] | keys[right]) & 0x80;
            if down {
                if keys[generic] & 0x80 == 0 { keys[generic] ^= 1; }
                keys[generic] |= 0x40;
            }
            keys[generic] = (keys[generic] & !0x80) | pressed;
        }
    }
}

pub(in crate::kernel::windows) fn enqueue(
    state: &mut WindowsState,
    event: lib::keyboard::Event,
    control: u32,
    now: u64,
) {
    let mut vk = extra::virtual_key(event.scan as u16, 0) as usize;
    vk = match event.scan {
        0x2a => 0xa0,
        0x36 => 0xa1,
        0x1d => {
            if event.extended {
                0xa3
            } else {
                0xa2
            }
        }
        0x38 => {
            if event.extended {
                0xa5
            } else {
                0xa4
            }
        }
        0x35 if event.extended => 0x6f,
        0x37 if event.extended => 0x2c,
        0x57 => 0x7a,
        0x58 => 0x7b,
        0x5b if event.extended => 0x5b,
        0x5c if event.extended => 0x5c,
        0x5d if event.extended => 0x5d,
        0x4c => 0x0c,
        _ => vk,
    };
    if lib::keyboard::current() == lib::keyboard::Layout::De {
        if event.scan == 0x15 {
            vk = b'Z' as usize;
        }
        if event.scan == 0x2c {
            vk = b'Y' as usize;
        }
    }
    if !event.extended && control & (1 << 5) != 0 && control & (1 << 4) == 0 {
        vk = match event.scan {
            0x47..=0x49 => 0x67 + (event.scan - 0x47) as usize,
            0x4b..=0x4d => 0x64 + (event.scan - 0x4b) as usize,
            0x4f..=0x51 => 0x61 + (event.scan - 0x4f) as usize,
            0x52 => 0x60,
            0x53 => 0x6e,
            _ => vk,
        };
    }
    if vk == 0 {
        return;
    }
    let keys = &mut state.user_queues.async_keys;
    let alt = keys[0x12] & 0x80 != 0;
    let ctrl = keys[0x11] & 0x80 != 0;
    let system = vk == 0x79 || (!ctrl && (alt || matches!(vk, 0xa4 | 0xa5)));
    let previous = keys[vk] & 0x80 != 0;
    update(keys, vk, event.pressed);
    for (key, bit) in [(0x14, 7), (0x90, 5), (0x91, 6)] {
        keys[key] = (keys[key] & 0xc0) | ((control >> bit) as u8 & 1);
    }
    let keys = *keys;
    let Some(queue) = state.user_queues.queues.iter_mut().find(|q| {
        let fg = q.foreground.lock();
        fg.tid == q.tid && fg.id == q.input_id && (q.focus != 0 || q.active != 0)
    }) else {
        return;
    };
    let hwnd = if queue.focus != 0 {
        queue.focus
    } else {
        queue.active
    };
    let message = if system || queue.focus == 0 {
        0x104
    } else {
        0x100
    } + u32::from(!event.pressed);
    let flags = 1
        | ((event.scan as u32) << 16)
        | (u32::from(event.extended) << 24)
        | (u32::from(alt) << 29)
        | (u32::from(previous || !event.pressed) << 30)
        | (u32::from(!event.pressed) << 31);
    queue.next_key = queue.next_key.wrapping_add(1).max(1);
    queue.keyboard.push(KeyMessage {
        id: queue.next_key,
        hwnd,
        message,
        vk: vk as u32,
        flags,
        time: (now / 1_000_000) as u32,
        keys,
    });
    queue.changed_bits |= 1;
    let tid = queue.tid;
    refresh(queue, &mut state.threads, now);
    user_objects::keyboard_state(state, tid, &keys);
}

pub(super) fn read<A: crate::Arch>(
    machine: &mut A,
    queue: &mut Queue,
    p: &[u32; 10],
    windows: &[u32],
    out: u32,
) -> bool {
    if p[7] != 0 {
        return false;
    }
    let hwnd_matches = |h| p[1] == 0 || (p[1] == u32::MAX && h == 0) || windows.contains(&h);
    let msg_matches = |m| p[2] == 0 && p[3] == 0 || (p[2]..=p[3]).contains(&m);
    let filter = p[0] >> 16;
    if filter == 0 || filter & 8 != 0 {
        if let Some(i) = queue
            .posted
            .iter()
            .position(|m| m.message == 0x12 || hwnd_matches(m.hwnd) && msg_matches(m.message))
        {
            let m = &queue.posted[i];
            machine.zero(out as usize, 48);
            machine.write::<u32>(out as usize, m.hwnd);
            machine.write::<u32>(out as usize + 4, m.message);
            machine.write::<u64>(out as usize + 8, m.wparam);
            machine.write::<u64>(out as usize + 16, m.lparam);
            machine.write::<u32>(out as usize + 24, MSG_POSTED);
            if p[0] & 1 != 0 {
                queue.posted.remove(i);
            }
            return true;
        }
    }
    if filter != 0 && filter & (1 | 0x400) == 0 {
        return false;
    }
    let start = queue
        .keyboard
        .iter()
        .position(|m| m.id == p[4])
        .map_or(0, |i| i + 1);
    let Some(m) = queue.keyboard[start..]
        .iter()
        .find(|m| hwnd_matches(m.hwnd) && msg_matches(m.message))
    else {
        return false;
    };
    machine.zero(out as usize, 48);
    for (i, v) in [
        (0, m.hwnd),
        (1, m.message),
        (2, m.vk),
        (4, m.flags),
        (6, 7),
        (9, m.time),
        (10, m.id),
    ] {
        machine.write::<u32>(out as usize + i * 4, v);
    }
    true
}

#[cfg(test)]
mod tests {
    use super::update;
    #[test]
    fn modifiers_keep_the_other_side_and_do_not_reassert_consumed_async_bits() {
        let mut keys=[0;256];
        update(&mut keys,0xa0,true);
        update(&mut keys,0xa1,true);
        update(&mut keys,0xa0,false);
        assert_eq!(keys[0x10]&0x80,0x80);
        keys[0x10]&=!0x40;
        update(&mut keys,b'A' as usize,true);
        assert_eq!(keys[0x10]&0x40,0);
        update(&mut keys,0xa1,false);
        assert_eq!(keys[0x10]&0x80,0);
    }
}
