//! Pixel transport only: Wine owns drawing and window policy; RetroOS owns
//! snapshots consumed by its compositor. Guest pointers never escape this call.
use super::*;

pub(super) fn call<A: crate::Arch>(machine: &mut A, state: &mut WindowsState, args: [u32; 3]) -> u32 {
    let [op, params, out] = args;
    if op == 0 {
        for (i, n) in [640u32, 480, 32].into_iter().enumerate() {
            machine.write::<u32>(out as usize + i * 4, n);
        }
        return 0;
    }
    if !(1..=3).contains(&op) { return 0xc000000d; }
    let p: [u32; 12] = core::array::from_fn(|i| machine.read::<u32>(params as usize + i * 4));
    let tid = machine.read::<u32>((state.teb_base + 0x24) as usize);
    let Some((hwnd, _, pid)) = user_objects::window_owner(state, tid, p[0]) else {
        return 0xc0010578;
    };
    if pid != machine.read::<u32>((state.teb_base + 0x20) as usize) { return 0xc0000022; }
    let mut p = p;
    p[0] = hwnd;
    transport(state, op, p, |address, bytes| machine.copy_from(address, bytes))
}

fn transport(state: &mut WindowsState, op: u32, p: [u32; 12], mut copy: impl FnMut(usize, &mut [u8])) -> u32 {
    let hwnd = p[0];
    let index = state.windows.iter().position(|w| w.hwnd == hwnd);
    if op == 2 {
        if let Some(i) = index { state.windows.remove(i); state.dirty = true; }
        return 0;
    }
    if op == 3 {
        if let Some(i) = index {
            let w = &mut state.windows[i];
            w.x = p[1] as i32; w.y = p[2] as i32; w.visible = p[10] != 0;
            // The compositor stores back-to-front order; HWND_BOTTOM is 1.
            let w = state.windows.remove(i);
            let at = if p[11] == 1 { 0 } else {
                state.windows.iter().position(|w| w.hwnd == p[11]).unwrap_or(state.windows.len())
            };
            state.windows.insert(at, w);
            state.dirty = true;
        }
        return 0;
    }
    let (width, height) = (p[3] as usize, p[4] as usize);
    if width == 0 || height == 0 || width > 4096 || height > 4096
        || p[5].checked_add((width * height * 4) as u32).is_none()
        || p[6] > p[8] || p[7] > p[9] || p[8] as usize > width || p[9] as usize > height {
        return 0xc000000d;
    }
    let i = if let Some(i) = index { i } else {
        state.windows.push(Window { hwnd, parent: 0, x: 0, y: 0, width: 0, height: 0, visible: false, pixels: Vec::new() });
        state.windows.len() - 1
    };
    let w = &mut state.windows[i];
    let resized = w.width != p[3] || w.height != p[4];
    w.width = p[3]; w.height = p[4]; w.x = p[1] as i32; w.y = p[2] as i32; w.visible = p[10] != 0;
    w.pixels.resize(width * height * 4, 0);
    // A newly allocated snapshot needs all pixels, even if Wine's damage is small.
    let [left, top, right, bottom] = if resized { [0, 0, width, height] }
        else { [p[6] as usize, p[7] as usize, p[8] as usize, p[9] as usize] };
    for y in top..bottom {
        let start = (y * width + left) * 4;
        let end = (y * width + right) * 4;
        copy(p[5] as usize + start, &mut w.pixels[start..end]);
        // Wine's top-down BI_RGB is BGRX; existing Windows surfaces use RGBX.
        for pixel in w.pixels[start..end].chunks_exact_mut(4) { pixel.swap(0, 2); pixel[3] = 255; }
    }
    state.dirty = true;
    0
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn snapshots_damage_resize_and_lifecycle() {
        let mut state = WindowsState::new();
        let mut p = [7, 10, 20, 2, 1, 0, 1, 0, 2, 1, 1, 0];
        let source = [3, 2, 1, 0, 6, 5, 4, 0];
        assert_eq!(transport(&mut state, 1, p, |a, b| b.copy_from_slice(&source[a..a+b.len()])), 0);
        assert_eq!(state.windows[0].pixels, [1, 2, 3, 255, 4, 5, 6, 255]);
        assert_eq!((state.windows[0].x, state.windows[0].y), (10, 20));
        let source = [30, 20, 10, 0, 60, 50, 40, 0];
        assert_eq!(transport(&mut state, 1, p, |a, b| b.copy_from_slice(&source[a..a+b.len()])), 0);
        assert_eq!(state.windows[0].pixels, [1, 2, 3, 255, 40, 50, 60, 255]);
        p[3] = 1; p[6] = 0; p[8] = 1;
        assert_eq!(transport(&mut state, 1, p, |a, b| b.copy_from_slice(&source[a..a+b.len()])), 0);
        assert_eq!(state.windows[0].pixels, [10, 20, 30, 255]);
        p[1] = 42; p[10] = 0;
        assert_eq!(transport(&mut state, 3, p, |_, _| panic!("position must not read pixels")), 0);
        assert_eq!(state.windows[0].x, 42);
        assert!(!state.windows[0].visible);
        p[8] = 2;
        assert_eq!(transport(&mut state, 1, p, |_, _| panic!("invalid damage must not read pixels")), 0xc000000d);
        assert_eq!(transport(&mut state, 2, p, |_, _| panic!("destroy must not read pixels")), 0);
        assert!(state.windows.is_empty());
    }
}
