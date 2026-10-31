//! Window damage in window-local coordinates. Regions are canonical horizontal
//! bands, as required by Wine's wire format, rather than bounding-box approximations.
use super::*;
type Rect = [i32; 4];
#[derive(Default)]
pub(super) struct Damage {
    pub region: Vec<Rect>,
    pub flags: u32,
}
fn valid(r: Rect) -> bool {
    r[0] < r[2] && r[1] < r[3]
}
fn shift(r: Rect, x: i32, y: i32) -> Rect {
    [
        r[0].saturating_add(x),
        r[1].saturating_add(y),
        r[2].saturating_add(x),
        r[3].saturating_add(y),
    ]
}
// operation: union=0, intersection=1, subtraction=2.
fn combine(a: &[Rect], b: &[Rect], op: u32) -> Vec<Rect> {
    let mut ys: Vec<i32> = a
        .iter()
        .chain(b)
        .filter(|r| valid(**r))
        .flat_map(|r| [r[1], r[3]])
        .collect();
    ys.sort_unstable();
    ys.dedup();
    let mut result: Vec<Rect> = Vec::new();
    let mut previous = 0..0;
    for y in ys.windows(2) {
        let active = |r: &&Rect| r[1] <= y[0] && r[3] >= y[1];
        let aa: Vec<_> = a.iter().filter(active).collect();
        let bb: Vec<_> = b.iter().filter(active).collect();
        let mut xs: Vec<i32> = aa.iter().chain(&bb).flat_map(|r| [r[0], r[2]]).collect();
        xs.sort_unstable();
        xs.dedup();
        let mut band: Vec<Rect> = Vec::new();
        for x in xs.windows(2) {
            let ina = aa.iter().any(|r| r[0] <= x[0] && r[2] >= x[1]);
            let inb = bb.iter().any(|r| r[0] <= x[0] && r[2] >= x[1]);
            if !match op {
                0 => ina || inb,
                1 => ina && inb,
                _ => ina && !inb,
            } {
                continue;
            }
            if let Some(last) = band.last_mut().filter(|r| r[2] == x[0]) {
                last[2] = x[1];
            } else {
                band.push([x[0], y[0], x[1], y[1]]);
            }
        }
        if !band.is_empty()
            && previous.len() == band.len()
            && result[previous.clone()]
                .iter()
                .zip(&band)
                .all(|(a, b)| a[0] == b[0] && a[2] == b[2] && a[3] == b[1])
        {
            for r in &mut result[previous.clone()] {
                r[3] = y[1];
            }
        } else {
            previous = result.len()..result.len() + band.len();
            result.extend(band);
        }
    }
    result
}
fn client(w: &WindowRecord) -> Rect {
    shift(
        w.client_rect,
        w.rect[0].saturating_neg(),
        w.rect[1].saturating_neg(),
    )
}
fn whole(w: &WindowRecord) -> Rect {
    [
        0,
        0,
        w.rect[2].saturating_sub(w.rect[0]),
        w.rect[3].saturating_sub(w.rect[1]),
    ]
}
fn origin(windows: &[WindowRecord], i: usize) -> (i32, i32) {
    let mut x = windows[i].rect[0];
    let mut y = windows[i].rect[1];
    let mut parent = windows[i].parent;
    while let Some(w) = windows.iter().find(|w| w.handle == parent) {
        x = x.saturating_add(w.client_rect[0]);
        y = y.saturating_add(w.client_rect[1]);
        parent = w.parent;
    }
    (x, y)
}
pub(super) fn visible(windows: &[WindowRecord], i: usize) -> bool {
    let mut handle = windows[i].handle;
    while let Some(w) = windows.iter().find(|w| w.handle == handle) {
        if !w.linked || w.style & 0x10000000 == 0 {
            return false;
        }
        handle = w.parent;
    }
    true
}
pub(super) fn positioned(w: &mut WindowRecord, old: Rect, flags: u32) {
    if flags & 8 != 0 {
        return;
    } // SWP_NOREDRAW
    if w.style & 0x10000000 == 0 {
        w.damage = Damage::default();
        return;
    }
    if old != w.rect || flags & (0x20 | 0x40) != 0 {
        w.damage.region = vec![whole(w)];
        w.damage.region.retain(|r| valid(*r));
        w.damage.flags |= 3;
    }
}
fn update_flags(w: &WindowRecord, wanted: u32) -> u32 {
    let mut flags = w.damage.flags & 8;
    if !w.damage.region.is_empty() {
        flags |= 4 | (w.damage.flags & 3);
    }
    flags &= wanted;
    if flags & 12 != 0 {
        flags |= w.damage.flags & 0x80;
    }
    flags
}
pub(super) fn call<A: crate::Arch>(
    machine: &mut A,
    windows: &mut Vec<WindowRecord>,
    op: u32,
    p: [u32; 16],
    out: u32,
) -> u32 {
    let Some(root) = windows
        .iter()
        .position(|w| matches_handle(w.handle, p[0]) || (op == 14 && p[0] == 0 && w.parent == 0))
    else {
        return 0xc0010578;
    };
    if op == 14 {
        // p: window, RDW flags, input region address, byte count.
        if p[3] % 16 != 0 || p[3] > 65536 {
            return 0xc000000d;
        }
        let mut input = Vec::new();
        for n in 0..p[3] / 16 {
            let r = core::array::from_fn(|j| {
                machine.read::<i32>(p[2] as usize + n as usize * 16 + j * 4)
            });
            if r[0] > r[2] || r[1] > r[3] {
                return 0xc000000d;
            }
            input.push(r);
        }
        let mut pending = vec![(root, if p[3] == 0 { None } else { Some(input) }, p[1])];
        while let Some((i, region, flags)) = pending.pop() {
            if !visible(windows, i) {
                continue;
            }
            let w = &mut windows[i];
            let c = client(w);
            let bounds = if flags & 0x400 != 0 && flags & 1 != 0 {
                whole(w)
            } else {
                c
            };
            let local: Vec<Rect> = region.as_ref().map_or_else(
                || vec![bounds],
                |rs| rs.iter().map(|r| shift(*r, c[0], c[1])).collect(),
            );
            let local = combine(&local, &[bounds], 1);
            if flags & 1 != 0 {
                w.damage.region = combine(&w.damage.region, &local, 0);
                if flags & 0x400 != 0 {
                    w.damage.flags |= 1;
                }
                if flags & 4 != 0 {
                    w.damage.flags |= 2;
                }
            } else if flags & 8 != 0 {
                if region.is_none() && flags & 0x800 != 0 {
                    w.damage.region.clear();
                } else {
                    w.damage.region = combine(&w.damage.region, &local, 2);
                }
                if flags & 0x800 != 0 {
                    w.damage.region = combine(&w.damage.region, &[c], 1);
                    w.damage.flags &= !1;
                }
                if flags & 0x20 != 0 {
                    w.damage.flags &= !(2 | 0x80);
                }
            }
            if flags & 2 != 0 {
                w.damage.flags |= 8;
            } else if flags & 0x10 != 0 {
                w.damage.flags &= !8;
            }
            if flags & 0x40 != 0
                || w.style & 0x20000000 != 0
                || (w.style & 0x2000000 != 0 && flags & 0x80 == 0)
            {
                continue;
            }
            let parent = w.handle;
            let parent_local = combine(&local, &[c], 1);
            for (j, child) in windows
                .iter()
                .enumerate()
                .rev()
                .filter(|(_, w)| w.parent == parent)
            {
                let child_region = parent_local
                    .iter()
                    .map(|r| {
                        shift(
                            *r,
                            c[0].saturating_neg().saturating_sub(child.client_rect[0]),
                            c[1].saturating_neg().saturating_sub(child.client_rect[1]),
                        )
                    })
                    .collect();
                pending.push((
                    j,
                    Some(child_region),
                    flags | if flags & 1 != 0 { 0x404 } else { 0 },
                ));
            }
        }
        return 0;
    }
    // p: window, from_child, UPDATE flags, output region, capacity.
    let from = if p[1] == 0 {
        None
    } else {
        windows.iter().position(|w| matches_handle(w.handle, p[1]))
    };
    if p[1] != 0 {
        let Some(mut i) = from else {
            return 0xc0010578;
        };
        while i != root {
            let Some(parent) = windows.iter().position(|w| w.handle == windows[i].parent) else {
                return 0xc000000d;
            };
            i = parent;
        }
    }
    if p[2] & 0x80 != 0 {
        windows[from.unwrap_or(root)].damage.flags |= 0x80;
    }
    let mut candidates = Vec::new();
    let mut pending = vec![root];
    while let Some(i) = pending.pop() {
        if !visible(windows, i) {
            continue;
        }
        candidates.push(i);
        if p[2] & 0x20 == 0
            && windows[i].style & 0x20000000 == 0
            && (p[2] & 0x10 != 0 || windows[i].style & 0x2000000 != 0)
        {
            pending.extend(
                windows
                    .iter()
                    .enumerate()
                    .rev()
                    .filter(|(_, w)| w.parent == windows[i].handle)
                    .map(|(i, _)| i),
            );
        }
    }
    let start = from
        .and_then(|i| candidates.iter().position(|&j| j == i))
        .map_or(0, |n| n + 1);
    let chosen = candidates
        .iter()
        .skip(start)
        .copied()
        .find(|&i| update_flags(&windows[i], p[2]) != 0);
    let i = chosen.unwrap_or(root);
    let flags = chosen.map_or(0, |i| update_flags(&windows[i], p[2]));
    machine.write::<u32>(out as usize, windows[i].handle);
    machine.write::<u32>(out as usize + 4, flags);
    if p[2] & 0x40 != 0 {
        return 0;
    }
    let mut region = windows[i].damage.region.clone();
    if p[2] & 0x100 != 0 && windows[i].style & 0x2000000 != 0 {
        let c = client(&windows[i]);
        for child in windows
            .iter()
            .filter(|w| w.parent == windows[i].handle && w.linked && w.style & 0x10000000 != 0)
        {
            region = combine(&region, &[shift(child.rect, c[0], c[1])], 2);
        }
    }
    let bytes = region.len() * 16;
    machine.write::<u32>(out as usize + 8, bytes as u32);
    if bytes > p[4] as usize {
        return 0x80000005;
    }
    let (x, y) = origin(windows, i);
    for (n, r) in region.iter().enumerate() {
        for (j, v) in shift(*r, x, y).iter().enumerate() {
            machine.write::<i32>(p[3] as usize + n * 16 + j * 4, *v);
        }
    }
    if flags & 12 != 0 {
        // Painting a child also validates that part of non-clipping ancestors.
        let damage = windows[i].damage.region.clone();
        let mut parent = windows[i].parent;
        while let Some(j) = windows.iter().position(|w| w.handle == parent) {
            if windows[j].style & 0x2000000 == 0 {
                let (px, py) = origin(windows, j);
                let mapped: Vec<_> = damage
                    .iter()
                    .map(|r| shift(*r, x.saturating_sub(px), y.saturating_sub(py)))
                    .collect();
                windows[j].damage.region = combine(&windows[j].damage.region, &mapped, 2);
            }
            parent = windows[j].parent;
        }
    }
    let w = &mut windows[i];
    if flags & 12 != 0 {
        w.damage = Damage::default();
    } else {
        if flags & 1 != 0 {
            w.damage.region = combine(&w.damage.region, &[client(w)], 1);
            w.damage.flags &= !1;
        }
        if flags & 2 != 0 {
            w.damage.flags &= !(2 | 0x80);
            if w.parent == 0 {
                w.damage = Damage::default();
            }
        }
    }
    0
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn regions_preserve_holes_and_merge_bands() {
        let a = [[0, 0, 10, 10]];
        let b = [[2, 2, 8, 8]];
        let cut = combine(&a, &b, 2);
        assert_eq!(
            cut,
            vec![[0, 0, 10, 2], [0, 2, 2, 8], [8, 2, 10, 8], [0, 8, 10, 10]]
        );
        assert_eq!(combine(&cut, &b, 0), a);
        assert!(combine(&cut, &b, 1).is_empty());
    }
}
