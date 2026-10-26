//! USER32 rectangle operations run entirely in guest memory.
use core::cmp::{max, min};

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Rect {
    pub(crate) left: i32,
    pub(crate) top: i32,
    pub(crate) right: i32,
    pub(crate) bottom: i32,
}
#[repr(C)]
pub struct Point {
    pub(crate) x: i32,
    pub(crate) y: i32,
}

impl Rect {
    const EMPTY: Self = Self {
        left: 0,
        top: 0,
        right: 0,
        bottom: 0,
    };
    fn empty(self) -> bool {
        self.left >= self.right || self.top >= self.bottom
    }
    fn intersection(self, other: Self) -> Self {
        let result = Self {
            left: max(self.left, other.left),
            top: max(self.top, other.top),
            right: min(self.right, other.right),
            bottom: min(self.bottom, other.bottom),
        };
        if result.empty() { Self::EMPTY } else { result }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "system" fn SetRect(
    out: *mut Rect,
    left: i32,
    top: i32,
    right: i32,
    bottom: i32,
) -> i32 {
    if out.is_null() {
        return 0;
    }
    unsafe {
        out.write(Rect {
            left,
            top,
            right,
            bottom,
        });
    }
    1
}
#[unsafe(no_mangle)]
pub unsafe extern "system" fn SetRectEmpty(out: *mut Rect) -> i32 {
    unsafe { SetRect(out, 0, 0, 0, 0) }
}
#[unsafe(no_mangle)]
pub unsafe extern "system" fn CopyRect(out: *mut Rect, source: *const Rect) -> i32 {
    if out.is_null() || source.is_null() {
        return 0;
    }
    unsafe {
        out.write(source.read());
    }
    1
}
#[unsafe(no_mangle)]
pub unsafe extern "system" fn EqualRect(a: *const Rect, b: *const Rect) -> i32 {
    if a.is_null() || b.is_null() {
        return 0;
    }
    unsafe { i32::from(a.read() == b.read()) }
}
#[unsafe(no_mangle)]
pub unsafe extern "system" fn IsRectEmpty(rect: *const Rect) -> i32 {
    if rect.is_null() {
        return 1;
    }
    unsafe { i32::from(rect.read().empty()) }
}
#[unsafe(no_mangle)]
pub unsafe extern "system" fn PtInRect(rect: *const Rect, point: Point) -> i32 {
    if rect.is_null() {
        return 0;
    }
    let r = unsafe { rect.read() };
    i32::from(point.x >= r.left && point.x < r.right && point.y >= r.top && point.y < r.bottom)
}
#[unsafe(no_mangle)]
pub unsafe extern "system" fn OffsetRect(rect: *mut Rect, dx: i32, dy: i32) -> i32 {
    if rect.is_null() {
        return 0;
    }
    let r = unsafe { rect.read() };
    unsafe {
        rect.write(Rect {
            left: r.left.wrapping_add(dx),
            top: r.top.wrapping_add(dy),
            right: r.right.wrapping_add(dx),
            bottom: r.bottom.wrapping_add(dy),
        });
    }
    1
}
#[unsafe(no_mangle)]
pub unsafe extern "system" fn InflateRect(rect: *mut Rect, dx: i32, dy: i32) -> i32 {
    if rect.is_null() {
        return 0;
    }
    let r = unsafe { rect.read() };
    unsafe {
        rect.write(Rect {
            left: r.left.wrapping_sub(dx),
            top: r.top.wrapping_sub(dy),
            right: r.right.wrapping_add(dx),
            bottom: r.bottom.wrapping_add(dy),
        });
    }
    1
}
#[unsafe(no_mangle)]
pub unsafe extern "system" fn IntersectRect(out: *mut Rect, a: *const Rect, b: *const Rect) -> i32 {
    if out.is_null() || a.is_null() || b.is_null() {
        return 0;
    }
    let r = unsafe { a.read().intersection(b.read()) };
    unsafe {
        out.write(r);
    }
    i32::from(!r.empty())
}
#[unsafe(no_mangle)]
pub unsafe extern "system" fn UnionRect(out: *mut Rect, a: *const Rect, b: *const Rect) -> i32 {
    if out.is_null() || a.is_null() || b.is_null() {
        return 0;
    }
    let (a, b) = unsafe { (a.read(), b.read()) };
    let r = match (a.empty(), b.empty()) {
        (true, true) => Rect::EMPTY,
        (true, false) => b,
        (false, true) => a,
        (false, false) => Rect {
            left: min(a.left, b.left),
            top: min(a.top, b.top),
            right: max(a.right, b.right),
            bottom: max(a.bottom, b.bottom),
        },
    };
    unsafe {
        out.write(r);
    }
    i32::from(!r.empty())
}
#[unsafe(no_mangle)]
pub unsafe extern "system" fn SubtractRect(out: *mut Rect, a: *const Rect, b: *const Rect) -> i32 {
    if out.is_null() || a.is_null() || b.is_null() {
        return 0;
    }
    let mut r = unsafe { a.read() };
    let cut = r.intersection(unsafe { b.read() });
    if r.empty() || cut == r {
        r = Rect::EMPTY;
    } else if !cut.empty() {
        // Return the bounding rectangle of what remains, not a region.
        if cut.left == r.left && cut.right == r.right {
            if cut.top == r.top {
                r.top = cut.bottom;
            } else if cut.bottom == r.bottom {
                r.bottom = cut.top;
            }
        } else if cut.top == r.top && cut.bottom == r.bottom {
            if cut.left == r.left {
                r.left = cut.right;
            } else if cut.right == r.right {
                r.right = cut.left;
            }
        }
    }
    unsafe {
        out.write(r);
    }
    i32::from(!r.empty())
}
