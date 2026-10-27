//! Guest-side USER32. Calls into an application use the ordinary guest stack:
//! no kernel continuation, host closure, or suspended host stack is involved.
#![no_std]
#![allow(non_snake_case)]
#![deny(unsafe_op_in_unsafe_fn)]

extern crate alloc;

mod bitmap;
mod class;
mod controls;
mod dialog;
mod drawing;
mod format;
mod frame;
mod input;
mod keyboard;
mod menu;
mod message;
mod paint;
mod rect;
mod resource;
mod runtime;
mod scrollbar;
mod state;
mod text;
mod win16;
mod win16_resource;
mod window;

use core::mem::transmute;

type Handle = u32;
type WndProc = unsafe extern "system" fn(Handle, u32, u32, u32) -> i32;
type TimerProc = unsafe extern "system" fn(Handle, u32, u32, u32);

// Both CREATESTRUCT variants have this layout; only the pointed-to strings
// differ. Keep the original pointers (including class atoms) for the callback.
#[repr(C)]
struct CreateStruct {
    parameter: u32,
    instance: Handle,
    menu: Handle,
    parent: Handle,
    height: i32,
    width: i32,
    y: i32,
    x: i32,
    style: u32,
    title: u32,
    class: u32,
    ex_style: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct Message {
    hwnd: Handle,
    message: u32,
    wparam: u32,
    lparam: u32,
    time: u32,
    x: i32,
    y: i32,
}

macro_rules! create_api {
    ($name:ident, $wide:expr) => {
        #[unsafe(no_mangle)]
        pub unsafe extern "system" fn $name(
            ex_style: u32,
            class: u32,
            title: u32,
            style: u32,
            x: i32,
            y: i32,
            width: i32,
            height: i32,
            parent: Handle,
            menu: Handle,
            instance: Handle,
            parameter: u32,
        ) -> Handle {
            unsafe {
                window::create(
                    CreateStruct {
                        parameter,
                        instance,
                        menu,
                        parent,
                        height,
                        width,
                        y,
                        x,
                        style,
                        title,
                        class,
                        ex_style,
                    },
                    $wide,
                )
            }
        }
    };
}
create_api!(CreateWindowExA, false);
create_api!(CreateWindowExW, true);

#[unsafe(no_mangle)]
pub unsafe extern "system" fn SendMessageW(
    hwnd: Handle,
    message: u32,
    wparam: u32,
    lparam: u32,
) -> i32 {
    unsafe { message::send(hwnd, message, wparam, lparam, true) }
}

#[unsafe(no_mangle)]
pub unsafe extern "system" fn SendMessageA(
    hwnd: Handle,
    message: u32,
    wparam: u32,
    lparam: u32,
) -> i32 {
    unsafe { message::send(hwnd, message, wparam, lparam, false) }
}

#[unsafe(no_mangle)]
pub unsafe extern "system" fn DispatchMessageW(message: *const Message) -> i32 {
    unsafe { dispatch(message, true) }
}

unsafe fn dispatch(message: *const Message, wide: bool) -> i32 {
    // Copy before calling guest code: it may change or release the caller's MSG.
    let Message {
        hwnd,
        message,
        wparam,
        lparam,
        time,
        ..
    } = unsafe { message.read() };
    if message == 0x113 && lparam != 0 {
        if let Some(result) = unsafe { win16::invoke(lparam, hwnd, message, wparam, time, false) } {
            return result;
        }
        let proc: TimerProc = unsafe { transmute(lparam) };
        unsafe {
            proc(hwnd, message, wparam, time);
        }
        0
    } else {
        unsafe { message::send(hwnd, message, wparam, lparam, wide) }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "system" fn DispatchMessageA(message: *const Message) -> i32 {
    unsafe { dispatch(message, false) }
}

#[unsafe(no_mangle)]
pub unsafe extern "system" fn CallWindowProcW(
    proc: WndProc,
    hwnd: Handle,
    message: u32,
    wparam: u32,
    lparam: u32,
) -> i32 {
    unsafe { call_procedure(proc as u32, hwnd, message, wparam, lparam, true) }
}

#[unsafe(no_mangle)]
pub unsafe extern "system" fn CallWindowProcA(
    proc: WndProc,
    hwnd: Handle,
    message: u32,
    wparam: u32,
    lparam: u32,
) -> i32 {
    unsafe { call_procedure(proc as u32, hwnd, message, wparam, lparam, false) }
}

// Called only on the window-owning thread, with USER state unlocked.
unsafe fn invoke(hwnd: u32, message: u32, wparam: u32, lparam: u32, wide: bool) -> i32 {
    let call = [lparam, wparam, message, hwnd];
    unsafe {
        input::hooks(4, 0, 1, call.as_ptr() as u32);
    }
    let result = unsafe { invoke_body(hwnd, message, wparam, lparam, wide) };
    let returned = [result as u32, lparam, wparam, message, hwnd];
    unsafe {
        input::hooks(12, 0, 1, returned.as_ptr() as u32);
    }
    result
}
unsafe fn invoke_body(hwnd: u32, message: u32, wparam: u32, lparam: u32, wide: bool) -> i32 {
    let target = state::with(|s| {
        s.windows
            .iter()
            .find(|w| w.hwnd == hwnd)
            .map(|w| (w.proc, w.wide))
    });
    let Some((address, target_wide)) = target.filter(|t| t.0 != 0) else {
        return 0;
    };
    if let Some(result) = unsafe { win16::invoke(address, hwnd, message, wparam, lparam, wide) } {
        return result;
    }
    let builtin = controls::builtin(address);
    let proc: WndProc = unsafe { transmute(controls::variant(address, wide)) };
    if builtin || wide == target_wide {
        return unsafe { proc(hwnd, message, wparam, lparam) };
    }
    unsafe { converted(address, target_wide, hwnd, message, wparam, lparam, wide) }
}

unsafe fn call_procedure(
    address: u32,
    hwnd: u32,
    message: u32,
    wparam: u32,
    lparam: u32,
    wide: bool,
) -> i32 {
    if let Some(result) = unsafe { win16::invoke(address, hwnd, message, wparam, lparam, wide) } {
        return result;
    }
    if address >> 16 == 0xffff {
        let entry = state::with(|s| {
            s.procedures
                .get((address & 0xffff).wrapping_sub(1) as usize)
                .copied()
        });
        let Some((proc, encoding)) = entry else {
            return 0;
        };
        unsafe { converted(proc, encoding, hwnd, message, wparam, lparam, wide) }
    } else if address != 0 {
        let proc: WndProc = unsafe { transmute(address) };
        unsafe { proc(hwnd, message, wparam, lparam) }
    } else {
        0
    }
}

// Win16 DLGPROC returns a 16-bit BOOL; DX is not part of its result.
unsafe fn call_dialog_procedure(
    address: u32,
    hwnd: u32,
    message: u32,
    wparam: u32,
    lparam: u32,
    wide: bool,
) -> i32 {
    if let Some(result) = unsafe { win16::invoke(address, hwnd, message, wparam, lparam, wide) } {
        return result as u16 as i16 as i32;
    }
    unsafe { call_procedure(address, hwnd, message, wparam, lparam, wide) }
}

unsafe fn converted(
    address: u32,
    target_wide: bool,
    hwnd: u32,
    message: u32,
    wparam: u32,
    lparam: u32,
    wide: bool,
) -> i32 {
    let proc: WndProc = unsafe { transmute(address) };
    if wide == target_wide {
        return unsafe { proc(hwnd, message, wparam, lparam) };
    }
    // Text messages cross the caller/window encoding boundary on the receiving
    // thread. Temporary buffers remain live throughout reentrant callbacks.
    match message {
        0x000c if lparam != 0 => {
            let mut value = unsafe { text::read(lparam, wide) };
            if target_wide {
                value.push(0);
                unsafe { proc(hwnd, message, wparam, value.as_ptr() as u32) }
            } else {
                let mut bytes = text::ansi(&value);
                bytes.push(0);
                unsafe { proc(hwnd, message, wparam, bytes.as_ptr() as u32) }
            }
        }
        0x000d | 0x000e => {
            if message == 0x000d && (wparam == 0 || lparam == 0) {
                return 0;
            }
            let length = unsafe { proc(hwnd, 0x000e, 0, 0) }.max(0) as usize;
            let capacity = length.saturating_add(1);
            // u16 backing also accommodates the ANSI result and its terminator.
            let mut buffer = alloc::vec![0u16; capacity];
            unsafe {
                proc(hwnd, 0x000d, capacity as u32, buffer.as_mut_ptr() as u32);
            }
            let value = unsafe { text::read(buffer.as_ptr() as u32, target_wide) };
            if message == 0x000e {
                if wide {
                    value.len() as i32
                } else {
                    text::ansi(&value).len() as i32
                }
            } else {
                unsafe { text::write(lparam, wparam as i32, &value, wide) as i32 }
            }
        }
        _ => unsafe { proc(hwnd, message, wparam, lparam) },
    }
}
