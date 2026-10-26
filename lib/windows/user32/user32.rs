//! Guest-side USER32. Calls into an application use the ordinary guest stack:
//! no kernel continuation, host closure, or suspended host stack is involved.
#![no_std]
#![allow(non_snake_case)]
#![deny(unsafe_op_in_unsafe_fn)]

extern crate alloc;

mod class;
mod message;
mod rect;
mod runtime;
mod state;
mod text;
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
    unsafe { message::send(hwnd, message, wparam, lparam) }
}

#[unsafe(no_mangle)]
pub unsafe extern "system" fn SendMessageA(
    hwnd: Handle,
    message: u32,
    wparam: u32,
    lparam: u32,
) -> i32 {
    unsafe { SendMessageW(hwnd, message, wparam, lparam) }
}

#[unsafe(no_mangle)]
pub unsafe extern "system" fn DispatchMessageW(message: *const Message) -> i32 {
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
        let proc: TimerProc = unsafe { transmute(lparam) };
        unsafe {
            proc(hwnd, message, wparam, time);
        }
        0
    } else {
        unsafe { SendMessageW(hwnd, message, wparam, lparam) }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "system" fn DispatchMessageA(message: *const Message) -> i32 {
    unsafe { DispatchMessageW(message) }
}

#[unsafe(no_mangle)]
pub unsafe extern "system" fn CallWindowProcW(
    proc: WndProc,
    hwnd: Handle,
    message: u32,
    wparam: u32,
    lparam: u32,
) -> i32 {
    unsafe { proc(hwnd, message, wparam, lparam) }
}

#[unsafe(no_mangle)]
pub unsafe extern "system" fn CallWindowProcA(
    proc: WndProc,
    hwnd: Handle,
    message: u32,
    wparam: u32,
    lparam: u32,
) -> i32 {
    unsafe { proc(hwnd, message, wparam, lparam) }
}

// Called only on the window-owning thread, with USER state unlocked.
unsafe fn invoke(hwnd: u32, message: u32, wparam: u32, lparam: u32) -> i32 {
    let address = state::with(|s| {
        s.windows
            .iter()
            .find(|w| w.hwnd == hwnd)
            .map_or(0, |w| w.proc)
    });
    if address == 0 {
        return 0;
    }
    let proc: WndProc = unsafe { transmute(address) };
    unsafe { proc(hwnd, message, wparam, lparam) }
}
