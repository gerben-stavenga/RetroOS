//! Process-local USER state lives in the DLL's guest address space. No reference
//! into it may survive a callback: snapshot handles/values, unlock, call, then
//! look up the handle again (the callback may destroy or subclass the window).
use crate::runtime;
use alloc::vec::Vec;
use core::{
    cell::UnsafeCell,
    sync::atomic::{AtomicBool, Ordering},
};

#[derive(Clone)]
pub struct Class {
    pub global: bool,
    pub atom: u32,
    pub name: Vec<u16>,
    pub style: u32,
    pub proc: u32,
    pub extra: Vec<u8>,
    pub window_extra: usize,
    pub instance: u32,
    pub icon: u32,
    pub cursor: u32,
    pub background: u32,
    pub menu: u32,
    pub small_icon: u32,
    pub wide: bool,
    pub live: usize,
}

pub struct Window {
    pub properties: Vec<(Vec<u16>, u32)>,
    pub hwnd: u32,
    pub class: u32,
    pub thread: u32,
    pub proc: u32,
    pub instance: u32,
    pub parent: u32,
    pub owner: u32,
    pub id: u32,
    pub style: u32,
    pub ex_style: u32,
    pub user: u32,
    pub extra: Vec<u8>,
    pub title: Vec<u16>,
    pub x: i32,
    pub y: i32,
    pub width: i32,
    pub height: i32,
    pub normal_rect: Option<[i32; 4]>,
    pub needs_size: bool,
    pub destroying: bool,
    pub wide: bool,
    pub control: crate::controls::Control,
}

pub struct State {
    pub mmio_buffers: Vec<(u32,u16)>,
    pub carets: Vec<crate::caret::Caret>,
    pub caret_interval: u32,
    pub win16_handles: Vec<u32>,
    pub win16_procs: Vec<u32>,
    pub win16_native_procs: Vec<u32>,
    pub keyboard: [u8; 256],
    pub menu_popup: Option<crate::menu::Popup>,
    pub menus: Vec<crate::menu::Menu>,
    pub attached_menus: Vec<crate::menu::Attached>,
    pub cursor: [i32; 2],
    pub cursor_handle: u32,
    pub cursor_count: i32,
    pub cursor_clip: Option<[i32; 4]>,
    pub inputs: Vec<crate::input::Input>,
    pub hooks: Vec<crate::input::Hook>,
    pub chains: Vec<crate::input::Chain>,
    pub dialogs: Vec<crate::dialog::Dialog>,
    pub procedures: Vec<(u32, bool)>,
    pub classes: Vec<Class>,
    pub windows: Vec<Window>,
    pub next_atom: u32,
    pub builtins: bool,
    pub dcs: Vec<crate::paint::WindowDc>,
    pub updates: Vec<crate::paint::Update>,
    pub resources: Vec<(u32, crate::resource::Resource)>,
    pub next_resource: u32,
    pub queues: Vec<crate::message::Queue>,
    pub timers: Vec<crate::message::Timer>,
    pub next_timer: u32,
    pub sent: Vec<crate::message::Sent>,
    pub next_send: u64,
}
struct Global {
    locked: AtomicBool,
    state: UnsafeCell<State>,
}
// The lock excludes guest threads. Never execute a window procedure under it.
unsafe impl Sync for Global {}
static GLOBAL: Global = Global {
    locked: AtomicBool::new(false),
    state: UnsafeCell::new(State {
        mmio_buffers: Vec::new(),
        carets: Vec::new(),
        caret_interval: 500,
        win16_handles: Vec::new(),
        win16_procs: Vec::new(),
        win16_native_procs: Vec::new(),
        keyboard: [0; 256],
        menu_popup: None,
        menus: Vec::new(),
        attached_menus: Vec::new(),
        cursor: [0; 2],
        cursor_handle: 0,
        cursor_count: 0,
        cursor_clip: None,
        inputs: Vec::new(),
        hooks: Vec::new(),
        chains: Vec::new(),
        dialogs: Vec::new(),
        procedures: Vec::new(),
        classes: Vec::new(),
        windows: Vec::new(),
        next_atom: 0xc000,
        builtins: false,
        dcs: Vec::new(),
        updates: Vec::new(),
        resources: Vec::new(),
        next_resource: 0x6000_0000,
        queues: Vec::new(),
        timers: Vec::new(),
        next_timer: 1,
        sent: Vec::new(),
        next_send: 1,
    }),
};
struct Guard;
impl Drop for Guard {
    fn drop(&mut self) {
        GLOBAL.locked.store(false, Ordering::Release);
    }
}
pub fn with<R>(f: impl FnOnce(&mut State) -> R) -> R {
    while GLOBAL
        .locked
        .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
        .is_err()
    {
        unsafe {
            runtime::Sleep(0);
        }
    }
    let _guard = Guard;
    f(unsafe { &mut *GLOBAL.state.get() })
}
pub fn error(code: u32) -> u32 {
    unsafe {
        runtime::SetLastError(code);
    }
    0
}
