//! Common MDI child defaults and keyboard shortcuts.
use crate::{Message, input, window};
unsafe extern "system" {fn GetKeyState(key:u32)->i32;}
#[unsafe(no_mangle)]
pub unsafe extern "system" fn DefMDIChildProcA(h:u32,m:u32,w:u32,l:u32)->i32 {
    if m==0x10 { return window::DestroyWindow(h); }
    unsafe {window::DefWindowProcA(h,m,w,l)}
}
#[unsafe(no_mangle)]
pub unsafe extern "system" fn DefMDIChildProcW(h:u32,m:u32,w:u32,l:u32)->i32 {
    if m==0x10 { return window::DestroyWindow(h); }
    unsafe {window::DefWindowProcW(h,m,w,l)}
}
#[unsafe(no_mangle)]
pub unsafe extern "system" fn TranslateMDISysAccel(client:u32,msg:*const Message)->i32 {
    if msg.is_null() || window::IsWindow(client)==0 {return 0;}
    let msg=unsafe {msg.read_unaligned()};
    if msg.message!=0x100 || unsafe {GetKeyState(0x11)} & 0x8000 == 0 {return 0;}
    let mut child=input::GetFocus();
    while child!=0 && window::GetParent(child)!=client {child=window::GetParent(child);}
    if child==0 {return 0;}
    if msg.wparam==0x73 { // Ctrl+F4 requests close through the child's procedure.
        unsafe {crate::SendMessageA(child,0x10,0,0);}
        return 1;
    }
    if msg.wparam==9 || msg.wparam==0x75 {
        let children=crate::state::with(|s|s.windows.iter().filter(|w|w.parent==client && w.style&0x18000000==0x10000000).map(|w|w.hwnd).collect::<alloc::vec::Vec<_>>());
        if children.is_empty() {return 0;}
        let index=children.iter().position(|&h|h==child).unwrap_or(0);
        let previous=unsafe {GetKeyState(0x10)} & 0x8000 != 0;
        let next=children[(index+if previous {children.len()-1}else{1})%children.len()];
        unsafe {input::SetFocus(next); }
        return 1;
    }
    0
}
