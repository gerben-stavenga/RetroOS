//! Guest runtime services. Allocation and waiting reuse KERNEL32 rather than
//! growing a second heap or scheduler interface in the Windows personality.
use core::alloc::{GlobalAlloc, Layout};
use core::ptr;

unsafe extern "system" {
    fn GetProcessHeap() -> u32;
    fn HeapAlloc(heap: u32, flags: u32, bytes: usize) -> *mut u8;
    fn HeapFree(heap: u32, flags: u32, pointer: *mut u8) -> i32;
    fn ExitProcess(code: u32) -> !;
    pub fn GetTickCount() -> u32;
    pub fn CreateEventA(attributes: u32, manual: u32, initial: u32, name: u32) -> u32;
    pub fn SetEvent(event: u32) -> u32;
    pub fn WaitForSingleObject(event: u32, timeout: u32) -> u32;
    pub fn Sleep(milliseconds: u32);
    pub fn GetCurrentThreadId() -> u32;
    pub fn GetCurrentProcessId() -> u32;
    pub fn GetModuleHandleA(name: u32) -> u32;
    pub fn SetLastError(error: u32);
}

struct Heap;
unsafe impl GlobalAlloc for Heap {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let align = layout.align().max(core::mem::align_of::<usize>());
        let Some(bytes) = layout
            .size()
            .max(1)
            .checked_add(align)
            .and_then(|n| n.checked_add(4))
        else {
            return ptr::null_mut();
        };
        let base = unsafe { HeapAlloc(GetProcessHeap(), 0, bytes) };
        if base.is_null() {
            return base;
        }
        let aligned = (base as usize + 4 + align - 1) & !(align - 1);
        unsafe {
            ((aligned - 4) as *mut *mut u8).write(base);
        }
        aligned as *mut u8
    }
    unsafe fn dealloc(&self, pointer: *mut u8, _: Layout) {
        let base = unsafe { pointer.sub(4).cast::<*mut u8>().read() };
        unsafe {
            HeapFree(GetProcessHeap(), 0, base);
        }
    }
}
#[global_allocator]
static HEAP: Heap = Heap;

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    unsafe {
        ExitProcess(0xff);
    }
}

// Volatile loops prevent LLVM lowering these runtime definitions back into
// calls to themselves. They have the C ABI, not Win32 stdcall.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn memcpy(dst: *mut u8, src: *const u8, len: usize) -> *mut u8 {
    for i in 0..len {
        unsafe {
            dst.add(i).write_volatile(src.add(i).read_volatile());
        }
    }
    dst
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn memmove(dst: *mut u8, src: *const u8, len: usize) -> *mut u8 {
    if (dst as usize) <= src as usize {
        return unsafe { memcpy(dst, src, len) };
    }
    for i in (0..len).rev() {
        unsafe {
            dst.add(i).write_volatile(src.add(i).read_volatile());
        }
    }
    dst
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn memset(dst: *mut u8, value: i32, len: usize) -> *mut u8 {
    for i in 0..len {
        unsafe {
            dst.add(i).write_volatile(value as u8);
        }
    }
    dst
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn memcmp(a: *const u8, b: *const u8, len: usize) -> i32 {
    for i in 0..len {
        let (a, b) = unsafe { (a.add(i).read_volatile(), b.add(i).read_volatile()) };
        if a != b {
            return i32::from(a) - i32::from(b);
        }
    }
    0
}
