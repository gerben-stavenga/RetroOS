#![no_std]
#![no_main]
use core::alloc::{GlobalAlloc, Layout};
struct NoAllocation;
unsafe impl GlobalAlloc for NoAllocation {
    unsafe fn alloc(&self, _: Layout) -> *mut u8 { panic!("arch attempted allocation") }
    unsafe fn dealloc(&self, _: *mut u8, _: Layout) { panic!("arch attempted deallocation") }
}
#[global_allocator]
static ALLOCATOR: NoAllocation = NoAllocation;
#[unsafe(no_mangle)]
pub unsafe extern "C" fn boot_kernel(_: u32, _: u32, _: u32) -> ! {
    unsafe { arch_metal::vm::boot() }
}
#[panic_handler]
fn panic(info: &core::panic::PanicInfo<'_>) -> ! {
    use core::fmt::Write;
    struct Output;
    impl core::fmt::Write for Output {
        fn write_str(&mut self, text: &str) -> core::fmt::Result {
            for byte in text.bytes() { arch_metal::x86::outb(0xe9, byte); }
            Ok(())
        }
    }
    let _ = writeln!(Output, "arch supervisor panic: {info}");
    arch_metal::x86::outl(arch_abi::vm::PANIC_PORT, 1);
    loop { arch_metal::x86::hlt(); }
}
