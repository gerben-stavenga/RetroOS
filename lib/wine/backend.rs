//! RetroOS host backend for Wine. Windows RTL and loader policy stay in Wine.
#![no_std]
#![allow(non_snake_case)]

unsafe extern "system" {
    fn RetroProcessExit(status: u32) -> !;
    fn RetroWriteFile(handle: u32, bytes: *const u8, count: u32, written: *mut u32, overlapped: u32) -> u32;
    fn RetroYield();
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! { unsafe { RetroProcessExit(0xc0000409) } }

#[unsafe(no_mangle)]
pub extern "system" fn RetroNtTerminateProcess(process: u32, status: u32) -> u32 {
    if process != u32::MAX { return 0xc0000008; }
    unsafe { RetroProcessExit(status) }
}

#[unsafe(no_mangle)]
pub extern "system" fn RetroNtYieldExecution() -> u32 {
    unsafe { RetroYield(); }
    0
}

#[repr(C)]
pub struct DebugWrite { bytes: *const u8, length: u32 }

#[unsafe(no_mangle)]
pub unsafe extern "system" fn RetroDebugWrite(parameters: *const DebugWrite) -> u32 {
    if parameters.is_null() { return 0xc000000d; }
    let parameters = unsafe { &*parameters };
    let mut written = 0;
    if unsafe { RetroWriteFile(2, parameters.bytes, parameters.length, &mut written, 0) } == 0 {
        return 0xc0000001;
    }
    0
}

unsafe extern "system" {
    fn RetroMemoryReserve(base: u32, size: u32) -> u32;
    fn RetroMemoryCommit(base: u32, size: u32, permissions: u32) -> u32;
    fn RetroMemoryDecommit(base: u32, size: u32) -> u32;
    fn RetroMemoryRelease(base: u32) -> u32;
}

const INVALID_PARAMETER: u32 = 0xc000000d;
const NOT_SUPPORTED: u32 = 0xc00000bb;
const CONFLICTING_ADDRESSES: u32 = 0xc0000018;

fn page_range(base: u32, size: u32, alignment: u32) -> Option<(u32, u32)> {
    if size == 0 { return None; }
    let end = base.checked_add(size)?.checked_add(4095)? & !4095;
    let start = base & !(alignment - 1);
    Some((start, end.checked_sub(start)?))
}

#[unsafe(no_mangle)]
pub unsafe extern "system" fn RetroNtAllocateVirtualMemory(process: u32, address: *mut u32,
    zero_bits: u32, size: *mut u32, allocation: u32, protection: u32) -> u32
{
    if process != u32::MAX { return 0xc0000008; }
    if address.is_null() || size.is_null() { return INVALID_PARAMETER; }
    if zero_bits != 0 { return NOT_SUPPORTED; }
    if allocation == 0 || allocation & !0x3000 != 0 { return NOT_SUPPORTED; }
    let permissions = match protection {
        2 => 0, 4 => 1, 0x10 | 0x20 => 2, 0x40 => 3,
        1 if allocation == 0x2000 => 0,
        _ => return NOT_SUPPORTED,
    };
    let requested = unsafe { *address };
    let reserve = allocation & 0x2000 != 0 || requested == 0;
    let Some((mut base, length)) = page_range(requested, unsafe { *size }, if reserve { 65536 } else { 4096 }) else { return INVALID_PARAMETER; };
    if requested != 0 && base == 0 { return CONFLICTING_ADDRESSES; }
    if reserve {
        base = unsafe { RetroMemoryReserve(base, length) };
        if base == 0 { return CONFLICTING_ADDRESSES; }
    }
    if allocation & 0x1000 != 0 && unsafe { RetroMemoryCommit(base, length, permissions) } == 0 {
        if reserve { unsafe { RetroMemoryRelease(base); } }
        return CONFLICTING_ADDRESSES;
    }
    unsafe { *address = base; *size = length; }
    0
}

#[unsafe(no_mangle)]
pub unsafe extern "system" fn RetroNtFreeVirtualMemory(process: u32, address: *mut u32,
    size: *mut u32, operation: u32) -> u32
{
    if process != u32::MAX { return 0xc0000008; }
    if address.is_null() || size.is_null() { return INVALID_PARAMETER; }
    let base = unsafe { *address };
    let length = unsafe { *size };
    if operation == 0x8000 {
        if length != 0 { return INVALID_PARAMETER; }
        return if unsafe { RetroMemoryRelease(base) } != 0 { 0 } else { CONFLICTING_ADDRESSES };
    }
    if operation != 0x4000 { return INVALID_PARAMETER; }
    // Whole-region decommit (size=0) will be added with the region query service.
    if length == 0 { return NOT_SUPPORTED; }
    let Some((base, length)) = page_range(base, length, 4096) else { return INVALID_PARAMETER; };
    if unsafe { RetroMemoryDecommit(base, length) } == 0 { return CONFLICTING_ADDRESSES; }
    unsafe { *address = base; *size = length; }
    0
}
