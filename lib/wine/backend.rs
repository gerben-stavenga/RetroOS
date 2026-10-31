//! RetroOS host backend for Wine. Windows RTL and loader policy stay in Wine.
#![no_std]
#![allow(non_snake_case)]

unsafe extern "system" {
    fn RetroProcessExit(status: u32) -> !;
    fn RetroWriteFile(
        handle: u32,
        bytes: *const u8,
        count: u32,
        written: *mut u32,
        overlapped: u32,
    ) -> u32;
    fn RetroYield();
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    unsafe { RetroProcessExit(0xc0000409) }
}

#[unsafe(no_mangle)]
pub extern "system" fn RetroNtTerminateProcess(process: u32, status: u32) -> u32 {
    if process != u32::MAX {
        return 0xc0000008;
    }
    unsafe { RetroProcessExit(status) }
}

#[unsafe(no_mangle)]
pub extern "system" fn RetroNtYieldExecution() -> u32 {
    unsafe {
        RetroYield();
    }
    0
}

#[repr(C)]
pub struct DebugWrite {
    bytes: *const u8,
    length: u32,
}

#[unsafe(no_mangle)]
pub unsafe extern "system" fn RetroDebugWrite(parameters: *const DebugWrite) -> u32 {
    if parameters.is_null() {
        return 0xc000000d;
    }
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
    if size == 0 {
        return None;
    }
    let end = base.checked_add(size)?.checked_add(4095)? & !4095;
    let start = base & !(alignment - 1);
    Some((start, end.checked_sub(start)?))
}

#[unsafe(no_mangle)]
pub unsafe extern "system" fn RetroNtAllocateVirtualMemory(
    process: u32,
    address: *mut u32,
    zero_bits: u32,
    size: *mut u32,
    allocation: u32,
    protection: u32,
) -> u32 {
    if process != u32::MAX {
        return 0xc0000008;
    }
    if address.is_null() || size.is_null() {
        return INVALID_PARAMETER;
    }
    if zero_bits != 0 {
        return NOT_SUPPORTED;
    }
    if allocation == 0 || allocation & !0x3000 != 0 {
        return NOT_SUPPORTED;
    }
    let permissions = match protection {
        2 => 0,
        4 => 1,
        0x10 | 0x20 => 2,
        0x40 => 3,
        1 if allocation == 0x2000 => 0,
        _ => return NOT_SUPPORTED,
    };
    let requested = unsafe { *address };
    let reserve = allocation & 0x2000 != 0 || requested == 0;
    let Some((mut base, length)) = page_range(
        requested,
        unsafe { *size },
        if reserve { 65536 } else { 4096 },
    ) else {
        return INVALID_PARAMETER;
    };
    if requested != 0 && base == 0 {
        return CONFLICTING_ADDRESSES;
    }
    if reserve {
        base = unsafe { RetroMemoryReserve(base, length) };
        if base == 0 {
            return CONFLICTING_ADDRESSES;
        }
    }
    if allocation & 0x1000 != 0 && unsafe { RetroMemoryCommit(base, length, permissions) } == 0 {
        if reserve {
            unsafe {
                RetroMemoryRelease(base);
            }
        }
        return CONFLICTING_ADDRESSES;
    }
    unsafe {
        *address = base;
        *size = length;
    }
    0
}

#[unsafe(no_mangle)]
pub unsafe extern "system" fn RetroNtFreeVirtualMemory(
    process: u32,
    address: *mut u32,
    size: *mut u32,
    operation: u32,
) -> u32 {
    if process != u32::MAX {
        return 0xc0000008;
    }
    if address.is_null() || size.is_null() {
        return INVALID_PARAMETER;
    }
    let base = unsafe { *address };
    let length = unsafe { *size };
    if operation == 0x8000 {
        if length != 0 {
            return INVALID_PARAMETER;
        }
        return if unsafe { RetroMemoryRelease(base) } != 0 {
            0
        } else {
            CONFLICTING_ADDRESSES
        };
    }
    if operation != 0x4000 {
        return INVALID_PARAMETER;
    }
    // Whole-region decommit (size=0) will be added with the region query service.
    if length == 0 {
        return NOT_SUPPORTED;
    }
    let Some((base, length)) = page_range(base, length, 4096) else {
        return INVALID_PARAMETER;
    };
    if unsafe { RetroMemoryDecommit(base, length) } == 0 {
        return CONFLICTING_ADDRESSES;
    }
    unsafe {
        *address = base;
        *size = length;
    }
    0
}

#[unsafe(no_mangle)]
pub unsafe extern "system" fn RetroNtQueryInformationProcess(
    process: u32,
    class: u32,
    output: *mut u32,
    length: u32,
    returned: *mut u32,
) -> u32 {
    if process != u32::MAX {
        return 0xc0000008;
    }
    let teb: u32;
    unsafe {
        core::arch::asm!("mov {0:e}, fs:[0x18]", out(reg) teb, options(nostack, readonly));
    }
    let words: &[u32] = match class {
        // PROCESS_BASIC_INFORMATION for this native 32-bit process.
        0 => &[
            0x103,
            unsafe { *((teb + 0x30) as *const u32) },
            1,
            8,
            unsafe { *((teb + 0x20) as *const u32) },
            0,
        ],
        7 => &[0],  // No debug port attached.
        26 => &[0], // Not a WoW64 process.
        31 => &[1], // No debug inheritance.
        _ => return 0xc0000003,
    };
    let required = words.len() as u32 * 4;
    if !returned.is_null() {
        unsafe {
            *returned = required;
        }
    }
    if length != required {
        return 0xc0000004;
    }
    if output.is_null() {
        return 0xc0000005;
    }
    for (i, value) in words.iter().enumerate() {
        unsafe {
            *output.add(i) = *value;
        }
    }
    0
}

unsafe extern "system" {
    fn RetroMapFile(path: *const u8, address: *mut u32, size: *mut u32) -> u32;
    fn RetroLocaleId() -> u32;
}

unsafe fn map_nls(name: &[u8], address: *mut u32, size: *mut u32) -> u32 {
    let prefix = b"C:\\RETROOS\\WINDOWS\\SYSTEM32\\";
    let mut path = [0u8; 96];
    if prefix.len() + name.len() + 5 > path.len() {
        return INVALID_PARAMETER;
    }
    for (i, value) in prefix.iter().chain(name).chain(b".nls").enumerate() {
        path[i] = *value;
    }
    unsafe { RetroMapFile(path.as_ptr(), address, size) }
}

#[unsafe(no_mangle)]
pub unsafe extern "system" fn RetroNtInitializeNlsFiles(
    address: *mut u32,
    locale: *mut u32,
    size: *mut u64,
) -> u32 {
    if address.is_null() || locale.is_null() {
        return INVALID_PARAMETER;
    }
    let mut length = 0;
    let status = unsafe { map_nls(b"locale", address, &mut length) };
    if status == 0 {
        unsafe {
            if !size.is_null() {
                *size = length as u64;
            }
            *locale = RetroLocaleId();
        }
    }
    status
}

#[unsafe(no_mangle)]
pub unsafe extern "system" fn RetroNtGetNlsSectionPtr(
    kind: u32,
    id: u32,
    _unknown: u32,
    address: *mut u32,
    size: *mut u32,
) -> u32 {
    if address.is_null() || size.is_null() {
        return INVALID_PARAMETER;
    }
    let mut buffer = [0u8; 16];
    let name: &[u8] = match kind {
        9 => b"sortdefault",
        10 => b"l_intl",
        11 => {
            let mut at = buffer.len();
            let mut value = id;
            loop {
                at -= 1;
                buffer[at] = b'0' + (value % 10) as u8;
                value /= 10;
                if value == 0 {
                    break;
                }
            }
            while buffer.len() - at < 3 {
                at -= 1;
                buffer[at] = b'0';
            }
            at -= 2;
            buffer[at] = b'c';
            buffer[at + 1] = b'_';
            &buffer[at..]
        }
        12 => match id {
            1 => b"normnfc",
            2 => b"normnfd",
            5 => b"normnfkc",
            6 => b"normnfkd",
            13 => b"normidna",
            _ => return INVALID_PARAMETER,
        },
        _ => return INVALID_PARAMETER,
    };
    unsafe { map_nls(name, address, size) }
}

#[unsafe(no_mangle)]
pub unsafe extern "system" fn RetroNtQueryDefaultLocale(_user: u32, locale: *mut u32) -> u32 {
    if locale.is_null() {
        return INVALID_PARAMETER;
    }
    unsafe {
        *locale = RetroLocaleId();
    }
    0
}

unsafe extern "system" {
    fn RetroRegistry(
        op: u32,
        handle: u32,
        name: u32,
        length: u32,
        data: u32,
        size: u32,
        info: *mut u32,
    ) -> u32;
}
#[repr(C)]
pub struct UnicodeString {
    length: u16,
    maximum: u16,
    buffer: *const u16,
}
#[repr(C)]
pub struct ObjectAttributes {
    length: u32,
    root: u32,
    name: *const UnicodeString,
    attributes: u32,
    security: u32,
    qos: u32,
}
unsafe fn registry_open(
    out: *mut u32,
    attr: *const ObjectAttributes,
    create: bool,
    options: u32,
    disposition: *mut u32,
) -> u32 {
    if out.is_null() || attr.is_null() {
        return INVALID_PARAMETER;
    }
    let attr = unsafe { &*attr };
    if attr.length != 24 || attr.name.is_null() {
        return INVALID_PARAMETER;
    }
    let name = unsafe { &*attr.name };
    let mut info = [0; 2];
    let result = unsafe {
        RetroRegistry(
            create as u32,
            attr.root,
            name.buffer as u32,
            name.length as u32,
            options | if attr.attributes & 0x100 != 0 { 8 } else { 0 },
            0,
            info.as_mut_ptr(),
        )
    };
    if result == 0 {
        unsafe {
            *out = info[0];
            if !disposition.is_null() {
                *disposition = info[1];
            }
        }
    }
    result
}
#[unsafe(no_mangle)]
pub unsafe extern "system" fn RetroNtCreateKey(
    out: *mut u32,
    _access: u32,
    attr: *const ObjectAttributes,
    _title: u32,
    _class: *const UnicodeString,
    options: u32,
    disposition: *mut u32,
) -> u32 {
    if options & !11 != 0 {
        return NOT_SUPPORTED;
    }
    unsafe { registry_open(out, attr, true, options, disposition) }
}
#[unsafe(no_mangle)]
pub unsafe extern "system" fn RetroNtOpenKey(
    out: *mut u32,
    _access: u32,
    attr: *const ObjectAttributes,
) -> u32 {
    unsafe { registry_open(out, attr, false, 0, core::ptr::null_mut()) }
}
#[unsafe(no_mangle)]
pub unsafe extern "system" fn RetroNtOpenKeyEx(
    out: *mut u32,
    access: u32,
    attr: *const ObjectAttributes,
    options: u32,
) -> u32 {
    if options & !8 != 0 {
        return NOT_SUPPORTED;
    }
    let _ = access;
    unsafe { registry_open(out, attr, false, options, core::ptr::null_mut()) }
}
#[unsafe(no_mangle)]
pub unsafe extern "system" fn RetroNtClose(handle: u32) -> u32 {
    if handle & 0xff000000 == 0x74000000 {
        return unsafe { RetroUserObject(4, handle, 0, 0, 0, core::ptr::null_mut()) };
    }
    if handle & 0xff000000 == 0x76000000 {
        return unsafe { RetroSection(2, handle, 0, 0, 0, core::ptr::null_mut()) };
    }
    if handle & 0xff000000 == 0x73000000 {
        return unsafe { RetroSession(2, handle, 0, 0, 0, core::ptr::null_mut()) };
    }
    if handle & 0xffff0000 == 0x40000000 {
        unsafe extern "C" {
            fn RetroCloseFile(fd: u32) -> u32;
        }
        return unsafe { RetroCloseFile(handle & 65535) };
    }
    if handle & 0xff000000 == 0x72000000 {
        return unsafe { RetroEvent(3, handle, 0, core::ptr::null_mut()) };
    }
    unsafe { RetroRegistry(4, handle, 0, 0, 0, 0, core::ptr::null_mut()) }
}
#[unsafe(no_mangle)]
pub unsafe extern "system" fn RetroNtSetValueKey(
    handle: u32,
    name: *const UnicodeString,
    _title: u32,
    kind: u32,
    data: u32,
    size: u32,
) -> u32 {
    if name.is_null() {
        return INVALID_PARAMETER;
    }
    let name = unsafe { &*name };
    let mut info = [kind, 0];
    unsafe {
        RetroRegistry(
            3,
            handle,
            name.buffer as u32,
            name.length as u32,
            data,
            size,
            info.as_mut_ptr(),
        )
    }
}
#[unsafe(no_mangle)]
pub unsafe extern "system" fn RetroNtQueryValueKey(
    handle: u32,
    name: *const UnicodeString,
    class: u32,
    buffer: *mut u8,
    size: u32,
    returned: *mut u32,
) -> u32 {
    if name.is_null() || returned.is_null() {
        return INVALID_PARAMETER;
    }
    let name = unsafe { &*name };
    let header = match class {
        0 => 12,
        1 => 20,
        2 => 12,
        _ => return 0xc0000003,
    };
    let name_len = if class == 2 { 0 } else { name.length as u32 };
    let data_offset = (header + name_len + 3) & !3;
    let mut info = [0; 2];
    let data = if class == 0 || size < data_offset {
        0
    } else {
        buffer as u32 + data_offset
    };
    let capacity = if data == 0 { 0 } else { size - data_offset };
    let status = unsafe {
        RetroRegistry(
            2,
            handle,
            name.buffer as u32,
            name.length as u32,
            data,
            capacity,
            info.as_mut_ptr(),
        )
    };
    if status != 0 && status != 0x80000005 {
        return status;
    }
    let required = if class == 0 {
        header + name_len
    } else {
        data_offset + info[1]
    };
    unsafe {
        *returned = required;
    }
    if size < header {
        return 0xc0000023;
    }
    unsafe {
        let words = buffer as *mut u32;
        *words = 0;
        *words.add(1) = info[0];
        if class == 1 {
            *words.add(2) = data_offset;
            *words.add(3) = info[1];
            *words.add(4) = name_len;
        } else {
            *words.add(2) = if class == 0 { name_len } else { info[1] };
        }
        if name_len != 0 {
            core::ptr::copy_nonoverlapping(
                name.buffer as *const u8,
                buffer.add(header as usize),
                name_len.min(size - header) as usize,
            );
        }
    }
    if size < required {
        0x80000005
    } else {
        0
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn memcpy(dst: *mut u8, src: *const u8, count: usize) -> *mut u8 {
    for i in 0..count {
        unsafe {
            dst.add(i).write_volatile(src.add(i).read_volatile());
        }
    }
    dst
}

// The current RetroOS Windows session has one local user. Use the same SID
// for token queries and the shared user registry hive.
#[unsafe(no_mangle)]
pub unsafe extern "system" fn RetroNtQueryInformationToken(
    token: u32,
    class: u32,
    buffer: *mut u8,
    size: u32,
    returned: *mut u32,
) -> u32 {
    if ![0xffff_fffc, 0xffff_fffb, 0xffff_fffa].contains(&token) {
        return 0xc0000008;
    }
    if class != 1 {
        return 0xc0000003;
    }
    if returned.is_null() {
        return INVALID_PARAMETER;
    }
    unsafe {
        *returned = 36;
    }
    if size < 36 {
        return 0xc0000023;
    }
    if buffer.is_null() {
        return INVALID_PARAMETER;
    }
    unsafe {
        let words = buffer as *mut u32;
        *words = buffer.add(8) as u32;
        *words.add(1) = 0;
        *words.add(2) = 0x00000501;
        *words.add(3) = 0x05000000;
        *words.add(4) = 21;
        *words.add(5) = 0;
        *words.add(6) = 0;
        *words.add(7) = 0;
        *words.add(8) = 1000;
    }
    0
}

unsafe extern "system" {
    fn RetroClock(snapshot: *mut u64) -> u32;
}
#[unsafe(no_mangle)]
pub unsafe extern "system" fn RetroNtQuerySystemTime(out: *mut u64) -> u32 {
    if out.is_null() {
        return INVALID_PARAMETER;
    }
    let mut clock = [0u64; 3];
    let result = unsafe { RetroClock(clock.as_mut_ptr()) };
    if result == 0 {
        unsafe {
            *out = clock[0];
        }
    }
    result
}
#[unsafe(no_mangle)]
pub unsafe extern "system" fn RetroNtQueryPerformanceCounter(
    out: *mut u64,
    frequency: *mut u64,
) -> u32 {
    if out.is_null() {
        return INVALID_PARAMETER;
    }
    let mut clock = [0u64; 3];
    let result = unsafe { RetroClock(clock.as_mut_ptr()) };
    if result == 0 {
        unsafe {
            *out = clock[1];
            if !frequency.is_null() {
                *frequency = 10_000_000;
            }
        }
    }
    result
}
#[unsafe(no_mangle)]
pub unsafe extern "system" fn RetroNtQuerySystemInformation(
    class: u32,
    out: *mut u8,
    size: u32,
    returned: *mut u32,
) -> u32 {
    let required = match class {
        0 => 44,
        3 => 48,
        44 => 172,
        102 => 432,
        _ => return 0xc0000003,
    };
    if !returned.is_null() {
        unsafe {
            *returned = required;
        }
    }
    if size < required {
        return 0xc0000004;
    }
    if out.is_null() {
        return INVALID_PARAMETER;
    }
    if class == 0 {
        let mut memory = [0u32; 2];
        let status = unsafe { RetroSystemInfo(memory.as_mut_ptr()) };
        if status != 0 {
            return status;
        }
        let values = [
            0,
            156250,
            4096,
            memory[0],
            0,
            memory[0].saturating_sub(1),
            65536,
            65536,
            0xbffeffff,
            1,
            1,
        ];
        for (i, value) in values.iter().enumerate() {
            unsafe {
                (out as *mut u32).add(i).write_unaligned(*value);
            }
        }
        return 0;
    }
    let mut clock = [0u64; 3];
    let status = unsafe { RetroClock(clock.as_mut_ptr()) };
    if status != 0 {
        return status;
    }
    for i in 0..required as usize {
        unsafe {
            out.add(i).write_volatile(0);
        }
    }
    unsafe {
        if class == 3 {
            (out as *mut u64).write_unaligned(clock[0].saturating_sub(clock[1]));
            (out.add(8) as *mut u64).write_unaligned(clock[0]);
            (out.add(16) as *mut i64).write_unaligned((clock[2] as i32 as i64) * 600_000_000);
        } else {
            (out as *mut u32).write_unaligned(clock[2] as u32);
            if class == 102 {
                *out.add(428) = 1;
            }
        }
    }
    0
}

#[unsafe(no_mangle)]
pub unsafe extern "system" fn RetroNtSetInformationProcess(
    process: u32,
    class: u32,
    _data: *const u8,
    size: u32,
) -> u32 {
    if process != u32::MAX {
        return 0xc0000008;
    }
    // Executability is currently a per-mapping RetroOS policy. Wine treats
    // refusal to disable DEP globally as optional; retain page permissions.
    if class == 34 {
        return if size != 4 { 0xc0000004 } else { NOT_SUPPORTED };
    }
    0xc0000003
}

unsafe extern "system" {
    fn RetroSetSelectors(
        first: u32,
        low1: u32,
        high1: u32,
        second: u32,
        low2: u32,
        high2: u32,
    ) -> u32;
}
#[unsafe(no_mangle)]
pub unsafe extern "system" fn RetroNtSetLdtEntries(
    first: u32,
    low1: u32,
    high1: u32,
    second: u32,
    low2: u32,
    high2: u32,
) -> u32 {
    let status = unsafe { RetroSetSelectors(first, low1, high1, second, low2, high2) };
    if status != 0 {
        return status;
    }
    let peb: u32;
    unsafe {
        core::arch::asm!("mov {0:e}, fs:[0x30]", out(reg) peb, options(nostack, readonly));
    }
    let copy = unsafe { *((peb + 0x220) as *const u32) } as *mut u32;
    if !copy.is_null() {
        for (selector, low, high) in [(first, low1, high1), (second, low2, high2)] {
            if selector == 0 {
                continue;
            }
            let index = (selector >> 3) as usize;
            let base = (low >> 16) | ((high & 255) << 16) | (high & 0xff000000);
            let bits = (low & 65535)
                | (high & 0xf0000)
                | (((high >> 8) & 31) << 24)
                | (((high >> 23) & 1) << 29)
                | (((high >> 22) & 1) << 30);
            unsafe {
                *copy.add(index) = base;
                *copy.add(8192 + index) = bits;
            }
        }
    }
    0
}

unsafe extern "system" {
    fn RetroMemoryProtect(base: u32, size: u32, protection: u32) -> u32;
    fn RetroSystemInfo(out: *mut u32) -> u32;
}
#[unsafe(no_mangle)]
pub unsafe extern "system" fn RetroNtProtectVirtualMemory(
    process: u32,
    base: *mut u32,
    size: *mut u32,
    protection: u32,
    old: *mut u32,
) -> u32 {
    if process != u32::MAX {
        return 0xc0000008;
    }
    if base.is_null() || size.is_null() || old.is_null() {
        return INVALID_PARAMETER;
    }
    let Some((address, length)) = page_range(unsafe { *base }, unsafe { *size }, 4096) else {
        return INVALID_PARAMETER;
    };
    let previous = unsafe { RetroMemoryProtect(address, length, protection) };
    if previous == 0 {
        return INVALID_PARAMETER;
    }
    unsafe {
        *base = address;
        *size = length;
        *old = previous;
    }
    0
}

unsafe extern "system" {
    fn RetroClearTls(index: u32) -> u32;
}
#[unsafe(no_mangle)]
pub unsafe extern "system" fn RetroNtSetInformationThread(
    thread: u32,
    class: u32,
    data: *const u32,
    size: u32,
) -> u32 {
    if thread != 0xffff_fffe {
        return 0xc0000008;
    }
    if class == 10 {
        if size != 4 || data.is_null() {
            return INVALID_PARAMETER;
        }
        return unsafe { RetroClearTls(*data) };
    }
    0xc0000003
}

#[unsafe(no_mangle)]
pub extern "system" fn RetroNtWow64IsProcessorFeaturePresent(feature: u32) -> u8 {
    let cpu = core::arch::x86::__cpuid(1);
    let present = match feature {
        2 => cpu.edx & (1 << 8) != 0,
        3 => cpu.edx & (1 << 23) != 0,
        6 => cpu.edx & (1 << 25) != 0,
        8 => cpu.edx & (1 << 4) != 0,
        10 => cpu.edx & (1 << 26) != 0,
        13 => cpu.ecx & 1 != 0,
        // Do not advertise extended register state that RetroOS does not save.
        _ => false,
    };
    present as u8
}

unsafe extern "system" {
    fn RetroFileKind(fd: u32) -> u32;
}
#[repr(C)]
pub struct IoStatus {
    status: u32,
    information: u32,
}
#[unsafe(no_mangle)]
pub unsafe extern "system" fn RetroNtQueryVolumeInformationFile(
    handle: u32,
    io: *mut IoStatus,
    buffer: *mut u32,
    size: u32,
    class: u32,
) -> u32 {
    if handle & 0xffff0000 != 0x40000000 {
        return 0xc0000008;
    }
    let kind = unsafe { RetroFileKind(handle & 65535) };
    if kind == 0 {
        return 0xc0000008;
    }
    if class != 4 {
        return 0xc0000003;
    }
    if size < 8 {
        return 0xc0000004;
    }
    if io.is_null() || buffer.is_null() {
        return INVALID_PARAMETER;
    }
    unsafe {
        *buffer = match kind {
            1 => 7,
            2 => 0x50,
            _ => 0x11,
        };
        *buffer.add(1) = 0;
        (*io).status = 0;
        (*io).information = 8;
    }
    0
}

unsafe extern "system" {
    fn RetroEvent(op: u32, handle: u32, flags: u32, out: *mut u32) -> u32;
}
#[unsafe(no_mangle)]
pub unsafe extern "system" fn RetroNtCreateEvent(
    out: *mut u32,
    _access: u32,
    attr: *const ObjectAttributes,
    kind: u32,
    initial: u8,
) -> u32 {
    if out.is_null() || kind > 1 {
        return INVALID_PARAMETER;
    }
    if !attr.is_null() {
        let a = unsafe { &*attr };
        if a.length != 24 {
            return INVALID_PARAMETER;
        }
        if a.root != 0 || (!a.name.is_null() && unsafe { (*a.name).length } != 0) {
            return NOT_SUPPORTED;
        }
    }
    unsafe {
        RetroEvent(
            0,
            0,
            (kind == 0) as u32 | (((initial != 0) as u32) << 1),
            out,
        )
    }
}
#[unsafe(no_mangle)]
pub unsafe extern "system" fn RetroNtSetEvent(handle: u32, previous: *mut u32) -> u32 {
    unsafe { RetroEvent(1, handle, 0, previous) }
}
#[unsafe(no_mangle)]
pub unsafe extern "system" fn RetroNtResetEvent(handle: u32, previous: *mut u32) -> u32 {
    unsafe { RetroEvent(2, handle, 0, previous) }
}
#[unsafe(no_mangle)]
pub unsafe extern "system" fn RetroNtClearEvent(handle: u32) -> u32 {
    unsafe { RetroEvent(2, handle, 0, core::ptr::null_mut()) }
}
#[unsafe(no_mangle)]
pub unsafe extern "system" fn RetroNtQueryEvent(
    handle: u32,
    class: u32,
    out: *mut u32,
    size: u32,
    returned: *mut u32,
) -> u32 {
    if class != 0 {
        return 0xc0000003;
    }
    if !returned.is_null() {
        unsafe {
            *returned = 8;
        }
    }
    if size < 8 {
        return 0xc0000004;
    }
    if out.is_null() {
        return INVALID_PARAMETER;
    }
    let mut flags = 0;
    let status = unsafe { RetroEvent(4, handle, 0, &mut flags) };
    if status == 0 {
        unsafe {
            *out = (flags & 1 == 0) as u32;
            *out.add(1) = flags >> 1;
        }
    }
    status
}

unsafe extern "system" {
    fn RetroFile(
        op: u32,
        fd: u32,
        data: u32,
        length: u32,
        offset: u32,
        flags: u32,
        out: *mut u32,
    ) -> u32;
}
unsafe fn open_native(
    out: *mut u32,
    access: u32,
    attr: *const ObjectAttributes,
    io: *mut IoStatus,
    share: u32,
    options: u32,
    disposition: u32,
) -> u32 {
    if out.is_null() || attr.is_null() || io.is_null() {
        return INVALID_PARAMETER;
    }
    let attr = unsafe { &*attr };
    if attr.length != 24 || attr.name.is_null() {
        return INVALID_PARAMETER;
    }
    if attr.root != 0 {
        return NOT_SUPPORTED;
    }
    let name = unsafe { &*attr.name };
    if name.length & 1 != 0 || name.length < 8 || name.buffer.is_null() {
        return INVALID_PARAMETER;
    }
    let prefix = unsafe { core::slice::from_raw_parts(name.buffer, 4) };
    if prefix != [92, 63, 63, 92] {
        return 0xc0000033;
    }
    // Reject options requiring semantics the synchronous VFS does not provide.
    if options & !(1 | 2 | 0x10 | 0x20 | 0x40 | 0x800 | 0x4000) != 0 {
        return NOT_SUPPORTED;
    }
    if disposition > 5 {
        return INVALID_PARAMETER;
    }
    let mut info = [0; 2];
    let status = unsafe {
        RetroFile(
            4,
            access,
            name.buffer.add(4) as u32,
            u32::from(name.length) - 8,
            share,
            options | (disposition << 24),
            info.as_mut_ptr(),
        )
    };
    unsafe {
        (*io).status = status;
        (*io).information = if status == 0 { info[1] } else { 0 };
        if status == 0 {
            *out = 0x40000000 | info[0];
        }
    }
    status
}
#[unsafe(no_mangle)]
pub unsafe extern "system" fn RetroNtOpenFile(
    out: *mut u32,
    access: u32,
    attr: *const ObjectAttributes,
    io: *mut IoStatus,
    share: u32,
    options: u32,
) -> u32 {
    unsafe { open_native(out, access, attr, io, share, options, 1) }
}
#[unsafe(no_mangle)]
pub unsafe extern "system" fn RetroNtCreateFile(
    out: *mut u32,
    access: u32,
    attr: *const ObjectAttributes,
    io: *mut IoStatus,
    allocation: *const i64,
    _attributes: u32,
    share: u32,
    disposition: u32,
    options: u32,
    _ea: u32,
    ea_size: u32,
) -> u32 {
    if ea_size != 0
        || (!allocation.is_null() && unsafe { core::ptr::read_unaligned(allocation) } != 0)
    {
        return NOT_SUPPORTED;
    }
    unsafe { open_native(out, access, attr, io, share, options, disposition) }
}
#[unsafe(no_mangle)]
pub unsafe extern "system" fn RetroNtReadFile(
    handle: u32,
    event: u32,
    apc: u32,
    _context: u32,
    io: *mut IoStatus,
    buffer: *mut u8,
    length: u32,
    offset: *const i64,
    _key: u32,
) -> u32 {
    unsafe {
        native_file_io(
            false, handle, event, apc, _context, io, buffer, length, offset, _key,
        )
    }
}
#[unsafe(no_mangle)]
pub unsafe extern "system" fn RetroNtWriteFile(
    handle: u32,
    event: u32,
    apc: u32,
    _context: u32,
    io: *mut IoStatus,
    buffer: *mut u8,
    length: u32,
    offset: *const i64,
    _key: u32,
) -> u32 {
    unsafe {
        native_file_io(
            true, handle, event, apc, _context, io, buffer, length, offset, _key,
        )
    }
}
unsafe fn native_file_io(
    write: bool,
    handle: u32,
    event: u32,
    apc: u32,
    _context: u32,
    io: *mut IoStatus,
    buffer: *mut u8,
    length: u32,
    offset: *const i64,
    _key: u32,
) -> u32 {
    if handle & 0xffff0000 != 0x40000000 {
        return 0xc0000008;
    }
    if io.is_null() || (buffer.is_null() && length != 0) {
        return INVALID_PARAMETER;
    }
    if apc != 0 {
        return NOT_SUPPORTED;
    }
    let position = if offset.is_null() {
        -2
    } else {
        unsafe { core::ptr::read_unaligned(offset) }
    };
    if position != -2 && !(write && position == -1) && !(0..=i32::MAX as i64).contains(&position) {
        return INVALID_PARAMETER;
    }
    let mut count = 0;
    let status = unsafe {
        RetroFile(
            if write { 8 } else { 2 },
            handle & 65535,
            buffer as u32,
            length,
            if position == -2 {
                u32::MAX
            } else {
                position as u32
            },
            (write && position == -1) as u32,
            &mut count,
        )
    };
    unsafe {
        (*io).status = status;
        (*io).information = count;
    }
    if event != 0 {
        unsafe {
            RetroNtSetEvent(event, core::ptr::null_mut());
        }
    }
    status
}
#[unsafe(no_mangle)]
pub unsafe extern "system" fn RetroNtQueryInformationFile(
    handle: u32,
    io: *mut IoStatus,
    out: *mut u8,
    size: u32,
    class: u32,
) -> u32 {
    if handle & 0xffff0000 != 0x40000000 {
        return 0xc0000008;
    }
    let required = match class {
        5 => 24,
        14 => 8,
        _ => return 0xc0000003,
    };
    if size < required {
        return 0xc0000004;
    }
    if out.is_null() || io.is_null() {
        return INVALID_PARAMETER;
    }
    let mut info = [0; 3];
    let status = unsafe { RetroFile(3, handle & 65535, 0, 0, 0, 0, info.as_mut_ptr()) };
    if status != 0 {
        return status;
    }
    unsafe {
        core::ptr::write_bytes(out, 0, required as usize);
        if class == 5 {
            core::ptr::write_unaligned(out as *mut u64, (u64::from(info[0]) + 4095) & !4095);
            core::ptr::write_unaligned(out.add(8) as *mut u64, u64::from(info[0]));
            core::ptr::write_unaligned(out.add(16) as *mut u32, 1);
            *out.add(21) = info[2] as u8;
        } else {
            core::ptr::write_unaligned(out as *mut u64, u64::from(info[1]));
        }
        (*io).status = 0;
        (*io).information = required;
    }
    0
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn memset(dst: *mut u8, value: i32, count: usize) -> *mut u8 {
    for i in 0..count {
        unsafe {
            dst.add(i).write_volatile(value as u8);
        }
    }
    dst
}

unsafe extern "system" {
    fn RetroSession(op: u32, handle: u32, offset: u32, size: u32, flags: u32, out: *mut u32)
        -> u32;
}
#[unsafe(no_mangle)]
pub unsafe extern "system" fn RetroNtOpenSection(
    out: *mut u32,
    access: u32,
    attributes: *const ObjectAttributes,
) -> u32 {
    if out.is_null() || attributes.is_null() {
        return INVALID_PARAMETER;
    }
    let attr = unsafe { &*attributes };
    if attr.length != 24 || attr.name.is_null() {
        return INVALID_PARAMETER;
    }
    if attr.root != 0 {
        return NOT_SUPPORTED;
    }
    let name = unsafe { &*attr.name };
    const SESSION: &[u8] = b"\\KernelObjects\\__wine_session";
    if name.length as usize != SESSION.len() * 2 || name.buffer.is_null() {
        return 0xc0000034;
    }
    for (i, &c) in SESSION.iter().enumerate() {
        let unit = unsafe { *name.buffer.add(i) };
        if unit != c as u16
            && !(attr.attributes & 0x40 != 0 && unit < 128 && (unit as u8).eq_ignore_ascii_case(&c))
        {
            return 0xc0000034;
        }
    }
    if access & !(4 | 1 | 0x20000) != 0 {
        return 0xc0000022;
    }
    unsafe { RetroSession(0, 0, 0, 0, 0, out) }
}
#[unsafe(no_mangle)]
pub unsafe extern "system" fn RetroNtMapViewOfSection(
    handle: u32,
    process: u32,
    base: *mut u32,
    zero: u32,
    commit: u32,
    offset: *mut i64,
    size: *mut u32,
    inherit: u32,
    allocation: u32,
    protection: u32,
) -> u32 {
    if process != u32::MAX {
        return 0xc0000008;
    }
    if base.is_null() || size.is_null() || !(1..=2).contains(&inherit) {
        return INVALID_PARAMETER;
    }
    if zero != 0 || commit != 0 || allocation != 0 {
        return NOT_SUPPORTED;
    }
    let start = if offset.is_null() {
        0
    } else {
        unsafe { core::ptr::read_unaligned(offset) }
    };
    if !(0..=u32::MAX as i64).contains(&start) {
        return INVALID_PARAMETER;
    }
    let mut info = [unsafe { *base }, 0];
    let status = unsafe {
        if handle & 0xff000000 == 0x76000000 {
            RetroSection(
                1,
                handle,
                start as u32,
                *size,
                protection,
                info.as_mut_ptr(),
            )
        } else {
            RetroSession(
                1,
                handle,
                start as u32,
                *size,
                protection,
                info.as_mut_ptr(),
            )
        }
    };
    if (status as i32) >= 0 {
        unsafe {
            *base = info[0];
            *size = info[1];
        }
    }
    status
}
#[unsafe(no_mangle)]
pub unsafe extern "system" fn RetroNtUnmapViewOfSection(process: u32, base: u32) -> u32 {
    if process != u32::MAX {
        return 0xc0000008;
    }
    let status = unsafe { RetroSection(3, base, 0, 0, 0, core::ptr::null_mut()) };
    if status == 0xc0000019 {
        unsafe { RetroSession(3, base, 0, 0, 0, core::ptr::null_mut()) }
    } else {
        status
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "system" fn RetroNtDeleteValueKey(
    handle: u32,
    name: *const UnicodeString,
) -> u32 {
    if name.is_null() {
        return INVALID_PARAMETER;
    }
    let name = unsafe { &*name };
    if name.length != 0 && name.buffer.is_null() {
        return INVALID_PARAMETER;
    }
    unsafe {
        RetroRegistry(
            5,
            handle,
            name.buffer as u32,
            u32::from(name.length),
            0,
            0,
            core::ptr::null_mut(),
        )
    }
}

unsafe extern "system" {
    fn RetroUserObject(
        op: u32,
        handle: u32,
        name: u32,
        length: u32,
        flags: u32,
        out: *mut u32,
    ) -> u32;
}

unsafe extern "system" {
    fn RetroAtom(op: u32, atom: u32, name: *const u16, length: u32, out: *mut u32) -> u32;
}
unsafe fn atom_name(op: u32, name: *const u16, length: u32, out: *mut u16) -> u32 {
    if out.is_null() || length & 1 != 0 || length > 510 {
        return INVALID_PARAMETER;
    }
    let integral = if (name as usize) < 65536 {
        Some(name as u32)
    } else {
        None
    };
    if let Some(n) = integral {
        if n == 0 || n >= 0xc000 {
            return INVALID_PARAMETER;
        }
        unsafe {
            *out = n as u16;
        }
        return 0;
    }
    let mut info = [0u32; 131];
    let status = unsafe { RetroAtom(op, 0, name, length, info.as_mut_ptr()) };
    if status == 0 {
        unsafe {
            *out = info[0] as u16;
        }
    }
    status
}
#[unsafe(no_mangle)]
pub unsafe extern "system" fn RetroNtAddAtom(name: *const u16, length: u32, out: *mut u16) -> u32 {
    unsafe { atom_name(0, name, length, out) }
}
#[unsafe(no_mangle)]
pub unsafe extern "system" fn RetroNtFindAtom(name: *const u16, length: u32, out: *mut u16) -> u32 {
    unsafe { atom_name(1, name, length, out) }
}
#[unsafe(no_mangle)]
pub unsafe extern "system" fn RetroNtDeleteAtom(atom: u16) -> u32 {
    if atom == 0 {
        return 0xc0000008;
    }
    if atom < 0xc000 {
        return 0;
    }
    unsafe {
        RetroAtom(
            2,
            u32::from(atom),
            core::ptr::null(),
            0,
            core::ptr::null_mut(),
        )
    }
}
#[unsafe(no_mangle)]
pub unsafe extern "system" fn RetroNtQueryInformationAtom(
    atom: u16,
    class: u32,
    out: *mut u8,
    size: u32,
    returned: *mut u32,
) -> u32 {
    if class != 0 {
        return 0xc0000003;
    }
    if atom == 0 || out.is_null() || size < 8 {
        return INVALID_PARAMETER;
    }
    let mut info = [0u32; 131];
    let text = unsafe { info.as_mut_ptr().add(3) as *mut u16 };
    if atom < 0xc000 {
        let mut digits = [0u16; 6];
        let mut n = atom;
        let mut count = 0;
        while n != 0 {
            digits[count] = 48 + n % 10;
            count += 1;
            n /= 10;
        }
        unsafe {
            *text = 35;
            for i in 0..count {
                *text.add(i + 1) = digits[count - 1 - i];
            }
        }
        info[1] = 1;
        info[2] = (count as u32 + 1) * 2;
    } else {
        let status =
            unsafe { RetroAtom(3, u32::from(atom), core::ptr::null(), 0, info.as_mut_ptr()) };
        if status != 0 {
            return status;
        }
    }
    if !returned.is_null() {
        unsafe {
            *returned = 8 + info[2];
        }
    }
    unsafe {
        core::ptr::write_unaligned(out as *mut u16, info[1].min(65535) as u16);
        core::ptr::write_unaligned(out.add(2) as *mut u16, (atom < 0xc000) as u16);
        core::ptr::write_unaligned(out.add(4) as *mut u16, info[2] as u16);
        let count = info[2].min((size - 8) & !1) as usize;
        core::ptr::copy_nonoverlapping(text as *const u8, out.add(6), count);
        core::ptr::write_unaligned(out.add(6 + count) as *mut u16, 0);
    }
    if size < 8 + info[2] {
        0xc0000023
    } else {
        0
    }
}

unsafe fn query_attributes(attr: *const ObjectAttributes, out: *mut u8, full: bool) -> u32 {
    if attr.is_null() || out.is_null() {
        return INVALID_PARAMETER;
    }
    let attr = unsafe { &*attr };
    if attr.length != 24 || attr.name.is_null() {
        return INVALID_PARAMETER;
    }
    if attr.root != 0 {
        return NOT_SUPPORTED;
    }
    let name = unsafe { &*attr.name };
    if name.length & 1 != 0 || name.length < 8 || name.buffer.is_null() {
        return INVALID_PARAMETER;
    }
    if unsafe { core::slice::from_raw_parts(name.buffer, 4) } != [92, 63, 63, 92] {
        return 0xc0000033;
    }
    let mut info = [0u32; 3];
    let status = unsafe {
        RetroFile(
            6,
            0,
            name.buffer.add(4) as u32,
            u32::from(name.length) - 8,
            0,
            0,
            info.as_mut_ptr(),
        )
    };
    if status != 0 {
        return status;
    }
    let time = if info[2] == 0 {
        0
    } else {
        (u64::from(info[2]) + 11644473600) * 10000000
    };
    unsafe {
        core::ptr::write_bytes(out, 0, if full { 56 } else { 40 });
        for i in 0..4 {
            core::ptr::write_unaligned(out.add(i * 8) as *mut u64, time);
        }
        if full {
            core::ptr::write_unaligned(
                out.add(32) as *mut u64,
                (u64::from(info[0]) + 4095) & !4095,
            );
            core::ptr::write_unaligned(out.add(40) as *mut u64, u64::from(info[0]));
            core::ptr::write_unaligned(out.add(48) as *mut u32, info[1]);
        } else {
            core::ptr::write_unaligned(out.add(32) as *mut u32, info[1]);
        }
    }
    0
}
#[unsafe(no_mangle)]
pub unsafe extern "system" fn RetroNtQueryAttributesFile(
    attr: *const ObjectAttributes,
    out: *mut u8,
) -> u32 {
    unsafe { query_attributes(attr, out, false) }
}
#[unsafe(no_mangle)]
pub unsafe extern "system" fn RetroNtQueryFullAttributesFile(
    attr: *const ObjectAttributes,
    out: *mut u8,
) -> u32 {
    unsafe { query_attributes(attr, out, true) }
}

unsafe extern "system" {
    fn RetroSection(op: u32, handle: u32, offset: u32, size: u32, flags: u32, out: *mut u32)
        -> u32;
}
#[unsafe(no_mangle)]
pub unsafe extern "system" fn RetroNtCreateSection(
    out: *mut u32,
    _access: u32,
    attr: *const ObjectAttributes,
    maximum: *const i64,
    protection: u32,
    attributes: u32,
    file: u32,
) -> u32 {
    if out.is_null() {
        return INVALID_PARAMETER;
    }
    if file & 0xffff0000 != 0x40000000 {
        return NOT_SUPPORTED;
    }
    if !attr.is_null() {
        let a = unsafe { &*attr };
        if a.length != 24 {
            return INVALID_PARAMETER;
        }
        if a.root != 0 || !a.name.is_null() {
            return NOT_SUPPORTED;
        }
    }
    if !((attributes == 0x8000000 && matches!(protection, 2 | 8))
        || (attributes == 0x1000000 && matches!(protection, 2 | 0x20)))
    {
        return NOT_SUPPORTED;
    }
    let size = if maximum.is_null() {
        0
    } else {
        unsafe { core::ptr::read_unaligned(maximum) }
    };
    if !(0..=i32::MAX as i64).contains(&size) {
        return INVALID_PARAMETER;
    }
    unsafe {
        RetroSection(
            0,
            file & 65535,
            0,
            size as u32,
            protection | attributes,
            out,
        )
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "system" fn RetroNtQueryVirtualMemory(
    process: u32,
    address: u32,
    class: u32,
    out: *mut u8,
    size: u32,
    returned: *mut u32,
) -> u32 {
    unsafe extern "system" {
        fn RetroMemoryQuery(address: u32, out: *mut u8) -> u32;
    }
    if process != u32::MAX {
        return 0xc0000008;
    }
    if class != 0 {
        return 0xc0000003;
    }
    if !returned.is_null() {
        unsafe {
            *returned = 28;
        }
    }
    if size < 28 {
        return 0xc0000004;
    }
    if out.is_null() {
        return INVALID_PARAMETER;
    }
    unsafe { RetroMemoryQuery(address, out) }
}

unsafe fn wait_milliseconds(timeout: *const i64) -> Result<u64, u32> {
    Ok(if timeout.is_null() {
        u64::MAX
    } else {
        let ticks = unsafe { core::ptr::read_unaligned(timeout) };
        let relative = if ticks <= 0 {
            ticks.unsigned_abs()
        } else {
            let mut now = 0u64;
            let status = unsafe { RetroNtQuerySystemTime(&mut now) };
            if status != 0 {
                return Err(status);
            }
            (ticks as u64).saturating_sub(now as u64)
        };
        relative.saturating_add(9999) / 10000
    })
}

unsafe fn wait_native(
    count: u32,
    handles: *const u32,
    all: u32,
    alertable: u8,
    timeout: *const i64,
) -> u32 {
    unsafe extern "system" {
        fn RetroWait(count: u32, handles: *const u32, all: u32, low: u32, high: u32) -> u32;
    }
    if alertable != 0 {
        return NOT_SUPPORTED;
    }
    if (count != 0 && handles.is_null()) || count > 64 {
        return INVALID_PARAMETER;
    }
    let milliseconds = match unsafe { wait_milliseconds(timeout) } {
        Ok(ms) => ms,
        Err(status) => return status,
    };
    unsafe {
        RetroWait(
            count,
            handles,
            all,
            milliseconds as u32,
            (milliseconds >> 32) as u32,
        )
    }
}
#[unsafe(no_mangle)]
pub unsafe extern "system" fn RetroNtWaitForSingleObject(
    handle: u32,
    alertable: u8,
    timeout: *const i64,
) -> u32 {
    unsafe { wait_native(1, &handle, 0, alertable, timeout) }
}
#[unsafe(no_mangle)]
pub unsafe extern "system" fn RetroNtWaitForMultipleObjects(
    count: u32,
    handles: *const u32,
    kind: u32,
    alertable: u8,
    timeout: *const i64,
) -> u32 {
    if kind > 1 || count == 0 {
        return INVALID_PARAMETER;
    }
    unsafe { wait_native(count, handles, (kind == 0) as u32, alertable, timeout) }
}

#[unsafe(no_mangle)]
pub unsafe extern "system" fn RetroNtFsControlFile(
    handle: u32,
    _event: u32,
    _apc: u32,
    _context: u32,
    io: *mut IoStatus,
    _code: u32,
    _input: u32,
    _input_size: u32,
    _output: u32,
    _output_size: u32,
) -> u32 {
    if handle & 0xffff0000 != 0x40000000 {
        return 0xc0000008;
    }
    if io.is_null() {
        return INVALID_PARAMETER;
    }
    let mut info = [0u32; 3];
    let status = unsafe { RetroFile(3, handle & 65535, 0, 0, 0, 0, info.as_mut_ptr()) };
    let status = if status == 0 { 0xc0000010 } else { status }; // VFS has no FSCTL operations.
    unsafe {
        (*io).status = status;
        (*io).information = 0;
    }
    status
}
#[unsafe(no_mangle)]
pub unsafe extern "system" fn RetroNtQuerySection(
    handle: u32,
    class: u32,
    out: *mut u8,
    size: u32,
    returned: *mut u32,
) -> u32 {
    if class != 1 {
        return 0xc0000003;
    }
    if !returned.is_null() {
        unsafe {
            *returned = 48;
        }
    }
    if size < 48 {
        return 0xc0000004;
    }
    if out.is_null() {
        return INVALID_PARAMETER;
    }
    unsafe { RetroSection(4, handle, 0, 0, 0, out as *mut u32) }
}

#[unsafe(no_mangle)]
pub unsafe extern "system" fn RetroNtSetInformationFile(
    handle: u32,
    io: *mut IoStatus,
    data: *const u8,
    length: u32,
    class: u32,
) -> u32 {
    if handle & 0xffff0000 != 0x40000000 {
        return 0xc0000008;
    }
    if io.is_null() || data.is_null() {
        return INVALID_PARAMETER;
    }
    let op = match class {
        14 => 7,
        20 => 9,
        _ => return 0xc0000003,
    };
    if length < 8 {
        return 0xc0000004;
    }
    let value = unsafe { core::ptr::read_unaligned(data as *const i64) };
    if !(0..=i32::MAX as i64).contains(&value) {
        return INVALID_PARAMETER;
    }
    let status = unsafe {
        RetroFile(
            op,
            handle & 65535,
            0,
            0,
            value as u32,
            0,
            core::ptr::null_mut(),
        )
    };
    unsafe {
        (*io).status = status;
        (*io).information = 0;
    }
    status
}
#[unsafe(no_mangle)]
pub unsafe extern "system" fn RetroNtFlushBuffersFile(handle: u32, io: *mut IoStatus) -> u32 {
    if handle & 0xffff0000 != 0x40000000 {
        return 0xc0000008;
    }
    if io.is_null() {
        return INVALID_PARAMETER;
    }
    let status = unsafe { RetroFile(10, handle & 65535, 0, 0, 0, 0, core::ptr::null_mut()) };
    unsafe {
        (*io).status = status;
        (*io).information = 0;
    }
    status
}

unsafe extern "system" {
    fn RetroSync(
        op: u32,
        handle: u32,
        value: u32,
        maximum: u32,
        out: *mut u32,
        reserved: u32,
    ) -> u32;
}
unsafe fn unnamed_attributes(attr: *const ObjectAttributes) -> u32 {
    if !attr.is_null() {
        let a = unsafe { &*attr };
        if a.length != 24 {
            return INVALID_PARAMETER;
        }
        if a.root != 0 || (!a.name.is_null() && unsafe { (*a.name).length } != 0) {
            return NOT_SUPPORTED;
        }
    }
    0
}
#[unsafe(no_mangle)]
pub unsafe extern "system" fn RetroNtCreateSemaphore(
    out: *mut u32,
    _access: u32,
    attr: *const ObjectAttributes,
    initial: i32,
    maximum: i32,
) -> u32 {
    if out.is_null() || initial < 0 || maximum <= 0 || initial > maximum {
        return INVALID_PARAMETER;
    }
    let status = unsafe { unnamed_attributes(attr) };
    if status != 0 {
        return status;
    }
    unsafe { RetroSync(0, 0, initial as u32, maximum as u32, out, 0) }
}
#[unsafe(no_mangle)]
pub unsafe extern "system" fn RetroNtCreateMutant(
    out: *mut u32,
    _access: u32,
    attr: *const ObjectAttributes,
    initial: u8,
) -> u32 {
    if out.is_null() {
        return INVALID_PARAMETER;
    }
    let status = unsafe { unnamed_attributes(attr) };
    if status != 0 {
        return status;
    }
    unsafe { RetroSync(1, 0, (initial != 0) as u32, 0, out, 0) }
}
#[unsafe(no_mangle)]
pub unsafe extern "system" fn RetroNtReleaseSemaphore(
    handle: u32,
    count: i32,
    previous: *mut u32,
) -> u32 {
    if count <= 0 {
        return INVALID_PARAMETER;
    }
    unsafe { RetroSync(2, handle, count as u32, 0, previous, 0) }
}
#[unsafe(no_mangle)]
pub unsafe extern "system" fn RetroNtReleaseMutant(handle: u32, previous: *mut u32) -> u32 {
    unsafe { RetroSync(3, handle, 0, 0, previous, 0) }
}
unsafe fn query_sync(
    op: u32,
    handle: u32,
    class: u32,
    out: *mut u32,
    length: u32,
    returned: *mut u32,
) -> u32 {
    if class != 0 {
        return 0xc0000003;
    }
    if !returned.is_null() {
        unsafe {
            *returned = 8;
        }
    }
    if length < 8 {
        return 0xc0000004;
    }
    if out.is_null() {
        return INVALID_PARAMETER;
    }
    unsafe { RetroSync(op, handle, 0, 0, out, 0) }
}
#[unsafe(no_mangle)]
pub unsafe extern "system" fn RetroNtQuerySemaphore(
    handle: u32,
    class: u32,
    out: *mut u32,
    length: u32,
    returned: *mut u32,
) -> u32 {
    unsafe { query_sync(4, handle, class, out, length, returned) }
}
#[unsafe(no_mangle)]
pub unsafe extern "system" fn RetroNtQueryMutant(
    handle: u32,
    class: u32,
    out: *mut u32,
    length: u32,
    returned: *mut u32,
) -> u32 {
    unsafe { query_sync(5, handle, class, out, length, returned) }
}
#[unsafe(no_mangle)]
pub unsafe extern "system" fn RetroNtDelayExecution(alertable: u8, timeout: *const i64) -> u32 {
    if timeout.is_null() {
        return INVALID_PARAMETER;
    }
    let status = unsafe { wait_native(0, core::ptr::null(), 0, alertable, timeout) };
    if status == 0x102 {
        0
    } else {
        status
    }
}

unsafe fn query_key_native(
    handle: u32,
    index: u32,
    enumerate: bool,
    class: u32,
    out: *mut u8,
    size: u32,
    returned: *mut u32,
) -> u32 {
    if returned.is_null() {
        return INVALID_PARAMETER;
    }
    let header = match class {
        0 => 16,
        1 => 24,
        2 => 44,
        3 if !enumerate => 4,
        _ => return 0xc0000003,
    };
    let op = if enumerate { 7 } else { 6 };
    let mut info = [0u32; 8];
    let status = unsafe { RetroRegistry(op, handle, index, 0, 0, 0, info.as_mut_ptr()) };
    if status != 0 && status != 0x80000005 {
        return status;
    }
    let required = header + if class == 2 { 0 } else { info[0] };
    unsafe {
        *returned = required;
    }
    if size < header {
        return 0xc0000023;
    }
    if out.is_null() {
        return INVALID_PARAMETER;
    }
    unsafe {
        core::ptr::write_bytes(out, 0, header as usize);
        if class != 3 {
            core::ptr::write_unaligned(out as *mut u64, info[6] as u64 | ((info[7] as u64) << 32));
        }
        match class {
            0 => core::ptr::write_unaligned(out.add(12) as *mut u32, info[0]),
            1 => {
                core::ptr::write_unaligned(out.add(12) as *mut u32, u32::MAX);
                core::ptr::write_unaligned(out.add(20) as *mut u32, info[0]);
            }
            2 => {
                core::ptr::write_unaligned(out.add(12) as *mut u32, u32::MAX);
                for (offset, value) in [
                    (20, info[1]),
                    (24, info[2]),
                    (32, info[3]),
                    (36, info[4]),
                    (40, info[5]),
                ] {
                    core::ptr::write_unaligned(out.add(offset) as *mut u32, value);
                }
                return 0;
            }
            3 => core::ptr::write_unaligned(out as *mut u32, info[0]),
            _ => {}
        }
        RetroRegistry(
            op,
            handle,
            index,
            0,
            out.add(header as usize) as u32,
            size - header,
            info.as_mut_ptr(),
        )
    }
}
#[unsafe(no_mangle)]
pub unsafe extern "system" fn RetroNtQueryKey(
    handle: u32,
    class: u32,
    out: *mut u8,
    size: u32,
    returned: *mut u32,
) -> u32 {
    unsafe { query_key_native(handle, 0, false, class, out, size, returned) }
}
#[unsafe(no_mangle)]
pub unsafe extern "system" fn RetroNtEnumerateKey(
    handle: u32,
    index: u32,
    class: u32,
    out: *mut u8,
    size: u32,
    returned: *mut u32,
) -> u32 {
    unsafe { query_key_native(handle, index, true, class, out, size, returned) }
}
#[unsafe(no_mangle)]
pub unsafe extern "system" fn RetroNtDeleteKey(handle: u32) -> u32 {
    unsafe { RetroRegistry(9, handle, 0, 0, 0, 0, core::ptr::null_mut()) }
}
#[unsafe(no_mangle)]
pub unsafe extern "system" fn RetroNtEnumerateValueKey(
    handle: u32,
    index: u32,
    class: u32,
    out: *mut u8,
    size: u32,
    returned: *mut u32,
) -> u32 {
    if returned.is_null() {
        return INVALID_PARAMETER;
    }
    let header = match class {
        0 | 2 => 12,
        1 => 20,
        _ => return 0xc0000003,
    };
    let mut info = [0u32; 4];
    let status = unsafe { RetroRegistry(8, handle, index, 0, 0, 0, info.as_mut_ptr()) };
    if status != 0 && status != 0x80000005 {
        return status;
    }
    let name = info[1];
    let data = info[2];
    let aligned_name = (name + 3) & !3;
    let required = header
        + match class {
            0 => name,
            1 => aligned_name + data,
            _ => data,
        };
    unsafe {
        *returned = required;
    }
    if size < header {
        return 0xc0000023;
    }
    if out.is_null() {
        return INVALID_PARAMETER;
    }
    unsafe {
        core::ptr::write_bytes(out, 0, header as usize);
        core::ptr::write_unaligned(out.add(4) as *mut u32, info[0]);
        match class {
            0 => {
                core::ptr::write_unaligned(out.add(8) as *mut u32, name);
                info[3] = 2;
            }
            1 => {
                core::ptr::write_unaligned(out.add(8) as *mut u32, header + aligned_name);
                core::ptr::write_unaligned(out.add(12) as *mut u32, data);
                core::ptr::write_unaligned(out.add(16) as *mut u32, name);
            }
            _ => {
                core::ptr::write_unaligned(out.add(8) as *mut u32, data);
                info[3] = 1;
            }
        }
        if size < required {
            return 0x80000005;
        }
        let status = RetroRegistry(
            8,
            handle,
            index,
            0,
            out.add(header as usize) as u32,
            size - header,
            info.as_mut_ptr(),
        );
        if status == 0 && class == 1 && aligned_name != name {
            core::ptr::copy(
                out.add((header + name) as usize),
                out.add((header + aligned_name) as usize),
                data as usize,
            );
            core::ptr::write_bytes(
                out.add((header + name) as usize),
                0,
                (aligned_name - name) as usize,
            );
        }
        status
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn memmove(dst: *mut u8, src: *const u8, count: usize) -> *mut u8 {
    if (dst as usize) <= src as usize {
        for i in 0..count {
            unsafe {
                dst.add(i).write_volatile(src.add(i).read_volatile());
            }
        }
    } else {
        for i in (0..count).rev() {
            unsafe {
                dst.add(i).write_volatile(src.add(i).read_volatile());
            }
        }
    }
    dst
}

unsafe extern "system" {
    fn RetroUniqueId(out: *mut u64) -> u32;
}
#[unsafe(no_mangle)]
pub unsafe extern "system" fn RetroNtAllocateLocallyUniqueId(out: *mut u64) -> u32 {
    if out.is_null() {
        return INVALID_PARAMETER;
    }
    unsafe { RetroUniqueId(out) }
}

unsafe extern "system" {
    fn RetroThread(op: u32, params: *const u32, out: *mut u32) -> u32;
}
#[unsafe(no_mangle)]
pub unsafe extern "system" fn RetroNtWaitForAlertByThreadId(
    address: u32,
    timeout: *const i64,
) -> u32 {
    let ms = match unsafe { wait_milliseconds(timeout) } {
        Ok(ms) => ms,
        Err(status) => return status,
    };
    let params = [address, ms as u32, (ms >> 32) as u32, 0, 0, 0];
    let mut out = [0u32; 8];
    unsafe { RetroThread(4, params.as_ptr(), out.as_mut_ptr()) }
}
#[unsafe(no_mangle)]
pub unsafe extern "system" fn RetroNtAlertThreadByThreadId(tid: u32) -> u32 {
    let params = [tid, 0, 0, 0, 0, 0];
    let mut out = [0u32; 8];
    unsafe { RetroThread(5, params.as_ptr(), out.as_mut_ptr()) }
}
