//! Windows' read-only shared clock page, consumed directly by Wine's PE code.
//! The kernel owns one backing page for the boot session; process aliases never
//! free it. Updates run on the guest core before returning to application code.
use core::ptr::NonNull;

const ADDRESS: usize = 0x7ffe_0000;
struct Backing {
    pointer: usize,
    last_ms: u64,
}
static BACKING: spin::Mutex<Backing> = spin::Mutex::new(Backing {
    pointer: 0,
    last_ms: u64::MAX,
});

pub(super) fn initialize<A: crate::Arch>(machine: &mut A) {
    let mut backing = BACKING.lock();
    if backing.pointer == 0 {
        let page = machine.alloc_shared_pages(1);
        backing.pointer = page.as_ptr() as usize;
        unsafe {
            core::ptr::write_bytes(page.as_ptr(), 0, 4096);
            // TickCount is milliseconds, so its fixed-point multiplier is one.
            put(page.as_ptr(), 4, 1 << 24);
            for (i, c) in "C:\\RETROOS\\WINDOWS\0".encode_utf16().enumerate() {
                page.as_ptr().add(0x30 + i * 2).cast::<u16>().write(c);
            }
            page.as_ptr().add(0x300).cast::<u64>().write(10_000_000);
        }
    }
    let page = NonNull::new(backing.pointer as *mut u8).unwrap();
    unsafe {
        machine.map_shared_pages(ADDRESS / 4096, page, 1);
    }
    machine.set_page_flags(ADDRESS / 4096, 1, false, false);
    drop(backing);
    update(machine);
}

unsafe fn put(page: *mut u8, offset: usize, value: u32) {
    unsafe {
        page.add(offset).cast::<u32>().write_volatile(value);
    }
}

// KSYSTEM_TIME readers sample High1, Low, High2 and retry on disagreement.
unsafe fn system_time(page: *mut u8, offset: usize, value: u64) {
    unsafe {
        put(page, offset + 8, (value >> 32) as u32);
        put(page, offset, value as u32);
        put(page, offset + 4, (value >> 32) as u32);
    }
}

pub(super) fn update<A: crate::Arch>(machine: &A) {
    let now = machine.now();
    let ms = now / 1_000_000;
    let mut backing = BACKING.lock();
    if backing.pointer == 0 || backing.last_ms == ms {
        return;
    }
    backing.last_ms = ms;
    let page = backing.pointer as *mut u8;
    unsafe {
        put(page, 0, ms as u32);
        system_time(page, 0x008, now / 100);
        system_time(page, 0x320, ms);
        if let Some(unix) = crate::kernel::clock::rtc_unix_timestamp() {
            system_time(page, 0x014, (u64::from(unix) + 11_644_473_600) * 10_000_000);
        }
        let bias = -i64::from(crate::kernel::clock::utc_offset_minutes()) * 600_000_000;
        system_time(page, 0x020, bias as u64);
    }
}
