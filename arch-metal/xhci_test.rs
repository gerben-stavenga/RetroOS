extern crate alloc;

// Exercise the real driver against allocated register/ring memory. Privileged
// operations are deliberately unavailable in this host test.
#[allow(dead_code)]
mod x86 {
    pub fn inl(_: u16) -> u32 {
        panic!("PCI read in host test")
    }
    pub fn outl(_: u16, _: u32) {
        panic!("PCI write in host test")
    }
    pub fn interrupts_enabled() -> bool {
        false
    }
}
#[allow(dead_code)]
mod paging2 {
    pub const PAGE_SIZE: usize = 4096;
    pub mod flags {
        pub const CACHE_DISABLE: u64 = 0;
    }
    pub fn map_user_page_phys(_: usize, _: u64, _: u64) {
        panic!("mapping in host test")
    }
}
#[allow(dead_code)]
mod phys_mm {
    pub fn alloc_contig(_: usize) -> Option<u64> {
        panic!("physical allocation in host test")
    }
}
#[allow(dead_code)]
mod irq {
    std::thread_local! {
        pub static KEYS: std::cell::RefCell<Vec<u8>> = const { std::cell::RefCell::new(Vec::new()) };
        pub static MOUSE: std::cell::RefCell<Vec<(i16, i16, u8)>> = const { std::cell::RefCell::new(Vec::new()) };
    }
    pub fn push_key(key: u8) {
        KEYS.with(|keys| keys.borrow_mut().push(key));
    }
    pub fn push_mouse(x: i16, y: i16, buttons: u8) {
        MOUSE.with(|events| events.borrow_mut().push((x, y, buttons)));
    }
    pub fn now(_: bool) -> u64 {
        panic!("clock in host test")
    }
}

#[allow(dead_code)]
#[path = "src/xhci.rs"]
mod xhci;
