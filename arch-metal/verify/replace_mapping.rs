// Model one completed hardware PTE store and the frame-release boundary.
// The runner prepends the actual replacement and ownership rules.
trait Entry: Copy {
    fn raw(&self) -> u64;
    fn page(&self) -> u64;
    fn present(&self) -> bool {
        self.raw() & flags::PRESENT != 0
    }
}

#[derive(Clone, Copy)]
struct Slot(u64);

impl Entry for Slot {
    fn raw(&self) -> u64 {
        self.0
    }

    fn page(&self) -> u64 {
        (self.0 >> 12) & ((1 << 40) - 1)
    }
}

static mut STORED: bool = false;
static mut RELEASED: Option<u64> = None;

fn replace_entry<E: Entry>(slot: &mut E, incoming: E) -> E {
    assert!(!unsafe { STORED });
    let previous = std::mem::replace(slot, incoming);
    unsafe { STORED = true; }
    previous
}

mod memory {
    pub fn release_page(page: u64) {
        assert!(unsafe { super::STORED });
        assert!(matches!(unsafe { super::RELEASED }, None));
        unsafe { super::RELEASED = Some(page); }
    }
}

#[kani::proof]
fn replacement_releases_exactly_the_displaced_owned_frame() {
    let old: u64 = kani::any();
    let incoming: u64 = kani::any();
    let neighbor: u64 = kani::any();
    let mut entries = [Slot(old), Slot(neighbor)];
    replace_mapping(&mut entries[0], Slot(incoming));

    assert!(unsafe { STORED });
    assert_eq!(entries[0].0, incoming);
    assert_eq!(entries[1].0, neighbor);
    let borrowed = old & (1 << 11) != 0;
    let has_backing = old & 1 != 0 || old & (1 << 10) != 0;
    let expected = (has_backing && !borrowed).then_some((old >> 12) % (1 << 40));
    assert_eq!(unsafe { RELEASED }, expected);
}
