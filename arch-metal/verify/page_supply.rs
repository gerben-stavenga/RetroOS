// The runner prepends the unmodified production page_supply module.
extern crate core;
use core::convert::TryFrom;

#[kani::proof]
#[kani::unwind(5)]
fn owned_frame_reference_transition() {
    let raw: u8 = kani::any();
    let neighbor: u8 = kani::any();
    let retain: bool = kani::any();
    // An owned frame starts exclusive (encoded as zero). The current
    // implementation supports up to 254 simultaneous references.
    kani::assume(raw == 0 || (2..=254).contains(&raw));
    kani::assume(!retain || raw < 254);

    let counts = [AtomicU8::new(raw), AtomicU8::new(neighbor)];
    let region = [FrameRegion { first: 32, end: 34, offset: 0 }];
    let ownership = FrameOwnership {
        regions: region.as_ptr(),
        regions_len: region.len(),
        counts: counts.as_ptr().cast_mut().cast(),
        active: counts.len(),
        zero_page: 0,
    };
    let previous = raw.max(1);
    assert_eq!(unsafe { ownership.references(32) }, previous);
    if retain {
        assert!(unsafe { ownership.retain(32) });
        assert_eq!(unsafe { ownership.references(32) }, previous + 1);
    } else {
        let transferred = unsafe { ownership.release_shared(32) };
        assert_eq!(transferred, previous == 1);
        // Last release moves the exclusive reference to the caller. The
        // allocator decides later when the returned frame becomes free.
        assert_eq!(unsafe { ownership.references(32) }, previous.saturating_sub(1).max(1));
        if previous <= 2 {
            assert_eq!(counts[0].load(Ordering::Acquire), 0);
        }
    }
    assert_eq!(counts[1].load(Ordering::Acquire), neighbor);
}

#[kani::proof]
fn reserve_transition_preserves_frame_order() {
    let mut reserve = PageReserve { pages: kani::any(), count: kani::any() };
    kani::assume(reserve.count <= SUPPLY_CAPACITY as u64);
    let before = reserve.len();
    let index: usize = kani::any();
    kani::assume(index < SUPPLY_CAPACITY);
    let saved = reserve.pages[index];
    let donate: bool = kani::any();

    // A populated reserve only contains nonzero frame numbers.
    if before != 0 { kani::assume(reserve.pages[before - 1] != 0); }
    if donate {
        kani::assume(before < SUPPLY_CAPACITY);
        let frame: u64 = kani::any();
        kani::assume(frame != 0);
        reserve.donate(unsafe { OwnedPage::from_number(frame) });
        assert_eq!(reserve.len(), before + 1);
        assert_eq!(reserve.pages[index], if index == before { frame } else { saved });
        assert_eq!(reserve.take().map(OwnedPage::into_number), Some(frame));
        assert_eq!(reserve.len(), before);
    } else {
        let expected = if before == 0 { None } else { Some(reserve.pages[before - 1]) };
        assert_eq!(reserve.take().map(OwnedPage::into_number), expected);
        assert_eq!(reserve.len(), before.saturating_sub(1));
        assert_eq!(reserve.pages[index], saved);
    }
}
