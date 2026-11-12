//! Linux virtual mapping placement. File contents use the unified kernel cache.
/// Place a downward allocation below every overlapping occupied range.
/// Loaded ELF images, the interpreter and fixed mappings must all
/// participate; guarding one special address still lets a large heap collide
/// with a different executable mapping.
pub(super) fn allocate_below(cursor: usize, floor: usize, size: usize, occupied: &[(usize, usize)]) -> Option<usize> {
    let mut end = cursor;
    loop {
        let base = end.checked_sub(size)?;
        if base < floor || base == 0 { return None; }
        let overlap = occupied.iter().filter(|(start, stop)| base < *stop && end > *start)
            .max_by_key(|(start, _)| *start);
        match overlap {
            Some((start, _)) => end = *start,
            None => return Some(base),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn heaps_avoid_interpreters_and_fixed_mappings_too() {
        let regions = [(0x40000000, 0x40040000), (0x7ff60000, 0x7ff61000)];
        assert_eq!(allocate_below(0xa6836000, 0x08000000, 0x40000000, &regions), None);
        let size = 0x20000000;
        let base = allocate_below(0x86836000, 0x08000000, size, &regions).unwrap();
        for (start, end) in regions { assert!(base + size <= start || base >= end); }
    }
    #[test]
    fn large_reservations_skip_occupied_ranges_and_respect_the_floor() {
        let idle = 0x7ff60000;
        let size = 0x40000000;
        let base = allocate_below(0xa6836000, 0x10000000, size, &[(idle, idle + 4096)]).unwrap();
        assert!(base + size <= idle);
        assert!(base >= 0x10000000);
        assert_eq!(allocate_below(idle, idle - 4096, 4096, &[(idle, idle + 4096)]), Some(idle - 4096));
        assert_eq!(allocate_below(idle + 4096, idle, 4096, &[(idle, idle + 4096)]), None);
        assert_eq!(allocate_below(0x1000, 0, usize::MAX, &[(idle, idle + 4096)]), None);
    }
}
