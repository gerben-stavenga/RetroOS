//! Linux mapping layout and eager file loads from any VFS backend.
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

/// Copy a file region into an already-zeroed mapping. EOF leaves the tail
/// zero; transport errors must fail the mapping rather than load corrupt ELF.
pub(super) fn copy_region(
    offset: usize,
    length: usize,
    mut read: impl FnMut(u32, &mut [u8]) -> i32,
    mut write: impl FnMut(usize, &[u8]),
) -> Result<(), i32> {
    let mut buffer = alloc::vec![0; length.min(32768)];
    let mut copied = 0;
    while copied < length {
        let position = offset
            .checked_add(copied)
            .and_then(|n| u32::try_from(n).ok())
            .ok_or(-22)?;
        let count = buffer.len().min(length - copied);
        let n = read(position, &mut buffer[..count]);
        if n < 0 {
            return Err(n);
        }
        if n == 0 {
            break;
        }
        let n = n as usize;
        if n > count {
            return Err(-5);
        }
        write(copied, &buffer[..n]);
        copied += n;
    }
    Ok(())
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
    #[test]
    fn short_reads_fill_large_mappings_and_eof_leaves_zero_tail() {
        let input: alloc::vec::Vec<u8> = (0..100003).map(|i| (i * 17 + 3) as u8).collect();
        let mut output = alloc::vec![0; 110000];
        copy_region(
            13,
            output.len(),
            |offset, bytes| {
                let start = (offset as usize).min(input.len());
                let n = bytes.len().min(701).min(input.len() - start);
                bytes[..n].copy_from_slice(&input[start..start + n]);
                n as i32
            },
            |offset, bytes| output[offset..offset + bytes.len()].copy_from_slice(bytes),
        )
        .unwrap();
        assert_eq!(&output[..input.len() - 13], &input[13..]);
        assert!(output[input.len() - 13..].iter().all(|&b| b == 0));
    }
    #[test]
    fn read_failures_and_invalid_lengths_fail_the_mapping() {
        assert_eq!(
            copy_region(0, 65536, |_, _| -110, |_, _| panic!()),
            Err(-110)
        );
        assert_eq!(
            copy_region(0, 12, |_, b| b.len() as i32 + 1, |_, _| panic!()),
            Err(-5)
        );
    }
    #[test]
    fn positioned_reads_do_not_wrap_large_offsets() {
        assert_eq!(
            copy_region(usize::MAX, 2, |_, _| panic!(), |_, _| panic!()),
            Err(-22)
        );
    }
}
