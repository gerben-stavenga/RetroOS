//! Eager file mappings must drain short reads from any VFS backend.
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
