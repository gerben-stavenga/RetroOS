//! Bounded staging of user buffers for regular-file writes.
pub(super) const MAX_WRITE: usize = 0x7fff_f000;
const CHUNK: usize = 65536;

/// Keep a short backend write short, preserving earlier progress on errors.
/// Retrying a large user write must never copy its entire remaining buffer.
pub(super) fn write_buffered<T>(
    context: &mut T,
    length: usize,
    mut copy: impl FnMut(&mut T, usize, &mut [u8]),
    mut write: impl FnMut(&mut T, &[u8]) -> i32,
) -> i32 {
    let length = length.min(MAX_WRITE);
    let mut buffer = alloc::vec![0; length.min(CHUNK)];
    let mut total = 0;
    while total < length {
        let count = buffer.len().min(length - total);
        copy(context, total, &mut buffer[..count]);
        let result = write(context, &buffer[..count]);
        if result < 0 { return if total == 0 { result } else { total as i32 }; }
        if result as usize > count { return if total == 0 { -5 } else { total as i32 }; }
        total += result as usize;
        if result as usize != count { break; }
    }
    total as i32
}

pub(super) fn write_user<A: crate::Arch>(machine: &mut A, handle: i32, pointer: usize, length: usize) -> i32 {
    let length = length.min(MAX_WRITE);
    if length != 0 && (pointer == 0 || pointer.checked_add(length).is_none_or(|end| end > super::elf::USER_STACK_TOP)) { return -14; }
    write_buffered(machine, length,
        |machine, offset, bytes| machine.copy_from(pointer + offset, bytes),
        |machine, bytes| super::vfs::write_by_handle(machine, handle, bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;

    #[test]
    fn large_writes_stage_each_byte_once_in_bounded_chunks() {
        struct Transfer { copied: usize, output: Vec<u8> }
        let mut transfer = Transfer { copied: 0, output: Vec::new() };
        let length = CHUNK * 3 + 17;
        assert_eq!(write_buffered(&mut transfer, length, |state, offset, bytes| {
            assert!(bytes.len() <= CHUNK);
            for (index, byte) in bytes.iter_mut().enumerate() { *byte = (offset + index) as u8; }
            state.copied += bytes.len();
        }, |state, bytes| { state.output.extend_from_slice(bytes); bytes.len() as i32 }), length as i32);
        assert_eq!(transfer.copied, length);
        assert_eq!(transfer.output, (0..length).map(|index| index as u8).collect::<Vec<_>>());
    }

    #[test]
    fn short_writes_and_later_errors_preserve_progress() {
        let mut copied = 0;
        assert_eq!(write_buffered(&mut copied, CHUNK * 100, |copied, _, bytes| *copied += bytes.len(), |_, _| 32768), 32768);
        assert_eq!(copied, CHUNK);
        let mut calls = 0;
        assert_eq!(write_buffered(&mut calls, CHUNK * 2, |_, _, _| {}, |calls, bytes| {
            *calls += 1;
            if *calls == 1 { bytes.len() as i32 } else { -28 }
        }), CHUNK as i32);
        assert_eq!(write_buffered(&mut (), 1, |_, _, _| {}, |_, _| -28), -28);
        assert_eq!(write_buffered(&mut (), 1, |_, _, _| {}, |_, _| 0), 0);
        assert_eq!(write_buffered(&mut (), 1, |_, _, _| {}, |_, _| 2), -5);
        assert_eq!(write_buffered(&mut (), 0, |_, _, _| panic!(), |_, _| panic!()), 0);
    }
}
