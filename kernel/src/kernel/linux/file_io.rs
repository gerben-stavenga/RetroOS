//! Bounded staging of user buffers for regular-file writes.
pub(super) const MAX_WRITE: usize = 0x7fff_f000;
const CHUNK: usize = 65536;

/// Keep a short backend write short, preserving earlier progress on errors.
/// Retrying a large user write must never copy its entire remaining buffer.
pub(super) fn write_buffered<T>(
    context: &mut T,
    length: usize,
    mut copy: impl FnMut(&mut T, usize, &mut [u8]) -> Result<(), i32>,
    mut write: impl FnMut(&mut T, &[u8]) -> i32,
) -> i32 {
    let length = length.min(MAX_WRITE);
    let mut buffer = alloc::vec![0; length.min(CHUNK)];
    let mut total = 0;
    while total < length {
        let count = buffer.len().min(length - total);
        if let Err(error) = copy(context, total, &mut buffer[..count]) {
            return if total == 0 { error } else { total as i32 };
        }
        let result = write(context, &buffer[..count]);
        if result < 0 { return if total == 0 { result } else { total as i32 }; }
        if result as usize > count { return if total == 0 { -5 } else { total as i32 }; }
        total += result as usize;
        if result as usize != count { break; }
    }
    total as i32
}

pub(super) fn write_user<A: crate::Arch>(machine: &mut A, handle: i32, pointer: u64, length: usize) -> i32 {
    let length = length.min(MAX_WRITE);
    if !super::high_memory::range(pointer, length as u64) { return -14; }
    super::vfs::with_file_io(handle, length, |file| write_buffered(machine, length,
        |machine, offset, bytes| {
            crate::kernel::memory::service(machine);
            if super::high_memory::copy_from(machine, pointer + offset as u64, bytes) { Ok(()) } else { Err(-14) }
        },
        |_, bytes| file.write(bytes))).unwrap_or_else(|error| error)
}

pub(super) fn read_user<A: crate::Arch>(machine: &mut A, handle: i32, pointer: u64, length: usize,
    buffer: &mut alloc::vec::Vec<u8>) -> i32 {
    let length = length.min(MAX_WRITE);
    if !super::high_memory::range(pointer, length as u64) { return -14; }
    let sample = crate::kernel::event_profile::file_io_start();
    buffer.resize(length.min(CHUNK), 0);
    crate::kernel::event_profile::file_io_finish(0, buffer.len(), sample);
    super::vfs::with_file_io(handle, length, |file| {
        let mut total = 0;
        while total < length {
            crate::kernel::memory::service(machine);
            let count = buffer.len().min(length - total);
            let sample = crate::kernel::event_profile::file_io_start();
            let n = file.read(&mut buffer[..count]);
            crate::kernel::event_profile::file_io_finish(1, n.max(0) as usize, sample);
            if n < 0 { return if total == 0 { n } else { total as i32 }; }
            if n as usize > count { return if total == 0 { -5 } else { total as i32 }; }
            let sample = crate::kernel::event_profile::file_io_start();
            let copied = super::high_memory::copy_to(machine, pointer + total as u64, &buffer[..n as usize]);
            crate::kernel::event_profile::file_io_finish(2, n as usize, sample);
            if !copied { return if total == 0 { -14 } else { total as i32 }; }
            total += n as usize;
            if n as usize != count { break; }
        }
        total as i32
    }).unwrap_or_else(|error| error)
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
            Ok(())
        }, |state, bytes| { state.output.extend_from_slice(bytes); bytes.len() as i32 }), length as i32);
        assert_eq!(transfer.copied, length);
        assert_eq!(transfer.output, (0..length).map(|index| index as u8).collect::<Vec<_>>());
    }

    #[test]
    fn short_writes_and_later_errors_preserve_progress() {
        let mut copied = 0;
        assert_eq!(write_buffered(&mut copied, CHUNK * 100, |copied, _, bytes| { *copied += bytes.len(); Ok(()) }, |_, _| 32768), 32768);
        assert_eq!(copied, CHUNK);
        let mut calls = 0;
        assert_eq!(write_buffered(&mut calls, CHUNK * 2, |_, _, _| Ok(()), |calls, bytes| {
            *calls += 1;
            if *calls == 1 { bytes.len() as i32 } else { -28 }
        }), CHUNK as i32);
        assert_eq!(write_buffered(&mut (), 1, |_, _, _| Ok(()), |_, _| -28), -28);
        assert_eq!(write_buffered(&mut (), 1, |_, _, _| Ok(()), |_, _| 0), 0);
        assert_eq!(write_buffered(&mut (), 1, |_, _, _| Ok(()), |_, _| 2), -5);
        assert_eq!(write_buffered(&mut (), 1, |_, _, _| Err(-14), |_, _| panic!()), -14);
        assert_eq!(write_buffered(&mut (), 0, |_, _, _| panic!(), |_, _| panic!()), 0);
    }
}
