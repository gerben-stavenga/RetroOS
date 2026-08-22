//! Filesystem backends.
//!
//! Each module here implements the trait surface `kernel::vfs` mounts: the
//! boot image's TAR archive, the hosted punch-through to the host's files,
//! and ext2/3/4 via the portable ext4 engine. `vfs` itself stays one level up — it is the API
//! the personalities call, not a filesystem.
//!
//! Backends read blocks through `kernel::block`, never a driver directly.

pub mod cdrom;
pub mod floppy;
pub mod grant;
pub mod hostfs;
pub mod iso9660;
pub mod portable_ext4;

use alloc::vec::Vec;

pub(crate) enum ImageReadError {
    TooBig,
    Io,
}

/// Slurp a whole media image from VFS into RAM — the loading half both
/// removable-media slots (CD-ROM, floppy) share. `max` is the slot's own
/// sanity bound; allocation failure reports as `Io` rather than aborting,
/// so a small machine refuses an insert instead of panicking.
pub(crate) fn read_image_file(path: &[u8], max: u32) -> Result<Vec<u8>, ImageReadError> {
    let handle = crate::kernel::vfs::open_to_handle(path);
    if handle < 0 {
        return Err(ImageReadError::Io);
    }
    let size = crate::kernel::vfs::file_size_by_handle(handle);
    if size > max {
        crate::kernel::vfs::close_vfs_handle(handle);
        return Err(ImageReadError::TooBig);
    }
    let mut data = Vec::new();
    if data.try_reserve_exact(size as usize).is_err() {
        crate::kernel::vfs::close_vfs_handle(handle);
        return Err(ImageReadError::Io);
    }
    data.resize(size as usize, 0);
    let mut offset = 0;
    while offset < data.len() {
        let n = crate::kernel::vfs::read_by_handle(handle, &mut data[offset..]);
        if n <= 0 {
            crate::kernel::vfs::close_vfs_handle(handle);
            return Err(ImageReadError::Io);
        }
        offset += n as usize;
    }
    crate::kernel::vfs::close_vfs_handle(handle);
    Ok(data)
}
