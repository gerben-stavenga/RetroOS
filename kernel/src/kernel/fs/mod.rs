//! Filesystem backends.
//!
//! Each module here implements the trait surface `kernel::vfs` mounts: the
//! boot image's TAR archive, the hosted punch-through to the host's files,
//! and ext2/3/4 via lwext4. `vfs` itself stays one level up — it is the API
//! the personalities call, not a filesystem.
//!
//! Backends read blocks through `kernel::block`, never a driver directly.

pub mod grant;
pub mod hostfs;
pub mod lwext4;
pub mod tarfs;
