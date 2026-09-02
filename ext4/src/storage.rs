//! The only persistent-effect boundary in the filesystem.

use alloc::boxed::Box;
use core::any::Any;
use core::fmt;

/// A thin owner for a caller-defined storage failure.
///
/// Storage failures are already exceptional and heap-owned. Keeping the fat
/// `dyn Any` box behind one thin box prevents its two-word representation from
/// widening every filesystem `Result`.
pub struct StorageError(Box<Box<dyn Any>>);

impl StorageError {
    pub fn new<T: Any>(error: T) -> Self {
        Self(Box::new(Box::new(error)))
    }

    pub fn downcast_ref<T: Any>(&self) -> Option<&T> {
        self.0.downcast_ref()
    }
}

impl fmt::Debug for StorageError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("StorageError(..)")
    }
}

/// Exact, synchronous byte I/O over a disk, partition, or image.
///
/// Implementations must not report success for a short operation. `flush`
/// establishes a durability and ordering barrier: after it succeeds, every
/// preceding successful write must survive loss of power.
pub trait Storage {
    /// Number of addressable bytes in this storage object.
    fn len(&self) -> u64;

    /// Fill `dst` from `offset`, or return an error without claiming success.
    fn read(&mut self, offset: u64, dst: &mut [u8]) -> Result<(), StorageError>;

    /// Write all of `src` at `offset`, or return an error.
    fn write(&mut self, offset: u64, src: &[u8]) -> Result<(), StorageError>;

    /// Make all preceding successful writes durable.
    fn flush(&mut self) -> Result<(), StorageError>;

    fn is_empty(&self) -> bool {
        self.len() == 0
    }
}
