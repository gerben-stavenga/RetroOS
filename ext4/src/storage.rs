//! The only persistent-effect boundary in the filesystem.

/// Exact, synchronous byte I/O over a disk, partition, or image.
///
/// Implementations must not report success for a short operation. `flush`
/// establishes a durability and ordering barrier: after it succeeds, every
/// preceding successful write must survive loss of power.
pub trait Storage {
    type Error;

    /// Number of addressable bytes in this storage object.
    fn len(&self) -> u64;

    /// Fill `dst` from `offset`, or return an error without claiming success.
    fn read(&mut self, offset: u64, dst: &mut [u8]) -> Result<(), Self::Error>;

    /// Write all of `src` at `offset`, or return an error.
    fn write(&mut self, offset: u64, src: &[u8]) -> Result<(), Self::Error>;

    /// Make all preceding successful writes durable.
    fn flush(&mut self) -> Result<(), Self::Error>;

    fn is_empty(&self) -> bool {
        self.len() == 0
    }
}
