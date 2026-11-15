//! User mapping addresses and errors.
use crate::page_entry::EncodingError;

/// A page-aligned user virtual address, independent of the kernel pointer width.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UserPage(u64);
impl UserPage {
    pub const fn new(address: u64) -> Result<Self, MappingError> {
        if address & 4095 != 0 || !(address < 0xc000_0000
            || address >= 1 << 39 && address < 1 << 47) {
            return Err(MappingError::InvalidAddress);
        }
        Ok(Self(address))
    }
    pub const fn address(self) -> u64 { self.0 }
    pub fn offset(self, pages: usize) -> Result<Self, MappingError> {
        let bytes = (pages as u64).checked_mul(4096).ok_or(MappingError::InvalidAddress)?;
        let end = self.0.checked_add(bytes).ok_or(MappingError::InvalidAddress)?;
        // A batch must not cross the compatibility kernel's reserved window.
        if self.0 < 0xc000_0000 && end >= 0xc000_0000 { return Err(MappingError::InvalidAddress); }
        Self::new(end)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MappingError {
    InvalidAddress,
    InvalidFrame,
    Unsupported,
    NeedPages,
    Encoding(EncodingError),
}
impl From<EncodingError> for MappingError {
    fn from(error: EncodingError) -> Self { Self::Encoding(error) }
}

/// A batch may finish a prefix before needing more backing. Resume at
/// `completed`, not by replaying already-completed replacements.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MappingFailure {
    pub completed: usize,
    pub error: MappingError,
}


pub(crate) fn validate_batch(start: UserPage, count: usize) -> Result<(), MappingFailure> {
    if count != 0 { start.offset(count - 1).map_err(|error| MappingFailure { completed: 0, error })?; }
    Ok(())
}
