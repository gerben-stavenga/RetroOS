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


/// Read one entry using the range primitive. The result does not own backing.
pub fn read_mapping<M: crate::Memory + ?Sized>(machine: &mut M, page: UserPage) -> Result<crate::page_entry::PageEntry, MappingError> {
    let mut entry = crate::page_entry::PageEntry::Absent;
    machine.read_mappings(page, core::slice::from_mut(&mut entry)).map_err(|failure| failure.error)?;
    Ok(entry)
}

/// Replace one entry using the range primitive.
/// # Safety
/// Same requirements as [`crate::Memory::replace_mappings`].
pub unsafe fn replace_mapping<M: crate::Memory + ?Sized>(machine: &mut M, page: UserPage,
    entry: crate::page_entry::PageEntry, pages: crate::page_supply::PageInput,
) -> (Result<(), MappingError>, crate::page_supply::PageInput) {
    let (result, pages) = unsafe { machine.replace_mappings(page, core::slice::from_ref(&entry), pages) };
    (result.map_err(|failure| failure.error), pages)
}
