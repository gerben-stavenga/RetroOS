//! User mapping addresses and errors.
use crate::{
    page_entry::{Attributes, Backing, EncodingError, Mapping, PageEntry, PhysicalFrame},
    page_supply::{OwnedPage, PageInput},
};

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
    AlreadyMapped,
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


/// Raw snapshots for architecture diagnostics and tests.
pub trait InspectMappings {
    fn read_mappings(&mut self, start: UserPage, entries: &mut [PageEntry]) -> Result<(), MappingFailure>;
    fn read_mapping_run(&mut self, start: UserPage, maximum: usize) -> Result<(PageEntry, usize), MappingError>;
}

pub fn read_mapping(machine: &mut impl InspectMappings, page: UserPage) -> Result<PageEntry, MappingError> {
    let mut entry = PageEntry::Absent;
    machine.read_mappings(page, core::slice::from_mut(&mut entry)).map_err(|failure| failure.error)?;
    Ok(entry)
}

/// The requested guest access to an installed mapping.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Access { None, ReadOnly, ReadWrite, CopyOnWrite }

impl Access {
    fn entry(self, mapping: Mapping) -> PageEntry {
        match self {
            Self::None => PageEntry::NoAccess(mapping),
            Self::ReadOnly => PageEntry::ReadOnly(mapping),
            Self::ReadWrite => PageEntry::Writable(mapping),
            Self::CopyOnWrite => PageEntry::CopyOnWrite(mapping),
        }
    }
}

/// Authorization to install a mapping. A PageEntry read from arch is only
/// a snapshot and cannot be used to construct this value.
#[repr(transparent)]
#[derive(Clone, Copy)]
pub struct Install<'a>(PageEntry, core::marker::PhantomData<&'a OwnedPage>);

impl<'a> Install<'a> {
    pub const ABSENT: Self = Self(PageEntry::Absent, core::marker::PhantomData);
    pub const INTERCEPTED: Self = Self(PageEntry::Intercepted, core::marker::PhantomData);

    /// # Safety
    /// The current address-space owner guarantees the entry's backing and
    /// access for every resulting alias. Prefer the typed constructors.
    pub unsafe fn from_entry(entry: PageEntry) -> Self {
        Self(entry, core::marker::PhantomData)
    }

    pub fn entry(self) -> PageEntry { self.0 }

    pub fn entries(entries: &[Self]) -> &[PageEntry] {
        // Install is transparent over PageEntry, with the same layout.
        unsafe { core::slice::from_raw_parts(entries.as_ptr().cast(), entries.len()) }
    }

    /// Arch retains its own counted reference before the caller releases this one.
    pub fn owned(page: &'a OwnedPage, access: Access, attributes: Attributes) -> Self {
        let backing = Backing::Owned(PhysicalFrame::new(page.number()).expect("valid owned frame"));
        Self(access.entry(Mapping { backing, attributes }), core::marker::PhantomData)
    }

    /// # Safety
    /// The frame must be authorized for this guest view and its owner must
    /// keep it alive through all aliases and forks. The caller also controls
    /// synchronization of guest access to shared RAM.
    pub unsafe fn borrowed(frame: PhysicalFrame, access: Access, attributes: Attributes) -> Self {
        Self(access.entry(Mapping { backing: Backing::Borrowed(frame), attributes }),
            core::marker::PhantomData)
    }
}

/// Replace one entry using the batch primitive.
pub fn replace_mapping<M: crate::Memory + ?Sized>(machine: &mut M, page: UserPage,
    entry: Install<'_>, pages: PageInput,
) -> (Result<(), MappingError>, PageInput) {
    let (result, pages) = machine.replace_mappings(page, core::slice::from_ref(&entry), pages);
    (result.map_err(|failure| failure.error), pages)
}

/// Policy for pages without backing during protection changes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Missing { Skip, Reject }

/// Guest permissions for a range edit. Arch decides how to implement writes.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Protection { None, ReadOnly, ReadWrite }

/// A virtual-range operation. Arch selects and manages the backing frames.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Edit {
    ReserveZero { access: Protection, executable: bool, only_if_vacant: bool },
    CommitZero,
    Protect { access: Protection, executable: bool, missing: Missing },
    Discard,
    MakePrivate,
}

/// Backend operations under the paging lock. Copies hold a temporary owned
/// reference until fill retains one for the mapping or returns an error.
pub trait EditMappings {
    fn read_run(&mut self, start: UserPage, maximum: usize) -> Result<(PageEntry, usize), MappingError>;
    fn fill(&mut self, start: UserPage, count: usize, entry: PageEntry) -> Result<(), MappingFailure>;
    fn copy(&mut self, frame: PhysicalFrame) -> Result<PhysicalFrame, MappingError>;
    fn release(&mut self, frame: PhysicalFrame);
}

fn mapped(entry: PageEntry) -> Option<Mapping> {
    match entry {
        PageEntry::NoAccess(mapping) | PageEntry::ReadOnly(mapping)
        | PageEntry::Writable(mapping) | PageEntry::CopyOnWrite(mapping) => Some(mapping),
        _ => None,
    }
}

pub fn edit_range(ops: &mut impl EditMappings, start: UserPage, count: usize,
    operation: Edit, zero: PhysicalFrame,
) -> Result<(), MappingFailure> {
    if count == 0 { return Ok(()); }
    let before = |error| MappingFailure { completed: 0, error };
    start.offset(count - 1).map_err(before)?;
    let check = match operation {
        Edit::ReserveZero { only_if_vacant: true, .. } => Some(MappingError::AlreadyMapped),
        Edit::Protect { missing: Missing::Reject, .. } | Edit::Discard | Edit::MakePrivate =>
            Some(MappingError::InvalidAddress),
        _ => None,
    };
    let mut first_run = None;
    if let Some(error) = check {
        let mut offset = 0;
        while offset < count {
            let (entry, run) = ops.read_run(start.offset(offset).unwrap(), count - offset).map_err(before)?;
            let valid = if error == MappingError::AlreadyMapped { entry == PageEntry::Absent }
                else { mapped(entry).is_some() };
            if !valid { return Err(before(error)); }
            if offset == 0 { first_run = Some((entry, run)); }
            offset += run;
        }
    }
    if let Edit::ReserveZero { access, executable, .. } = operation {
        let mapping = Mapping {
            backing: Backing::Borrowed(zero),
            attributes: Attributes::default().with_executable(executable),
        };
        let entry = match access {
            Protection::None => PageEntry::NoAccess(mapping),
            Protection::ReadOnly => PageEntry::ReadOnly(mapping),
            Protection::ReadWrite => PageEntry::CopyOnWrite(mapping),
        };
        return ops.fill(start, count, entry);
    }

    let mut completed = 0;
    while completed < count {
        let page = start.offset(completed).unwrap();
        let fail = |error| MappingFailure { completed, error };
        let (entry, mut run, mut mapping) = if operation == Edit::CommitZero {
            let mapping = Mapping { backing: Backing::Borrowed(zero), attributes: Attributes::EXECUTABLE };
            (PageEntry::CopyOnWrite(mapping), 1, mapping)
        } else {
            let (entry, run) = match first_run.take() {
                Some(run) => run,
                None => ops.read_run(page, count - completed).map_err(fail)?,
            };
            let Some(mapping) = mapped(entry) else {
                debug_assert!(matches!(operation, Edit::Protect { missing: Missing::Skip, .. }));
                completed += run;
                continue;
            };
            (entry, run, mapping)
        };
        let mut copy = false;
        let next = match operation {
            Edit::CommitZero | Edit::MakePrivate => {
                copy = true;
                Access::ReadWrite
            }
            Edit::Protect { access, executable, .. } => {
                mapping.attributes = mapping.attributes.with_executable(executable);
                copy = access != Protection::ReadWrite
                    && matches!(entry, PageEntry::CopyOnWrite(_))
                    && matches!(mapping.backing, Backing::Borrowed(frame) if frame != zero);
                match access {
                    Protection::None => Access::None,
                    Protection::ReadOnly => Access::ReadOnly,
                    Protection::ReadWrite if matches!(entry, PageEntry::CopyOnWrite(_))
                        || matches!(mapping.backing, Backing::Owned(_)) && !matches!(entry, PageEntry::Writable(_))
                        || mapping.backing.frame() == zero => Access::CopyOnWrite,
                    Protection::ReadWrite => Access::ReadWrite,
                }
            }
            Edit::Discard => {
                mapping.backing = Backing::Borrowed(zero);
                match entry {
                    PageEntry::NoAccess(_) => Access::None,
                    PageEntry::ReadOnly(_) => Access::ReadOnly,
                    _ => Access::CopyOnWrite,
                }
            }
            Edit::ReserveZero { .. } => unreachable!(),
        };
        let owned = if copy {
            run = 1;
            let frame = ops.copy(mapping.backing.frame()).map_err(fail)?;
            mapping.backing = Backing::Owned(frame);
            Some(frame)
        } else { None };
        let result = ops.fill(page, run, next.entry(mapping));
        if let Some(frame) = owned { ops.release(frame); }
        result.map_err(|failure| MappingFailure { completed: completed + failure.completed, error: failure.error })?;
        completed += run;
    }
    Ok(())
}

/// Internal paging mechanisms used while the backend holds its paging lock.
/// Preparation may consume supplied frames; replacement after preparation must
/// not need more table storage. No operation allocates host/kernel storage.
pub trait Rearrange {
    fn read(&mut self, page: UserPage) -> Result<crate::page_entry::PageEntry, MappingError>;
    fn prepare(&mut self, page: UserPage) -> Result<(), MappingError>;
    fn private_alias(&mut self, page: UserPage) -> Result<(), MappingError>;
    fn replace(&mut self, page: UserPage, entry: crate::page_entry::PageEntry) -> Result<(), MappingError>;
    fn retain(&mut self, entry: crate::page_entry::PageEntry);
    fn release(&mut self, entry: crate::page_entry::PageEntry);
}

/// No destination changes occur until preparation succeeds. NeedPages can be
/// retried with more supplied storage: prepared tables and private COW sources
/// persist, but no aliases or swaps have yet been applied.
pub fn rearrange(ops: &mut impl Rearrange, a: UserPage, b: UserPage, count: usize, swap: bool) -> Result<(), MappingError> {
    if count == 0 { return Ok(()); }
    a.offset(count - 1)?;
    b.offset(count - 1)?;
    if a == b { return Ok(()); }
    for i in 0..count {
        let left = a.offset(i)?;
        ops.prepare(left)?;
        if !swap { ops.private_alias(left)?; }
        ops.prepare(b.offset(i)?)?;
    }
    // Aliases have memmove semantics. Preparing all sources first and copying
    // in this direction preserves the original source snapshot on overlap.
    for step in 0..count {
        let i = if !swap && b.address() > a.address() { count - 1 - step } else { step };
        let left = a.offset(i)?;
        let right = b.offset(i)?;
        let l = ops.read(left)?;
        if swap {
            let r = ops.read(right)?;
            ops.retain(l);
            ops.retain(r);
            let result = ops.replace(left, r).and_then(|()| ops.replace(right, l));
            ops.release(l);
            ops.release(r);
            result?;
        } else {
            ops.replace(right, l)?;
        }
    }
    Ok(())
}
