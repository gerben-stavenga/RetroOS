//! Eight-byte semantic leaf entries and checked x86 encoding.
//!
//! This new format is not the historical backend PTE encoding. It describes
//! 4 KiB leaves, not non-leaf entries, large pages or hardware PAE PDPTEs.
//! Fork policy belongs to the caller. Copying a value does not retain backing.
//! Decode ignores present-entry accessed/dirty bits; encode starts them clear.
//! Mapping operations must harvest those observations before replacing a PTE.

#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PageEntry {
    Absent,
    Intercepted,
    /// Retain backing and contents, but prohibit all accesses.
    NoAccess(Mapping),
    ReadOnly(Mapping),
    Writable(Mapping),
    /// A write must obtain private backing before modifying its contents.
    CopyOnWrite(Mapping),
}

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Mapping {
    pub backing: Backing,
    pub attributes: Attributes,
}

#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Backing {
    /// Mapping holds an allocator reference, released when removed.
    Owned(PhysicalFrame),
    /// Another owner guarantees lifetime; removing the mapping releases no frame.
    Borrowed(PhysicalFrame),
}
impl Backing {
    pub const fn frame(self) -> PhysicalFrame {
        match self { Self::Owned(frame) | Self::Borrowed(frame) => frame }
    }
}

// Byte-aligned fields: entry tag (1), backing tag + frame (6), attributes (1).
// No repr(packed), unaligned integer references, or hidden fork/write policy.
const _: () = assert!(core::mem::size_of::<PageEntry>() == 8);
const _: () = assert!(core::mem::align_of::<PageEntry>() == 1);
const _: () = assert!(core::mem::size_of::<Mapping>() == 7);

/// 40-bit physical page number, covering 52-bit physical byte addresses.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PhysicalFrame([u8; 5]);
impl PhysicalFrame {
    pub const fn new(page: u64) -> Result<Self, EncodingError> {
        if page >= 1 << 40 { return Err(EncodingError::FrameOutOfRange); }
        let b = page.to_le_bytes();
        Ok(Self([b[0], b[1], b[2], b[3], b[4]]))
    }
    pub const fn number(self) -> u64 {
        let b = self.0;
        u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], 0, 0, 0])
    }
}

/// Executability and raw x86 cache selection, combined with `|`.
/// Effective cache behavior depends on PAT/MTRR configuration. Access state
/// belongs to PageEntry; ownership belongs to Backing; U/S comes from the VA.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Attributes(u8);
impl Attributes {
    pub const EXECUTABLE: Self = Self(1);
    pub const WRITE_THROUGH: Self = Self(2);
    pub const CACHE_DISABLE: Self = Self(4);
    pub const PAT: Self = Self(8);
    pub const fn with_executable(self, executable: bool) -> Self { Self((self.0 & !1) | executable as u8) }
    pub const fn contains(self, flag: Self) -> bool { self.0 & flag.0 == flag.0 }
}
impl core::ops::BitOr for Attributes {
    type Output = Self;
    fn bitor(self, other: Self) -> Self { Self(self.0 | other.0) }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum X86PteFormat {
    Legacy32,
    /// Common PAE/long-mode leaf format; `nx` means NXE is enabled.
    Wide { physical_address_bits: u8, nx: bool },
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EncodingError {
    InvalidPhysicalWidth,
    FrameOutOfRange,
    InvalidVirtualAddress,
    InvalidEncoding,
}

const P: u64 = 1;
const RW: u64 = 1 << 1;
const US: u64 = 1 << 2;
const PWT: u64 = 1 << 3;
const PCD: u64 = 1 << 4;
const A: u64 = 1 << 5;
const D: u64 = 1 << 6;
const PAT: u64 = 1 << 7;
const COW: u64 = 1 << 9;
const NO_ACCESS: u64 = 1 << 10;
const BORROWED: u64 = 1 << 11;
const NX: u64 = 1 << 63;
// With P=0, this bit denotes interception rather than COW.
const TRAP: u64 = COW;
const KERNEL_START: u64 = 0xc000_0000;

impl X86PteFormat {
    fn layout(self) -> Result<(u64, bool), EncodingError> {
        match self {
            Self::Legacy32 => Ok((0xffff_f000, false)),
            Self::Wide { physical_address_bits, nx } if (32..=52).contains(&physical_address_bits) =>
                Ok((((1u64 << physical_address_bits) - 1) & !0xfff, nx)),
            Self::Wide { .. } => Err(EncodingError::InvalidPhysicalWidth),
        }
    }
}

/// The low 32-bit layout reserves [0xC0000000, 4 GiB) for the kernel.
/// Sparse long-mode user mappings remain above its PML4 slot, as in high_paging.
/// This is a virtual-address classification, independent of the physical frame.
fn user_bit(address: u64, format: X86PteFormat) -> Result<u64, EncodingError> {
    if address & 4095 != 0 { return Err(EncodingError::InvalidVirtualAddress); }
    if address < 1 << 32 { return Ok(if address < KERNEL_START { US } else { 0 }); }
    if matches!(format, X86PteFormat::Wide { .. }) && (1 << 39..1 << 47).contains(&address) {
        return Ok(US);
    }
    Err(EncodingError::InvalidVirtualAddress)
}

impl PageEntry {
    /// Encode a leaf for a page-aligned virtual address. This does not install
    /// it, retain a frame, or invalidate translations. Execute-disable requests
    /// are ignored when this format cannot enforce them.
    pub fn encode(self, format: X86PteFormat, address: u64) -> Result<u64, EncodingError> {
        use Attributes as F;
        let (mask, nx) = format.layout()?;
        let user = user_bit(address, format)?;
        let mapping = match self {
            Self::Absent => return Ok(0),
            Self::Intercepted => return Ok(TRAP),
            Self::NoAccess(m) | Self::ReadOnly(m) | Self::Writable(m) | Self::CopyOnWrite(m) => m,
        };
        let frame = mapping.backing.frame().number();
        if frame > mask >> 12 { return Err(EncodingError::FrameOutOfRange); }
        let f = mapping.attributes;
        let executable = f.contains(F::EXECUTABLE);
        let state = match self {
            Self::NoAccess(_) => NO_ACCESS,
            Self::ReadOnly(_) => P,
            Self::Writable(_) => P | RW,
            Self::CopyOnWrite(_) => P | COW,
            _ => unreachable!(),
        };
        Ok((frame << 12) | state | user | flag(nx && !executable, NX)
            | flag(matches!(mapping.backing, Backing::Borrowed(_)), BORROWED)
            | flag(f.contains(F::WRITE_THROUGH), PWT) | flag(f.contains(F::CACHE_DISABLE), PCD)
            | flag(f.contains(F::PAT), PAT))
    }

    /// Decode this module's encoding, checking that U/S matches the VA layout.
    pub fn decode(raw: u64, format: X86PteFormat, address: u64) -> Result<Self, EncodingError> {
        use Attributes as F;
        let (mask, nx) = format.layout()?;
        let user = user_bit(address, format)?;
        if raw == 0 { return Ok(Self::Absent); }
        if raw == TRAP { return Ok(Self::Intercepted); }
        let allowed = mask | P | RW | US | PWT | PCD | A | D | PAT | COW | NO_ACCESS | BORROWED
            | if nx { NX } else { 0 };
        if raw & !allowed != 0 || raw & US != user { return Err(EncodingError::InvalidEncoding); }
        let state = raw & (P | RW | COW | NO_ACCESS);
        if !matches!(state, NO_ACCESS | P) && state != P | RW && state != P | COW {
            return Err(EncodingError::InvalidEncoding);
        }
        if state == NO_ACCESS && raw & (A | D) != 0 { return Err(EncodingError::InvalidEncoding); }
        let frame = PhysicalFrame::new((raw & mask) >> 12)?;
        let backing = if raw & BORROWED != 0 { Backing::Borrowed(frame) } else { Backing::Owned(frame) };
        let mut attributes = F::default();
        for (enabled, value) in [(raw & NX == 0, F::EXECUTABLE),
            (raw & PWT != 0, F::WRITE_THROUGH), (raw & PCD != 0, F::CACHE_DISABLE),
            (raw & PAT != 0, F::PAT)] {
            if enabled { attributes = attributes | value; }
        }
        let mapping = Mapping { backing, attributes };
        Ok(if state == NO_ACCESS { Self::NoAccess(mapping) }
            else if state & COW != 0 { Self::CopyOnWrite(mapping) }
            else if state & RW != 0 { Self::Writable(mapping) }
            else { Self::ReadOnly(mapping) })
    }
}
const fn flag(enabled: bool, bits: u64) -> u64 { if enabled { bits } else { 0 } }

#[cfg(test)]
mod tests {
    use super::*;
    const WIDE: X86PteFormat = X86PteFormat::Wide { physical_address_bits: 36, nx: true };
    const USER_PAGE: u64 = 0x10000;

    #[test]
    fn all_mapping_states_round_trip() {
        for format in [X86PteFormat::Legacy32, WIDE,
            X86PteFormat::Wide { physical_address_bits: 52, nx: true },
            X86PteFormat::Wide { physical_address_bits: 52, nx: false }] {
            let (mask, nx) = format.layout().unwrap();
            for address in [0, USER_PAGE, KERNEL_START - 4096, KERNEL_START, 0xffff_f000] {
                for entry in [PageEntry::Absent, PageEntry::Intercepted] {
                    assert_eq!(PageEntry::decode(entry.encode(format, address).unwrap(), format, address), Ok(entry));
                }
                for bits in 0..16 {
                    let attributes = Attributes(bits);
                    if !nx && !attributes.contains(Attributes::EXECUTABLE) { continue; }
                    for number in [0, 0x12345, mask >> 12] {
                        let frame = PhysicalFrame::new(number).unwrap();
                        for backing in [Backing::Owned(frame), Backing::Borrowed(frame)] {
                            let m = Mapping { backing, attributes };
                            for entry in [PageEntry::NoAccess(m), PageEntry::ReadOnly(m),
                                PageEntry::Writable(m), PageEntry::CopyOnWrite(m)] {
                                let raw = entry.encode(format, address).unwrap();
                                assert_eq!(raw & US != 0, address < KERNEL_START);
                                assert_eq!(PageEntry::decode(raw, format, address), Ok(entry));
                            }
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn hardware_permissions_and_zero_page() {
        let m = Mapping { backing: Backing::Borrowed(PhysicalFrame::new(0x12345).unwrap()),
            attributes: Attributes::CACHE_DISABLE | Attributes::PAT };
        let entry = PageEntry::CopyOnWrite(m);
        let raw = entry.encode(WIDE, USER_PAGE).unwrap();
        assert_eq!(raw, 0x8000_0000_1234_5a95);
        assert_eq!(PageEntry::decode(raw | A | D, WIDE, USER_PAGE), Ok(entry));
        let no_access = PageEntry::NoAccess(m).encode(WIDE, USER_PAGE).unwrap();
        assert_eq!(no_access & P, 0);
        assert_eq!(PageEntry::decode(no_access, WIDE, USER_PAGE), Ok(PageEntry::NoAccess(m)));
        // The shared zero frame needs no special entry state.
        let zero = Mapping { backing: Backing::Borrowed(PhysicalFrame::new(7).unwrap()),
            attributes: Attributes::EXECUTABLE };
        assert_eq!(PageEntry::CopyOnWrite(zero).encode(WIDE, USER_PAGE).unwrap() & (P | RW | COW), P | COW);
        assert_eq!(PageEntry::ReadOnly(zero).encode(WIDE, USER_PAGE).unwrap() & (P | RW | COW), P);
    }

    #[test]
    fn virtual_address_determines_user_access() {
        let m = Mapping { backing: Backing::Owned(PhysicalFrame::new(0).unwrap()), attributes: Attributes::EXECUTABLE };
        let entry = PageEntry::Writable(m);
        for (address, expected) in [(KERNEL_START - 4096, US), (KERNEL_START, 0),
            (0xffff_f000, 0), (1 << 39, US), ((1 << 47) - 4096, US)] {
            let raw = entry.encode(WIDE, address).unwrap();
            assert_eq!(raw & US, expected);
            assert_eq!(PageEntry::decode(raw, WIDE, address), Ok(entry));
            assert_eq!(PageEntry::decode(raw ^ US, WIDE, address), Err(EncodingError::InvalidEncoding));
        }
        for address in [1, 1 << 32, 1 << 47] {
            assert_eq!(entry.encode(WIDE, address), Err(EncodingError::InvalidVirtualAddress));
        }
        assert_eq!(entry.encode(X86PteFormat::Legacy32, 1 << 39), Err(EncodingError::InvalidVirtualAddress));
    }

    #[test]
    fn execute_disable_is_enforced_only_when_available() {
        let m = Mapping { backing: Backing::Owned(PhysicalFrame::new(7).unwrap()),
            attributes: Attributes::CACHE_DISABLE };
        for entry in [PageEntry::ReadOnly(m), PageEntry::Writable(m),
            PageEntry::CopyOnWrite(m), PageEntry::NoAccess(m)] {
            for format in [X86PteFormat::Legacy32,
                X86PteFormat::Wide { physical_address_bits: 36, nx: false }] {
                let raw = entry.encode(format, USER_PAGE).unwrap();
                assert_eq!(raw & NX, 0);
                let executable = Mapping { attributes: m.attributes.with_executable(true), ..m };
                let expected = match entry {
                    PageEntry::ReadOnly(_) => PageEntry::ReadOnly(executable),
                    PageEntry::Writable(_) => PageEntry::Writable(executable),
                    PageEntry::CopyOnWrite(_) => PageEntry::CopyOnWrite(executable),
                    PageEntry::NoAccess(_) => PageEntry::NoAccess(executable),
                    _ => unreachable!(),
                };
                assert_eq!(PageEntry::decode(raw, format, USER_PAGE), Ok(expected));
            }
            let raw = entry.encode(WIDE, USER_PAGE).unwrap();
            assert_ne!(raw & NX, 0);
            assert_eq!(PageEntry::decode(raw, WIDE, USER_PAGE), Ok(entry));
        }
    }

    #[test]
    fn rejects_out_of_range_and_malformed_entries() {
        assert_eq!(PhysicalFrame::new(1 << 40), Err(EncodingError::FrameOutOfRange));
        assert_eq!(PageEntry::Absent.encode(X86PteFormat::Wide { physical_address_bits: 64, nx: true }, USER_PAGE),
            Err(EncodingError::InvalidPhysicalWidth));
        let m = Mapping { backing: Backing::Owned(PhysicalFrame::new(1 << 20).unwrap()), attributes: Attributes::EXECUTABLE };
        assert_eq!(PageEntry::ReadOnly(m).encode(X86PteFormat::Legacy32, USER_PAGE), Err(EncodingError::FrameOutOfRange));
        assert!(PageEntry::ReadOnly(m).encode(WIDE, USER_PAGE).is_ok());
        for raw in [NX | P | US, 1 << 32, TRAP | US, NO_ACCESS | RW | US,
            NO_ACCESS | COW | US, P | COW | RW | US, P | NO_ACCESS | US, P | (1 << 8) | US] {
            assert_eq!(PageEntry::decode(raw, X86PteFormat::Legacy32, USER_PAGE), Err(EncodingError::InvalidEncoding));
        }
    }
}
