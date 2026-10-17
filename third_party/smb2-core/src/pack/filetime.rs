//! Windows FILETIME type for SMB2.
//!
//! A FILETIME is a 64-bit value representing 100-nanosecond intervals
//! since 1601-01-01 00:00:00 UTC.

#[allow(unused_imports)]
use alloc::{vec::Vec, string::{String, ToString}, borrow::ToOwned};


use super::{Pack, ReadCursor, Unpack, WriteCursor};
use crate::error::Result;

/// Difference between the Windows epoch (1601-01-01) and Unix epoch (1970-01-01)
/// in 100-nanosecond intervals.
#[cfg(test)]
const EPOCH_DIFF_100NS: u64 = 116_444_736_000_000_000;

/// Windows FILETIME: 100-nanosecond intervals since 1601-01-01 00:00:00 UTC.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct FileTime(
    /// The raw 100-nanosecond tick count.
    pub u64,
);

impl FileTime {
    /// A zero filetime, meaning "not set" or "unknown".
    pub const ZERO: Self = Self(0);

}

impl Pack for FileTime {
    fn pack(&self, cursor: &mut WriteCursor) {
        cursor.write_u64_le(self.0);
    }
}

impl Unpack for FileTime {
    fn unpack(cursor: &mut ReadCursor<'_>) -> Result<Self> {
        let val = cursor.read_u64_le()?;
        Ok(Self(val))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_filetime() {
        assert_eq!(FileTime::ZERO, FileTime(0));
    }

    #[test]
    fn pack_zero() {
        let mut w = WriteCursor::new();
        FileTime::ZERO.pack(&mut w);
        assert_eq!(w.as_bytes(), &[0u8; 8]);
    }

    #[test]
    fn unpack_zero() {
        let bytes = [0u8; 8];
        let mut r = ReadCursor::new(&bytes);
        let ft = FileTime::unpack(&mut r).unwrap();
        assert_eq!(ft, FileTime::ZERO);
    }

    #[test]
    fn known_value_2024_01_01() {
        // 2024-01-01 00:00:00 UTC = FileTime(133_485_408_000_000_000)
        // (Unix timestamp 1_704_067_200 * 10_000_000 + 116_444_736_000_000_000)
        let expected_raw: u64 = 133_485_408_000_000_000;
        let ft = FileTime(expected_raw);

        // Pack and verify roundtrip
        let mut w = WriteCursor::new();
        ft.pack(&mut w);
        let mut r = ReadCursor::new(w.as_bytes());
        let unpacked = FileTime::unpack(&mut r).unwrap();
        assert_eq!(unpacked, ft);

        // Verify SystemTime conversion
        // 2024-01-01 00:00:00 UTC = Unix timestamp 1_704_067_200
        let st = ft.to_system_time().unwrap();
        let unix_dur = st.duration_since(UNIX_EPOCH).unwrap();
        assert_eq!(unix_dur.as_secs(), 1_704_067_200);
        assert_eq!(unix_dur.subsec_nanos(), 0);
    }

    #[test]
    fn from_system_time_roundtrip() {
        // Use a known Unix timestamp: 2024-01-01 00:00:00 UTC
        let unix_secs = 1_704_067_200u64;
        let st = UNIX_EPOCH + Duration::from_secs(unix_secs);
        let ft = FileTime::from_system_time(st);
        assert_eq!(ft.0, 133_485_408_000_000_000);

        let st2 = ft.to_system_time().unwrap();
        let dur = st2.duration_since(UNIX_EPOCH).unwrap();
        assert_eq!(dur.as_secs(), unix_secs);
    }

    #[test]
    fn pre_unix_epoch_returns_none() {
        // A FILETIME value that represents a date before 1970-01-01
        let ft = FileTime(EPOCH_DIFF_100NS - 1);
        assert!(ft.to_system_time().is_none());

        // Zero is also before Unix epoch
        assert!(FileTime::ZERO.to_system_time().is_none());
    }

    #[test]
    fn unix_epoch_exactly() {
        let ft = FileTime(EPOCH_DIFF_100NS);
        let st = ft.to_system_time().unwrap();
        assert_eq!(st, UNIX_EPOCH);
    }

    #[test]
    fn from_system_time_unix_epoch() {
        let ft = FileTime::from_system_time(UNIX_EPOCH);
        assert_eq!(ft.0, EPOCH_DIFF_100NS);
    }

    #[test]
    fn pack_unpack_roundtrip() {
        let ft = FileTime(133_476_576_000_000_000);
        let mut w = WriteCursor::new();
        ft.pack(&mut w);
        let mut r = ReadCursor::new(w.as_bytes());
        let unpacked = FileTime::unpack(&mut r).unwrap();
        assert_eq!(unpacked, ft);
    }

    #[test]
    fn unpack_insufficient_bytes() {
        let bytes = [0u8; 4]; // need 8
        let mut r = ReadCursor::new(&bytes);
        assert!(FileTime::unpack(&mut r).is_err());
    }
}
