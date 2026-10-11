//! RTC interpretation and local time shared by filesystem metadata and guest personalities.

use core::sync::atomic::{AtomicBool, AtomicI32, Ordering};

static RTC_UTC: AtomicBool = AtomicBool::new(false);
static OFFSET_MINUTES: AtomicI32 = AtomicI32::new(0);

fn cmos_read(index: u8) -> u8 {
    crate::kernel::portio::outb(0x70, index);
    crate::kernel::portio::inb(0x71)
}

fn decode(value: u8, binary: bool) -> u8 {
    if binary { value } else { (value & 0x0F).saturating_add((value >> 4).saturating_mul(10)) }
}

fn ready() -> bool {
    for _ in 0..10_000 {
        let status = cmos_read(0x0A);
        if status == 0xff { return false; }
        if status & 0x80 == 0 { return true; }
    }
    false
}

/// RTC calendar date. Invalid firmware values have no wall-clock timestamp.
fn rtc_date() -> Option<(u16, u8, u8)> {
    if !ready() { return None; }
    let binary = cmos_read(0x0B) & 0x04 != 0;
    let day = decode(cmos_read(0x07), binary);
    let month = decode(cmos_read(0x08), binary);
    let year_lo = decode(cmos_read(0x09), binary);
    let century = decode(cmos_read(0x32), binary);
    let year = if (19..=99).contains(&century) {
        century as u16 * 100 + year_lo as u16
    } else if year_lo >= 80 {
        1900 + year_lo as u16
    } else {
        2000 + year_lo as u16
    };
    if !(1980..=2099).contains(&year) || !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }
    Some((year, month, day))
}

/// RTC time of day as binary (hour, minute, second).
fn rtc_time() -> Option<(u8, u8, u8)> {
    if !ready() { return None; }
    let status_b = cmos_read(0x0B);
    let binary = status_b & 0x04 != 0;
    let sec = decode(cmos_read(0x00), binary);
    let min = decode(cmos_read(0x02), binary);
    let raw_hour = cmos_read(0x04);
    let mut hour = decode(raw_hour & 0x7F, binary);
    if status_b & 0x02 == 0 {
        hour %= 12;
        if raw_hour & 0x80 != 0 { hour += 12; }
    }
    if sec > 59 || min > 59 || hour > 23 { return None; }
    Some((hour, min, sec))
}

/// UTC seconds since the Unix epoch, interpreting the RTC using boot policy.
pub fn rtc_unix_timestamp() -> Option<u32> {
    let (year, month, day) = rtc_date()?;
    let (hour, minute, second) = rtc_time()?;
    let (year, month, day) = (year as u32, month as u32, day as u32);
    let days_in_month = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    let leap = year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400));
    if month == 0 || month > 12 || day == 0
        || day > days_in_month[month as usize - 1] + u32::from(month == 2 && leap) {
        return None;
    }
    let y = year as i64 - i64::from(month <= 2);
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let m = month as i64;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + day as i64 - 1;
    let days = era * 146097 + (yoe * 365 + yoe / 4 - yoe / 100 + doy) - 719468;
    let seconds = days * 86_400 + hour as i64 * 3600
        + minute as i64 * 60 + second as i64;
    let unix = u32::try_from(seconds).ok()?;
    Some(if RTC_UTC.load(Ordering::Relaxed) { unix } else { local_to_unix(unix) })
}

/// Calendar fields: year, month, weekday (Sunday = 0), day, hour, minute,
/// second and milliseconds. Shared by the Windows and OS/2 time APIs.
pub(crate) fn calendar_from_unix(unix: i64) -> [u16; 8] {
    let days = unix.div_euclid(86_400);
    let seconds = unix.rem_euclid(86_400) as u32;
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let year = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = mp + if mp < 10 { 3 } else { -9 };
    [
        (year + i64::from(month <= 2)) as u16,
        month as u16,
        (days + 4).rem_euclid(7) as u16,
        day as u16,
        (seconds / 3_600) as u16,
        ((seconds / 60) % 60) as u16,
        (seconds % 60) as u16,
        0,
    ]
}

pub fn configure(rtc: Option<&[u8]>, offset: Option<&[u8]>) -> Result<(), &'static str> {
    let utc = match rtc.unwrap_or(b"local") {
        value if value.eq_ignore_ascii_case(b"utc") => true,
        value if value.eq_ignore_ascii_case(b"local") => false,
        _ => return Err("clock rtc must be utc or local"),
    };
    let minutes = parse_offset(offset.unwrap_or(b"+00:00"))
        .ok_or("clock utc_offset must be +/-HH:MM (up to 14:00)")?;
    OFFSET_MINUTES.store(minutes, Ordering::Relaxed);
    RTC_UTC.store(utc, Ordering::Relaxed);
    Ok(())
}

fn parse_offset(value: &[u8]) -> Option<i32> {
    if value.len() != 6 || !matches!(value[0], b'+' | b'-') || value[3] != b':' {
        return None;
    }
    if ![value[1], value[2], value[4], value[5]].iter().all(u8::is_ascii_digit) {
        return None;
    }
    let hours = i32::from(value[1] - b'0') * 10 + i32::from(value[2] - b'0');
    let minutes = i32::from(value[4] - b'0') * 10 + i32::from(value[5] - b'0');
    if minutes >= 60 || hours > 14 || (hours == 14 && minutes != 0) { return None; }
    Some((hours * 60 + minutes) * if value[0] == b'-' { -1 } else { 1 })
}

pub fn rtc_to_local(date: (u16, u8, u8), time: (u8, u8, u8)) -> ((u16, u8, u8), (u8, u8, u8)) {
    let offset = if RTC_UTC.load(Ordering::Relaxed) { OFFSET_MINUTES.load(Ordering::Relaxed) } else { 0 };
    shift_date_time(date, time, offset)
}

fn month_days(year: u16, month: u8) -> u8 {
    let leap = year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400));
    [31, 28 + u8::from(leap), 31, 30, 31, 30, 31, 31, 30, 31, 30, 31][usize::from(month - 1)]
}

fn shift_date_time(mut date: (u16, u8, u8), time: (u8, u8, u8), offset: i32)
    -> ((u16, u8, u8), (u8, u8, u8))
{
    let minutes = i32::from(time.0) * 60 + i32::from(time.1) + offset;
    let day_shift = minutes.div_euclid(1440);
    if day_shift < 0 {
        if date.2 > 1 { date.2 -= 1; }
        else {
            if date.1 > 1 { date.1 -= 1; } else { date.0 -= 1; date.1 = 12; }
            date.2 = month_days(date.0, date.1);
        }
    } else if day_shift > 0 {
        if date.2 < month_days(date.0, date.1) { date.2 += 1; }
        else {
            date.2 = 1;
            if date.1 < 12 { date.1 += 1; } else { date.0 += 1; date.1 = 1; }
        }
    }
    let minutes = minutes.rem_euclid(1440);
    (date, ((minutes / 60) as u8, (minutes % 60) as u8, time.2))
}

fn shift_timestamp(unix: u32, offset: i32) -> u32 {
    if unix == 0 { return 0; }
    u32::try_from(i64::from(unix) + i64::from(offset) * 60).unwrap_or(0)
}

pub fn unix_to_local(unix: u32) -> u32 {
    shift_timestamp(unix, OFFSET_MINUTES.load(Ordering::Relaxed))
}

pub fn utc_offset_minutes() -> i32 {
    OFFSET_MINUTES.load(Ordering::Relaxed)
}

pub fn local_to_unix(local: u32) -> u32 {
    shift_timestamp(local, -OFFSET_MINUTES.load(Ordering::Relaxed))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn offsets_validate_and_support_partial_hours() {
        assert_eq!(parse_offset(b"+05:45"), Some(345));
        assert_eq!(parse_offset(b"-03:30"), Some(-210));
        assert_eq!(parse_offset(b"+14:00"), Some(840));
        for invalid in [b"+14:01".as_slice(), b"+01:60", b"05:00", b"+aa:00", b"+99:00"] {
            assert_eq!(parse_offset(invalid), None);
        }
    }

    #[test]
    fn local_date_crosses_year_and_leap_day() {
        assert_eq!(shift_date_time((2026, 1, 1), (2, 15, 42), -420), ((2025, 12, 31), (19, 15, 42)));
        assert_eq!(shift_date_time((2024, 3, 1), (0, 0, 0), -60), ((2024, 2, 29), (23, 0, 0)));
        assert_eq!(shift_date_time((2100, 3, 1), (0, 0, 0), -60), ((2100, 2, 28), (23, 0, 0)));
        assert_eq!(shift_date_time((2026, 12, 31), (23, 30, 0), 345), ((2027, 1, 1), (5, 15, 0)));
        assert_eq!(shift_date_time((2026, 10, 11), (12, 0, 0), 0), ((2026, 10, 11), (12, 0, 0)));
    }

    #[test]
    fn filesystem_times_round_trip_and_preserve_unknown() {
        let unix = 1_700_000_000;
        assert_eq!(shift_timestamp(shift_timestamp(unix, -420), 420), unix);
        assert_eq!(shift_timestamp(0, 345), 0);
        assert_eq!(shift_timestamp(1, -60), 0);
    }
}
