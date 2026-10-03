//! Host RTC wall clock shared by filesystem metadata and guest personalities.

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

/// Seconds since the Unix epoch, for VFS modification times. The RTC is read
/// as local firmware time, matching the existing DOS and FAT clock convention.
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
    u32::try_from(seconds).ok()
}
