//! DOS calendar, RTC and BIOS tick conversions.

use crate::Regs;

const PIT_INPUT_HZ: u64 = 1_193_182;
const BIOS_TICK_DIVISOR: u64 = 65_536;

pub(super) fn bios_time_of_day<A: crate::Arch>(machine: &mut A) -> (u8, u8, u8, u8) {
    // BIOS tick count at 0040:006C advances at PIT_INPUT_HZ / 65536 Hz.
    // DOS AH=2Ch returns hundredths, so convert through centiseconds instead
    // of approximating the tick rate as 18 Hz. (BDA = guest address space.)
    let ticks = crate::kernel::dos::Bda::tick_count(machine) as u64;
    let total_centis = ticks
        .saturating_mul(BIOS_TICK_DIVISOR)
        .saturating_mul(100)
        / PIT_INPUT_HZ;
    let total_secs = total_centis / 100;

    (
        ((total_secs / 3600) % 24) as u8,
        ((total_secs / 60) % 60) as u8,
        (total_secs % 60) as u8,
        (total_centis % 100) as u8,
    )
}

fn cmos_read<A: crate::Arch>(machine: &mut A, index: u8) -> u8 {
    machine.outb(0x70, index);
    machine.inb(0x71)
}

fn cmos_decode(value: u8, binary: bool) -> u8 {
    if binary {
        value
    } else {
        (value & 0x0F).saturating_add((value >> 4).saturating_mul(10))
    }
}

fn day_of_week(mut year: u16, mut month: u8, day: u8) -> u8 {
    // Sakamoto algorithm, returns 0=Sunday .. 6=Saturday (DOS convention).
    const OFFSETS: [u8; 12] = [0, 3, 2, 5, 0, 3, 5, 1, 4, 6, 2, 4];
    if month < 3 {
        year = year.saturating_sub(1);
    }
    month = month.clamp(1, 12);
    let y = year as u32;
    ((y + y / 4 - y / 100 + y / 400 + OFFSETS[month as usize - 1] as u32 + day as u32) % 7) as u8
}

fn raw_cmos_date<A: crate::Arch>(machine: &mut A) -> (u16, u8, u8, u8) {
    for _ in 0..10_000 {
        if cmos_read(machine, 0x0A) & 0x80 == 0 {
            break;
        }
    }

    let status_b = cmos_read(machine, 0x0B);
    let binary = status_b & 0x04 != 0;
    let day = cmos_decode(cmos_read(machine, 0x07), binary);
    let month = cmos_decode(cmos_read(machine, 0x08), binary);
    let year_lo = cmos_decode(cmos_read(machine, 0x09), binary);
    let century = cmos_decode(cmos_read(machine, 0x32), binary);

    let year = if (19..=99).contains(&century) {
        century as u16 * 100 + year_lo as u16
    } else if year_lo >= 80 {
        1900 + year_lo as u16
    } else {
        2000 + year_lo as u16
    };

    if !(1980..=2099).contains(&year) || !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return (2026, 3, 22, 6);
    }

    (year, month, day, day_of_week(year, month, day))
}

/// RTC time of day as binary (hour, minute, second), handling BCD/binary and
/// 12/24-hour CMOS formats. Implausible values collapse to midnight — a
/// wrong-but-sane clock beats letting firmware garbage through.
fn raw_rtc_time<A: crate::Arch>(machine: &mut A) -> (u8, u8, u8) {
    for _ in 0..10_000 {
        if cmos_read(machine, 0x0A) & 0x80 == 0 {
            break;
        }
    }
    let status_b = cmos_read(machine, 0x0B);
    let binary = status_b & 0x04 != 0;
    let sec = cmos_decode(cmos_read(machine, 0x00), binary);
    let min = cmos_decode(cmos_read(machine, 0x02), binary);
    let raw_hour = cmos_read(machine, 0x04);
    let mut hour = cmos_decode(raw_hour & 0x7F, binary);
    if status_b & 0x02 == 0 {
        // 12-hour mode: bit 7 = PM, hour 12 wraps to 0.
        hour %= 12;
        if raw_hour & 0x80 != 0 {
            hour += 12;
        }
    }
    if sec > 59 || min > 59 || hour > 23 {
        return (0, 0, 0);
    }
    (hour, min, sec)
}

/// Local date and time derived together so UTC offsets carry across midnight.
fn local_rtc<A: crate::Arch>(machine: &mut A) -> ((u16, u8, u8), (u8, u8, u8)) {
    let (year, month, day, _) = raw_cmos_date(machine);
    let time = raw_rtc_time(machine);
    crate::kernel::clock::rtc_to_local((year, month, day), time)
}

pub(in crate::kernel::dos) fn cmos_date<A: crate::Arch>(machine: &mut A) -> (u16, u8, u8, u8) {
    let ((year, month, day), _) = local_rtc(machine);
    (year, month, day, day_of_week(year, month, day))
}

pub(in crate::kernel::dos) fn rtc_time<A: crate::Arch>(machine: &mut A) -> (u8, u8, u8) {
    local_rtc(machine).1
}

/// BIOS tick-of-day counter value for "now", read from the RTC — what a real
/// POST stores at 40:6C. Guarded time source: DOS/4GW's 16-bit ticks→time
/// conversion #DEs on a counter whose high word exceeds ~24 hours' worth of
/// ticks, so this never returns more than a day.
pub(in crate::kernel::dos) fn rtc_ticks_today<A: crate::Arch>(machine: &mut A) -> u32 {
    let (hour, min, sec) = rtc_time(machine);
    let secs = (hour as u64) * 3600 + (min as u64) * 60 + sec as u64;
    (secs * PIT_INPUT_HZ / BIOS_TICK_DIVISOR) as u32
}

pub(super) fn current_dos_timestamp<A: crate::Arch>(machine: &mut A, _regs: &Regs) -> (u16, u16) {
    let (hour, min, sec, _) = bios_time_of_day(machine);
    let (year, month, day, _) = cmos_date(machine);
    let dos_time = ((hour as u16) << 11) | ((min as u16) << 5) | ((sec as u16) / 2);
    let dos_date = ((year.saturating_sub(1980)) << 9) | ((month as u16) << 5) | day as u16;
    (dos_time, dos_date)
}

/// Unix epoch seconds → DOS `(time, date)` as INT 21h reports them in the DTA.
///
/// Time packs hh:mm:(ss/2) into 5/6/5 bits; date packs (year-1980):month:day
/// into 7/4/5. The representable window is 1980-01-01 through 2107-12-31 —
/// anything outside it, including the `0` that means "no timestamp", reports
/// `(0, 0)`. A zero date renders as blank rather than as a plausible-looking
/// 1980-01-01, so an unknown time never masquerades as a real one.
pub(super) fn unix_to_dos_datetime(unix: u32) -> (u16, u16) {
    let unix = crate::kernel::clock::unix_to_local(unix);
    const DOS_EPOCH: u32 = 315_532_800; // 1980-01-01T00:00:00Z
    if unix < DOS_EPOCH {
        return (0, 0);
    }
    let days = (unix / 86_400) as i64;
    let secs = unix % 86_400;

    // Days since the Unix epoch → civil date (Howard Hinnant's algorithm,
    // shifted to an era starting 0000-03-01 so leap days land at the end).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let month = (if mp < 10 { mp + 3 } else { mp - 9 }) as u32;
    let year = (y + i64::from(month <= 2)) as u32;

    if !(1980..=2107).contains(&year) {
        return (0, 0);
    }
    let dos_date = ((year - 1980) << 9) | (month << 5) | day;
    let dos_time = ((secs / 3_600) << 11) | ((secs % 3_600 / 60) << 5) | ((secs % 60) / 2);
    (dos_time as u16, dos_date as u16)
}

pub(crate) fn dos_to_unix_datetime(time: u16, date: u16) -> Option<u32> {
    let year = 1980u32 + ((date >> 9) & 0x7F) as u32;
    let month = ((date >> 5) & 0x0F) as u32;
    let day = (date & 0x1F) as u32;
    let hour = ((time >> 11) & 0x1F) as u32;
    let minute = ((time >> 5) & 0x3F) as u32;
    let second = ((time & 0x1F) as u32) * 2;
    if month == 0 || month > 12 || day == 0 || hour > 23 || minute > 59 || second > 59 {
        return None;
    }
    const MONTH_DAYS: [u32; 12] = [31,28,31,30,31,30,31,31,30,31,30,31];
    let leap = |y: u32| y.is_multiple_of(4) && (!y.is_multiple_of(100) || y.is_multiple_of(400));
    let max_day = MONTH_DAYS[month as usize - 1] + u32::from(month == 2 && leap(year));
    if day > max_day { return None; }
    let days = epoch_days_fast(year, month, day);
    let local = days.checked_mul(86_400)?
        .checked_add(hour * 3_600 + minute * 60 + second)?;
    Some(crate::kernel::clock::local_to_unix(local))
}

/// Branchless Gregorian Y/M/D -> days since 1970-01-01. This is the
/// power-of-two month-polynomial formulation from
/// https://blog.reverberate.org/2020/05/12/optimizing-date-algorithms.html
pub(super) fn epoch_days_fast(year: u32, month: u32, day: u32) -> u32 {
    const YEAR_BASE: u32 = 4800;
    let month_adjusted = month.wrapping_sub(3);
    let carry = u32::from(month_adjusted > month);
    let adjusted_year = year + YEAR_BASE - carry;
    let month_days = ((month_adjusted + carry * 12) * 62_719 + 769) >> 11;
    let leap_days = adjusted_year / 4 - adjusted_year / 100 + adjusted_year / 400;
    adjusted_year * 365 + leap_days + month_days + day - 1 - 2_472_632
}

#[cfg(test)]
mod tests {
    use super::{dos_to_unix_datetime, epoch_days_fast, unix_to_dos_datetime};

    #[test]
    fn branchless_epoch_days_matches_known_dates() {
        assert_eq!(epoch_days_fast(1970, 1, 1), 0);
        assert_eq!(epoch_days_fast(2000, 1, 1), 10_957);
        assert_eq!(epoch_days_fast(2020, 4, 29), 18_381);
    }

    #[test]
    fn dos_datetime_round_trips_at_two_second_resolution() {
        for unix in [315_532_800, 946_684_800, 1_709_251_198, 4_102_444_798] {
            let (time, date) = unix_to_dos_datetime(unix);
            assert_eq!(dos_to_unix_datetime(time, date), Some(unix));
        }
    }

    #[test]
    fn rejects_invalid_dos_dates() {
        assert_eq!(dos_to_unix_datetime(0, 0), None);
        assert_eq!(dos_to_unix_datetime(0, (44 << 9) | (2 << 5) | 30), None);
    }
}
