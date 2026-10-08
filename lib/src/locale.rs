//! Shared locale policy. Strings are Unicode; guest encodings live at API edges.
use core::sync::atomic::{AtomicU16, Ordering};

pub struct Locale {
    pub tag: &'static str,
    pub posix: &'static str,
    pub country: u16,
    pub lcid: u32,
    pub ansi: u16,
    pub oem: u16,
    pub keyboard: &'static str,
    pub language: &'static str,
    pub native_language: &'static str,
    pub native_name: &'static str,
    pub english_country: &'static str,
    pub native_country: &'static str,
    pub iso_language: &'static str,
    pub iso_country: &'static str,
    pub date_order: u16, // DOS: 0 MDY, 1 DMY, 2 YMD
    pub date_separator: &'static str,
    pub short_date: &'static str,
    pub long_date: &'static str,
    pub time_format: &'static str,
    pub time24: bool,
    pub decimal: &'static str,
    pub thousands: &'static str,
    pub list_separator: &'static str,
    pub currency: &'static str,
    pub currency_iso: &'static str,
    pub currency_format: u8, // bit 0: suffix, bit 1: separating space
    pub negative_currency: u8, // Windows LOCALE_INEGCURR
}

pub static PROFILES: [Locale; 6] = [
    Locale {
        tag: "en-US", posix: "en_US.UTF-8", country: 1, lcid: 0x0409,
        ansi: 1252, oem: 437, keyboard: "us", language: "English", native_language: "English",
        native_name: "English (United States)", english_country: "United States", native_country: "United States",
        iso_language: "en", iso_country: "US", date_order: 0, date_separator: "/",
        short_date: "M/d/yyyy", long_date: "dddd, MMMM dd, yyyy", time_format: "h:mm:ss tt", time24: false,
        decimal: ".", thousands: ",", list_separator: ",", currency: "$", currency_iso: "USD",
        currency_format: 0, negative_currency: 0,
    },
    Locale {
        tag: "ru-RU", posix: "ru_RU.UTF-8", country: 7, lcid: 0x0419,
        ansi: 1251, oem: 866, keyboard: "ru", language: "Russian", native_language: "Русский",
        native_name: "Русский (Россия)", english_country: "Russia", native_country: "Россия",
        iso_language: "ru", iso_country: "RU", date_order: 1, date_separator: ".",
        short_date: "dd.MM.yyyy", long_date: "d MMMM yyyy 'г.'", time_format: "H:mm:ss", time24: true,
        decimal: ",", thousands: "\u{a0}", list_separator: ";", currency: "руб.", currency_iso: "RUB",
        currency_format: 3, negative_currency: 8,
    },
    Locale {
        tag: "pl-PL", posix: "pl_PL.UTF-8", country: 48, lcid: 0x0415,
        ansi: 1250, oem: 852, keyboard: "pl", language: "Polish", native_language: "Polski",
        native_name: "Polski (Polska)", english_country: "Poland", native_country: "Polska",
        iso_language: "pl", iso_country: "PL", date_order: 1, date_separator: ".",
        short_date: "dd.MM.yyyy", long_date: "d MMMM yyyy", time_format: "HH:mm:ss", time24: true,
        decimal: ",", thousands: "\u{a0}", list_separator: ";", currency: "zł", currency_iso: "PLN",
        currency_format: 3, negative_currency: 8,
    },
    Locale {
        tag: "de-DE", posix: "de_DE.UTF-8", country: 49, lcid: 0x0407,
        ansi: 1252, oem: 850, keyboard: "de", language: "German", native_language: "Deutsch",
        native_name: "Deutsch (Deutschland)", english_country: "Germany", native_country: "Deutschland",
        iso_language: "de", iso_country: "DE", date_order: 1, date_separator: ".",
        short_date: "dd.MM.yyyy", long_date: "dddd, d. MMMM yyyy", time_format: "HH:mm:ss", time24: true,
        decimal: ",", thousands: ".", list_separator: ";", currency: "€", currency_iso: "EUR",
        currency_format: 3, negative_currency: 8,
    },
    Locale {
        tag: "it-IT", posix: "it_IT.UTF-8", country: 39, lcid: 0x0410,
        ansi: 1252, oem: 850, keyboard: "it", language: "Italian", native_language: "Italiano",
        native_name: "Italiano (Italia)", english_country: "Italy", native_country: "Italia",
        iso_language: "it", iso_country: "IT", date_order: 1, date_separator: "/",
        short_date: "dd/MM/yyyy", long_date: "dddd d MMMM yyyy", time_format: "HH:mm:ss", time24: true,
        decimal: ",", thousands: ".", list_separator: ";", currency: "€", currency_iso: "EUR",
        currency_format: 2, negative_currency: 9,
    },
    Locale {
        tag: "nl-NL", posix: "nl_NL.UTF-8", country: 31, lcid: 0x0413,
        ansi: 1252, oem: 850, keyboard: "us", language: "Dutch", native_language: "Nederlands",
        native_name: "Nederlands (Nederland)", english_country: "Netherlands", native_country: "Nederland",
        iso_language: "nl", iso_country: "NL", date_order: 1, date_separator: "-",
        short_date: "d-M-yyyy", long_date: "dddd d MMMM yyyy", time_format: "HH:mm:ss", time24: true,
        decimal: ",", thousands: ".", list_separator: ";", currency: "€", currency_iso: "EUR",
        currency_format: 2, negative_currency: 12,
    },
];

static CURRENT: AtomicU16 = AtomicU16::new(0);
static SYSTEM_OEM: AtomicU16 = AtomicU16::new(437);

pub fn current() -> &'static Locale { &PROFILES[CURRENT.load(Ordering::Acquire) as usize] }
pub fn by_tag(tag: &str) -> Option<&'static Locale> {
    PROFILES.iter().find(|profile| profile.tag.eq_ignore_ascii_case(tag))
}
pub fn by_country(country: u16) -> Option<&'static Locale> {
    PROFILES.iter().find(|profile| profile.country == country)
}
pub fn by_lcid(lcid: u32) -> Option<&'static Locale> {
    match lcid {
        0 | 0x0400 | 0x0800 => Some(current()),
        _ => PROFILES.iter().find(|profile| profile.lcid == lcid),
    }
}

/// Startup-only selection, before any guest processes exist.
pub fn select(tag: &str) -> bool {
    let Some(index) = PROFILES.iter().position(|profile| profile.tag.eq_ignore_ascii_case(tag)) else { return false; };
    CURRENT.store(index as u16, Ordering::Release);
    true
}

pub fn system_oem() -> u16 { SYSTEM_OEM.load(Ordering::Acquire) }
pub fn set_system_oem(id: u16) -> bool {
    if crate::codepage::codepage(id).is_none() { return false; }
    SYSTEM_OEM.store(id, Ordering::Release);
    crate::codepage::select_codepage(id)
}
