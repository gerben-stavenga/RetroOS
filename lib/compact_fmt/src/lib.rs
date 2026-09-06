#![no_std]
#![feature(optimize_attribute)]

//! Allocation-free formatting with compact compile-time bytecode.
//!
//! Bytes 1 through 254 introduce a literal run of that length. Zero
//! introduces a packed argument format byte and an optional width byte;
//! 255 terminates the stream.

pub use compact_fmt_macros::{write, writeln};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Error;

pub type Result = core::result::Result<(), Error>;

pub trait Write {
    fn write_str(&mut self, text: &str) -> Result;
}

impl<T: Write + ?Sized> Write for &mut T {
    fn write_str(&mut self, text: &str) -> Result {
        (**self).write_str(text)
    }
}

fn write_char(out: &mut dyn Write, character: char) -> Result {
    out.write_str(character.encode_utf8(&mut [0; 4]))
}

const PRESENT_MASK: u8 = 0x07;
const ALTERNATE: u8 = 0x08;
const ZERO_PAD: u8 = 0x10;
const SIGN_PLUS: u8 = 0x20;
const HAS_WIDTH: u8 = 0x40;

const DISPLAY: u8 = 0;
const LOWER_HEX: u8 = 1;
const UPPER_HEX: u8 = 2;
const BINARY: u8 = 3;
const OCTAL: u8 = 4;
const POINTER: u8 = 5;
const DEBUG: u8 = 6;
const DEBUG_HEX: u8 = 7;
const DEBUG_UPPER: u8 = 0x80;

/// One machine word of argument storage.
#[repr(C)]
#[derive(Copy, Clone)]
pub union RawValue {
    word: usize,
    reference: *const (),
}

/// Formatting flags passed to project-defined compact formatters.
#[derive(Copy, Clone)]
pub struct FormatSpec {
    raw: u8,
    width: Option<u8>,
}

impl FormatSpec {
    pub fn width(self) -> Option<u8> { self.width }
    pub fn is_debug(self) -> bool { self.raw & PRESENT_MASK == DEBUG }
}

/// Formatting for the uncommon structured values that cannot fit inline.
pub trait Format {
    fn format(&self, out: &mut dyn Write, spec: FormatSpec) -> Result;
}

impl<T: Format + ?Sized> Format for &T {
    fn format(&self, out: &mut dyn Write, spec: FormatSpec) -> Result {
        (*self).format(out, spec)
    }
}

macro_rules! optional_integer {
    ($ty:ty) => {
        impl Format for Option<$ty> {
            fn format(&self, out: &mut dyn Write, spec: FormatSpec) -> Result {
                match self {
                    Some(value) => {
                        out.write_str("Some(")?;
                        number(out, *value as u64, false, spec.raw, spec.width)?;
                        write_char(out, ')')
                    }
                    None => out.write_str("None"),
                }
            }
        }
    };
}

optional_integer!(u8);
optional_integer!(u32);

#[doc(hidden)]
pub type FormatFn = unsafe fn(&mut dyn Write, RawValue, u8, Option<u8>) -> Result;

unsafe fn format_value<T: Format>(
    out: &mut dyn Write,
    value: RawValue,
    raw: u8,
    width: Option<u8>,
) -> Result {
    unsafe { (&*value.reference.cast::<T>()).format(out, FormatSpec { raw, width }) }
}

#[doc(hidden)]
pub trait Capture {
    const FORMAT: FormatFn;
    fn value(&self) -> RawValue;
}

macro_rules! inline_unsigned {
    ($($ty:ty),+ $(,)?) => {$(
        impl Capture for $ty {
            const FORMAT: FormatFn = format_u32;
            #[inline]
            fn value(&self) -> RawValue {
                RawValue { word: *self as usize }
            }
        }
    )+};
}

macro_rules! inline_signed {
    ($($ty:ty => $format:ident),+ $(,)?) => {$(
        impl Capture for $ty {
            const FORMAT: FormatFn = $format;
            #[inline]
            fn value(&self) -> RawValue {
                RawValue { word: (*self as i32) as usize }
            }
        }
    )+};
}

inline_unsigned!(u8, u16, u32);
inline_signed!(i8 => format_i8, i16 => format_i16, i32 => format_i32);

impl Capture for usize {
    const FORMAT: FormatFn = format_usize;
    #[inline]
    fn value(&self) -> RawValue {
        RawValue { word: *self }
    }
}

impl Capture for isize {
    const FORMAT: FormatFn = format_isize;
    #[inline]
    fn value(&self) -> RawValue {
        RawValue { word: *self as usize }
    }
}

impl Capture for u64 {
    const FORMAT: FormatFn = format_u64;
    #[inline]
    fn value(&self) -> RawValue {
            #[cfg(target_pointer_width = "64")]
            let value = RawValue {
                word: *self as usize,
            };
            #[cfg(not(target_pointer_width = "64"))]
            let value = RawValue {
                reference: self as *const u64 as *const (),
            };
            value
    }
}

impl Capture for i64 {
    const FORMAT: FormatFn = format_i64;
    #[inline]
    fn value(&self) -> RawValue {
            #[cfg(target_pointer_width = "64")]
            let value = RawValue {
                word: *self as usize,
            };
            #[cfg(not(target_pointer_width = "64"))]
            let value = RawValue {
                reference: self as *const i64 as *const (),
            };
            value
    }
}

impl Capture for &str {
    const FORMAT: FormatFn = format_str;
    #[inline]
    fn value(&self) -> RawValue {
        RawValue { reference: self as *const &str as *const () }
    }
}

impl Capture for bool {
    const FORMAT: FormatFn = format_bool;
    #[inline]
    fn value(&self) -> RawValue {
        RawValue { word: usize::from(*self) }
    }
}

impl Capture for char {
    const FORMAT: FormatFn = format_char;
    #[inline]
    fn value(&self) -> RawValue {
        RawValue { word: *self as usize }
    }
}

impl Capture for &[u8] {
    const FORMAT: FormatFn = format_bytes;
    #[inline]
    fn value(&self) -> RawValue {
        RawValue { reference: self as *const &[u8] as *const () }
    }
}

impl Capture for &[u32] {
    const FORMAT: FormatFn = format_words;
    #[inline]
    fn value(&self) -> RawValue {
        RawValue { reference: self as *const &[u32] as *const () }
    }
}

impl<T: Format> Capture for T {
    const FORMAT: FormatFn = format_value::<T>;
    #[inline]
    fn value(&self) -> RawValue {
        RawValue { reference: self as *const T as *const () }
    }
}

#[doc(hidden)]
#[inline]
pub fn capture<T: Capture + ?Sized>(value: &T) -> RawValue {
    value.value()
}

fn malformed() -> Result {
    Err(Error)
}

fn repeat(out: &mut dyn Write, byte: u8, mut count: usize) -> Result {
    let block = [byte; 8];
    while count >= block.len() {
        out.write_str(unsafe { core::str::from_utf8_unchecked(&block) })?;
        count -= block.len();
    }
    out.write_str(unsafe { core::str::from_utf8_unchecked(&block[..count]) })
}

fn text(out: &mut dyn Write, value: &str, width: Option<u8>) -> Result {
    repeat(out, b' ', usize::from(width.unwrap_or(0)).saturating_sub(value.len()))?;
    out.write_str(value)
}

#[inline(never)]
#[optimize(size)]
fn number(
    out: &mut dyn Write,
    mut value: u64,
    negative: bool,
    spec: u8,
    width: Option<u8>,
) -> Result {
    let presentation = spec & PRESENT_MASK;
    let (base, upper) = match presentation {
        DISPLAY | DEBUG => (10, false),
        LOWER_HEX | POINTER => (16, false),
        UPPER_HEX => (16, true),
        BINARY => (2, false),
        OCTAL => (8, false),
        _ => return malformed(),
    };
    let prefix = if spec & ALTERNATE != 0 || presentation == POINTER {
        match presentation {
            LOWER_HEX | POINTER | UPPER_HEX => "0x",
            BINARY => "0b",
            OCTAL => "0o",
            _ => "",
        }
    } else {
        ""
    };
    let sign = if negative { "-" } else if spec & SIGN_PLUS != 0 { "+" } else { "" };
    let mut storage = [0u8; 64];
    let mut start = storage.len();
    loop {
        let digit = (value % base) as u8;
        value /= base;
        start -= 1;
        storage[start] = if digit < 10 { b'0' + digit } else if upper {
            b'A' + digit - 10
        } else {
            b'a' + digit - 10
        };
        if value == 0 { break; }
    }
    let digits = unsafe { core::str::from_utf8_unchecked(&storage[start..]) };
    let padding = usize::from(width.unwrap_or(0))
        .saturating_sub(sign.len() + prefix.len() + digits.len());
    if spec & ZERO_PAD == 0 { repeat(out, b' ', padding)?; }
    out.write_str(sign)?;
    out.write_str(prefix)?;
    if spec & ZERO_PAD != 0 { repeat(out, b'0', padding)?; }
    out.write_str(digits)
}

fn signed(out: &mut dyn Write, value: i64, bits: u64, spec: u8, width: Option<u8>) -> Result {
    let decimal = matches!(spec & PRESENT_MASK, DISPLAY | DEBUG);
    let negative = decimal && value < 0;
    number(out, if negative { value.unsigned_abs() } else { bits }, negative, spec, width)
}

unsafe fn format_u32(out: &mut dyn Write, value: RawValue, spec: u8, width: Option<u8>) -> Result {
    number(out, unsafe { value.word } as u32 as u64, false, spec, width)
}
unsafe fn format_usize(out: &mut dyn Write, value: RawValue, spec: u8, width: Option<u8>) -> Result {
    number(out, unsafe { value.word } as u64, false, spec, width)
}
unsafe fn format_i8(out: &mut dyn Write, value: RawValue, spec: u8, width: Option<u8>) -> Result {
    let value = unsafe { value.word } as i8;
    signed(out, value as i64, value as u8 as u64, spec, width)
}
unsafe fn format_i16(out: &mut dyn Write, value: RawValue, spec: u8, width: Option<u8>) -> Result {
    let value = unsafe { value.word } as i16;
    signed(out, value as i64, value as u16 as u64, spec, width)
}
unsafe fn format_i32(out: &mut dyn Write, value: RawValue, spec: u8, width: Option<u8>) -> Result {
    let value = unsafe { value.word } as i32;
    signed(out, value as i64, value as u32 as u64, spec, width)
}
unsafe fn format_isize(out: &mut dyn Write, value: RawValue, spec: u8, width: Option<u8>) -> Result {
    let value = unsafe { value.word } as isize;
    signed(out, value as i64, value as usize as u64, spec, width)
}
unsafe fn format_u64(out: &mut dyn Write, value: RawValue, spec: u8, width: Option<u8>) -> Result {
    #[cfg(target_pointer_width = "64")]
    let value = unsafe { value.word } as u64;
    #[cfg(not(target_pointer_width = "64"))]
    let value = unsafe { *value.reference.cast::<u64>() };
    number(out, value, false, spec, width)
}
unsafe fn format_i64(out: &mut dyn Write, value: RawValue, spec: u8, width: Option<u8>) -> Result {
    #[cfg(target_pointer_width = "64")]
    let value = unsafe { value.word } as i64;
    #[cfg(not(target_pointer_width = "64"))]
    let value = unsafe { *value.reference.cast::<i64>() };
    signed(out, value, value as u64, spec, width)
}

fn quoted(out: &mut dyn Write, value: &str, quote: char) -> Result {
    write_char(out, quote)?;
    for character in value.chars() {
        match character {
            c if c == quote => { write_char(out, '\\')?; write_char(out, c)?; }
            '\\' => out.write_str("\\\\")?,
            '\n' => out.write_str("\\n")?,
            '\r' => out.write_str("\\r")?,
            '\t' => out.write_str("\\t")?,
            '\0' => out.write_str("\\0")?,
            c => write_char(out, c)?,
        }
    }
    write_char(out, quote)
}

unsafe fn format_str(out: &mut dyn Write, value: RawValue, spec: u8, width: Option<u8>) -> Result {
    let value = unsafe { *value.reference.cast::<&str>() };
    match spec & PRESENT_MASK {
        DISPLAY => text(out, value, width),
        DEBUG => quoted(out, value, '"'),
        _ => malformed(),
    }
}
unsafe fn format_bool(out: &mut dyn Write, value: RawValue, spec: u8, width: Option<u8>) -> Result {
    if !matches!(spec & PRESENT_MASK, DISPLAY | DEBUG) { return malformed(); }
    text(out, if unsafe { value.word } != 0 { "true" } else { "false" }, width)
}
unsafe fn format_char(out: &mut dyn Write, value: RawValue, spec: u8, _width: Option<u8>) -> Result {
    let Some(value) = char::from_u32(unsafe { value.word } as u32) else { return malformed(); };
    match spec & PRESENT_MASK {
        DISPLAY => write_char(out, value),
        DEBUG => quoted(out, value.encode_utf8(&mut [0; 4]), '\''),
        _ => malformed(),
    }
}
unsafe fn format_bytes(out: &mut dyn Write, value: RawValue, spec: u8, width: Option<u8>) -> Result {
    if spec & PRESENT_MASK != DEBUG_HEX { return malformed(); }
    let values = unsafe { *value.reference.cast::<&[u8]>() };
    write_char(out, '[')?;
    for (index, &value) in values.iter().enumerate() {
        if index != 0 { out.write_str(", ")?; }
        let presentation = if spec & DEBUG_UPPER != 0 { UPPER_HEX } else { LOWER_HEX };
        number(out, value as u64, false, presentation | (spec & (ALTERNATE | ZERO_PAD)), width)?;
    }
    write_char(out, ']')
}

unsafe fn format_words(out: &mut dyn Write, value: RawValue, spec: u8, width: Option<u8>) -> Result {
    if spec & PRESENT_MASK != DEBUG_HEX { return malformed(); }
    let values = unsafe { *value.reference.cast::<&[u32]>() };
    write_char(out, '[')?;
    for (index, &value) in values.iter().enumerate() {
        if index != 0 { out.write_str(", ")?; }
        let presentation = if spec & DEBUG_UPPER != 0 { UPPER_HEX } else { LOWER_HEX };
        number(out, value as u64, false, presentation | (spec & (ALTERNATE | ZERO_PAD)), width)?;
    }
    write_char(out, ']')
}

/// Execute trusted bytecode produced by write! or writeln!.
///
/// # Safety
///
/// `program` must point to a valid, 255-terminated bytecode stream. `values`
/// and `formats` must each contain one entry for every argument operation, each
/// formatter must accept its corresponding value, and referenced temporaries must
/// remain alive for this call. The macros establish these invariants.
#[doc(hidden)]
#[inline(never)]
#[optimize(size)]
pub unsafe fn emit(
    out: &mut dyn Write,
    mut program: *const u8,
    mut values: *const RawValue,
    mut formats: *const FormatFn,
) -> Result {
    loop {
        let operation = unsafe { *program };
        program = unsafe { program.add(1) };
        if operation == u8::MAX {
            return Ok(());
        }
        if operation != 0 {
            let bytes = unsafe { core::slice::from_raw_parts(program, usize::from(operation)) };
            let text = unsafe { core::str::from_utf8_unchecked(bytes) };
            out.write_str(text)?;
            program = unsafe { program.add(usize::from(operation)) };
            continue;
        }

        let spec = unsafe { *program };
        program = unsafe { program.add(1) };
        let width = if spec & HAS_WIDTH != 0 {
            let width = unsafe { *program };
            program = unsafe { program.add(1) };
            Some(width)
        } else {
            None
        };
        let value = unsafe { *values };
        let format = unsafe { *formats };
        unsafe { format(out, value, spec, width)? };
        values = unsafe { values.add(1) };
        formats = unsafe { formats.add(1) };
    }
}

#[doc(hidden)]
pub mod __private {
    pub use super::{Capture, FormatFn, RawValue, capture, emit};
}
