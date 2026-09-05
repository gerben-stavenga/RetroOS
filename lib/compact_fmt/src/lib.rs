#![no_std]
#![feature(formatting_options)]
#![feature(optimize_attribute)]

//! Allocation-free formatting with compact compile-time bytecode.
//!
//! Bytes 1 through 255 introduce a literal run of that length. Zero
//! introduces a packed argument format byte and an optional width byte.

use core::fmt::{
    self, Binary, Debug, Display, FormattingOptions, LowerHex, Octal, Sign, UpperHex, Write,
};

pub use compact_fmt_macros::{write, writeln};

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

/// One machine word of argument storage.
#[repr(C)]
#[derive(Copy, Clone)]
pub union RawValue {
    word: usize,
    reference: *const (),
}

/// Interpretation of the RawValue at the same array index.
#[repr(u8)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum ValueTag {
    U32,
    I32,
    Usize,
    Isize,
    U64,
    I64,
    Str,
    Bool,
    Char,
}

#[doc(hidden)]
#[derive(Copy, Clone)]
pub struct Captured<'a> {
    pub value: RawValue,
    pub tag: ValueTag,
    lifetime: core::marker::PhantomData<&'a ()>,
}

#[doc(hidden)]
pub trait Capture {
    fn capture(&self) -> Captured<'_>;
}

macro_rules! inline_unsigned {
    ($($ty:ty),+ $(,)?) => {$(
        impl Capture for $ty {
            #[inline]
            fn capture(&self) -> Captured<'_> {
                Captured {
                    value: RawValue { word: *self as usize },
                    tag: ValueTag::U32,
                    lifetime: core::marker::PhantomData,
                }
            }
        }
    )+};
}

macro_rules! inline_signed {
    ($($ty:ty),+ $(,)?) => {$(
        impl Capture for $ty {
            #[inline]
            fn capture(&self) -> Captured<'_> {
                Captured {
                    value: RawValue { word: (*self as i32) as usize },
                    tag: ValueTag::I32,
                    lifetime: core::marker::PhantomData,
                }
            }
        }
    )+};
}

inline_unsigned!(u8, u16, u32);
inline_signed!(i8, i16, i32);

impl Capture for usize {
    #[inline]
    fn capture(&self) -> Captured<'_> {
        Captured {
            value: RawValue { word: *self },
            tag: ValueTag::Usize,
            lifetime: core::marker::PhantomData,
        }
    }
}

impl Capture for isize {
    #[inline]
    fn capture(&self) -> Captured<'_> {
        Captured {
            value: RawValue {
                word: *self as usize,
            },
            tag: ValueTag::Isize,
            lifetime: core::marker::PhantomData,
        }
    }
}

impl Capture for u64 {
    #[inline]
    fn capture(&self) -> Captured<'_> {
        Captured {
            #[cfg(target_pointer_width = "64")]
            value: RawValue {
                word: *self as usize,
            },
            #[cfg(not(target_pointer_width = "64"))]
            value: RawValue {
                reference: self as *const u64 as *const (),
            },
            tag: ValueTag::U64,
            lifetime: core::marker::PhantomData,
        }
    }
}

impl Capture for i64 {
    #[inline]
    fn capture(&self) -> Captured<'_> {
        Captured {
            #[cfg(target_pointer_width = "64")]
            value: RawValue {
                word: *self as usize,
            },
            #[cfg(not(target_pointer_width = "64"))]
            value: RawValue {
                reference: self as *const i64 as *const (),
            },
            tag: ValueTag::I64,
            lifetime: core::marker::PhantomData,
        }
    }
}

impl Capture for &str {
    #[inline]
    fn capture(&self) -> Captured<'_> {
        Captured {
            value: RawValue {
                reference: self as *const &str as *const (),
            },
            tag: ValueTag::Str,
            lifetime: core::marker::PhantomData,
        }
    }
}

impl Capture for bool {
    #[inline]
    fn capture(&self) -> Captured<'_> {
        Captured {
            value: RawValue {
                word: usize::from(*self),
            },
            tag: ValueTag::Bool,
            lifetime: core::marker::PhantomData,
        }
    }
}

impl Capture for char {
    #[inline]
    fn capture(&self) -> Captured<'_> {
        Captured {
            value: RawValue {
                word: *self as usize,
            },
            tag: ValueTag::Char,
            lifetime: core::marker::PhantomData,
        }
    }
}

#[doc(hidden)]
#[inline]
pub fn capture<T: Capture + ?Sized>(value: &T) -> Captured<'_> {
    value.capture()
}

fn malformed() -> fmt::Result {
    Err(fmt::Error)
}

fn formatting_options(spec: u8, width: Option<u8>) -> FormattingOptions {
    let mut options = FormattingOptions::new();
    options
        .alternate(spec & ALTERNATE != 0 || spec & PRESENT_MASK == POINTER)
        .sign_aware_zero_pad(spec & ZERO_PAD != 0)
        .sign(if spec & SIGN_PLUS != 0 {
            Some(Sign::Plus)
        } else {
            None
        })
        .width(width.map(u16::from));
    options
}

macro_rules! primitive {
    ($out:expr, $options:expr, $presentation:expr, $value:expr) => {{
        let mut formatter = $options.create_formatter($out);
        match $presentation {
            DISPLAY => Display::fmt(&$value, &mut formatter),
            LOWER_HEX | POINTER => LowerHex::fmt(&$value, &mut formatter),
            UPPER_HEX => UpperHex::fmt(&$value, &mut formatter),
            BINARY => Binary::fmt(&$value, &mut formatter),
            OCTAL => Octal::fmt(&$value, &mut formatter),
            DEBUG => Debug::fmt(&$value, &mut formatter),
            _ => malformed(),
        }
    }};
}

macro_rules! display_or_debug {
    ($out:expr, $options:expr, $presentation:expr, $value:expr) => {{
        let mut formatter = $options.create_formatter($out);
        match $presentation {
            DISPLAY => Display::fmt(&$value, &mut formatter),
            DEBUG => Debug::fmt(&$value, &mut formatter),
            _ => malformed(),
        }
    }};
}

#[inline(never)]
#[optimize(size)]
unsafe fn emit_value(
    out: &mut dyn Write,
    value: RawValue,
    tag: ValueTag,
    spec: u8,
    width: Option<u8>,
) -> fmt::Result {
    let presentation = spec & PRESENT_MASK;
    let options = formatting_options(spec, width);
    match tag {
        ValueTag::U32 => primitive!(out, options, presentation, unsafe { value.word } as u32),
        ValueTag::I32 => primitive!(out, options, presentation, unsafe { value.word } as i32),
        ValueTag::Usize => primitive!(out, options, presentation, unsafe { value.word }),
        ValueTag::Isize => primitive!(out, options, presentation, unsafe { value.word } as isize),
        ValueTag::U64 => {
            #[cfg(target_pointer_width = "64")]
            let number = unsafe { value.word } as u64;
            #[cfg(not(target_pointer_width = "64"))]
            let number = unsafe { *(value.reference as *const u64) };
            primitive!(out, options, presentation, number)
        }
        ValueTag::I64 => {
            #[cfg(target_pointer_width = "64")]
            let number = unsafe { value.word } as i64;
            #[cfg(not(target_pointer_width = "64"))]
            let number = unsafe { *(value.reference as *const i64) };
            primitive!(out, options, presentation, number)
        }
        ValueTag::Str => {
            let text = unsafe { *(value.reference as *const &str) };
            display_or_debug!(out, options, presentation, text)
        }
        ValueTag::Bool => {
            display_or_debug!(out, options, presentation, unsafe { value.word } != 0)
        }
        ValueTag::Char => {
            let Some(character) = char::from_u32(unsafe { value.word } as u32) else {
                return malformed();
            };
            display_or_debug!(out, options, presentation, character)
        }
    }
}

/// Execute trusted bytecode produced by write! or writeln!.
///
/// # Safety
///
/// Every tag must describe the value at the same index, and referenced
/// temporaries must remain alive for this call. The macros establish both.
#[doc(hidden)]
#[inline(never)]
#[optimize(size)]
pub unsafe fn emit(
    out: &mut dyn Write,
    program: &[u8],
    values: &[RawValue],
    tags: &[ValueTag],
) -> fmt::Result {
    let mut pc = 0;
    let mut argument = 0;
    while pc < program.len() {
        let operation = program[pc];
        pc += 1;
        if operation != 0 {
            let end = pc + usize::from(operation);
            let Some(bytes) = program.get(pc..end) else {
                return malformed();
            };
            let text = unsafe { core::str::from_utf8_unchecked(bytes) };
            out.write_str(text)?;
            pc = end;
            continue;
        }

        let Some(&spec) = program.get(pc) else {
            return malformed();
        };
        pc += 1;
        let width = if spec & HAS_WIDTH != 0 {
            let Some(&width) = program.get(pc) else {
                return malformed();
            };
            pc += 1;
            Some(width)
        } else {
            None
        };
        let (Some(&value), Some(&tag)) = (values.get(argument), tags.get(argument)) else {
            return malformed();
        };
        unsafe { emit_value(out, value, tag, spec, width)? };
        argument += 1;
    }
    if argument != values.len() || values.len() != tags.len() {
        return malformed();
    }
    Ok(())
}

#[doc(hidden)]
pub mod __private {
    pub use super::{Capture, Captured, RawValue, ValueTag, capture, emit};
}
