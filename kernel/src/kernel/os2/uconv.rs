//! OS/2 Unicode conversion objects. Text tables are shared with DOS and Win32.
use super::*;
use crate::kernel::text::Encoding;
use alloc::{format, string::String};

const INVALID: u32 = 0x2040e;
const BAD_OBJECT: u32 = 0x2040f;
const BUFFER_FULL: u32 = 0x20412;
const ILLEGAL_SEQUENCE: u32 = 0x20402;
const UNSUPPORTED: u32 = 0x20414;
const BAD_ATTR: u32 = 0x20415;

#[derive(Clone, Copy)]
pub(super) struct Converter { encoding: Encoding, replacement: u8 }

fn encoding(cp: u32) -> Option<Encoding> {
    if cp == 0 { Some(Encoding::oem()) }
    else { Encoding::for_codepage(if cp == 1208 { 65001 } else { cp }) }
}

fn parse(name: &str) -> Result<Converter, u32> {
    let (name, attributes) = name.split_once('@').unwrap_or((name, ""));
    let cp = if name.is_empty() { 0 } else {
        let upper = name.to_ascii_uppercase();
        if upper == "UTF-8" { 1208 } else {
            upper.strip_prefix("IBM-").unwrap_or(&upper).parse::<u32>().map_err(|_| UNSUPPORTED)?
        }
    };
    let mut converter = Converter { encoding: encoding(cp).ok_or(UNSUPPORTED)?, replacement: b'?' };
    if !attributes.is_empty() {
        let value = attributes.strip_prefix("subchar=\\x").ok_or(BAD_ATTR)?;
        if value.len() != 2 { return Err(BAD_ATTR); }
        converter.replacement = u8::from_str_radix(value, 16).map_err(|_| BAD_ATTR)?;
    }
    Ok(converter)
}

pub(super) fn dispatch<A: crate::Arch>(machine: &mut A, state: &mut Os2State, regs: &Regs, ordinal: u16) -> u32 {
    let a = arg32(machine, regs, 0);
    match ordinal {
        1 => {
            let output = arg32(machine, regs, 1) as usize;
            if a == 0 || output == 0 { return INVALID; }
            machine.write::<u32>(output, 0);
            let mut units = Vec::new();
            for i in 0..128 {
                let unit = machine.read::<u16>(a as usize + i * 2);
                if unit == 0 {
                    let Ok(name) = String::from_utf16(&units) else { return INVALID; };
                    let converter = match parse(&name) { Ok(c) => c, Err(e) => return e };
                    let handle = state.next_converter;
                    let Some(next) = handle.checked_add(1) else { return 0x2040d; };
                    state.next_converter = next;
                    state.converters.push((handle, converter));
                    machine.write::<u32>(output, handle);
                    return NO_ERROR;
                }
                units.push(unit);
            }
            INVALID
        }
        4 => {
            let Some(index) = state.converters.iter().position(|&(handle, _)| handle == a) else { return BAD_OBJECT; };
            state.converters.swap_remove(index);
            NO_ERROR
        }
        10 => {
            let output = arg32(machine, regs, 1) as usize;
            let capacity = arg32(machine, regs, 2) as usize;
            if output == 0 { return INVALID; }
            if encoding(a).is_none() { return UNSUPPORTED; }
            let cp = if a == 0 { u32::from(lib::codepage::current_codepage().id) } else { a };
            let name = format!("IBM-{cp}");
            if capacity < name.len() + 1 { return BUFFER_FULL; }
            for (i, unit) in name.encode_utf16().chain(core::iter::once(0)).enumerate() {
                machine.write::<u16>(output + i * 2, unit);
            }
            NO_ERROR
        }
        2 | 3 => {
            let Some(&(_, converter)) = state.converters.iter().find(|&&(handle, _)| handle == a) else { return BAD_OBJECT; };
            convert(machine, regs, converter, ordinal == 2)
        }
        _ => UNSUPPORTED,
    }
}

fn convert<A: crate::Arch>(machine: &mut A, regs: &Regs, converter: Converter, to_ucs: bool) -> u32 {
    let args: [usize; 5] = core::array::from_fn(|i| arg32(machine, regs, i + 1) as usize);
    if args.contains(&0) { return INVALID; }
    let [input_pointer, input_count, output_pointer, output_count, substitutions] = args;
    let mut input = machine.read::<u32>(input_pointer) as usize;
    let mut left = machine.read::<u32>(input_count) as usize;
    let mut output = machine.read::<u32>(output_pointer) as usize;
    let mut room = machine.read::<u32>(output_count) as usize;
    if (left != 0 && input == 0) || (room != 0 && output == 0) { return INVALID; }
    let mut nonidentical = 0;
    let mut result = NO_ERROR;
    while left != 0 {
        if room == 0 { result = BUFFER_FULL; break; }
        let (ch, consumed) = if to_ucs {
            match converter.encoding {
                Encoding::SingleByte(page) => (page.decode(machine.read::<u8>(input)), 1),
                Encoding::Utf8 => {
                    let first = machine.read::<u8>(input);
                    let length = match first { 0..=0x7f => 1, 0xc2..=0xdf => 2, 0xe0..=0xef => 3, 0xf0..=0xf4 => 4, _ => 0 };
                    if length == 0 || length > left { result = ILLEGAL_SEQUENCE; break; }
                    let bytes: [u8; 4] = core::array::from_fn(|i| if i < length { machine.read::<u8>(input + i) } else { 0 });
                    let Ok(text) = core::str::from_utf8(&bytes[..length]) else { result = ILLEGAL_SEQUENCE; break; };
                    (text.chars().next().unwrap(), length)
                }
            }
        } else {
            // ULS exposes UCS-2 elements, not Windows UTF-16 surrogate pairs.
            let Some(ch) = char::from_u32(machine.read::<u16>(input) as u32) else { result = ILLEGAL_SEQUENCE; break; };
            (ch, 1)
        };
        if to_ucs {
            if ch as u32 > 0xffff { result = ILLEGAL_SEQUENCE; break; }
            machine.write::<u16>(output, ch as u16);
            output += 2;
            room -= 1;
            input += consumed;
        } else {
            let mut utf8 = [0; 4];
            let (bytes, substituted): (&[u8], bool) = match converter.encoding {
                Encoding::Utf8 => (ch.encode_utf8(&mut utf8).as_bytes(), false),
                Encoding::SingleByte(page) => {
                    let encoded = page.encode_exact(ch);
                    utf8[0] = encoded.unwrap_or(converter.replacement);
                    (&utf8[..1], encoded.is_none())
                }
            };
            if bytes.len() > room { result = BUFFER_FULL; break; }
            machine.copy_to(output, bytes);
            output += bytes.len();
            room -= bytes.len();
            input += 2;
            nonidentical += u32::from(substituted);
        }
        left -= consumed;
    }
    machine.write::<u32>(input_pointer, input as u32);
    machine.write::<u32>(input_count, left as u32);
    machine.write::<u32>(output_pointer, output as u32);
    machine.write::<u32>(output_count, room as u32);
    machine.write::<u32>(substitutions, nonidentical);
    result
}
