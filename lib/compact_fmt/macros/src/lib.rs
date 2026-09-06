//! Compile-time frontend for compact_fmt.

extern crate proc_macro;

use proc_macro::{Delimiter, Group, Literal, TokenStream, TokenTree};
use std::collections::{BTreeMap, BTreeSet};

const ALTERNATE: u8 = 0x08;
const ZERO_PAD: u8 = 0x10;
const SIGN_PLUS: u8 = 0x20;
const HAS_WIDTH: u8 = 0x40;
const DEBUG_UPPER: u8 = 0x80;

struct Hole {
    selector: String,
    spec: u8,
    width: Option<u8>,
}

enum Part {
    Literal(Vec<u8>),
    Hole(Hole),
}

fn error(message: impl AsRef<str>) -> TokenStream {
    let message = format!("{:?}", message.as_ref());
    format!("compile_error!({message})").parse().unwrap()
}

fn splice(stream: TokenStream, replacements: &[TokenStream]) -> TokenStream {
    stream
        .into_iter()
        .flat_map(|token| match token {
            TokenTree::Ident(ident) => ident
                .to_string()
                .strip_prefix("__compact_fmt_input_")
                .and_then(|index| index.parse::<usize>().ok())
                .and_then(|index| replacements.get(index).cloned())
                .unwrap_or_else(|| TokenTree::Ident(ident).into()),
            TokenTree::Group(group) => {
                let mut replacement = Group::new(group.delimiter(), splice(group.stream(), replacements));
                replacement.set_span(group.span());
                TokenTree::Group(replacement).into()
            }
            token => token.into(),
        })
        .collect()
}

fn split_arguments(input: TokenStream) -> Vec<TokenStream> {
    let mut result = Vec::new();
    let mut current = TokenStream::new();
    for token in input {
        if matches!(&token, TokenTree::Punct(p) if p.as_char() == ',') {
            result.push(current);
            current = TokenStream::new();
        } else {
            current.extend([token]);
        }
    }
    if !current.is_empty() {
        result.push(current);
    }
    result
}

fn decode_string(literal: &str) -> Result<String, String> {
    if literal.starts_with('r') {
        let quote = literal.find('"').ok_or("invalid raw format literal")?;
        let hashes = &literal[1..quote];
        if !hashes.bytes().all(|byte| byte == b'#') {
            return Err("format must be a string literal".into());
        }
        let suffix = format!("\"{hashes}");
        if !literal.ends_with(&suffix) {
            return Err("invalid raw format literal".into());
        }
        return Ok(literal[quote + 1..literal.len() - suffix.len()].into());
    }
    if !literal.starts_with('"') || !literal.ends_with('"') {
        return Err("format must be a string literal".into());
    }

    let mut output = String::new();
    let mut chars = literal[1..literal.len() - 1].chars().peekable();
    while let Some(character) = chars.next() {
        if character != '\\' {
            output.push(character);
            continue;
        }
        let escape = chars.next().ok_or("unterminated string escape")?;
        match escape {
            '\\' => output.push('\\'),
            '"' => output.push('"'),
            'n' => output.push('\n'),
            'r' => output.push('\r'),
            't' => output.push('\t'),
            '0' => output.push('\0'),
            'x' => {
                let hi = chars.next().ok_or("short hexadecimal escape")?;
                let lo = chars.next().ok_or("short hexadecimal escape")?;
                let byte = u8::from_str_radix(&format!("{hi}{lo}"), 16)
                    .map_err(|_| "invalid hexadecimal escape")?;
                output.push(char::from(byte));
            }
            'u' => {
                if chars.next() != Some('{') {
                    return Err("invalid Unicode escape".into());
                }
                let mut digits = String::new();
                loop {
                    match chars.next() {
                        Some('}') => break,
                        Some('_') => {}
                        Some(c) => digits.push(c),
                        None => return Err("unterminated Unicode escape".into()),
                    }
                }
                let value =
                    u32::from_str_radix(&digits, 16).map_err(|_| "invalid Unicode escape")?;
                output.push(char::from_u32(value).ok_or("invalid Unicode scalar")?);
            }
            '\n' => {
                while matches!(chars.peek(), Some(c) if c.is_whitespace()) {
                    chars.next();
                }
            }
            _ => return Err(format!("unsupported string escape \\{escape}")),
        }
    }
    Ok(output)
}

fn parse_spec(source: &str) -> Result<(u8, Option<u8>), String> {
    let mut rest = source;
    let mut spec = 0u8;
    if let Some(next) = rest.strip_prefix('+') {
        spec |= SIGN_PLUS;
        rest = next;
    }
    if let Some(next) = rest.strip_prefix('#') {
        spec |= ALTERNATE;
        rest = next;
    }
    if rest.starts_with('0') && rest.len() > 1 {
        spec |= ZERO_PAD;
        rest = &rest[1..];
    }

    let digits = rest.bytes().take_while(u8::is_ascii_digit).count();
    let width = if digits == 0 {
        None
    } else {
        let width: u16 = rest[..digits].parse().map_err(|_| "invalid format width")?;
        if width > u16::from(u8::MAX) {
            return Err("format width exceeds 255".into());
        }
        rest = &rest[digits..];
        spec |= HAS_WIDTH;
        Some(width as u8)
    };

    spec |= match rest {
        "" => 0,
        "x" => 1,
        "X" => 2,
        "b" => 3,
        "o" => 4,
        "p" => 5,
        "?" => 6,
        "x?" => 7,
        "X?" => 7 | DEBUG_UPPER,
        _ => return Err(format!("unsupported compact format specifier :{source}")),
    };
    Ok((spec, width))
}

fn parse_format(format: &str, newline: bool) -> Result<Vec<Part>, String> {
    let mut parts = Vec::new();
    let mut literal = Vec::new();
    let bytes = format.as_bytes();
    let mut cursor = 0;
    let mut implicit = 0usize;

    while cursor < bytes.len() {
        match bytes[cursor] {
            b'{' if bytes.get(cursor + 1) == Some(&b'{') => {
                literal.push(b'{');
                cursor += 2;
            }
            b'}' if bytes.get(cursor + 1) == Some(&b'}') => {
                literal.push(b'}');
                cursor += 2;
            }
            b'{' => {
                if !literal.is_empty() {
                    parts.push(Part::Literal(core::mem::take(&mut literal)));
                }
                let tail = &format[cursor + 1..];
                let close = tail.find('}').ok_or("unclosed format placeholder")?;
                let field = &tail[..close];
                if field.contains('{') || field.contains('}') {
                    return Err("nested format placeholders are unsupported".into());
                }
                let (selector, format_spec) = field.split_once(':').unwrap_or((field, ""));
                let selector = if selector.is_empty() {
                    let selected = implicit;
                    implicit += 1;
                    selected.to_string()
                } else {
                    selector.to_string()
                };
                let (spec, width) = parse_spec(format_spec)?;
                parts.push(Part::Hole(Hole {
                    selector,
                    spec,
                    width,
                }));
                cursor += close + 2;
            }
            b'}' => return Err("unmatched closing brace in format literal".into()),
            _ => {
                let character = format[cursor..].chars().next().unwrap();
                let mut encoded = [0; 4];
                literal.extend_from_slice(character.encode_utf8(&mut encoded).as_bytes());
                cursor += character.len_utf8();
            }
        }
    }
    if newline {
        literal.push(b'\n');
    }
    if !literal.is_empty() {
        parts.push(Part::Literal(literal));
    }
    Ok(parts)
}

fn encode(parts: &[Part]) -> Vec<u8> {
    let mut program = Vec::new();
    for part in parts {
        match part {
            Part::Literal(bytes) => {
                let mut start = 0;
                while start < bytes.len() {
                    let mut end = (start + 254).min(bytes.len());
                    while core::str::from_utf8(&bytes[start..end]).is_err() {
                        end -= 1;
                    }
                    program.push((end - start) as u8);
                    program.extend_from_slice(&bytes[start..end]);
                    start = end;
                }
            }
            Part::Hole(hole) => {
                program.push(0);
                program.push(hole.spec);
                if let Some(width) = hole.width {
                    program.push(width);
                }
            }
        }
    }
    program.push(u8::MAX);
    program
}

fn expand(input: TokenStream, newline: bool) -> TokenStream {
    let fields = split_arguments(input);
    if fields.len() < 2 {
        return error("expected writer and format string");
    }
    let writer = fields[0].clone();
    let mut format_field = fields[1].clone();
    loop {
        let tokens: Vec<_> = format_field.clone().into_iter().collect();
        match tokens.as_slice() {
            [TokenTree::Group(group)] if group.delimiter() == Delimiter::None => {
                format_field = group.stream();
            }
            _ => break,
        }
    }
    let mut format_tokens = format_field.into_iter();
    let Some(TokenTree::Literal(format_literal)) = format_tokens.next() else {
        return error("format must be a string literal");
    };
    if format_tokens.next().is_some() {
        return error("format must be one string literal");
    }
    let format = match decode_string(&format_literal.to_string()) {
        Ok(format) => format,
        Err(message) => return error(message),
    };

    let mut positional = Vec::new();
    let mut named = Vec::new();
    for field in &fields[2..] {
        let tokens: Vec<_> = field.clone().into_iter().collect();
        if tokens.len() >= 3
            && matches!(&tokens[0], TokenTree::Ident(_))
            && matches!(&tokens[1], TokenTree::Punct(p) if p.as_char() == '=')
        {
            let TokenTree::Ident(name) = &tokens[0] else {
                unreachable!()
            };
            let expression: TokenStream = tokens[2..].iter().cloned().collect();
            named.push((name.to_string(), expression));
        } else {
            positional.push(field.clone());
        }
    }

    let parts = match parse_format(&format, newline) {
        Ok(parts) => parts,
        Err(message) => return error(message),
    };
    let mut captures = positional;
    let mut capture_names = BTreeMap::new();
    for (name, expression) in named {
        if capture_names.contains_key(&name) {
            return error(format!("duplicate named argument {name}"));
        }
        let index = captures.len();
        captures.push(expression);
        capture_names.insert(name, index);
    }
    let explicit_count = captures.len();
    let mut order = Vec::new();
    let mut used = BTreeSet::new();
    for part in &parts {
        let Part::Hole(hole) = part else { continue };
        let index = if let Ok(index) = hole.selector.parse::<usize>() {
            if index >= captures.len() {
                return error("format argument index is out of range");
            }
            index
        } else if let Some(&index) = capture_names.get(&hole.selector) {
            index
        } else {
            if !hole.selector.bytes().enumerate().all(|(index, byte)| {
                byte == b'_' || byte.is_ascii_alphabetic() || index != 0 && byte.is_ascii_digit()
            }) {
                return error("invalid captured argument name");
            }
            let index = captures.len();
            captures.push(hole.selector.parse().unwrap());
            capture_names.insert(hole.selector.clone(), index);
            index
        };
        used.insert(index);
        order.push(index);
    }
    if (0..explicit_count).any(|index| !used.contains(&index)) {
        return error("an explicit format argument is never used");
    }

    let program = Literal::byte_string(&encode(&parts)).to_string();
    let bindings = captures
        .iter()
        .enumerate()
        .map(|(index, _)| {
            format!(
                "let __compact_fmt_arg_{index} = &(__compact_fmt_input_{});",
                index + 1,
            )
        })
        .collect::<Vec<_>>()
        .join("\n");
    let values = order
        .iter()
        .map(|index| format!("::compact_fmt::__private::capture(__compact_fmt_arg_{index})"))
        .collect::<Vec<_>>()
        .join(",");
    let formats = if order.is_empty() {
        "::core::ptr::null()".into()
    } else {
        let parameters = (0..order.len())
            .map(|index| format!("__A{index}: ::compact_fmt::__private::Capture + ?Sized"))
            .collect::<Vec<_>>()
            .join(",");
        let tuple_types = (0..order.len())
            .map(|index| format!("&__A{index},"))
            .collect::<String>();
        let tuple_values = order
            .iter()
            .map(|index| format!("__compact_fmt_arg_{index},"))
            .collect::<String>();
        let pointers = (0..order.len())
            .map(|index| format!("<__A{index} as ::compact_fmt::__private::Capture>::FORMAT"))
            .collect::<Vec<_>>()
            .join(",");
        format!(
            "{{ #[inline(always)] fn __compact_fmt_list<{parameters}>(_: ({tuple_types})) \
                 -> &'static [::compact_fmt::__private::FormatFn; {count}] {{ &[{pointers}] }} \
               __compact_fmt_list(({tuple_values})).as_ptr() }}",
            count = order.len(),
        )
    };
    let expanded: TokenStream = format!(
        "{{ {bindings}\n\
           let __compact_fmt_values: [::compact_fmt::__private::RawValue; {count}] = [{values}];\n\
           let __compact_fmt_formats = {formats};\n\
           unsafe {{ ::compact_fmt::__private::emit(\
               __compact_fmt_input_0, {program}.as_ptr(), __compact_fmt_values.as_ptr(), \
               __compact_fmt_formats) }}\
         }}",
        count = order.len(),
    )
    .parse()
    .unwrap_or_else(|_| error("compact format expansion failed"));
    let mut replacements = Vec::with_capacity(captures.len() + 1);
    replacements.push(writer);
    replacements.extend(captures);
    splice(expanded, &replacements)
}

#[proc_macro]
pub fn write(input: TokenStream) -> TokenStream {
    expand(input, false)
}

#[proc_macro]
pub fn writeln(input: TokenStream) -> TokenStream {
    expand(input, true)
}
