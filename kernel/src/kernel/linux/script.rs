//! Linux interpreter headers, parsed before cross-personality format fallback.
use alloc::vec::Vec;
#[derive(Debug, PartialEq, Eq)]
pub(super) struct Interpreter {
    pub path: Vec<u8>,
    pub argument: Option<Vec<u8>>,
}
pub(super) fn parse(bytes: &[u8]) -> Result<Option<Interpreter>, i32> {
    if !bytes.starts_with(b"#!") {
        return Ok(None);
    }
    let line = bytes[2..].split(|b| *b == b'\n').next().unwrap_or_default();
    if line.len() > 253 || line.contains(&0) {
        return Err(8);
    }
    let line = line.trim_ascii_start();
    let end = line
        .iter()
        .position(|b| matches!(b, b' ' | b'\t'))
        .unwrap_or(line.len());
    if end == 0 {
        return Err(8);
    }
    let argument = line[end..].trim_ascii();
    Ok(Some(Interpreter {
        path: line[..end].to_vec(),
        argument: (!argument.is_empty()).then(|| argument.to_vec()),
    }))
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn optional_argument_stays_one_string() {
        assert_eq!(
            parse(b"#! \t/usr/bin/env\t-S python -u \t\nbody").unwrap(),
            Some(Interpreter {
                path: b"/usr/bin/env".to_vec(),
                argument: Some(b"-S python -u".to_vec())
            })
        );
        assert_eq!(parse(b"#!/bin/sh\n").unwrap().unwrap().argument, None);
    }
    #[test]
    fn malformed_headers_fail_before_exec_and_other_formats_pass_through() {
        assert_eq!(parse(b"#! \t\n"), Err(8));
        assert_eq!(parse(b"#!/bin/sh\0bad\n"), Err(8));
        assert_eq!(parse(&[b"#!".as_slice(), &[b'x'; 254]].concat()), Err(8));
        assert_eq!(parse(b"\x7fELF"), Ok(None));
        assert_eq!(parse(b"MZ"), Ok(None));
    }
}
