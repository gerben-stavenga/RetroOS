//! INI syntax, independent of any application's settings.
//! Borrowed strings preserve case and literal values. Ordered sections and
//! entries retain duplicates so consumers can validate or merge them.
#![no_std]
extern crate alloc;
use alloc::vec::Vec;

#[derive(Debug, PartialEq, Eq)]
pub struct Entry<'a> {
    pub key: &'a str,
    pub value: &'a str,
    /// Trimmed source line, for consumers with line-length constraints.
    pub source: &'a str,
}

#[derive(Debug, PartialEq, Eq)]
pub struct Section<'a> {
    pub name: &'a str,
    pub entries: Vec<Entry<'a>>,
}

pub fn parse(bytes: &[u8]) -> Result<Vec<Section<'_>>, &'static str> {
    let text = core::str::from_utf8(bytes).map_err(|_| "INI must be UTF-8")?;
    let mut sections: Vec<Section<'_>> = Vec::new();
    for line in text.lines().map(str::trim) {
        if line.is_empty() || line.starts_with(['#', ';']) { continue; }
        if line.contains('\0') { return Err("NUL in INI"); }
        if line.starts_with('[') {
            let name = line.strip_prefix('[').and_then(|s| s.strip_suffix(']'))
                .ok_or("invalid section")?.trim();
            if name.is_empty() { return Err("empty section"); }
            sections.push(Section { name, entries: Vec::new() });
        } else {
            let (key, value) = line.split_once('=').ok_or("expected key=value")?;
            let (key, value) = (key.trim(), value.trim());
            if key.is_empty() { return Err("empty key"); }
            if sections.is_empty() {
                sections.push(Section { name: "", entries: Vec::new() });
            }
            sections.last_mut().unwrap().entries.push(Entry { key, value, source: line });
        }
    }
    Ok(sections)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn preserves_sections_duplicates_and_literal_values() {
        let ini = parse(b"; comment\r\nroot = x\r\n[one]\r\nk=\r\nk=a=b;#c\r\n[one]\r\nk=last\r\n").unwrap();
        assert_eq!(ini.len(), 3);
        assert_eq!(ini[0].name, "");
        assert_eq!(ini[1].entries[0].value, "");
        assert_eq!(ini[1].entries[1].value, "a=b;#c");
        assert_eq!(ini[2].name, "one");
    }
    #[test]
    fn rejects_malformed_syntax() {
        for input in [b"[broken".as_slice(), b"[]=x", b"[]", b"=x", b"key", b"a=\0", b"\xff"] {
            assert!(parse(input).is_err());
        }
    }
}
