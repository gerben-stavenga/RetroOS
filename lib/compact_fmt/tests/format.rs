macro_rules! nested_write {
    ($out:expr, $($arg:tt)*) => {
        compact_fmt::write!($out, $($arg)*)
    };
}

#[derive(Default)]
struct Buffer {
    bytes: Vec<u8>,
}

impl compact_fmt::Write for Buffer {
    fn write_str(&mut self, text: &str) -> compact_fmt::Result {
        self.bytes.extend_from_slice(text.as_bytes());
        Ok(())
    }
}

impl Buffer {
    fn text(&self) -> &str {
        core::str::from_utf8(&self.bytes).unwrap()
    }
}

#[test]
fn literals_and_integer_formats() {
    let mut output = Buffer::default();
    let irq = 3u8;
    let eax = 0x2au32;
    compact_fmt::writeln!(&mut output, "IRQ {} eax={:#08x}", irq, eax).unwrap();
    assert_eq!(output.text(), "IRQ 3 eax=0x00002a\n");
}

#[test]
fn named_capture_strings_and_escaped_braces() {
    let mut output = Buffer::default();
    let name = "Jazz";
    let count = 17usize;
    compact_fmt::write!(&mut output, "{{{name}}} count={count:04X}").unwrap();
    assert_eq!(output.text(), "{Jazz} count=0011");
}

#[test]
fn signed_wide_boolean_and_character_values() {
    let mut output = Buffer::default();
    compact_fmt::write!(
        &mut output,
        "{} {} {} {}",
        -42i32,
        0x1234_5678_9abc_def0u64,
        true,
        'x',
    )
    .unwrap();
    assert_eq!(output.text(), "-42 1311768467463790320 true x");
}

#[test]
fn positional_arguments_are_evaluated_once() {
    let mut output = Buffer::default();
    let mut calls = 0;
    let mut next = || {
        calls += 1;
        7u32
    };
    compact_fmt::write!(&mut output, "{0} {0:x}", next()).unwrap();
    assert_eq!(calls, 1);
    assert_eq!(output.text(), "7 7");
}

#[test]
fn preserves_nested_macro_hygiene() {
    let mut output = Buffer::default();
    let local = 23u32;
    nested_write!(&mut output, "value={}", local).unwrap();
    assert_eq!(output.text(), "value=23");
}

#[test]
fn long_unicode_literals_split_on_character_boundaries() {
    let mut output = Buffer::default();
    compact_fmt::write!(
        &mut output,
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
         aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
         aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
         aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaé{}",
        9u32,
    )
    .unwrap();
    assert!(output.text().ends_with("é9"));
    assert_eq!(output.text().chars().count(), 256);
    assert_eq!(output.text().len(), 257);
}

#[test]
fn raw_literal_and_named_argument() {
    let mut output = Buffer::default();
    compact_fmt::write!(&mut output, r#"raw\n value={value}"#, value = 5u16).unwrap();
    assert_eq!(output.text(), r#"raw\n value=5"#);
}

#[test]
fn supported_presentations_match_core_fmt() {
    let mut output = Buffer::default();
    compact_fmt::write!(
        &mut output,
        "{:x} {:X} {:#b} {:#o} {:+} {:p} {:?}",
        0x2au32,
        0x2au32,
        5u32,
        9u32,
        7i32,
        0x1234usize,
        "a\nb",
    )
    .unwrap();
    assert_eq!(output.text(), "2a 2A 0b101 0o11 +7 0x1234 \"a\\nb\"");
}

#[test]
fn signed_hex_keeps_the_source_width() {
    let mut output = Buffer::default();
    compact_fmt::write!(&mut output, "{:x} {:x} {:x}", -2i8, -2i16, -2i32).unwrap();
    assert_eq!(output.text(), "fe fffe fffffffe");
}

#[test]
fn hexadecimal_slices_share_the_slice_formatter() {
    let mut output = Buffer::default();
    let bytes = [0x0au8, 0xff];
    let words = [0x1234u32, 0xabcdef];
    compact_fmt::write!(&mut output, "{:02x?} {:08X?}", &bytes[..], &words[..]).unwrap();
    assert_eq!(output.text(), "[0a, ff] [00001234, 00ABCDEF]");
}

struct Pair(u32, &'static str);

impl compact_fmt::Format for Pair {
    fn format(
        &self,
        out: &mut dyn compact_fmt::Write,
        _: compact_fmt::FormatSpec,
    ) -> compact_fmt::Result {
        compact_fmt::write!(out, "Pair({}, {})", self.0, self.1)
    }
}

#[test]
fn project_types_supply_one_formatter_pointer() {
    let mut output = Buffer::default();
    compact_fmt::write!(&mut output, "{:?}", Pair(7, "seven")).unwrap();
    assert_eq!(output.text(), "Pair(7, seven)");
}
