# compact-fmt

compact-fmt is a no_std, allocation-free formatter optimized for small call
sites. A proc macro checks each static format literal and emits bytecode; the
target runtime interprets that bytecode and delegates primitive conversion to
core::fmt.

Example:

    let mut output = MyCoreFmtWriter;
    compact_fmt::writeln!(&mut output, "IRQ {} eax={:#08x}", irq, eax)?;

The bytecode contains only two operation shapes:

- 1 through 255, followed by that many UTF-8 literal bytes.
- 0, followed by a packed presentation byte and an optional width byte.

Arguments use parallel arrays. One machine word holds each value: integers no
wider than usize are inline, while strings and wider integers borrow a
macro-owned temporary. A parallel one-byte ValueTag array describes those
words. Formatter function pointers and arrays of fat literal slices are absent
from call sites.

Supported values are u8 through u64, i8 through i64, usize, isize, str, bool,
and char. Supported presentations are display, lower/upper hexadecimal,
binary, octal, pointer-style hexadecimal, and primitive debug, with fixed
width, zero padding, plus signs, and alternate prefixes. Named capture, named
arguments, positional arguments, repeated arguments, escaped braces, ordinary
string literals, and raw string literals are accepted.

The target crate needs nightly Rust while FormattingOptions remains unstable.
It uses neither alloc nor an allocator.
