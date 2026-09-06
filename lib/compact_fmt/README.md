# compact-fmt

compact-fmt is a no_std, allocation-free formatter optimized for small call
sites. A proc macro checks each static format literal and emits bytecode; the
target runtime interprets that bytecode and performs primitive conversion
without `core::fmt`.

Example:

    let mut output = MyCompactWriter;
    compact_fmt::writeln!(&mut output, "IRQ {} eax={:#08x}", irq, eax)?;

The bytecode contains only two operation shapes:

- 1 through 254, followed by that many UTF-8 literal bytes.
- 0, followed by a packed presentation byte and an optional width byte.
- 255, terminating the stream.

The trusted bytecode is passed as a terminated pointer, so calls carry no
slice lengths and the decoder needs no bounds checks. Arguments use parallel
arrays. One machine word holds each value: integers no wider than usize are
inline, while strings and wider integers borrow a macro-owned temporary. A
linker-deduplicable read-only array selects the formatter for each value.
Arrays of fat literal slices are absent from call sites.

Supported values are u8 through u64, i8 through i64, usize, isize, str, bool,
and char. Supported presentations are display, lower/upper hexadecimal,
binary, octal, pointer-style hexadecimal, and primitive debug, with fixed
width, zero padding, plus signs, and alternate prefixes. Named capture, named
arguments, positional arguments, repeated arguments, escaped braces, ordinary
string literals, and raw string literals are accepted.

The target runtime uses neither `alloc` nor an allocator.
