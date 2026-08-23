//! Syntax-only parsing for boot and launch command lines.

/// Compare command-line bytes using ASCII case-insensitive matching.
pub fn eq_ignore_ascii_case(left: &[u8], right: &[u8]) -> bool {
    left.eq_ignore_ascii_case(right)
}

/// Compare a command-line key using the parameter convention: ASCII
/// insensitive, with no normalization of the value.
pub fn key_eq(key: &[u8], expected: &[u8]) -> bool {
    eq_ignore_ascii_case(key, expected)
}

/// Split one token into its non-empty key and value.
pub fn parse_key_value(token: &[u8]) -> Option<(&[u8], &[u8])> {
    let eq = token.iter().position(|&b| b == b'=')?;
    if eq == 0 { return None; }
    Some((&token[..eq], &token[eq + 1..]))
}

/// Visit every key/value token without assigning meaning to its key.
pub fn for_each_key_value(mut input: &[u8], mut visit: impl FnMut(&[u8], &[u8])) {
    while !input.is_empty() {
        let split = input.iter().position(|b| b.is_ascii_whitespace() || *b == b';');
        let (token, rest) = match split {
            Some(index) => (&input[..index], &input[index + 1..]),
            None => (input, &[][..]),
        };
        if let Some((key, value)) = parse_key_value(token) {
            visit(key, value);
        }
        input = rest;
    }
}

/// Split non-empty semicolon-separated launch segments after trimming ASCII
/// whitespace.
pub struct Segments<'a> { input: &'a [u8] }

pub fn segments(input: &[u8]) -> Segments<'_> { Segments { input } }

impl<'a> Iterator for Segments<'a> {
    type Item = &'a [u8];

    fn next(&mut self) -> Option<Self::Item> {
        while !self.input.is_empty() {
            let (segment, rest) = match self.input.iter().position(|&b| b == b';') {
                Some(index) => (&self.input[..index], &self.input[index + 1..]),
                None => (self.input, &[][..]),
            };
            self.input = rest;
            let segment = trim_ascii(segment);
            if !segment.is_empty() { return Some(segment); }
        }
        None
    }
}

/// One token in a launch segment, optionally omitting consumer-owned
/// key/value directives.
pub struct LaunchTokens<'a> {
    input: &'a [u8],
    is_directive: fn(&[u8]) -> bool,
}

fn tokens(input: &[u8], is_directive: fn(&[u8]) -> bool) -> LaunchTokens<'_> {
    LaunchTokens { input, is_directive }
}

impl<'a> Iterator for LaunchTokens<'a> {
    type Item = &'a [u8];

    fn next(&mut self) -> Option<Self::Item> {
        while !self.input.is_empty() {
            let start = self.input.iter().position(|b| !b.is_ascii_whitespace())?;
            self.input = &self.input[start..];
            let end = self.input.iter().position(|b| b.is_ascii_whitespace())
                .unwrap_or(self.input.len());
            let token = &self.input[..end];
            self.input = &self.input[end..];
            if parse_key_value(token).is_some_and(|(key, _)| (self.is_directive)(key)) {
                continue;
            }
            return Some(token);
        }
        None
    }
}

/// A launch segment after the caller's directives have been removed. The first
/// remaining token is the executable and the rest are its arguments.
pub struct Launch<'a> {
    program: &'a [u8],
    tokens: LaunchTokens<'a>,
}

impl<'a> Launch<'a> {
    pub fn program(&self) -> &'a [u8] { self.program }
    pub fn arguments(self) -> LaunchTokens<'a> { self.tokens }

    /// Copy space-separated arguments into a caller-provided bounded buffer.
    /// Stops after the first truncated argument and never emits a trailing space.
    pub fn write_arguments(self, out: &mut [u8]) -> usize {
        let mut len = 0;
        for argument in self.arguments() {
            if len != 0 {
                if len == out.len() { break; }
                out[len] = b' ';
                len += 1;
            }
            let available = out.len() - len;
            let copied = argument.len().min(available);
            out[len..len + copied].copy_from_slice(&argument[..copied]);
            len += copied;
            if copied != argument.len() { break; }
        }
        len
    }
}

/// Parse one launch segment using a consumer-owned directive predicate.
pub fn launch(segment: &[u8], is_directive: fn(&[u8]) -> bool) -> Option<Launch<'_>> {
    let mut tokens = tokens(segment, is_directive);
    let program = tokens.next()?;
    Some(Launch { program, tokens })
}

fn trim_ascii(s: &[u8]) -> &[u8] {
    let start = s.iter().position(|&c| c > b' ').unwrap_or(s.len());
    let end = s.iter().rposition(|&c| c > b' ').map_or(start, |i| i + 1);
    &s[start..end]
}

#[cfg(test)]
mod tests {
    use super::{eq_ignore_ascii_case, for_each_key_value, key_eq, launch, parse_key_value, segments};

    fn hostfs_directive(key: &[u8]) -> bool { key_eq(key, b"hostfs") }

    #[test]
    fn compares_keys_case_insensitively() {
        assert!(key_eq(b"HOSTFS", b"hostfs"));
        assert!(eq_ignore_ascii_case(b"COM2", b"com2"));
        assert!(!key_eq(b"hostfsx", b"hostfs"));
    }

    #[test]
    fn parses_one_token() {
        assert_eq!(parse_key_value(b"hostfs=com2"), Some((&b"hostfs"[..], &b"com2"[..])));
        assert_eq!(parse_key_value(b"program"), None);
        assert_eq!(parse_key_value(b"=value"), None);
    }

    #[test]
    fn visits_segments_without_splitting_arguments() {
        let mut found = [&[][..]; 2];
        let mut count = 0;
        for segment in segments(b" hostfs=com1 ; TESTS/X.COM arg=one; ") {
            found[count] = segment;
            count += 1;
        }
        assert_eq!(count, 2);
        assert_eq!(found[0], b"hostfs=com1");
        assert_eq!(found[1], b"TESTS/X.COM arg=one");
    }

    #[test]
    fn visits_all_key_value_tokens_without_semantic_filtering() {
        let expected_keys = [b"arg".as_slice(), b"hostfs", b"retroos.mount"];
        let expected_values = [b"one".as_slice(), b"com1", b"/data"];
        let mut count = 0;
        for_each_key_value(b"TESTS/X.COM arg=one;hostfs=com1 retroos.mount=/data", |key, value| {
            assert_eq!(key, expected_keys[count]);
            assert_eq!(value, expected_values[count]);
            count += 1;
        });
        assert_eq!(count, 3);
    }

    #[test]
    fn filters_only_the_consumer_owned_directive() {
        let parsed = launch(
            b"hostfs=com1 TESTS/X.COM arg=one retroos.mount=/data",
            hostfs_directive,
        ).unwrap();
        assert_eq!(parsed.program(), b"TESTS/X.COM");
        let mut args = parsed.arguments();
        assert_eq!(args.next(), Some(&b"arg=one"[..]));
        assert_eq!(args.next(), Some(&b"retroos.mount=/data"[..]));
        assert_eq!(args.next(), None);
    }

    #[test]
    fn directive_only_segment_has_no_launch() {
        assert!(launch(b"HOSTFS=COM2", hostfs_directive).is_none());
    }

    #[test]
    fn writes_arguments_with_bounded_space_separation() {
        let parsed = launch(b"TESTS/X.COM one two", hostfs_directive).unwrap();
        let mut output = [0u8; 7];
        let len = parsed.write_arguments(&mut output);
        assert_eq!(&output[..len], b"one two");

        let parsed = launch(b"TESTS/X.COM abc def", hostfs_directive).unwrap();
        let mut output = [0u8; 5];
        let len = parsed.write_arguments(&mut output);
        assert_eq!(&output[..len], b"abc d");
    }
}
