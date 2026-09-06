//! Shared serial-port selection used by boot configuration and serial drivers.

/// Standard ISA COM ports supported by RetroOS serial consumers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ComPort {
    Com1,
    Com2,
}

impl ComPort {
    /// Parse the user-facing `com1`/`com2` spelling.
    pub fn parse_ascii(value: &[u8]) -> Option<Self> {
        if value.eq_ignore_ascii_case(b"com1") {
            Some(Self::Com1)
        } else if value.eq_ignore_ascii_case(b"com2") {
            Some(Self::Com2)
        } else {
            None
        }
    }
}

impl compact_fmt::Format for ComPort {
    fn format(
        &self,
        out: &mut dyn compact_fmt::Write,
        _spec: compact_fmt::FormatSpec,
    ) -> compact_fmt::Result {
        out.write_str(match self { Self::Com1 => "Com1", Self::Com2 => "Com2" })
    }
}

#[cfg(test)]
mod tests {
    use super::ComPort;

    #[test]
    fn parses_supported_ports_case_insensitively() {
        assert_eq!(ComPort::parse_ascii(b"com1"), Some(ComPort::Com1));
        assert_eq!(ComPort::parse_ascii(b"COM2"), Some(ComPort::Com2));
        assert_eq!(ComPort::parse_ascii(b"com3"), None);
    }
}
