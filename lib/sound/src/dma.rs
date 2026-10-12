//! DMA actions, without a controller, guest address, or memory callback.
//! The host chooses the wired channel and executes the action. Read offsets
//! are relative to that channel's buffer; `wrap_bytes` describes a cyclic
//! buffer when the consumer needs a linear window across its end.

#[derive(Debug, PartialEq, Eq)]
pub enum Request<'a> {
    Read { offset: usize, bytes: usize, wrap_bytes: Option<usize> },
    Write { bytes: &'a [u8] },
}

/// What actually moved, including a short or empty transfer. Merely asking
/// for a transfer does not count as completing it.
#[derive(Clone, Copy, Debug)]
pub enum Completion<'a> {
    Read { bytes: &'a [u8], terminal_count: bool },
    Write { bytes: usize, terminal_count: bool },
}
