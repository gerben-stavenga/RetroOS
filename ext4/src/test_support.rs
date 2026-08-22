//! Deterministic storage for fault and power-loss testing.
//!
//! This is public rather than `cfg(test)`: downstream kernels should be able to
//! run the exact same filesystem code against the model in their own tests.

use crate::Storage;
use alloc::vec::Vec;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EffectKind {
    Read,
    Write,
    Flush,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Effect {
    pub sequence: usize,
    pub kind: EffectKind,
    pub offset: u64,
    pub len: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Inject {
    None,
    IoErrorAt(usize),
    PowerLossAt(usize),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ModelError {
    OutOfBounds,
    InjectedIo,
    PowerLoss,
}

#[derive(Clone, Debug)]
struct PendingWrite {
    offset: usize,
    bytes: Vec<u8>,
}

/// A byte-addressed device with explicit volatile and durable state.
///
/// Successful writes are immediately visible to reads but do not become
/// durable until `flush`. Before simulating a power loss, tests may call
/// `persist_pending_prefix` to model any ordered prefix having reached media.
#[derive(Clone, Debug)]
pub struct ModelStorage {
    durable: Vec<u8>,
    visible: Vec<u8>,
    pending: Vec<PendingWrite>,
    effects: Vec<Effect>,
    inject: Inject,
    next_sequence: usize,
}

impl ModelStorage {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self {
            durable: bytes.clone(),
            visible: bytes,
            pending: Vec::new(),
            effects: Vec::new(),
            inject: Inject::None,
            next_sequence: 0,
        }
    }

    pub fn with_injection(mut self, inject: Inject) -> Self {
        self.inject = inject;
        self
    }

    pub fn effects(&self) -> &[Effect] {
        &self.effects
    }

    pub fn durable_bytes(&self) -> &[u8] {
        &self.durable
    }

    pub fn pending_writes(&self) -> usize {
        self.pending.len()
    }

    /// Persist an ordered prefix of currently pending writes, then lose power.
    pub fn persist_pending_prefix(&mut self, count: usize) {
        self.persist_pending_with_torn(count.min(self.pending.len()), 0)
            .unwrap();
    }

    /// Persist `complete` whole pending writes and `torn_bytes` of the next
    /// write, then lose power. This models a device whose atomic-write unit is
    /// smaller than the filesystem write submitted to it.
    pub fn persist_pending_with_torn(
        &mut self,
        complete: usize,
        torn_bytes: usize,
    ) -> Result<(), ModelError> {
        if complete > self.pending.len()
            || (torn_bytes != 0
                && self
                    .pending
                    .get(complete)
                    .is_none_or(|write| torn_bytes > write.bytes.len()))
        {
            return Err(ModelError::OutOfBounds);
        }
        for write in self.pending.iter().take(complete) {
            let end = write.offset + write.bytes.len();
            self.durable[write.offset..end].copy_from_slice(&write.bytes);
        }
        if torn_bytes != 0 {
            let write = &self.pending[complete];
            self.durable[write.offset..write.offset + torn_bytes]
                .copy_from_slice(&write.bytes[..torn_bytes]);
        }
        self.power_loss();
        Ok(())
    }

    /// Discard volatile state, as reconstructing the device after power loss.
    pub fn power_loss(&mut self) {
        self.visible.clone_from(&self.durable);
        self.pending.clear();
    }

    fn begin(&mut self, kind: EffectKind, offset: u64, len: usize) -> Result<(), ModelError> {
        let sequence = self.next_sequence;
        self.next_sequence += 1;
        self.effects.push(Effect {
            sequence,
            kind,
            offset,
            len,
        });
        match self.inject {
            Inject::IoErrorAt(n) if n == sequence => Err(ModelError::InjectedIo),
            Inject::PowerLossAt(n) if n == sequence => {
                self.power_loss();
                Err(ModelError::PowerLoss)
            }
            _ => Ok(()),
        }
    }

    fn range(&self, offset: u64, len: usize) -> Result<core::ops::Range<usize>, ModelError> {
        let start = usize::try_from(offset).map_err(|_| ModelError::OutOfBounds)?;
        let end = start.checked_add(len).ok_or(ModelError::OutOfBounds)?;
        if end > self.visible.len() {
            return Err(ModelError::OutOfBounds);
        }
        Ok(start..end)
    }
}

impl Storage for ModelStorage {
    type Error = ModelError;

    fn len(&self) -> u64 {
        self.visible.len() as u64
    }

    fn read(&mut self, offset: u64, dst: &mut [u8]) -> Result<(), Self::Error> {
        self.begin(EffectKind::Read, offset, dst.len())?;
        let range = self.range(offset, dst.len())?;
        dst.copy_from_slice(&self.visible[range]);
        Ok(())
    }

    fn write(&mut self, offset: u64, src: &[u8]) -> Result<(), Self::Error> {
        self.begin(EffectKind::Write, offset, src.len())?;
        let range = self.range(offset, src.len())?;
        self.visible[range.clone()].copy_from_slice(src);
        self.pending.push(PendingWrite {
            offset: range.start,
            bytes: src.to_vec(),
        });
        Ok(())
    }

    fn flush(&mut self) -> Result<(), Self::Error> {
        self.begin(EffectKind::Flush, 0, 0)?;
        self.durable.clone_from(&self.visible);
        self.pending.clear();
        Ok(())
    }
}
