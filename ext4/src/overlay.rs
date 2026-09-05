//! Ordered RAM-resident filesystem-block layers.

use crate::{BlockEdit, FsError, Storage, StorageError, apply_block_edits};
use alloc::vec::Vec;

/// A volatile byte-addressed view which stores each changed filesystem block
/// exactly once.  It is independent of ext4 semantics: graph algorithms write
/// typed records through `Storage`, then the journal consumes `finish()`.
pub struct BlockOverlay<'a> {
    base: &'a mut dyn Storage,
    block_size: u64,
    dirty: BlockChanges,
}

impl<'a> BlockOverlay<'a> {
    pub fn new(base: &'a mut dyn Storage, block_size: u32) -> Self {
        Self {
            base,
            block_size: u64::from(block_size),
            dirty: BlockChanges::default(),
        }
    }

    fn block(&mut self, number: u64) -> Result<usize, StorageError> {
        match self
            .dirty
            .blocks
            .binary_search_by_key(&number, |block| block.number)
        {
            Ok(index) => Ok(index),
            Err(index) => {
                let size = usize::try_from(self.block_size)
                    .map_err(|_| StorageError::new(FsError::InvalidArgument))?;
                let mut bytes = Vec::new();
                bytes
                    .try_reserve_exact(size)
                    .map_err(|_| StorageError::new(FsError::OutOfMemory))?;
                bytes.resize(size, 0);
                self.base.read(number * self.block_size, &mut bytes)?;
                self.dirty
                    .blocks
                    .try_reserve(1)
                    .map_err(|_| StorageError::new(FsError::OutOfMemory))?;
                self.dirty.blocks.insert(index, BlockEdit { number, bytes });
                Ok(index)
            }
        }
    }

    pub fn finish(self) -> BlockChanges {
        self.dirty
    }
}

impl Storage for BlockOverlay<'_> {
    fn len(&self) -> u64 {
        self.base.len()
    }

    fn read(&mut self, offset: u64, output: &mut [u8]) -> Result<(), StorageError> {
        self.base.read(offset, output)?;
        if output.is_empty() {
            return Ok(());
        }
        let end = offset.saturating_add(output.len() as u64);
        for block in &self.dirty.blocks {
            let start = block.number.saturating_mul(self.block_size);
            let stop = start.saturating_add(self.block_size);
            let overlap_start = offset.max(start);
            let overlap_end = end.min(stop);
            if overlap_start < overlap_end {
                let destination = (overlap_start - offset) as usize;
                let source = (overlap_start - start) as usize;
                let count = (overlap_end - overlap_start) as usize;
                output[destination..destination + count]
                    .copy_from_slice(&block.bytes[source..source + count]);
            }
        }
        Ok(())
    }

    fn write(&mut self, offset: u64, input: &[u8]) -> Result<(), StorageError> {
        let end = offset
            .checked_add(input.len() as u64)
            .filter(|end| *end <= self.len())
            .ok_or_else(|| StorageError::new(FsError::InvalidArgument))?;
        let mut position = offset;
        while position < end {
            let number = position / self.block_size;
            let within = (position % self.block_size) as usize;
            let count = (end - position).min(self.block_size - within as u64) as usize;
            let index = self.block(number)?;
            let source = (position - offset) as usize;
            self.dirty.blocks[index].bytes[within..within + count]
                .copy_from_slice(&input[source..source + count]);
            position += count as u64;
        }
        Ok(())
    }

    fn flush(&mut self) -> Result<(), StorageError> {
        Ok(())
    }
}

/// A sorted, unique map from physical block number to prospective contents.
///
/// The same representation is used for recovered committed state and
/// prospective edits. Visibility and durability are properties of the
/// storage layer, not separate block-map implementations.
#[derive(Default)]
pub struct BlockChanges {
    pub(crate) blocks: Vec<BlockEdit>,
}

impl BlockChanges {
    #[inline(never)]
    pub(crate) fn index(&self, number: u64) -> Result<usize, usize> {
        self.blocks
            .binary_search_by_key(&number, |block| block.number)
    }

    pub(crate) fn apply(&self, block_size: u64, offset: u64, dst: &mut [u8]) {
        apply_block_edits(&self.blocks, block_size, offset, dst);
    }
}
