//! BHIE receive vectors for firmware crash dumps. This handles the MHI register
//! format, independently of the device-specific contents of the downloaded bytes.
use super::{Error, Layout, Memory, Registers, Result, SEGMENT, wait};
use alloc::vec::Vec;
use core::sync::atomic::{Ordering, fence};

const DATA: usize = 4096;
const SEQUENCE: u32 = 3;
pub struct CrashDump<M> {
    memory: M,
    bytes: usize,
    armed: bool,
    used: bool,
}
impl<M: Memory> CrashDump<M> {
    pub fn required_bytes(bytes: usize) -> Result<usize> {
        if bytes == 0 || bytes.div_ceil(SEGMENT) > DATA / 16 {
            return Err(Error::Allocation);
        }
        DATA.checked_add(bytes).ok_or(Error::Allocation)
    }
    /// `capacity` must describe the actual DMA allocation owned by `memory`.
    pub fn new(mut memory: M, capacity: usize, bytes: usize) -> Result<Self> {
        let needed = Self::required_bytes(bytes)?;
        if capacity < needed
            || !memory.physical().is_multiple_of(4096)
            || memory.physical().checked_add(needed as u64).is_none()
        {
            return Err(Error::Pointer);
        }
        for (index, start) in (0..bytes).step_by(SEGMENT).enumerate() {
            memory.write64(index * 16, memory.physical() + (DATA + start) as u64);
            memory.write64(index * 16 + 8, (bytes - start).min(SEGMENT) as u64);
        }
        Ok(Self {
            memory,
            bytes,
            armed: false,
            used: false,
        })
    }
    pub fn arm(&mut self, io: &mut impl Registers, layout: Layout) -> Result<()> {
        if self.used {
            return Err(Error::State);
        }
        let address = self.memory.physical();
        io.write(layout.bhie + 0x64, (address >> 32) as u32)?;
        io.write(layout.bhie + 0x60, address as u32)?;
        io.write(
            layout.bhie + 0x68,
            (self.bytes.div_ceil(SEGMENT) * 16) as u32,
        )?;
        fence(Ordering::Release);
        io.write(layout.bhie + 0x70, SEQUENCE)?;
        self.armed = true;
        self.used = true;
        Ok(())
    }
    /// Wait only when firmware has entered RDDM. Never force a healthy device
    /// into an error state, and never expose incomplete DMA as a valid dump.
    pub fn collect(&mut self, io: &mut impl Registers, layout: Layout) -> Result<Option<Vec<u8>>> {
        if !self.armed || io.read(layout.bhi + 0x28)? != 3 {
            return Ok(None);
        }
        wait(io, |io| {
            let status = io.read(layout.bhie + 0x78)?;
            match status >> 30 {
                2 => Ok(true),
                3 => Err(Error::Firmware),
                _ => Ok(false),
            }
        })?;
        fence(Ordering::Acquire);
        self.armed = false;
        Ok(Some(self.memory.copy_out(DATA, self.bytes)))
    }
}
