//! Fixed-width kernel/arch exchange for a supervisor running inside a VM.
//! Pointers never cross this boundary. The host and supervisor share this
//! resident buffer; the supervisor owns the live application stack frame.
use crate::{Regs, page_entry::PageEntry, page_supply::{PageInput, SUPPLY_CAPACITY}};
/// Direct CPU interruption from the host; no PIC or LAPIC is present.
pub const INTERRUPT_VECTOR: u32 = 32;
pub const EXIT_PORT: u16 = 0xf4;
pub const PANIC_PORT: u16 = 0xf5;
pub const PLANAR_PHYSICAL: u64 = 0x3100_0000;
pub const PLANAR_VIRTUAL: usize = 0xe020_0000;
pub const COUNTS_PHYSICAL: u64 = 0x3000_0000;
pub const COUNTS_VIRTUAL: usize = 0xe000_0000;
pub const IMAGE_PHYSICAL: usize = 0x1000;
pub const IMAGE_VIRTUAL: usize = 0xc0b0_0000;
pub const IMAGE_LIMIT: usize = 0x100000;
pub const DATA_SIZE: usize = 65536;
pub const MAPPINGS: usize = 128;

pub mod op {
    pub const BIND_PLANAR: u64 = 28;
    pub const CONFIGURE: u64 = 0;
    pub const EXECUTE: u64 = 1;
    pub const SUPPLY: u64 = 2;
    pub const READ_MAPPINGS: u64 = 3;
    pub const REPLACE_MAPPINGS: u64 = 4;
    pub const FILL_MAPPINGS: u64 = 5;
    pub const READ_RUN: u64 = 6;
    pub const ALIAS: u64 = 7;
    pub const SWAP: u64 = 8;
    pub const ACTIVATE: u64 = 9;
    pub const FORK: u64 = 10;
    pub const CLEAN: u64 = 11;
    pub const DESTROY: u64 = 12;
    pub const COPY_FROM: u64 = 13;
    pub const COPY_TO: u64 = 14;
    pub const ZERO: u64 = 15;
    pub const COPY_WITHIN: u64 = 16;
    pub const LOAD_LDT: u64 = 17;
    pub const TLS: u64 = 18;
    pub const SEGMENT: u64 = 19;
    pub const INTERCEPTED: u64 = 20;
    pub const FX_SWITCH: u64 = 21;
    pub const FPU_ST0: u64 = 22;
    pub const FPU_POP: u64 = 23;
    pub const TRANSLATE: u64 = 24;
    pub const DEBUG_WATCH: u64 = 26;
    pub const COPY_CSTR: u64 = 27;
}

#[repr(C, align(16))]
pub struct Exchange {
    pub operation: u64,
    pub args: [u64; 6],
    pub result: [u64; 3],
    pub regs: Regs,
    pub pages: [u64; SUPPLY_CAPACITY],
    pub page_count: u64,
    pub root: [u32; 768],
    pub entries: [PageEntry; MAPPINGS],
    pub data: [u8; DATA_SIZE],
}
impl Exchange {
    pub const fn new() -> Self {
        Self { operation: 0, args: [0; 6], result: [0; 3], regs: Regs::empty(),
            pages: [0; SUPPLY_CAPACITY], page_count: 0, root: [0; 768],
            entries: [PageEntry::Absent; MAPPINGS], data: [0; DATA_SIZE] }
    }
    pub fn take_pages(&mut self) -> PageInput {
        let count = usize::try_from(self.page_count).unwrap();
        assert!(count <= SUPPLY_CAPACITY);
        self.page_count = 0;
        PageInput { pages: self.pages, count }
    }
    pub fn put_pages(&mut self, pages: PageInput) {
        self.pages = pages.pages;
        self.page_count = pages.count as u64;
    }
    pub fn mapping_result(&mut self, result: Result<(), crate::MappingError>) {
        use crate::MappingError::*;
        self.result[0] = match result { Ok(()) => 0, Err(NeedPages) => 1,
            Err(InvalidAddress) => 2, Err(InvalidFrame) => 3, Err(Unsupported) => 4,
            Err(Encoding(error)) => 5 + match error {
                crate::page_entry::EncodingError::InvalidEncoding => 0,
                crate::page_entry::EncodingError::InvalidPhysicalWidth => 1,
                crate::page_entry::EncodingError::FrameOutOfRange => 2,
                crate::page_entry::EncodingError::InvalidVirtualAddress => 3,
            } };
    }
    pub fn mapping_status(&self) -> Result<(), crate::MappingError> {
        use crate::MappingError::*;
        match self.result[0] { 0 => Ok(()), 1 => Err(NeedPages), 2 => Err(InvalidAddress),
            3 => Err(InvalidFrame), 4 => Err(Unsupported), 5 => Err(Encoding(crate::page_entry::EncodingError::InvalidEncoding)),
            6 => Err(Encoding(crate::page_entry::EncodingError::InvalidPhysicalWidth)),
            7 => Err(Encoding(crate::page_entry::EncodingError::FrameOutOfRange)),
            8 => Err(Encoding(crate::page_entry::EncodingError::InvalidVirtualAddress)),
            _ => panic!("invalid supervisor response") }
    }
}
const _: () = assert!(core::mem::offset_of!(Exchange, data) % 8 == 0);
