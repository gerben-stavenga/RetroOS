//! Fixed-width kernel/arch exchange for a supervisor running inside a VM.
//! Pointers never cross this boundary. The host and supervisor share this
//! resident buffer; the supervisor owns the live application stack frame.
use crate::{Regs, page_entry::PageEntry, page_supply::{PageInput, SUPPLY_CAPACITY}};
/// Direct CPU interruption from the host; no PIC or LAPIC is present.
pub const INTERRUPT_VECTOR: u32 = 32;
pub const EXIT_PORT: u16 = 0xf4;
pub const PANIC_PORT: u16 = 0xf5;
pub const HOOK_PHYSICAL: u64 = 0x3100_0000;
pub const HOOK_VIRTUAL: usize = 0xe020_0000;
pub const HOOK_PAGES: usize = 512;
pub const COUNTS_PHYSICAL: u64 = 0x3000_0000;
pub const COUNTS_VIRTUAL: usize = 0xe000_0000;
pub const IMAGE_PHYSICAL: usize = 0x1000;
pub const IMAGE_VIRTUAL: usize = 0xc0b0_0000;
pub const IMAGE_LIMIT: usize = 0x100000;
pub const DATA_SIZE: usize = 65536;
pub const MAPPINGS: usize = 128;

pub mod op {
    pub const INSTALL_TRAP_HOOK: u64 = 28;
    pub const EDIT_MAPPINGS: u64 = 29;
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
    pub const LOAD_LDT: u64 = 17;
    pub const TLS: u64 = 18;
    pub const SEGMENT: u64 = 19;
    pub const INTERCEPTED: u64 = 20;
    pub const FX_SWITCH: u64 = 21;
    pub const FPU_ST0: u64 = 22;
    pub const FPU_POP: u64 = 23;
    pub const DEBUG_WATCH: u64 = 26;
}

/// Physical roots of the active user space. Frame numbers, never host pointers.
/// KVM uses a low PAE tree and a high x86-64 tree, both with 64-bit entries.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct UserMemory {
    pub low_root: u64,
    pub high_root: u64,
    pub zero_page: u64,
}
impl UserMemory {
    pub const EMPTY: Self = Self { low_root: 0, high_root: 0, zero_page: 0 };

}

#[repr(C, align(16))]
pub struct Exchange {
    pub operation: u64,
    pub args: [u64; 6],
    pub result: [u64; 3],
    pub supply_returned: u64,
    pub memory: UserMemory,
    pub reserve_address: u64,
    pub tables_changed: u64,
    pub regs: Regs,
    pub pages: [u64; SUPPLY_CAPACITY],
    pub page_count: u64,
    pub root: [u32; 768],
    pub entries: [PageEntry; MAPPINGS],
    pub data: [u8; DATA_SIZE],
}
impl Exchange {
    pub const fn new() -> Self {
        Self { operation: 0, args: [0; 6], result: [0; 3], supply_returned: 0, memory: UserMemory::EMPTY, reserve_address: 0, tables_changed: 0, regs: Regs::empty(),
            pages: [0; SUPPLY_CAPACITY], page_count: 0, root: [0; 768],
            entries: [PageEntry::Absent; MAPPINGS], data: [0; DATA_SIZE] }
    }
    /// # Safety
    /// The other side of the exchange must have transferred ownership of
    /// every frame named by the active slots, and be stopped while we take it.
    pub unsafe fn take_pages(&mut self) -> PageInput {
        let count = usize::try_from(core::mem::take(&mut self.page_count)).unwrap();
        unsafe { PageInput::from_raw_parts(self.pages, count) }
    }
    pub fn put_pages(&mut self, pages: PageInput) {
        assert_eq!(self.page_count, 0, "unclaimed pages in exchange");
        let (frames, count) = pages.into_raw_parts();
        self.pages = frames;
        self.page_count = count as u64;
    }
    pub fn put_edit(&mut self, edit: crate::mapping::Edit) {
        use crate::mapping::{Edit, Missing};
        let (kind, access, executable, policy) = match edit {
            Edit::ReserveZero { access, executable, only_if_vacant } => (0, access as u64, executable, only_if_vacant),
            Edit::CommitZero => (1, 0, false, false),
            Edit::Protect { access, executable, missing } => (2, access as u64, executable, missing == Missing::Reject),
            Edit::Discard => (3, 0, false, false),
            Edit::MakePrivate => (4, 0, false, false),
        };
        self.args[2..].copy_from_slice(&[kind, access, executable as u64, policy as u64]);
    }

    pub fn edit(&self) -> crate::mapping::Edit {
        use crate::mapping::{Edit, Missing, Protection};
        let access = match self.args[3] {
            0 => Protection::None, 1 => Protection::ReadOnly, 2 => Protection::ReadWrite,
            _ => panic!("invalid mapping protection"),
        };
        let executable = self.args[4] != 0;
        let policy = self.args[5] != 0;
        match self.args[2] {
            0 => Edit::ReserveZero { access, executable, only_if_vacant: policy },
            1 => Edit::CommitZero,
            2 => Edit::Protect { access, executable, missing: if policy { Missing::Reject } else { Missing::Skip } },
            3 => Edit::Discard,
            4 => Edit::MakePrivate,
            _ => panic!("invalid mapping edit"),
        }
    }

    pub fn mapping_result(&mut self, result: Result<(), crate::MappingError>) {
        use crate::MappingError::*;
        self.result[0] = match result { Ok(()) => 0, Err(NeedPages) => 1,
            Err(InvalidAddress) => 2, Err(InvalidFrame) => 3, Err(Unsupported) => 4, Err(AlreadyMapped) => 9,
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
            9 => Err(AlreadyMapped),
            _ => panic!("invalid supervisor response") }
    }
}
const _: () = assert!(core::mem::offset_of!(Exchange, data) % 8 == 0);
