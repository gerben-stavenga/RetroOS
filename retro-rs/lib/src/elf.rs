//! ELF executable parsing for 32-bit x86

/// ELF magic number: "\x7FELF"
const ELF_MAGIC: u32 = 0x464C_457F;

/// ELF header (52 bytes for 32-bit)
#[repr(C, packed)]
pub struct ElfHeader {
    pub magic: u32,
    pub elf: [u8; 12],
    pub typ: u16,
    pub machine: u16,
    pub version: u32,
    pub entry: u32,
    pub phoff: u32,
    pub shoff: u32,
    pub flags: u32,
    pub ehsize: u16,
    pub phentsize: u16,
    pub phnum: u16,
    pub shentsize: u16,
    pub shnum: u16,
    pub shstrndx: u16,
}

/// Program header (32 bytes for 32-bit)
#[repr(C, packed)]
pub struct ProgramHeader {
    pub typ: u32,
    pub off: u32,
    pub vaddr: u32,
    pub paddr: u32,
    pub filesz: u32,
    pub memsz: u32,
    pub flags: u32,
    pub align: u32,
}

/// Program header types
pub const PT_LOAD: u32 = 1;

/// Program header flags
pub const PF_EXEC: u32 = 1;
pub const PF_WRITE: u32 = 2;
pub const PF_READ: u32 = 4;

/// ELF parse error
#[derive(Debug)]
pub enum ElfError {
    InvalidMagic,
    InvalidClass,
    InvalidEndian,
    InvalidType,
    InvalidMachine,
    OutOfMemory,
}

/// Parsed ELF file
pub struct Elf<'a> {
    data: &'a [u8],
    header: &'a ElfHeader,
}

impl<'a> Elf<'a> {
    /// Parse an ELF file from raw bytes
    pub fn parse(data: &'a [u8]) -> Result<Self, ElfError> {
        if data.len() < core::mem::size_of::<ElfHeader>() {
            return Err(ElfError::InvalidMagic);
        }

        let header = unsafe { &*(data.as_ptr() as *const ElfHeader) };

        if header.magic != ELF_MAGIC {
            return Err(ElfError::InvalidMagic);
        }
        if header.elf[0] != 1 {
            return Err(ElfError::InvalidClass);
        }
        if header.elf[1] != 1 {
            return Err(ElfError::InvalidEndian);
        }
        if header.typ != 2 {
            return Err(ElfError::InvalidType);
        }
        if header.machine != 3 {
            return Err(ElfError::InvalidMachine);
        }

        Ok(Self { data, header })
    }

    /// Get entry point address
    pub fn entry(&self) -> u32 {
        self.header.entry
    }

    /// Iterate over loadable program segments
    pub fn segments(&self) -> SegmentIter<'a> {
        SegmentIter {
            data: self.data,
            offset: self.header.phoff as usize,
            size: self.header.phentsize as usize,
            count: self.header.phnum as usize,
            index: 0,
        }
    }
}

/// Iterator over ELF segments
pub struct SegmentIter<'a> {
    data: &'a [u8],
    offset: usize,
    size: usize,
    count: usize,
    index: usize,
}

impl<'a> Iterator for SegmentIter<'a> {
    type Item = Segment<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        while self.index < self.count {
            let ph_start = self.offset + self.index * self.size;
            self.index += 1;

            if ph_start + core::mem::size_of::<ProgramHeader>() > self.data.len() {
                continue;
            }

            let ph = unsafe { &*(self.data.as_ptr().add(ph_start) as *const ProgramHeader) };

            if ph.typ == PT_LOAD {
                let off = ph.off as usize;
                let filesz = ph.filesz as usize;
                let file_data = if filesz > 0 && off + filesz <= self.data.len() {
                    Some(&self.data[off..off + filesz])
                } else {
                    None
                };

                return Some(Segment {
                    vaddr: ph.vaddr as usize,
                    memsz: ph.memsz as usize,
                    flags: ph.flags,
                    data: file_data,
                });
            }
        }
        None
    }
}

/// A loadable ELF segment
pub struct Segment<'a> {
    pub vaddr: usize,
    pub memsz: usize,
    pub flags: u32,
    pub data: Option<&'a [u8]>,
}

impl Segment<'_> {
    pub fn is_writable(&self) -> bool {
        (self.flags & PF_WRITE) != 0
    }
}
