//! ELF executable parsing for 32-bit x86

/// ELF magic number: "\x7FELF"
pub const ELF_MAGIC: u32 = 0x464C_457F;

/// Section header types
pub const SHT_SYMTAB: u32 = 2;
pub const SHT_STRTAB: u32 = 3;

/// Symbol types (low 4 bits of info)
pub const STT_NOTYPE: u8 = 0;
pub const STT_FUNC: u8 = 2;

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

    pub fn is_executable(&self) -> bool {
        (self.flags & PF_EXEC) != 0
    }
}

/// ELF section header (40 bytes for 32-bit)
#[repr(C)]
#[derive(Clone, Copy)]
pub struct SectionHeader {
    pub name: u32,
    pub typ: u32,
    pub flags: u32,
    pub addr: u32,
    pub offset: u32,
    pub size: u32,
    pub link: u32,
    pub info: u32,
    pub addralign: u32,
    pub entsize: u32,
}

/// ELF symbol table entry (16 bytes for 32-bit)
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Sym32 {
    pub name: u32,
    pub value: u32,
    pub size: u32,
    pub info: u8,
    pub other: u8,
    pub shndx: u16,
}

impl Sym32 {
    /// Get symbol type (low 4 bits of info)
    pub fn typ(&self) -> u8 {
        self.info & 0xf
    }
}

/// Parsed symbol table - references into original ELF data
pub struct SymbolTable<'a> {
    symbols: &'a [Sym32],
    strtab: &'a [u8],
}

impl<'a> SymbolTable<'a> {
    /// Parse symbol table from ELF data
    pub fn parse(elf_data: &'a [u8]) -> Option<Self> {
        if elf_data.len() < 52 {
            return None;
        }

        let header = unsafe { &*(elf_data.as_ptr() as *const ElfHeader) };
        if header.magic != ELF_MAGIC {
            return None;
        }

        let shoff = header.shoff as usize;
        let shnum = header.shnum as usize;
        let shstrndx = header.shstrndx as usize;

        if shoff == 0 || shnum == 0 || shstrndx >= shnum {
            return None;
        }

        // Get section headers
        let sh_size = core::mem::size_of::<SectionHeader>();
        if shoff + shnum * sh_size > elf_data.len() {
            return None;
        }

        let sections = unsafe {
            core::slice::from_raw_parts(
                elf_data.as_ptr().add(shoff) as *const SectionHeader,
                shnum
            )
        };

        // Get section header string table
        let shstrtab = &sections[shstrndx];
        let shstrtab_off = shstrtab.offset as usize;
        let shstrtab_size = shstrtab.size as usize;
        if shstrtab_off + shstrtab_size > elf_data.len() {
            return None;
        }
        let shstrtab_data = &elf_data[shstrtab_off..shstrtab_off + shstrtab_size];

        // Find .symtab and .strtab
        let mut symtab: Option<&SectionHeader> = None;
        let mut strtab: Option<&SectionHeader> = None;

        for section in sections {
            let name_offset = section.name as usize;
            if name_offset >= shstrtab_data.len() {
                continue;
            }

            let name = get_str(shstrtab_data, name_offset);

            if name == b".symtab" && section.typ == SHT_SYMTAB {
                symtab = Some(section);
            } else if name == b".strtab" && section.typ == SHT_STRTAB {
                strtab = Some(section);
            }
        }

        let (sym_section, str_section) = match (symtab, strtab) {
            (Some(s), Some(t)) => (s, t),
            _ => return None,
        };

        // Get symbol table slice
        let sym_off = sym_section.offset as usize;
        let sym_size = sym_section.size as usize;
        let sym_count = sym_size / core::mem::size_of::<Sym32>();

        if sym_off + sym_size > elf_data.len() {
            return None;
        }

        let symbols = unsafe {
            core::slice::from_raw_parts(
                elf_data.as_ptr().add(sym_off) as *const Sym32,
                sym_count
            )
        };

        // Get string table slice
        let str_off = str_section.offset as usize;
        let str_size = str_section.size as usize;

        if str_off + str_size > elf_data.len() {
            return None;
        }

        let strtab = &elf_data[str_off..str_off + str_size];

        Some(SymbolTable { symbols, strtab })
    }

    /// Get symbols slice
    pub fn symbols(&self) -> &[Sym32] {
        self.symbols
    }

    /// Get string table
    pub fn strtab(&self) -> &[u8] {
        self.strtab
    }

    /// Look up symbol name by string table offset
    pub fn symbol_name(&self, sym: &Sym32) -> &'a str {
        let bytes = get_str(self.strtab, sym.name as usize);
        core::str::from_utf8(bytes).unwrap_or("")
    }

    /// Find the symbol containing an address, returns (name, offset)
    pub fn lookup(&self, addr: u32) -> (&'a str, u32) {
        let mut best_sym: Option<&Sym32> = None;
        let mut best_addr: u32 = 0;

        for sym in self.symbols {
            let typ = sym.typ();
            if typ != STT_FUNC && typ != STT_NOTYPE {
                continue;
            }

            if sym.value == 0 || sym.name == 0 {
                continue;
            }

            if sym.value <= addr && sym.value > best_addr {
                best_addr = sym.value;
                best_sym = Some(sym);
            }
        }

        if let Some(sym) = best_sym {
            (self.symbol_name(sym), addr - sym.value)
        } else {
            ("", 0)
        }
    }
}

/// Get null-terminated string from byte slice
fn get_str(data: &[u8], offset: usize) -> &[u8] {
    if offset >= data.len() {
        return &[];
    }
    let start = &data[offset..];
    let len = start.iter().position(|&c| c == 0).unwrap_or(start.len());
    &start[..len]
}
