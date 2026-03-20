//! ELF executable parsing for 32-bit and 64-bit x86

/// ELF magic number: "\x7FELF"
pub const ELF_MAGIC: u32 = 0x464C_457F;

/// Section header types
pub const SHT_SYMTAB: u32 = 2;
pub const SHT_STRTAB: u32 = 3;

/// Symbol types (low 4 bits of info)
pub const STT_NOTYPE: u8 = 0;
pub const STT_FUNC: u8 = 2;

/// ELF class
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ElfClass {
    Elf32,
    Elf64,
}

// =============================================================================
// ELF32 structures
// =============================================================================

/// ELF32 header (52 bytes)
#[repr(C, packed)]
pub struct ElfHeader32 {
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

/// ELF32 program header (32 bytes)
#[repr(C, packed)]
pub struct ProgramHeader32 {
    pub typ: u32,
    pub off: u32,
    pub vaddr: u32,
    pub paddr: u32,
    pub filesz: u32,
    pub memsz: u32,
    pub flags: u32,
    pub align: u32,
}

/// ELF32 section header (40 bytes)
#[repr(C)]
#[derive(Clone, Copy)]
pub struct SectionHeader32 {
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

/// ELF32 symbol table entry (16 bytes)
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
    pub fn typ(&self) -> u8 { self.info & 0xf }
}

// =============================================================================
// ELF64 structures
// =============================================================================

/// ELF64 header (64 bytes)
#[repr(C, packed)]
pub struct ElfHeader64 {
    pub magic: u32,
    pub elf: [u8; 12],
    pub typ: u16,
    pub machine: u16,
    pub version: u32,
    pub entry: u64,
    pub phoff: u64,
    pub shoff: u64,
    pub flags: u32,
    pub ehsize: u16,
    pub phentsize: u16,
    pub phnum: u16,
    pub shentsize: u16,
    pub shnum: u16,
    pub shstrndx: u16,
}

/// ELF64 program header (56 bytes) — note flags moved before offset
#[repr(C, packed)]
pub struct ProgramHeader64 {
    pub typ: u32,
    pub flags: u32,
    pub off: u64,
    pub vaddr: u64,
    pub paddr: u64,
    pub filesz: u64,
    pub memsz: u64,
    pub align: u64,
}

/// ELF64 section header (64 bytes)
#[repr(C)]
#[derive(Clone, Copy)]
pub struct SectionHeader64 {
    pub name: u32,
    pub typ: u32,
    pub flags: u64,
    pub addr: u64,
    pub offset: u64,
    pub size: u64,
    pub link: u32,
    pub info: u32,
    pub addralign: u64,
    pub entsize: u64,
}

/// ELF64 symbol table entry (24 bytes) — note reordered fields
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Sym64 {
    pub name: u32,
    pub info: u8,
    pub other: u8,
    pub shndx: u16,
    pub value: u64,
    pub size: u64,
}

impl Sym64 {
    pub fn typ(&self) -> u8 { self.info & 0xf }
}

// =============================================================================
// Backwards-compatible type aliases
// =============================================================================

pub type ElfHeader = ElfHeader32;
pub type ProgramHeader = ProgramHeader32;
pub type SectionHeader = SectionHeader32;

// =============================================================================
// Common types
// =============================================================================

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

// =============================================================================
// Unified parser
// =============================================================================

/// Parsed ELF file (32-bit or 64-bit)
pub struct Elf<'a> {
    data: &'a [u8],
    class: ElfClass,
}

impl<'a> Elf<'a> {
    /// Parse an ELF file from raw bytes (accepts both ELF32 and ELF64)
    pub fn parse(data: &'a [u8]) -> Result<Self, ElfError> {
        if data.len() < 16 {
            return Err(ElfError::InvalidMagic);
        }

        let magic = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        if magic != ELF_MAGIC {
            return Err(ElfError::InvalidMagic);
        }
        if data[5] != 1 {
            return Err(ElfError::InvalidEndian);
        }

        let class = match data[4] {
            1 => ElfClass::Elf32,
            2 => ElfClass::Elf64,
            _ => return Err(ElfError::InvalidClass),
        };

        // Validate header size
        let min_size = match class {
            ElfClass::Elf32 => core::mem::size_of::<ElfHeader32>(),
            ElfClass::Elf64 => core::mem::size_of::<ElfHeader64>(),
        };
        if data.len() < min_size {
            return Err(ElfError::InvalidMagic);
        }

        // Validate type (must be ET_EXEC=2) and machine
        let (typ, machine) = match class {
            ElfClass::Elf32 => {
                let h = unsafe { &*(data.as_ptr() as *const ElfHeader32) };
                (h.typ, h.machine)
            }
            ElfClass::Elf64 => {
                let h = unsafe { &*(data.as_ptr() as *const ElfHeader64) };
                (h.typ, h.machine)
            }
        };

        if typ != 2 {
            return Err(ElfError::InvalidType);
        }
        let expected_machine = match class {
            ElfClass::Elf32 => 3,     // EM_386
            ElfClass::Elf64 => 0x3E,  // EM_X86_64
        };
        if machine != expected_machine {
            return Err(ElfError::InvalidMachine);
        }

        Ok(Self { data, class })
    }

    /// ELF class (32-bit or 64-bit)
    pub fn class(&self) -> ElfClass {
        self.class
    }

    /// Entry point address
    pub fn entry(&self) -> u64 {
        match self.class {
            ElfClass::Elf32 => {
                let h = unsafe { &*(self.data.as_ptr() as *const ElfHeader32) };
                h.entry as u64
            }
            ElfClass::Elf64 => {
                let h = unsafe { &*(self.data.as_ptr() as *const ElfHeader64) };
                h.entry
            }
        }
    }

    /// Iterate over loadable program segments
    pub fn segments(&self) -> SegmentIter<'a> {
        let (offset, size, count) = match self.class {
            ElfClass::Elf32 => {
                let h = unsafe { &*(self.data.as_ptr() as *const ElfHeader32) };
                (h.phoff as usize, h.phentsize as usize, h.phnum as usize)
            }
            ElfClass::Elf64 => {
                let h = unsafe { &*(self.data.as_ptr() as *const ElfHeader64) };
                (h.phoff as usize, h.phentsize as usize, h.phnum as usize)
            }
        };
        SegmentIter { data: self.data, class: self.class, offset, size, count, index: 0 }
    }
}

/// Iterator over ELF segments
pub struct SegmentIter<'a> {
    data: &'a [u8],
    class: ElfClass,
    offset: usize,
    size: usize,
    count: usize,
    index: usize,
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

impl<'a> Iterator for SegmentIter<'a> {
    type Item = Segment<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        while self.index < self.count {
            let ph_start = self.offset + self.index * self.size;
            self.index += 1;

            let (typ, flags, off, vaddr, filesz, memsz) = match self.class {
                ElfClass::Elf32 => {
                    if ph_start + core::mem::size_of::<ProgramHeader32>() > self.data.len() {
                        continue;
                    }
                    let ph = unsafe { &*(self.data.as_ptr().add(ph_start) as *const ProgramHeader32) };
                    (ph.typ, ph.flags, ph.off as usize, ph.vaddr as usize,
                     ph.filesz as usize, ph.memsz as usize)
                }
                ElfClass::Elf64 => {
                    if ph_start + core::mem::size_of::<ProgramHeader64>() > self.data.len() {
                        continue;
                    }
                    let ph = unsafe { &*(self.data.as_ptr().add(ph_start) as *const ProgramHeader64) };
                    (ph.typ, ph.flags, ph.off as usize, ph.vaddr as usize,
                     ph.filesz as usize, ph.memsz as usize)
                }
            };

            if typ == PT_LOAD {
                let file_data = if filesz > 0 && off + filesz <= self.data.len() {
                    Some(&self.data[off..off + filesz])
                } else {
                    None
                };

                return Some(Segment { vaddr, memsz, flags, data: file_data });
            }
        }
        None
    }
}

// =============================================================================
// Symbol table (32-bit and 64-bit)
// =============================================================================

/// Find .symtab and .strtab section offsets/sizes from section headers.
/// Returns (sym_off, sym_size, str_off, str_size).
fn find_symtab_strtab(
    elf_data: &[u8],
    shoff: usize,
    shnum: usize,
    shstrndx: usize,
    sh_entry_size: usize,
    // Closures to extract fields from section headers of either width
    get_name: fn(&[u8]) -> u32,
    get_typ: fn(&[u8]) -> u32,
    get_offset: fn(&[u8]) -> usize,
    get_size: fn(&[u8]) -> usize,
) -> Option<(usize, usize, usize, usize)> {
    if shoff == 0 || shnum == 0 || shstrndx >= shnum {
        return None;
    }
    if shoff + shnum * sh_entry_size > elf_data.len() {
        return None;
    }

    // Get section header string table
    let shstrtab_raw = &elf_data[shoff + shstrndx * sh_entry_size..];
    let shstrtab_off = get_offset(shstrtab_raw);
    let shstrtab_size = get_size(shstrtab_raw);
    if shstrtab_off + shstrtab_size > elf_data.len() {
        return None;
    }
    let shstrtab_data = &elf_data[shstrtab_off..shstrtab_off + shstrtab_size];

    let mut sym_result: Option<(usize, usize)> = None;
    let mut str_result: Option<(usize, usize)> = None;

    for i in 0..shnum {
        let sh = &elf_data[shoff + i * sh_entry_size..];
        let name_offset = get_name(sh) as usize;
        if name_offset >= shstrtab_data.len() { continue; }
        let name = get_str(shstrtab_data, name_offset);
        let typ = get_typ(sh);
        if name == b".symtab" && typ == SHT_SYMTAB {
            sym_result = Some((get_offset(sh), get_size(sh)));
        } else if name == b".strtab" && typ == SHT_STRTAB {
            str_result = Some((get_offset(sh), get_size(sh)));
        }
    }

    match (sym_result, str_result) {
        (Some((so, ss)), Some((ro, rs))) => Some((so, ss, ro, rs)),
        _ => None,
    }
}

/// Parsed symbol table - works with both ELF32 and ELF64
pub struct SymbolTable<'a> {
    syms32: Option<&'a [Sym32]>,
    syms64: Option<&'a [Sym64]>,
    strtab: &'a [u8],
}

impl<'a> SymbolTable<'a> {
    /// Parse symbol table from ELF data (auto-detects 32/64-bit)
    pub fn parse(elf_data: &'a [u8]) -> Option<Self> {
        if elf_data.len() < 16 { return None; }
        let magic = u32::from_le_bytes([elf_data[0], elf_data[1], elf_data[2], elf_data[3]]);
        if magic != ELF_MAGIC { return None; }

        let class = elf_data[4];
        match class {
            1 => Self::parse32(elf_data),
            2 => Self::parse64(elf_data),
            _ => None,
        }
    }

    fn parse32(elf_data: &'a [u8]) -> Option<Self> {
        if elf_data.len() < core::mem::size_of::<ElfHeader32>() { return None; }
        let h = unsafe { &*(elf_data.as_ptr() as *const ElfHeader32) };

        let (sym_off, sym_size, str_off, str_size) = find_symtab_strtab(
            elf_data, h.shoff as usize, h.shnum as usize, h.shstrndx as usize,
            core::mem::size_of::<SectionHeader32>(),
            |s| unsafe { (*(s.as_ptr() as *const SectionHeader32)).name },
            |s| unsafe { (*(s.as_ptr() as *const SectionHeader32)).typ },
            |s| unsafe { (*(s.as_ptr() as *const SectionHeader32)).offset as usize },
            |s| unsafe { (*(s.as_ptr() as *const SectionHeader32)).size as usize },
        )?;

        if sym_off + sym_size > elf_data.len() || str_off + str_size > elf_data.len() {
            return None;
        }

        let sym_count = sym_size / core::mem::size_of::<Sym32>();
        let symbols = unsafe {
            core::slice::from_raw_parts(elf_data.as_ptr().add(sym_off) as *const Sym32, sym_count)
        };
        let strtab = &elf_data[str_off..str_off + str_size];

        Some(SymbolTable { syms32: Some(symbols), syms64: None, strtab })
    }

    fn parse64(elf_data: &'a [u8]) -> Option<Self> {
        if elf_data.len() < core::mem::size_of::<ElfHeader64>() { return None; }
        let h = unsafe { &*(elf_data.as_ptr() as *const ElfHeader64) };

        let (sym_off, sym_size, str_off, str_size) = find_symtab_strtab(
            elf_data, h.shoff as usize, h.shnum as usize, h.shstrndx as usize,
            core::mem::size_of::<SectionHeader64>(),
            |s| unsafe { (*(s.as_ptr() as *const SectionHeader64)).name },
            |s| unsafe { (*(s.as_ptr() as *const SectionHeader64)).typ },
            |s| unsafe { (*(s.as_ptr() as *const SectionHeader64)).offset as usize },
            |s| unsafe { (*(s.as_ptr() as *const SectionHeader64)).size as usize },
        )?;

        if sym_off + sym_size > elf_data.len() || str_off + str_size > elf_data.len() {
            return None;
        }

        let sym_count = sym_size / core::mem::size_of::<Sym64>();
        let symbols = unsafe {
            core::slice::from_raw_parts(elf_data.as_ptr().add(sym_off) as *const Sym64, sym_count)
        };
        let strtab = &elf_data[str_off..str_off + str_size];

        Some(SymbolTable { syms32: None, syms64: Some(symbols), strtab })
    }

    /// Total symbol count
    pub fn symbol_count(&self) -> usize {
        if let Some(s) = self.syms32 { s.len() }
        else if let Some(s) = self.syms64 { s.len() }
        else { 0 }
    }

    /// Count function symbols
    pub fn func_count(&self) -> usize {
        if let Some(s) = self.syms32 {
            s.iter().filter(|s| s.typ() == STT_FUNC).count()
        } else if let Some(s) = self.syms64 {
            s.iter().filter(|s| s.typ() == STT_FUNC).count()
        } else { 0 }
    }

    /// Get string table
    pub fn strtab(&self) -> &[u8] {
        self.strtab
    }

    fn str_name(&self, name_idx: u32) -> &'a str {
        let bytes = get_str(self.strtab, name_idx as usize);
        core::str::from_utf8(bytes).unwrap_or("")
    }

    /// Find the function symbol containing a 64-bit address, returns (name, offset).
    /// Prefers symbols with known size that contain the address over nearest-below
    /// symbols with size=0.
    pub fn lookup(&self, addr: u64) -> (&'a str, u64) {
        if let Some(symbols) = self.syms32 {
            let addr32 = addr as u32;
            let mut best: Option<&Sym32> = None;
            let mut best_addr: u32 = 0;
            let mut best_has_size = false;
            for sym in symbols.iter() {
                let typ = sym.typ();
                if typ != STT_FUNC && typ != STT_NOTYPE { continue; }
                if sym.value == 0 || sym.name == 0 { continue; }
                if sym.value > addr32 { continue; }
                let has_size = sym.size > 0;
                if has_size && addr32 > sym.value + sym.size { continue; }
                if has_size > best_has_size || (has_size == best_has_size && sym.value > best_addr) {
                    best_addr = sym.value;
                    best_has_size = has_size;
                    best = Some(sym);
                }
            }
            if let Some(sym) = best {
                return (self.str_name(sym.name), (addr32 - sym.value) as u64);
            }
        } else if let Some(symbols) = self.syms64 {
            let mut best: Option<&Sym64> = None;
            let mut best_addr: u64 = 0;
            let mut best_has_size = false;
            for sym in symbols.iter() {
                let typ = sym.typ();
                if typ != STT_FUNC && typ != STT_NOTYPE { continue; }
                if sym.value == 0 || sym.name == 0 { continue; }
                if sym.value > addr { continue; }
                let has_size = sym.size > 0;
                if has_size && addr > sym.value + sym.size { continue; }
                if has_size > best_has_size || (has_size == best_has_size && sym.value > best_addr) {
                    best_addr = sym.value;
                    best_has_size = has_size;
                    best = Some(sym);
                }
            }
            if let Some(sym) = best {
                return (self.str_name(sym.name), addr - sym.value);
            }
        }
        ("", 0)
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
