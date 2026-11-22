//! Hosted kernel transport to the freestanding arch-metal supervisor.
mod entry;
mod run;
mod setup;
#[cfg(test)] mod tests;
pub use run::execute;
pub(crate) use setup::kick;
use arch_abi::{Memory, X86, GuestBytes, UserPage, MappingError, MappingFailure, page_entry::PageEntry, page_supply::PageInput, vm::{self, Exchange, op}};
use crate::{backend::Interp, space::AddressSpace};

pub(crate) fn supply_status() -> arch_abi::page_supply::SupplyStatus {
    setup::with(|cpu| {
        let returned = unsafe { (*cpu.message).supply_returned as usize };
        arch_abi::page_supply::SupplyStatus {
            needed: arch_abi::page_supply::SUPPLY_CAPACITY - cpu.reserve().len(),
            returned,
        }
    })
}

fn request<R>(operation: u64, args: [u64; 6], prepare: impl FnOnce(&mut Exchange), finish: impl FnOnce(&mut Exchange) -> R) -> R {
    setup::with(|cpu| {
        let message = unsafe { &mut *cpu.message };
        message.operation = operation;
        message.args = args;
        message.page_count = 0;
        prepare(message);
        run::until_return(cpu, false);
        finish(unsafe { &mut *cpu.message })
    })
}
fn empty(operation: u64) { request(operation, [0; 6], |_| {}, |_| {}); }
fn root_operation(operation: u64, root: &mut AddressSpace, pages: PageInput) -> PageInput {
    let incoming = root.0;
    request(operation, [0; 6], |m| { m.root = incoming; m.put_pages(pages); }, |m| { root.0 = m.root; m.take_pages() })
}
fn batch_result(m: &Exchange) -> Result<(), MappingFailure> {
    m.mapping_status().map_err(|error| MappingFailure { error, completed: m.result[1] as usize })
}
impl Memory for Interp {
    type AddressSpace = AddressSpace;
    fn activate(&mut self, mut root: AddressSpace) -> AddressSpace { root_operation(op::ACTIVATE, &mut root, PageInput::new()); root }
    fn supply_pages(&self, pages: PageInput) -> (usize, PageInput) {
        request(op::SUPPLY, [0; 6], |m| m.put_pages(pages), |m| (m.result[0] as usize, m.take_pages()))
    }
    fn user_fork(&mut self, root: &mut AddressSpace, pages: PageInput) -> ((), PageInput) { ((), root_operation(op::FORK, root, pages)) }
    fn free_user_pages(&mut self) { empty(op::CLEAN); }
    fn destroy_space(&mut self, root: &mut AddressSpace) { root_operation(op::DESTROY, root, PageInput::new()); }
    fn alias_mappings(&mut self, a: UserPage, b: UserPage, count: usize, pages: PageInput) -> (Result<(), MappingError>, PageInput) {
        request(op::ALIAS, [a.address(), count as u64, b.address(), 0, 0, 0], |m| m.put_pages(pages), |m| (m.mapping_status(), m.take_pages()))
    }
    fn swap_mappings(&mut self, a: UserPage, b: UserPage, count: usize, pages: PageInput) -> (Result<(), MappingError>, PageInput) {
        request(op::SWAP, [a.address(), count as u64, b.address(), 0, 0, 0], |m| m.put_pages(pages), |m| (m.mapping_status(), m.take_pages()))
    }
    fn read_mappings(&mut self, start: UserPage, entries: &mut [PageEntry]) -> Result<(), MappingFailure> {
        if !entries.is_empty() { start.offset(entries.len() - 1).map_err(|error| MappingFailure { error, completed: 0 })?; }
        for (chunk, entries) in entries.chunks_mut(vm::MAPPINGS).enumerate() {
            let base = chunk * vm::MAPPINGS;
            let page = start.offset(base).map_err(|error| MappingFailure { error, completed: base })?;
            request(op::READ_MAPPINGS, [page.address(), entries.len() as u64, 0, 0, 0, 0], |_| {}, |m| {
                let result = batch_result(m);
                let copied = result.as_ref().err().map_or(entries.len(), |e| e.completed);
                entries[..copied].copy_from_slice(&m.entries[..copied]);
                result.map_err(|mut e| { e.completed += base; e })
            })?;
        }
        Ok(())
    }
    fn read_mapping_run(&mut self, start: UserPage, maximum: usize) -> Result<(PageEntry, usize), MappingError> {
        request(op::READ_RUN, [start.address(), maximum as u64, 0, 0, 0, 0], |_| {}, |m| m.mapping_status().map(|()| (m.entries[0], m.result[1] as usize)))
    }
    unsafe fn replace_mappings(&mut self, start: UserPage, entries: &[PageEntry], mut pages: PageInput) -> (Result<(), MappingFailure>, PageInput) {
        if !entries.is_empty() {
            if let Err(error) = start.offset(entries.len() - 1) { return (Err(MappingFailure { error, completed: 0 }), pages); }
        }
        for (chunk, entries) in entries.chunks(vm::MAPPINGS).enumerate() {
            let base = chunk * vm::MAPPINGS;
            let page = match start.offset(base) { Ok(page) => page, Err(error) => return (Err(MappingFailure { error, completed: base }), pages) };
            let (result, unused) = request(op::REPLACE_MAPPINGS, [page.address(), entries.len() as u64, 0, 0, 0, 0],
                |m| { m.entries[..entries.len()].copy_from_slice(entries); m.put_pages(pages); },
                |m| (batch_result(m), m.take_pages()));
            pages = unused;
            if let Err(mut error) = result { error.completed += base; return (Err(error), pages); }
        }
        (Ok(()), pages)
    }
    unsafe fn fill_mappings(&mut self, start: UserPage, count: usize, entry: PageEntry, pages: PageInput) -> (Result<(), MappingFailure>, PageInput) {
        request(op::FILL_MAPPINGS, [start.address(), count as u64, 0, 0, 0, 0], |m| { m.entries[0] = entry; m.put_pages(pages); }, |m| (batch_result(m), m.take_pages()))
    }
}

// Hosted byte access walks arch-owned live tables through the RAM mapping.
// setup::with excludes supervisor execution and other CPUs' paging mutations.
struct PhysicalAccess<'a> {
    cpu: &'a mut setup::KvmCpu,
    pages: Option<PageInput>,
    ownership: arch_abi::page_supply::FrameOwnership,
}
impl<'a> PhysicalAccess<'a> {
    fn new(cpu: &'a mut setup::KvmCpu, pages: Option<PageInput>) -> Self {
        let mut ownership = crate::phys::ownership();
        ownership.zero_page = unsafe { (*cpu.message).memory.zero_page };
        Self { cpu, pages, ownership }
    }
    fn resolve(&mut self, address: u64, write: bool) -> Option<*mut u8> {
        let page = self.resolve_page(address, write)?;
        Some(unsafe { self.cpu.frame(page).add(address as usize & 4095) })
    }

    /// Resolve without dereferencing a guest virtual address. The caller holds
    /// the paging lock and invalidates translations after any table writes.
    fn resolve_page(&mut self, address: u64, write: bool) -> Option<u64> {
        use arch_abi::vm::UserMemory;
        const PRESENT: u64 = 1;
        const READ_WRITE: u64 = 2;
        const USER: u64 = 4;
        const FOREIGN: u64 = 1 << 11;
        const NO_ACCESS: u64 = 1 << 10;
        const SOFT_RO: u64 = 1 << 9;
        let UserMemory { low_root, high_root, zero_page } = unsafe { (*self.cpu.message).memory };
        const RESERVED: u64 = 1 << 10;
        const BLOCKED: u64 = 1 << 8;
        UserPage::new(address & !4095).ok()?;
        let low = address < 0xc000_0000;
        if !low && high_root == 0 { return None; }
        let levels = if low { 3 } else { 4 };
        let root = if low { low_root } else { high_root };
        let mask = 0x000f_ffff_ffff_f000;
        let zero = (zero_page << 12) | PRESENT | USER | FOREIGN;
        let index = |level| ((address >> (12 + 9 * level)) & 511u64) as usize;
        // Check the semantic leaf before consuming any donated backing.
        let mut table = root;
        let mut leaf = 0;
        for level in (0..levels).rev() {
            let entry = self.read_entry(table, index(level));
            if entry & PRESENT == 0 {
                leaf = if low {
                    if level != 0 || entry == 0 { zero } else { return None; }
                } else {
                    if entry & RESERVED == 0 || entry & BLOCKED != 0 { return None; }
                    (entry & !RESERVED) | PRESENT
                };
                break;
            }
            if level == 0 { leaf = entry; break; }
            table = (entry & mask) >> 12;
        }
        if write && leaf & SOFT_RO != 0 { return None; }
        if !write { return Some((leaf & mask) >> 12); }

        table = root;
        for level in (1..levels).rev() {
            let at = index(level);
            let old = self.read_entry(table, at);
            let mut entry = old;
            if entry & PRESENT == 0 {
                let page = self.take_page().expect("guest copy has insufficient supplied table pages");
                let fill = if low { 0 } else { entry };
                for i in 0..512 { self.write_entry(page, i, fill); }
                entry = (page << 12) | PRESENT | READ_WRITE | USER;
            } else if entry & READ_WRITE == 0 {
                let old_page = (entry & mask) >> 12;
                if self.references(old_page) == 1 && entry & FOREIGN == 0 {
                    entry |= READ_WRITE;
                } else {
                    let page = self.take_page().expect("guest copy has insufficient supplied table pages");
                    for i in 0..512 {
                        let mut child = self.read_entry(old_page, i);
                        let owns = child & FOREIGN == 0 && if low {
                            child & (PRESENT | NO_ACCESS) != 0
                        } else { child & PRESENT != 0 || level == 1 && child & RESERVED != 0 };
                        if owns {
                            child &= !READ_WRITE;
                            self.retain((child & mask) >> 12);
                            self.write_entry(old_page, i, child);
                        }
                        self.write_entry(page, i, child);
                    }
                    if entry & FOREIGN == 0 { self.release(old_page); }
                    entry = (page << 12) | PRESENT | READ_WRITE | USER;
                }
            }
            if entry != old { self.write_entry(table, at, entry); }
            table = (entry & mask) >> 12;
        }
        let at = index(0);
        let old = self.read_entry(table, at);
        let mut entry = if low && old == 0 { zero }
            else if !low && old & PRESENT == 0 { (old & !RESERVED) | PRESENT }
            else { old };
        if entry & READ_WRITE == 0 {
            let old_page = (entry & mask) >> 12;
            if entry & FOREIGN != 0 || self.references(old_page) > 1 {
                let page = self.take_page().expect("guest copy has insufficient supplied data pages");
                self.copy_page(old_page, page);
                if entry & FOREIGN == 0 { self.release(old_page); }
                entry = (entry & !mask & !FOREIGN) | (page << 12);
            }
            entry |= READ_WRITE;
        }
        if entry != old { self.write_entry(table, at, entry); }
        Some((entry & mask) >> 12)
    }

    fn read_entry(&self, page: u64, index: usize) -> u64 {
        unsafe { self.cpu.frame(page).cast::<u64>().add(index).read_volatile() }
    }
    fn write_entry(&mut self, page: u64, index: usize, entry: u64) {
        unsafe {
            self.cpu.frame(page).cast::<u64>().add(index).write_volatile(entry);
            (*self.cpu.message).tables_changed = 1;
        }
    }
    fn take_page(&mut self) -> Option<u64> {
        match &mut self.pages { Some(pages) => pages.take(), None => self.cpu.reserve().take() }
    }
    fn copy_page(&mut self, from: u64, to: u64) {
        unsafe { core::ptr::copy_nonoverlapping(self.cpu.frame(from), self.cpu.frame(to), 4096); }
    }
    fn references(&self, page: u64) -> u8 { unsafe { self.ownership.references(page) } }
    fn retain(&mut self, page: u64) { assert!(unsafe { self.ownership.retain(page) }); }
    fn release(&mut self, page: u64) {
        // COW replaces only shared backing. Exclusive frames are reused.
        assert!(!unsafe { self.ownership.release_shared(page) });
    }
}
fn valid_range(address: u64, length: usize) -> bool {
    address.checked_add(length as u64).is_some_and(|end|
        end <= 0xc0000000 || address >= 1 << 39 && end <= 1 << 47)
}
fn transfer(address: u64, buffer: *mut u8, length: usize, supplied: Option<PageInput>, write: bool) -> (Option<()>, PageInput) {
    if !valid_range(address, length) { return (None, supplied.unwrap_or_default()); }
    setup::with(|cpu| {
        let mut access = PhysicalAccess::new(cpu, supplied);
        let mut offset = 0;
        while offset < length {
            let at = address + offset as u64;
            let n = (length - offset).min(4096 - (at as usize & 4095));
            let Some(pointer) = access.resolve(at, write) else { return (None, access.pages.unwrap_or_default()); };
            for i in 0..n { unsafe {
                if write { pointer.add(i).write_volatile(buffer.add(offset + i).read()); }
                else { buffer.add(offset + i).write(pointer.add(i).read_volatile()); }
            } }
            offset += n;
        }
        (Some(()), access.pages.unwrap_or_default())
    })
}
impl GuestBytes for Interp {
    fn read<T: Copy>(&self, address: u64) -> T {
        let mut value = core::mem::MaybeUninit::<T>::uninit();
        transfer(address, value.as_mut_ptr().cast(), core::mem::size_of::<T>(), None, false).0.expect("inaccessible guest read");
        unsafe { value.assume_init() }
    }
    fn write<T: Copy>(&mut self, address: u64, value: T) { transfer(address, (&value as *const T).cast_mut().cast(), core::mem::size_of::<T>(), None, true).0.unwrap_or_else(|| panic!("inaccessible guest write at {address:#x}")); }
    fn copy_from(&self, address: u64, bytes: &mut [u8], pages: PageInput) -> (Option<()>, PageInput) { transfer(address, bytes.as_mut_ptr(), bytes.len(), Some(pages), false) }
    fn copy_to(&mut self, address: u64, bytes: &[u8], pages: PageInput) -> (Option<()>, PageInput) { transfer(address, bytes.as_ptr().cast_mut(), bytes.len(), Some(pages), true) }
    fn zero(&mut self, address: u64, length: usize) {
        assert!(valid_range(address, length), "invalid guest zero range");
        setup::with(|cpu| {
            let mut access = PhysicalAccess::new(cpu, None);
            let mut offset = 0;
            while offset < length {
                let at = address + offset as u64;
                let n = (length - offset).min(4096 - (at as usize & 4095));
                let p = access.resolve(at, true).expect("inaccessible guest zero");
                for i in 0..n { unsafe { p.add(i).write_volatile(0); } }
                offset += n;
            }
        });
    }
    fn copy_within(&mut self, src: u64, dst: u64, length: usize) {
        assert!(valid_range(src, length) && valid_range(dst, length), "invalid guest copy range");
        setup::with(|cpu| {
            let mut access = PhysicalAccess::new(cpu, None);
            let mut remaining = length;
            while remaining != 0 {
                let backwards = dst > src;
                let (s, d, n) = if backwards {
                    let s_end = src + remaining as u64;
                    let d_end = dst + remaining as u64;
                    let n = remaining.min(((s_end - 1) as usize & 4095) + 1)
                        .min(((d_end - 1) as usize & 4095) + 1);
                    (s_end - n as u64, d_end - n as u64, n)
                } else {
                    let offset = (length - remaining) as u64;
                    let s = src + offset; let d = dst + offset;
                    (s, d, remaining.min(4096 - (s as usize & 4095)).min(4096 - (d as usize & 4095)))
                };
                let to = access.resolve(d, true).expect("inaccessible guest copy destination");
                let from = access.resolve(s, false).expect("inaccessible guest copy source");
                for step in 0..n {
                    let i = if backwards { n - step - 1 } else { step };
                    unsafe { to.add(i).write_volatile(from.add(i).read_volatile()); }
                }
                remaining -= n;
            }
        });
    }
    fn copy_cstr(&self, address: u64, bytes: &mut [u8]) -> usize {
        setup::with(|cpu| {
            let mut access = PhysicalAccess::new(cpu, None);
            let mut copied = 0;
            while copied < bytes.len() {
                let at = address.checked_add(copied as u64).expect("guest string address overflow");
                let p = access.resolve(at, false).expect("inaccessible guest string");
                let n = (bytes.len() - copied).min(4096 - (at as usize & 4095));
                for i in 0..n {
                    let b = unsafe { p.add(i).read_volatile() };
                    if b == 0 { return copied + i; }
                    bytes[copied + i] = b;
                }
                copied += n;
            }
            copied
        })
    }

}
thread_local! { static LDT: std::cell::Cell<(*const u64, usize, bool)> = const { std::cell::Cell::new((core::ptr::null(), 0, false)) }; }
fn descriptors_ready() {
    LDT.with(|slot| {
        let (pointer, length, dirty) = slot.get();
        if !dirty { return; }
        request(op::LOAD_LDT, [0, length as u64, 0, 0, 0, 0], |m| {
            if length != 0 { unsafe { core::ptr::copy_nonoverlapping(pointer.cast::<u8>(), m.data.as_mut_ptr(), length * 8); } }
        }, |_| {});
        slot.set((pointer, length, false));
    });
}
impl X86 for Interp {
    unsafe fn install_trap_hook(&mut self, hook: Option<arch_abi::entry::TrapHook>) {
        unsafe { setup::install_trap_hook(hook) }
    }
    fn isa_unmask_irq(&mut self, _: u8) { panic!("hosted has no physical ISA interrupt controller"); }
    fn set_debug_watch(&mut self, addresses: Option<(u32, u32)>) {
        let (n, a, b) = addresses.map_or((0, 0, 0), |(a, b)| (if b == 0 { 1 } else { 2 }, a, b));
        request(op::DEBUG_WATCH, [n, a as u64, b as u64, 0, 0, 0], |_| {}, |_| {});
    }
    type Fx = crate::machine::FxState;
    fn fx_state_bytes(fx: &Self::Fx) -> Option<&[u8; 512]> { Some(&fx.0) }
    fn fx_state_bytes_mut(fx: &mut Self::Fx) -> Option<&mut [u8; 512]> { Some(&mut fx.0) }
    fn inb(&mut self, port: u16) -> u8 { crate::machine::inb(port) }
    fn inw(&mut self, port: u16) -> u16 { crate::machine::inw(port) }
    fn inl(&mut self, port: u16) -> u32 { crate::machine::inl(port) }
    fn outb(&mut self, port: u16, value: u8) { crate::machine::outb(port, value) }
    fn outw(&mut self, port: u16, value: u16) { crate::machine::outw(port, value) }
    fn outl(&mut self, port: u16, value: u32) { crate::machine::outl(port, value) }
    fn user_64_supported(&self) -> bool { true }
    fn switch_fx(&mut self, fx: &mut Self::Fx) { fx_switch(fx); }
    fn clean_fx_template(&self) -> Self::Fx { crate::machine::clean_fx_template() }
    fn fpu_st0(&self) -> [u8; 10] { fpu_st0() }
    fn fpu_pop(&mut self) { fpu_pop(); }
    fn load_ldt(&mut self, table: &[u64]) { assert!(table.len() <= 8192); LDT.with(|s| s.set((table.as_ptr(), table.len(), true))); descriptors_ready(); }
    fn on_ldt_changed(&mut self) { LDT.with(|s| { let (p, n, _) = s.get(); s.set((p, n, true)); }); }
    fn set_tls_entry(&mut self, index: i32, base: u32, limit: u32, pages: bool) -> i32 {
        request(op::TLS, [index as u64, base as u64, limit as u64, pages as u64, 0, 0], |_| {}, |m| m.result[0] as i32)
    }
    fn seg_base(selector: u16) -> u32 { descriptors_ready(); request(op::SEGMENT, [selector as u64, 0, 0, 0, 0, 0], |_| {}, |m| m.result[0] as u32) }
    fn seg_is_32(selector: u16) -> bool { descriptors_ready(); request(op::SEGMENT, [selector as u64, 0, 0, 0, 0, 0], |_| {}, |m| m.result[1] != 0) }
    fn int_intercepted(vector: u8) -> bool { request(op::INTERCEPTED, [vector as u64, 0, 0, 0, 0, 0], |_| {}, |m| m.result[0] != 0) }
}
pub fn fx_switch(fx: &mut crate::machine::FxState) {
    let incoming = fx.0;
    request(op::FX_SWITCH, [0; 6], |m| m.data[..512].copy_from_slice(&incoming), |m| fx.0.copy_from_slice(&m.data[..512]));
}
pub fn fpu_st0() -> [u8; 10] { request(op::FPU_ST0, [0; 6], |_| {}, |m| m.data[..10].try_into().unwrap()) }
pub fn fpu_pop() { empty(op::FPU_POP); }

pub(crate) mod paging {
    pub const PAGING_PAGES: usize = 1;
    pub unsafe fn initialize(storage: u64) {
        use arch_abi::Memory;
        let mut machine = crate::Interp::local();
        let mut old = machine.activate(crate::AddressSpace::empty());
        machine.destroy_space(&mut old);
        let mut pages = arch_abi::page_supply::PageInput::new(); pages.push(storage);
        machine.supply_pages(pages);
    }
}
