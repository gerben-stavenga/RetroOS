//! Hosted kernel transport to the freestanding arch-metal supervisor.
mod entry;
mod run;
mod setup;
#[cfg(test)] mod tests;
pub use run::execute;
pub(crate) use setup::kick;
use arch_abi::{Memory, X86, GuestBytes, UserPage, MappingError, MappingFailure, page_entry::PageEntry, page_supply::PageInput, vm::{self, Exchange, op}};
use crate::{backend::Interp, space::RootPageTable};

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
fn root_operation(operation: u64, root: &mut RootPageTable, pages: PageInput) -> PageInput {
    let incoming = root.0;
    request(operation, [0; 6], |m| { m.root = incoming; m.put_pages(pages); }, |m| { root.0 = m.root; m.take_pages() })
}
fn batch_result(m: &Exchange) -> Result<(), MappingFailure> {
    m.mapping_status().map_err(|error| MappingFailure { error, completed: m.result[1] as usize })
}
impl Memory for Interp {
    type PageTable = RootPageTable;
    fn activate(&mut self, mut root: RootPageTable) -> RootPageTable { root_operation(op::ACTIVATE, &mut root, PageInput::new()); root }
    fn supply_pages(&self, pages: PageInput) -> (usize, PageInput) {
        request(op::SUPPLY, [0; 6], |m| m.put_pages(pages), |m| (m.result[0] as usize, m.take_pages()))
    }
    fn user_fork(&mut self, root: &mut RootPageTable, pages: PageInput) -> ((), PageInput) { ((), root_operation(op::FORK, root, pages)) }
    fn free_user_pages(&mut self) { empty(op::CLEAN); }
    fn destroy_space(&mut self, root: &mut RootPageTable) { root_operation(op::DESTROY, root, PageInput::new()); }
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

fn transfer(mut address: u64, buffer: *mut u8, length: usize, supplied: Option<PageInput>, write: bool) -> (Option<()>, PageInput) {
    let explicit = supplied.is_some();
    let mut pages = supplied.unwrap_or_default();
    let Some(end) = address.checked_add(length as u64) else { return (None, pages); };
    if !(end <= 0xc0000000 || address >= 1 << 39 && end <= 1 << 47) { return (None, pages); }
    let mut offset = 0;
    while offset < length {
        let n = (length - offset).min(4096 - (address as usize & 4095));
        let (ok, unused) = request(if write { op::COPY_TO } else { op::COPY_FROM }, [address, n as u64, explicit as u64, 0, 0, 0], |m| {
            m.put_pages(pages);
            if write { unsafe { core::ptr::copy_nonoverlapping(buffer.add(offset), m.data.as_mut_ptr(), n); } }
        }, |m| {
            let ok = m.result[0] != 0;
            if ok && !write { unsafe { core::ptr::copy_nonoverlapping(m.data.as_ptr(), buffer.add(offset), n); } }
            (ok, m.take_pages())
        });
        pages = unused;
        if !ok { return (None, pages); }
        address += n as u64;
        offset += n;
    }
    (Some(()), pages)
}
impl GuestBytes for Interp {
    fn read<T: Copy>(&self, address: u64) -> T {
        let mut value = core::mem::MaybeUninit::<T>::uninit();
        transfer(address, value.as_mut_ptr().cast(), core::mem::size_of::<T>(), None, false).0.expect("inaccessible guest read");
        unsafe { value.assume_init() }
    }
    fn write<T: Copy>(&mut self, address: u64, value: T) { transfer(address, (&value as *const T).cast_mut().cast(), core::mem::size_of::<T>(), None, true).0.expect("inaccessible guest write"); }
    fn copy_from(&self, address: u64, bytes: &mut [u8], pages: PageInput) -> (Option<()>, PageInput) { transfer(address, bytes.as_mut_ptr(), bytes.len(), Some(pages), false) }
    fn copy_to(&mut self, address: u64, bytes: &[u8], pages: PageInput) -> (Option<()>, PageInput) { transfer(address, bytes.as_ptr().cast_mut(), bytes.len(), Some(pages), true) }
    fn zero(&mut self, address: u64, length: usize) { request(op::ZERO, [address, length as u64, 0, 0, 0, 0], |_| {}, |_| {}); }
    fn copy_within(&mut self, src: u64, dst: u64, length: usize) { request(op::COPY_WITHIN, [src, length as u64, dst, 0, 0, 0], |_| {}, |_| {}); }
    fn copy_cstr(&self, address: u64, bytes: &mut [u8]) -> usize {
        let mut copied = 0;
        for chunk in bytes.chunks_mut(vm::DATA_SIZE) {
            let next = address.checked_add(copied as u64).expect("guest address overflow");
            let length = chunk.len();
            let n = request(op::COPY_CSTR, [next, length as u64, 0, 0, 0, 0], |_| {}, |m| {
                let n = m.result[0] as usize;
                chunk[..n].copy_from_slice(&m.data[..n]);
                n
            });
            copied += n;
            if n != length { break; }
        }
        copied
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
    unsafe fn bind_planar(&mut self, binding: Option<planar::Binding>) {
        unsafe { setup::bind_planar(binding) }
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

// Compatibility for the internal byte-view helpers: translations are resolved
// by arch, never by a host page-table walker.
pub(crate) mod paging {
    pub const PAGING_PAGES: usize = 1;
    pub unsafe fn initialize(storage: u64) {
        use arch_abi::Memory;
        let mut machine = crate::Interp;
        let mut old = machine.activate(crate::RootPageTable::empty());
        machine.destroy_space(&mut old);
        let mut pages = arch_abi::page_supply::PageInput::new(); pages.push(storage);
        machine.supply_pages(pages);
    }
    pub fn space_resolve(address: u32) -> *mut u8 { resolve(address, false) }
    fn resolve(address: u32, write: bool) -> *mut u8 {
        let page = super::request(super::op::TRANSLATE, [address as u64, 0, write as u64, 0, 0, 0], |_| {}, |m| m.result[0]);
        unsafe { crate::phys::frame_ptr(page).add(address as usize & 4095) }
    }
}
