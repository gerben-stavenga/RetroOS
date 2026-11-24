//! KVM kernel transition. The supervisor owns recursive paging, descriptors,
//! traps and guest return. Host byte access uses its live physical tables.
use arch_abi::{Regs, UserPage, MappingError, MappingFailure};
use arch_abi::vm::{self, Exchange, op};
use crate::{mapping, paging2, traps::{arch_call, arch_dispatch}};

#[unsafe(no_mangle)]
static mut VM_EXCHANGE: Exchange = Exchange::new();
static mut REGIONS: [arch_abi::page_supply::FrameRegion; 256] = [arch_abi::page_supply::FrameRegion { first: 0, end: 0, offset: 0 }; 256];
static mut HOOK_TABLE: paging2::RawPage = paging2::RawPage([0; 4096]);
static mut COUNTS_TABLE: paging2::RawPage = paging2::RawPage([0; 4096]);
static mut HOOKS: &[(&str, arch_abi::entry::TrapHandler)] = &[];
static mut LDT: [u64; 8192] = [0; 8192];

/// Called once by the loader's shared assembly startup, before any app runs.
pub unsafe fn boot(hooks: &'static [(&'static str, arch_abi::entry::TrapHandler)]) -> ! {
    unsafe { HOOKS = hooks; }
    unsafe { crate::smp::init_core(0); }
    paging2::finish_setup_paging();
    // The resident supervisor has its own terminal state and no VGA aperture.
    lib::term::term().set_aperture(None);
    lib::log::set_debug_sink(|byte| crate::x86::outb(0xe9, byte));
    lib::log::set_fatal_handler(|| {
        crate::x86::outl(vm::PANIC_PORT, 1);
        loop { crate::x86::hlt(); }
    });
    unsafe { crate::boot_mem::BootMemory::new().finish(); }
    unsafe {
        (*exchange()).memory = paging2::user_memory();
        (*exchange()).reserve_address = (crate::memory::reserve_address() - vm::IMAGE_VIRTUAL + vm::IMAGE_PHYSICAL) as u64;
    }
    unsafe extern "C" { fn vm_supervisor_start() -> !; }
    unsafe { vm_supervisor_start() }
}

fn exchange() -> *mut Exchange { &raw mut VM_EXCHANGE }
fn handoff() {
    let status = crate::memory::supply_status();
    unsafe {
        (*exchange()).supply_returned = status.returned as u64;
    }
    // A user OUT on this port stays denied in the TSS. Only this CPL0
    // instruction denotes a completed arch call or a returned kernel event.
    // Unlike ordinary port I/O, the host reads and replaces the mailbox while
    // this instruction is suspended. The asm must therefore clobber memory.
    unsafe { core::arch::asm!("out dx, eax", in("dx") vm::EXIT_PORT,
        in("eax") exchange() as u32, options(nostack, preserves_flags)); }
}
pub(crate) fn return_to_kernel(frame: &mut Regs, event: arch_abi::KernelEvent) {
    let message = unsafe { &mut *exchange() };
    message.regs = *frame;
    let (kind, extra) = event.encode();
    message.result = [kind as u64, extra, 0];
    requests(frame);
}

/// One loop, on the existing trap stack. Execute breaks it, allowing the
/// ordinary entry call chain to unwind into the shared IRET epilogue.
pub(crate) fn requests(frame: &mut Regs) {
    loop {
        handoff();
        let message = unsafe { &mut *exchange() };
        if message.tables_changed != 0 {
            paging2::flush_tlb();
            message.tables_changed = 0;
        }
        message.result = [0; 3];
        if message.operation == op::EXECUTE {
            *frame = message.regs;
            // There is no physical device passthrough in this VM. All app
            // port instructions are monitored; F4 can never forge a handoff.
            crate::descriptors::install_io_policy(&arch_abi::IoPolicy::deny_all());
            break;
        }
        // The stopped host transferred the frames in this request.
        let pages = unsafe { message.take_pages() };
        if message.operation == op::SUPPLY {
            let (needed, unused) = crate::memory::supply_pages(pages);
            message.result[0] = needed as u64;
            message.put_pages(unused);
        } else {
            let (_, unused) = crate::memory::with_input(pages, || operation(message));
            message.put_pages(unused);
        }
    }
}
fn call<T>(number: u64, value: &mut T) {
    let mut call = arch_abi::entry::KernelCall { rax: number, rdx: value as *mut T as u64,
        rbx: 0, rcx: 0, rsi: 0, rdi: 0 };
    assert!(matches!(arch_dispatch(&mut call), arch_abi::entry::CallOutcome::Complete));
}
fn batch(message: &mut Exchange, result: Result<(), MappingFailure>) {
    message.result[1] = result.as_ref().err().map_or(message.args[1], |failure| failure.completed as u64);
    message.mapping_result(result.map_err(|failure| failure.error));
}
fn operation(message: &mut Exchange) {
    let a = message.args;
    let count = usize::try_from(a[1]).unwrap();
    match message.operation {
        op::CONFIGURE => {
            let region_count = a[0] as usize;
            assert!(region_count <= 256 && count <= 2 * 1024 * 1024);
            for (index, bytes) in message.data[..region_count * 24].chunks_exact(24).enumerate() {
                unsafe { REGIONS[index] = arch_abi::page_supply::FrameRegion {
                    first: u64::from_le_bytes(bytes[..8].try_into().unwrap()),
                    end: u64::from_le_bytes(bytes[8..16].try_into().unwrap()),
                    offset: u64::from_le_bytes(bytes[16..24].try_into().unwrap()) as usize,
                }; }
            }
            let table = paging2::physical_page((&raw const COUNTS_TABLE) as usize);
            paging2::prepare_kernel_mapping(vm::COUNTS_VIRTUAL / 4096, count.div_ceil(4096), table);
            assert!(paging2::map_kernel_foreign_range(vm::COUNTS_VIRTUAL / 4096, vm::COUNTS_PHYSICAL / 4096, count.div_ceil(4096)));
            let table = paging2::physical_page((&raw const HOOK_TABLE) as usize);
            paging2::prepare_kernel_mapping(vm::HOOK_VIRTUAL / 4096, vm::HOOK_PAGES, table);
            assert!(paging2::map_kernel_foreign_range(vm::HOOK_VIRTUAL / 4096, vm::HOOK_PHYSICAL / 4096, vm::HOOK_PAGES));
            crate::memory::configure(arch_abi::page_supply::FrameOwnership {
                regions: (&raw const REGIONS).cast(), regions_len: region_count,
                counts: vm::COUNTS_VIRTUAL as *mut u8, active: count,
                zero_page: paging2::physical_page((&raw const crate::ZERO_PAGE) as usize),
            });
        }
        op::INSTALL_TRAP_HOOK => {
            use arch_abi::entry::{HookRegion, TrapHook};
            let len = a[0] as usize;
            let hook = (len != 0).then(|| {
                let &(name, handler) = unsafe { HOOKS }.iter()
                    .find(|(name, _)| name.as_bytes() == &message.data[..len])
                    .expect("trap handler missing from execution image");
                let first = a[1] as usize;
                let second = a[2] as usize;
                assert!(first % 4096 == 0 && second % 4096 == 0 && first + second <= vm::HOOK_PAGES * 4096);
                TrapHook {
                    name, handler,
                    regions: [
                        HookRegion { base: vm::HOOK_VIRTUAL as *mut u8, bytes: first },
                        HookRegion { base: (vm::HOOK_VIRTUAL + first) as *mut u8, bytes: second },
                    ],
                }
            });
            unsafe { crate::entry::install_hook(hook); }
        }
        op::READ_MAPPINGS | op::REPLACE_MAPPINGS | op::FILL_MAPPINGS | op::READ_RUN | op::ALIAS | op::SWAP | op::EDIT_MAPPINGS => {
            let page = match UserPage::new(a[0]) { Ok(page) => page, Err(error) => { message.mapping_result(Err(error)); return; } };
            match message.operation {
                op::EDIT_MAPPINGS => {
                    let mut request = mapping::Edit { page, count, operation: message.edit(), result: Ok(()) };
                    call(arch_call::EDIT_MAPPINGS, &mut request);
                    batch(message, request.result);
                }
                op::READ_MAPPINGS => {
                    let mut request = mapping::Read { page, entries: &mut message.entries[..count], result: Ok(()) };
                    call(arch_call::READ_MAPPINGS, &mut request);
                    let result = request.result;
                    batch(message, result);
                }
                op::REPLACE_MAPPINGS => {
                    let mut request = mapping::Replace { page, entries: &message.entries[..count], result: Ok(()) };
                    call(arch_call::REPLACE_MAPPINGS, &mut request);
                    batch(message, request.result);
                }
                op::FILL_MAPPINGS => {
                    let mut request = mapping::Fill { page, count, entry: message.entries[0], result: Ok(()) };
                    call(arch_call::FILL_MAPPINGS, &mut request);
                    batch(message, request.result);
                }
                op::READ_RUN => {
                    let mut request = mapping::ReadRun { page, maximum: count, result: Err(MappingError::InvalidAddress) };
                    call(arch_call::READ_MAPPING_RUN, &mut request);
                    match request.result {
                        Ok((entry, n)) => { message.entries[0] = entry; message.result[1] = n as u64; }
                        Err(error) => message.mapping_result(Err(error)),
                    }
                }
                _ => {
                    let b = match UserPage::new(a[2]) { Ok(page) => page, Err(error) => { message.mapping_result(Err(error)); return; } };
                    let mut request = mapping::Rearrange { a: page, b, count, swap: message.operation == op::SWAP, result: Ok(()) };
                    call(arch_call::REARRANGE_MAPPINGS, &mut request);
                    message.mapping_result(request.result);
                }
            }
        }
        op::ACTIVATE | op::FORK | op::DESTROY => {
            let root = unsafe { &mut *message.root.as_mut_ptr().cast::<paging2::AddressSpace>() };
            match message.operation {
                op::ACTIVATE => call(arch_call::ACTIVATE, root),
                op::FORK => call(arch_call::FORK, root),
                _ => { root.swap_and_activate(); paging2::free_user_pages(); root.swap_and_activate(); },
            }
        }
        op::CLEAN => call(arch_call::CLEAN, &mut ()),
        op::LOAD_LDT => {
            assert!(count <= 8192);
            unsafe { core::ptr::copy_nonoverlapping(message.data.as_ptr(), (&raw mut LDT).cast::<u8>(), count * 8); }
            crate::descriptors::load_ldt((&raw const LDT) as u32, (count * 8).saturating_sub(1) as u32);
        }
        op::DEBUG_WATCH => {
            let mut call = arch_abi::entry::KernelCall { rax: arch_call::SET_DEBUG_WATCH,
                rbx: a[0], rdx: a[1], rcx: a[2], rsi: 0, rdi: 0 };
            let _ = arch_dispatch(&mut call);
        }
        op::TLS => {
            let mut call = arch_abi::entry::KernelCall { rax: arch_call::SET_TLS_ENTRY,
                rdx: a[0], rcx: a[1], rbx: a[2], rdi: a[3], rsi: 0 };
            let _ = arch_dispatch(&mut call);
            message.result[0] = call.rax;
        }
        op::SEGMENT => { message.result[0] = crate::descriptors::seg_base(a[0] as u16) as u64; message.result[1] = crate::descriptors::seg_is_32(a[0] as u16) as u64; }
        op::INTERCEPTED => message.result[0] = crate::descriptors::int_intercepted(a[0] as u8) as u64,
        op::FX_SWITCH => {
            let mut fx = crate::FxState::zeroed();
            fx.0.copy_from_slice(&message.data[..512]);
            call(arch_call::SWITCH_FX, &mut fx);
            message.data[..512].copy_from_slice(&fx.0);
        }
        op::FPU_ST0 => message.data[..10].copy_from_slice(&crate::x86::fpu_st0()),
        op::FPU_POP => crate::x86::fpu_pop(),
        _ => panic!("unknown VM arch call {}", message.operation),
    }
}
