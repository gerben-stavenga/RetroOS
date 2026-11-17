//! KVM kernel transition. All paging, descriptors, traps and return processing
//! remain the metal implementation; only the suspended kernel lives elsewhere.
use arch_abi::{GuestBytes, Regs, UserPage, MappingError, MappingFailure};
use arch_abi::vm::{self, Exchange, op};
use crate::{mapping, paging2, traps::{arch_call, arch_dispatch}};

#[unsafe(no_mangle)]
static mut VM_EXCHANGE: Exchange = Exchange::new();
static mut REGIONS: [arch_abi::page_supply::FrameRegion; 256] = [arch_abi::page_supply::FrameRegion { first: 0, end: 0, offset: 0 }; 256];
static mut COUNTS_TABLE: paging2::RawPage = paging2::RawPage([0; 4096]);
static mut LDT: [u64; 8192] = [0; 8192];

/// Called once by the loader's shared assembly startup, before any app runs.
pub unsafe fn boot() -> ! {
    unsafe { crate::smp::init_core(0); }
    paging2::finish_setup_paging();
    unsafe { crate::boot_mem::BootMemory::new().finish(); }
    unsafe extern "C" { fn vm_supervisor_start() -> !; }
    unsafe { vm_supervisor_start() }
}

fn exchange() -> *mut Exchange { &raw mut VM_EXCHANGE }
fn handoff() {
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
        message.result = [0; 3];
        if message.operation == op::EXECUTE {
            *frame = message.regs;
            // There is no physical device passthrough in this VM. All app
            // port instructions are monitored; F4 can never forge a handoff.
            crate::descriptors::install_io_policy(&arch_abi::IoPolicy::deny_all());
            break;
        }
        let pages = message.take_pages();
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
    let mut machine = crate::Metal;
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
            crate::memory::configure(arch_abi::page_supply::FrameOwnership {
                regions: (&raw const REGIONS).cast(), regions_len: region_count,
                counts: vm::COUNTS_VIRTUAL as *mut u8, active: count,
                zero_page: paging2::physical_page((&raw const crate::ZERO_PAGE) as usize),
            });
        }
        op::READ_MAPPINGS | op::REPLACE_MAPPINGS | op::FILL_MAPPINGS | op::READ_RUN | op::ALIAS | op::SWAP => {
            let page = match UserPage::new(a[0]) { Ok(page) => page, Err(error) => { message.mapping_result(Err(error)); return; } };
            match message.operation {
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
            let root = unsafe { &mut *message.root.as_mut_ptr().cast::<paging2::RootPageTable>() };
            match message.operation {
                op::ACTIVATE => call(arch_call::ACTIVATE, root),
                op::FORK => call(arch_call::FORK, root),
                _ => { root.swap_and_activate(); paging2::free_user_pages(); root.swap_and_activate(); },
            }
        }
        op::CLEAN => call(arch_call::CLEAN, &mut ()),
        op::COPY_FROM => machine.copy_from(a[0], &mut message.data[..count]),
        op::COPY_TO => machine.copy_to(a[0], &message.data[..count]),
        op::COPY_CSTR => message.result[0] = machine.copy_cstr(a[0], &mut message.data[..count]) as u64,
        op::ZERO => machine.zero(a[0], count),
        op::COPY_WITHIN => machine.copy_within(a[0], a[2], count),
        op::HIGH_COPY => {
            let request = crate::high_paging::Request { address: a[0], length: a[1], to_user: a[2] != 0,
                buffer: message.data.as_mut_ptr() as usize, result: 0 };
            message.result[0] = (crate::high_paging::request(&request) == 0) as u64;
        }
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
        op::TRANSLATE => {
            let _ = machine.read::<u8>(a[0]);
            if a[2] != 0 { let byte = machine.read::<u8>(a[0]); machine.write(a[0], byte); }
            message.result[0] = paging2::physical_page(a[0] as usize);
        }
        _ => panic!("unknown VM arch call {}", message.operation),
    }
}
