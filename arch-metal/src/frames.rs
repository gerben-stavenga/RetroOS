//! Physical-frame operations only; file identities and reclamation policy
//! belong to the kernel. Requests cross ring 1/0 with an explicit record.
use crate::paging2;
#[repr(C)]
pub(crate) struct Request { operation: u32, frame: u64, address: usize, flags: u32, table: u64, result: u64 }
fn invoke(operation: u32, frame: u64, address: usize, flags: u32) -> u64 {
    let mut request = Request { operation, frame, address, flags, table: 0, result: 0 };
    dispatch(&mut request);
    request.result
}
fn dispatch(request: &mut Request) {
    let cs: u16;
    unsafe { core::arch::asm!("mov {0:x}, cs", out(reg) cs); }
    if cs & 3 == 0 { handle(request); }
    else { unsafe { core::arch::asm!("int 0x80", in("eax") crate::arch_call::FRAME_OPERATION as u32,
        in("edx") request as *mut Request as usize); } }
}

/// Install caller-owned resident heap storage. Returns whether the supplied
/// table frame was consumed. The data frame always remains kernel-owned.
pub fn map_heap_page(address: usize, frame: u64, table: u64) -> bool {
    let mut request = Request { operation: 5, frame, address, flags: 0, table, result: 0 };
    dispatch(&mut request);
    request.result != 0
}

pub fn read(page: u64, offset: usize, bytes: &mut [u8]) {
    assert!(crate::aperture::copy_from_physical(page * 4096 + offset as u64, bytes));
}
pub fn write(page: u64, offset: usize, bytes: &[u8]) {
    assert!(crate::aperture::copy_to_physical(page * 4096 + offset as u64, bytes));
}
pub fn physical(address: usize) -> u64 { invoke(4, 0, address, 0) }
pub(crate) fn handle(request: &mut Request) {
    request.result = match request.operation {
        4 => {
            assert!(request.address & 4095 == 0 && (paging2::heap_base()..paging2::HEAP_END).contains(&request.address));
            paging2::physical_page(request.address)
        }
        5 => paging2::map_heap_page(request.address, request.frame, request.table) as u64,
        _ => 0,
    };
}
