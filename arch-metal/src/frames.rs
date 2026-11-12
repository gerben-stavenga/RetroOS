//! Physical-frame operations only; file identities and reclamation policy
//! belong to the kernel. Requests cross ring 1/0 with an explicit record.
use crate::paging2;
#[repr(C)]
pub(crate) struct Request { operation: u32, frame: u64, address: usize, flags: u32, result: u64 }
fn invoke(operation: u32, frame: u64, address: usize, flags: u32) -> u64 {
    let mut request = Request { operation, frame, address, flags, result: 0 };
    let cs: u16;
    unsafe { core::arch::asm!("mov {0:x}, cs", out(reg) cs); }
    if cs & 3 == 0 { handle(&mut request); }
    else { unsafe { core::arch::asm!("int 0x80", in("eax") crate::arch_call::FRAME_OPERATION as u32,
        in("edx") &mut request as *mut Request as usize); } }
    request.result
}
fn read(page: u64, offset: usize, bytes: &mut [u8]) {
    assert!(crate::aperture::copy_from_physical(page * 4096 + offset as u64, bytes));
}
fn write(page: u64, offset: usize, bytes: &[u8]) {
    assert!(crate::aperture::copy_to_physical(page * 4096 + offset as u64, bytes));
}
pub fn io() -> arch_abi::PhysicalFrameIo { arch_abi::PhysicalFrameIo { read, write } }
pub fn map(vpage: usize, page: u64, shared: bool, writable: bool, executable: bool) -> bool {
    invoke(3, page, vpage, u32::from(shared) | (u32::from(writable) << 1) | (u32::from(executable) << 2)) != 0
}
pub(crate) fn handle(request: &mut Request) {
    request.result = match request.operation {
        3 => u64::from(paging2::map_frame(request.address, request.frame,
            request.flags & 1 != 0, request.flags & 2 != 0, request.flags & 4 != 0)),
        _ => 0,
    };
}
