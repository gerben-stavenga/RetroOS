//! Explicit byte transfers over the active user address space.
use arch_abi::GuestBytes;
pub type Vcpu = arch_abi::Vcpu<crate::backend::Metal>;

/// User bytes are translated explicitly and copied through the resident
/// physical window. No supervisor access dereferences a guest address.
impl GuestBytes for crate::backend::Metal {
    fn read<T: Copy>(&self, addr: u64) -> T {
        let mut value = core::mem::MaybeUninit::<T>::uninit();
        transfer(addr, value.as_mut_ptr().cast(), core::mem::size_of::<T>(), false);
        unsafe { value.assume_init() }
    }
    fn write<T: Copy>(&mut self, addr: u64, val: T) {
        transfer(addr, (&val as *const T).cast_mut().cast(), core::mem::size_of::<T>(), true);
    }
    fn copy_from(&self, addr: u64, dst: &mut [u8], pages: arch_abi::page_supply::PageInput) -> (Option<()>, arch_abi::page_supply::PageInput) {
        crate::memory::with_input(pages, || checked_transfer(addr, dst.as_mut_ptr(), dst.len(), false))
    }
    fn copy_to(&mut self, addr: u64, src: &[u8], pages: arch_abi::page_supply::PageInput) -> (Option<()>, arch_abi::page_supply::PageInput) {
        crate::memory::with_input(pages, || checked_transfer(addr, src.as_ptr().cast_mut(), src.len(), true))
    }
    fn copy_cstr(&self, addr: u64, dst: &mut [u8]) -> usize {
        for (index, byte) in dst.iter_mut().enumerate() {
            let value = self.read::<u8>(addr.checked_add(index as u64).expect("guest address overflow"));
            if value == 0 { return index; }
            *byte = value;
        }
        dst.len()
    }
    fn zero(&mut self, mut addr: u64, mut len: usize) {
        let zeros = [0; 4096];
        while len != 0 {
            let n = len.min(zeros.len());
            transfer(addr, zeros.as_ptr().cast_mut(), n, true);
            addr = addr.checked_add(n as u64).expect("guest address overflow");
            len -= n;
        }
    }
    fn copy_within(&mut self, src: u64, dst: u64, len: usize) {
        let mut buffer = [0; 4096];
        let mut left = len;
        while left != 0 {
            let n = left.min(buffer.len());
            let offset = (if dst > src { left - n } else { len - left }) as u64;
            transfer(src.checked_add(offset).expect("guest address overflow"), buffer.as_mut_ptr(), n, false);
            transfer(dst.checked_add(offset).expect("guest address overflow"), buffer.as_mut_ptr(), n, true);
            left -= n;
        }
    }
}

/// Core-internal monitor accesses use the already donated execution reserve.
fn transfer(mut address: u64, mut buffer: *mut u8, mut len: usize, to_user: bool) {
    while len != 0 {
        let n = len.min(4096 - (address as usize & 4095));
        let _reserve = crate::memory::FaultGuard::enter();
        checked_transfer(address, buffer, n, to_user).expect("inaccessible guest access");
        address = address.checked_add(n as u64).expect("guest address overflow");
        buffer = unsafe { buffer.add(n) };
        len -= n;
    }
}
fn checked_transfer(address: u64, buffer: *mut u8, len: usize, to_user: bool) -> Option<()> {
    (crate::high_paging::invoke(crate::high_paging::Request {
        address, length: len as u64, to_user, buffer: buffer as usize, result: 0,
    }) == 0).then_some(())
}
