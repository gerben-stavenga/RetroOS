//! Vcpu — one execution context: register state plus the address space it
//! runs in.
//!
//! This is the unit `arch` hands the kernel: "a set of registers and a place
//! to run them." Bundling the two is what lets the kernel stop caring whether
//! it is driving real silicon or a software interpreter — both can present a
//! `Vcpu`.
//!
//! Single-core for now, so `space` is simply the thread's full per-thread
//! page-table root. When multiple cores share one address space (SMP), `space`
//! becomes a shared handle and the per-core register state stays here; the
//! kernel-facing shape of this type does not change.

use arch_abi::GuestBytes;

/// Register state + address-space handle for one execution context. The shape is
/// shared across backends, so it is `arch_abi::Vcpu<P>` over this backend's
/// page-table type. Derefs to `Regs` so every `regs.rax` / `regs.mode()` keeps
/// working and a `&mut Vcpu` coerces where a `&mut Regs` is expected. Guest
/// memory comes from the blanket `GuestBytes for Vcpu<P>` impl in `arch-abi`,
/// forwarding to the `GuestBytes for RootPageTable` impl below.
pub type Vcpu = arch_abi::Vcpu<crate::backend::Metal>;

/// Bulk guest-memory moves via x86 fast strings.
///
/// These keep the `GuestBytes` contract — no reference into guest memory is
/// ever formed, only raw pointers — while replacing per-byte `read_volatile`
/// loops that ran at ~0.5 bytes/cycle. `rep movsb` is a single instruction the
/// compiler cannot elide, reorder against other memory, or coalesce, so the
/// volatility the contract asks for is preserved; it is byte-granular, so
/// unaligned guest addresses are still fine. Measured ~30 bytes/cycle, ~60x the
/// loop it replaces, and every guest copy in the system goes through it: DOS
/// file reads and writes, the VGA aperture scanout, EMS/XMS block moves.
///
/// ESI is saved inside the block rather than named as an operand; LLVM reserves
/// it on x86-32.
#[inline]
unsafe fn rep_movsb(dst: *mut u8, src: *const u8, len: usize) {
    unsafe {
        core::arch::asm!(
            "push esi",
            "mov esi, {src}",
            "cld",
            "rep movsb",
            "pop esi",
            src = in(reg) src,
            inout("edi") dst => _,
            inout("ecx") len => _,
            options(preserves_flags),
        );
    }
}

/// Backwards `rep movsb` for an upward-overlapping move; pointers address the
/// LAST byte of each region. Clears DF before returning — the rest of the
/// kernel, and the ABI, assume DF=0.
#[inline]
unsafe fn rep_movsb_back(dst_last: *mut u8, src_last: *const u8, len: usize) {
    if len == 0 {
        return;
    }
    unsafe {
        core::arch::asm!(
            "push esi",
            "mov esi, {src}",
            "std",
            "rep movsb",
            "cld",
            "pop esi",
            src = in(reg) src_last,
            inout("edi") dst_last => _,
            inout("ecx") len => _,
            options(preserves_flags),
        );
    }
}

#[inline]
unsafe fn rep_stosb(dst: *mut u8, val: u8, len: usize) {
    unsafe {
        core::arch::asm!(
            "cld",
            "rep stosb",
            inout("edi") dst => _,
            inout("ecx") len => _,
            in("eax") val as u32,
            options(nostack, preserves_flags),
        );
    }
}


/// Guest byte access over this core's active address space. Low addresses use
/// direct volatile transfers; high addresses use the physical mapping window.
/// No reference into guest memory escapes either path.
impl GuestBytes for crate::backend::Metal {
    fn high_copy(&mut self, address: u64, buffer: &mut [u8], to_user: bool, pages: arch_abi::page_supply::PageInput) -> (bool, arch_abi::page_supply::PageInput) {
        crate::memory::with_input(pages, || {
            super::high_paging::invoke(super::high_paging::Request {
                address, length: buffer.len() as u64, to_user, buffer: buffer.as_mut_ptr() as usize, result: 0,
            }) == 0
        })
    }
    fn read<T: Copy>(&self, addr: u64) -> T {
        let mut value = core::mem::MaybeUninit::<T>::uninit();
        transfer(addr, value.as_mut_ptr().cast(), core::mem::size_of::<T>(), false);
        unsafe { value.assume_init() }
    }
    fn write<T: Copy>(&mut self, addr: u64, val: T) {
        transfer(addr, (&val as *const T).cast_mut().cast(), core::mem::size_of::<T>(), true);
    }
    fn copy_from(&self, addr: u64, dst: &mut [u8]) {
        transfer(addr, dst.as_mut_ptr(), dst.len(), false);
    }
    fn copy_to(&mut self, addr: u64, src: &[u8]) {
        transfer(addr, src.as_ptr().cast_mut(), src.len(), true);
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
        if addr.checked_add(len as u64).is_some_and(|end| end <= 0xc0000000) {
            unsafe { rep_stosb(addr as usize as *mut u8, 0, len); }
            return;
        }
        let zeros = [0; 4096];
        while len != 0 {
            let n = len.min(zeros.len());
            self.copy_to(addr, &zeros[..n]);
            addr = addr.checked_add(n as u64).expect("guest address overflow");
            len -= n;
        }
    }
    fn copy_within(&mut self, src: u64, dst: u64, len: usize) {
        if src.checked_add(len as u64).is_some_and(|end| end <= 0xc0000000)
            && dst.checked_add(len as u64).is_some_and(|end| end <= 0xc0000000) {
            if len == 0 { return; }
            unsafe {
                if dst > src && dst < src + len as u64 {
                    rep_movsb_back((dst + len as u64 - 1) as usize as *mut u8, (src + len as u64 - 1) as usize as *const u8, len);
                } else { rep_movsb(dst as usize as *mut u8, src as usize as *const u8, len); }
            }
            return;
        }
        let mut buffer = [0; 4096];
        let mut left = len;
        while left != 0 {
            let n = left.min(buffer.len());
            let offset = (if dst > src { left - n } else { len - left }) as u64;
            self.copy_from(src.checked_add(offset).expect("guest address overflow"), &mut buffer[..n]);
            self.copy_to(dst.checked_add(offset).expect("guest address overflow"), &buffer[..n]);
            left -= n;
        }
    }
}

/// Direct low access and windowed high access share one full-width address API.
fn transfer(mut address: u64, mut buffer: *mut u8, mut len: usize, to_user: bool) {
    let end = address.checked_add(len as u64).expect("guest address overflow");
    if end <= 0xc0000000 {
        unsafe {
            if to_user { rep_movsb(address as usize as *mut u8, buffer, len); }
            else { rep_movsb(buffer, address as usize as *const u8, len); }
        }
        return;
    }
    assert!(address >= crate::high_paging::START && end <= crate::high_paging::END, "invalid guest address");
    while len != 0 {
        let n = len.min(4096 - (address as usize & 4095));
        // Like direct low accesses, demand/COW faults consume the donated reserve.
        let _fault = crate::memory::FaultGuard::enter();
        assert_eq!(crate::high_paging::invoke(crate::high_paging::Request {
            address, length: n as u64, to_user, buffer: buffer as usize, result: 0,
        }), 0, "invalid guest access");
        address += n as u64;
        buffer = unsafe { buffer.add(n) };
        len -= n;
    }
}
