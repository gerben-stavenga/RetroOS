//! Hypothesis: the interp executes a STALE translated block when guest code is
//! overwritten *host-side* (an INT 21h overlay/file read loads new code into a
//! guest page via vcpu.rs's direct host-pointer write, bypassing Unicorn's
//! self-modifying-code detection). The interp's `flush_tlb` only does
//! `ctl_flush_tlb` (softmmu TLB) — it does NOT remove cached TBs. So Unicorn
//! keeps running the OLD overlay's JIT'd code at the new bytes' addresses, which
//! is the `+2/+1` mid-instruction hook pattern seen at DN's `les di,[bp+6]`.
//!
//! This test reproduces the mechanism in isolation: map a page by host pointer,
//! cache a TB for layout A (all 1-byte NOPs), then overwrite the page host-side
//! with layout B (`les di,[bp+6]` = 3-byte), and re-run. If Unicorn runs the
//! stale TB, the code hook fires at A's 1-byte boundaries even though the bytes
//! are now B.

use std::alloc::{alloc_zeroed, Layout};
use std::ffi::c_void;
use std::sync::Mutex;
use unicorn_engine::unicorn_const::{Arch, Mode, Prot};
use unicorn_engine::{RegisterX86 as R, Unicorn};

static ADDRS: Mutex<Vec<u64>> = Mutex::new(Vec::new());

#[test]
fn host_side_code_overwrite_runs_stale_tb() {
    // Page-aligned host buffer mapped into Unicorn by pointer (as the interp's
    // software MMU does via uc_mem_map_ptr).
    let size = 0x1000usize;
    let layout = Layout::from_size_align(size, 0x1000).unwrap();
    let host = unsafe { alloc_zeroed(layout) };
    assert!(!host.is_null());
    let page: &mut [u8] = unsafe { std::slice::from_raw_parts_mut(host, size) };

    let mut uc = Unicorn::new(Arch::X86, Mode::MODE_32).expect("uc");
    unsafe {
        uc.mem_map_ptr(0, size as u64, Prot::ALL, host as *mut c_void).expect("map_ptr");
    }
    // VM86, matching DN.
    let cr0 = uc.reg_read(R::CR0).unwrap();
    uc.reg_write(R::CR0, cr0 | 1).unwrap();
    uc.reg_write(R::EFLAGS, 0x2_0002).unwrap();
    uc.reg_write(R::CS, 0).unwrap();
    uc.reg_write(R::SS, 0x3F4A).unwrap();
    uc.reg_write(R::EBP, 0x40B8).unwrap();

    uc.add_code_hook(0, size as u64, |_uc, addr, _sz| {
        ADDRS.lock().unwrap().push(addr);
    })
    .expect("hook");

    // ---- Layout A: 5 single-byte NOPs then HLT. Cache its TB. ----
    page[0..6].copy_from_slice(&[0x90, 0x90, 0x90, 0x90, 0x90, 0xF4]);
    ADDRS.lock().unwrap().clear();
    let _ = uc.emu_start(0, 6, 0, 0);
    let a = ADDRS.lock().unwrap().clone();
    eprintln!("[A nops] hook addrs: {a:#04x?}  (1-byte boundaries: 0,1,2,3,4)");
    assert_eq!(a, vec![0, 1, 2, 3, 4, 5], "layout A should step 1 byte at a time (incl HLT@5)");

    // ---- Layout B: overwrite host-side (bypasses SMC) with a 3-byte
    //      `mov ax,0x1234` (B8 34 12) then HLT padding. NO uc.mem_write, NO
    //      invalidation — exactly what vcpu.rs's host-pointer write does on an
    //      overlay load. (3-byte op, no memory operand, so the only observable
    //      is the instruction boundary, like the les.) ----
    page[0..6].copy_from_slice(&[0xB8, 0x34, 0x12, 0xF4, 0xF4, 0xF4]);
    ADDRS.lock().unwrap().clear();
    let _ = uc.emu_start(0, 6, 0, 0);
    let b = ADDRS.lock().unwrap().clone();
    eprintln!(
        "[B les, host-overwritten] hook addrs: {b:#04x?}  (correct=[0,3]; STALE=[0,1,2,3,4,5] like A)"
    );

    // If invalidation were correct, Unicorn re-translates -> les(3) then HLT@3:
    // addrs == [0, 3]. If the TB is stale, it runs A's 1-byte layout -> [0,1,2,3,4].
    let stale = b == vec![0, 1, 2, 3, 4, 5];
    eprintln!("STALE TB REPRODUCED: {stale}");
    assert_eq!(b, vec![0, 3], "stale TB: Unicorn ran the OLD layout after a host-side code overwrite");
}
