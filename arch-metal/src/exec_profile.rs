//! Deterministic cycle accounting for the ring-1 ↔ ring-0 ↔ guest path.

use core::sync::atomic::{AtomicBool, Ordering};
use arch_abi::{ExecutionProfile, ExecutionProfileStage};

static ENABLED: AtomicBool = AtomicBool::new(false);
static mut PROFILE: ExecutionProfile = ExecutionProfile {
    calls: 0,
    ring1: 0,
    policy_lookup: 0,
    policy_install: 0,
    bridge_in: 0,
    ring0_enter_frame_in: 0,
    ring0_enter_dispatch: 0,
    ring0_enter_frame_out: 0,
    guest: 0,
    ring0_exit_frame_in: 0,
    ring0_exit_dispatch: 0,
    ring0_exit_frame_out: 0,
    bridge_out: 0,
    decode: 0,
};
static mut LAST: u64 = 0;

#[inline]
pub(super) fn enabled() -> bool { ENABLED.load(Ordering::Relaxed) }

pub(super) fn set(enabled: bool) {
    let was_enabled = ENABLED.load(Ordering::Relaxed);
    if enabled && !was_enabled {
        ENABLED.store(true, Ordering::Relaxed);
        unsafe {
            core::ptr::write_volatile(&raw mut PROFILE, ExecutionProfile::default());
            core::ptr::write_volatile(&raw mut LAST, crate::x86::rdtsc());
        }
    } else if !enabled && was_enabled {
        time(ExecutionProfileStage::Ring1);
        ENABLED.store(false, Ordering::Relaxed);
    }
}

#[inline]
pub(super) fn begin() {
    if !enabled() { return; }
    unsafe {
        let calls = &raw mut PROFILE.calls;
        calls.write_volatile(calls.read_volatile().wrapping_add(1));
    }
    time(ExecutionProfileStage::Ring1);
}

/// Charge the interval since the preceding boundary to `stage` and make this
/// one timestamp the next boundary. Every interval therefore has one owner.
#[inline]
pub(super) fn time(stage: ExecutionProfileStage) {
    if !enabled() { return; }
    let now = crate::x86::rdtsc();
    unsafe {
        let old = core::ptr::read_volatile(&raw const LAST);
        core::ptr::write_volatile(&raw mut LAST, now);
        let target = match stage {
            ExecutionProfileStage::Ring1 => &raw mut PROFILE.ring1,
            ExecutionProfileStage::PolicyLookup => &raw mut PROFILE.policy_lookup,
            ExecutionProfileStage::PolicyInstall => &raw mut PROFILE.policy_install,
            ExecutionProfileStage::BridgeIn => &raw mut PROFILE.bridge_in,
            ExecutionProfileStage::Ring0EnterFrameIn => &raw mut PROFILE.ring0_enter_frame_in,
            ExecutionProfileStage::Ring0EnterDispatch => &raw mut PROFILE.ring0_enter_dispatch,
            ExecutionProfileStage::Ring0EnterFrameOut => &raw mut PROFILE.ring0_enter_frame_out,
            ExecutionProfileStage::Guest => &raw mut PROFILE.guest,
            ExecutionProfileStage::Ring0ExitFrameIn => &raw mut PROFILE.ring0_exit_frame_in,
            ExecutionProfileStage::Ring0ExitDispatch => &raw mut PROFILE.ring0_exit_dispatch,
            ExecutionProfileStage::Ring0ExitFrameOut => &raw mut PROFILE.ring0_exit_frame_out,
            ExecutionProfileStage::Decode => &raw mut PROFILE.decode,
            ExecutionProfileStage::BridgeOut => &raw mut PROFILE.bridge_out,
        };
        target.write_volatile(target.read_volatile().wrapping_add(now.wrapping_sub(old)));
    }
}

pub(super) fn snapshot() -> ExecutionProfile {
    unsafe { core::ptr::read_volatile(&raw const PROFILE) }
}
