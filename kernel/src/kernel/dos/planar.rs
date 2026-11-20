//! Planar handler lifetime follows the active DOS device, not execute calls.
#![allow(static_mut_refs)]
#[thread_local]
static mut INSTALLED: Option<::vga::registers::RegisterFile> = None;

pub fn install<A: crate::Arch>(machine: &mut A, video: &crate::kernel::bios_display::DosVideo) {
    let state = video.emulated().map(|vga| &vga.planar);
    // Display handoffs may keep the same device. They do not reinstall it.
    if unsafe { INSTALLED.as_ref() }.zip(state).is_some_and(|(old, new)| old.same_device(new)) { return; }
    uninstall(machine);
    if let Some(state) = state
        && let Some(planes) = super::machine::vga::live_vram_ptr_if_initialized()
    {
        state.profile_enabled.set(crate::kernel::startup::profile_enabled() as u8);
        let owner = state.share();
        // The retained owner and permanent VRAM remain resident until uninstall.
        unsafe {
            machine.bind_planar(Some(::planar::Binding { registers: &*owner, planes: planes.as_ptr() }));
            INSTALLED = Some(owner);
        }
    }
}
pub fn uninstall<A: crate::Arch>(machine: &mut A) {
    if unsafe { INSTALLED.is_some() } {
        unsafe { machine.bind_planar(None); INSTALLED = None; }
    }
}
/// Read already-published counters; no arch call and no handler changes.
pub fn collect() -> u64 {
    let Some(state) = (unsafe { INSTALLED.as_ref() }) else { return 0 };
    let report = state.profile.take();
    state.profile_enabled.set(crate::kernel::startup::profile_enabled() as u8);
    if crate::kernel::startup::profile_enabled() {
        crate::kernel::event_profile::record_device_entries(report.details);
    }
    report.cycles
}
