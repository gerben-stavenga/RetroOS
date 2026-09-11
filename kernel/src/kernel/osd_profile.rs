//! Opt-in OSD stage timings. Only the single-threaded kernel loop records
//! samples; reporting is explicit, never inside a measured frame.
//!
//! F12 -> Debug -> Profile enables/reset counters; Print profile reports them.
//! Capture/raster/compose/present are disjoint stage totals. Compose includes
//! OSD painting and scene preparation. Pack/bank/copy are nested subdivisions
//! of banked presentation, not additional time to add to the present total.
//! Osd and scene subdivide compose; osd includes panel repaint/preparation.
//! Pixel counts describe work, not changed pixels; capture counts visible
//! pixels even when planar VRAM capture reads more backing storage.

#[derive(Clone, Copy)]
pub(crate) enum Stage { Capture, Raster, Compose, Present, Pack, Bank, Copy, Osd, Scene }

#[derive(Clone, Copy)]
struct Counter { calls: u64, cycles: u64, max: u64, pixels: u64 }

const EMPTY: Counter = Counter { calls: 0, cycles: 0, max: 0, pixels: 0 };
static mut COUNTERS: [Counter; 9] = [EMPTY; 9];

#[derive(Clone, Copy)]
pub(crate) enum Blit { Packed, Convert, Scale }
// Counts only, keyed by source geometry and path. No timing inside pixel loops.
#[derive(Clone, Copy)]
struct BlitCounter { path: usize, width: usize, height: usize, calls: u64, pixels: u64 }
const EMPTY_BLIT: BlitCounter = BlitCounter { path: 0, width: 0, height: 0, calls: 0, pixels: 0 };
static mut BLITS: [BlitCounter; 16] = [EMPTY_BLIT; 16];

pub(crate) fn blit(path: Blit, width: usize, height: usize, pixels: usize) {
    if !super::startup::profile_enabled() || !super::osd::is_open() { return; }
    unsafe {
        for counter in &mut *core::ptr::addr_of_mut!(BLITS) {
            if counter.calls == 0 || (counter.path == path as usize
                && counter.width == width && counter.height == height)
            {
                counter.path = path as usize;
                counter.width = width;
                counter.height = height;
                counter.calls += 1;
                counter.pixels += pixels as u64;
                return;
            }
        }
    }
}

pub(crate) struct Sample(Option<u64>);

impl Sample {
    pub(crate) fn start<A: crate::Arch>(machine: &A) -> Self {
        Self((super::startup::profile_enabled() && super::osd::is_open())
            .then(|| machine.rdtsc()))
    }

    pub(crate) fn finish<A: crate::Arch>(self, machine: &A, stage: Stage, pixels: usize) {
        let Some(start) = self.0 else { return };
        let cycles = machine.rdtsc().wrapping_sub(start);
        // Kernel execution is cooperative: no ISR touches this storage.
        unsafe {
            let counter = &mut (*core::ptr::addr_of_mut!(COUNTERS))[stage as usize];
            counter.calls += 1;
            counter.cycles += cycles;
            counter.max = counter.max.max(cycles);
            counter.pixels += pixels as u64;
        }
    }
}

pub(crate) fn reset() {
    unsafe { core::ptr::write(core::ptr::addr_of_mut!(COUNTERS), [EMPTY; 9]); }
    unsafe { core::ptr::write(core::ptr::addr_of_mut!(BLITS), [EMPTY_BLIT; 16]); }
}

pub(crate) fn print() {
    let counters = unsafe { core::ptr::read(core::ptr::addr_of!(COUNTERS)) };
    for (name, counter) in ["capture", "raster", "compose", "present", "pack", "bank", "copy", "osd", "scene"]
        .into_iter().zip(counters)
    {
        crate::compact_println!(
            "[osd-prof] {} calls={} cycles={} max={} pixels={}",
            name, counter.calls, counter.cycles, counter.max, counter.pixels,
        );
    }
    let blits = unsafe { core::ptr::read(core::ptr::addr_of!(BLITS)) };
    for counter in blits.into_iter().filter(|counter| counter.calls != 0) {
        crate::compact_println!("[osd-blit] {} source={}x{} calls={} pixels={}",
            ["packed", "convert", "scale"][counter.path],
            counter.width, counter.height, counter.calls, counter.pixels);
    }
}
