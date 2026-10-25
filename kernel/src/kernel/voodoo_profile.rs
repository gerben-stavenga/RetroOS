//! Opt-in BSP-only Voodoo timings; worker health/throughput counters are atomic. MMIO includes all nested stages; read
//! includes its fence. Queue-full waits and read fences do not overlap.
//! The injected monotonic clock keeps this independent of the arch backend.
use core::sync::atomic::{AtomicU32, Ordering};
static SWAPS: AtomicU32 = AtomicU32::new(0);
static DMA_DEFERRED: AtomicU32 = AtomicU32::new(0);
static AUDIO_GAP_US: AtomicU32 = AtomicU32::new(0);
static mut AUDIO_BASE: (u32, u32) = (0, 0);
pub(crate) fn swap() { SWAPS.fetch_add(1, Ordering::Relaxed); }
pub(crate) fn dma_deferred() { DMA_DEFERRED.fetch_add(1, Ordering::Relaxed); }
pub(crate) fn audio_gap(ns: u64) {
    AUDIO_GAP_US.fetch_max((ns / 1000).min(u32::MAX as u64) as u32, Ordering::Relaxed);
}
#[derive(Clone, Copy)]
pub(crate) enum Stage { Mmio, Read, StatusFence, OtherFence, QueueFull }
#[derive(Clone, Copy)]
struct Counter { calls: u64, ns: u64, max: u64 }
const EMPTY: Counter = Counter { calls: 0, ns: 0, max: 0 };
static mut COUNTERS: [Counter; 5] = [EMPTY; 5];
pub(crate) struct Sample(Option<(Stage, u64)>);
impl Sample {
    pub(crate) fn start(stage: Stage) -> Self {
        Self(super::startup::profile_enabled().then(|| (stage, super::portio::now_ns())))
    }
}
impl Drop for Sample {
    fn drop(&mut self) {
        let Some((stage, start)) = self.0 else { return };
        let ns = super::portio::now_ns().wrapping_sub(start);
        // Only the cooperative BSP event loop records or reports these.
        unsafe {
            let counter = &mut (*core::ptr::addr_of_mut!(COUNTERS))[stage as usize];
            counter.calls += 1;
            counter.ns += ns;
            counter.max = counter.max.max(ns);
        }
    }
}
pub(crate) fn reset() {
    SWAPS.store(0, Ordering::Relaxed);
    DMA_DEFERRED.store(0, Ordering::Relaxed);
    AUDIO_GAP_US.store(0, Ordering::Relaxed);
    unsafe { AUDIO_BASE = super::sound::diagnostic_counts(); }
    unsafe { core::ptr::write(core::ptr::addr_of_mut!(COUNTERS), [EMPTY; 5]); }
}
pub(crate) fn print() {
    let (underruns, spikes) = super::sound::diagnostic_counts();
    let (old_underruns, old_spikes) = unsafe { AUDIO_BASE };
    crate::compact_println!("[voodoo-prof] swaps={} dma_deferred={} audio_gap_us={} underruns={} rate_spikes={}",
        SWAPS.load(Ordering::Relaxed), DMA_DEFERRED.load(Ordering::Relaxed), AUDIO_GAP_US.load(Ordering::Relaxed),
        underruns.wrapping_sub(old_underruns), spikes.wrapping_sub(old_spikes));
    let counters = unsafe { core::ptr::read(core::ptr::addr_of!(COUNTERS)) };
    for (name, counter) in ["mmio", "read", "status-fence", "other-fence", "queue-full"].into_iter().zip(counters) {
        crate::compact_println!("[voodoo-prof] {} calls={} ns={} max_ns={}",
            name, counter.calls, counter.ns, counter.max);
    }
}
