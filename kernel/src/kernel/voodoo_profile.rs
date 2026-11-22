//! Opt-in BSP-only Voodoo timings; worker health/throughput counters are atomic. MMIO includes all nested stages; read
//! includes its fence. Queue-full waits and read fences do not overlap.
//! The injected monotonic clock keeps this independent of the arch backend.

#![forbid(unsafe_code)]
use core::sync::atomic::{AtomicU32, Ordering};
static SWAPS: AtomicU32 = AtomicU32::new(0);
static AUDIO_GAP_US: AtomicU32 = AtomicU32::new(0);
static AUDIO_BASE: spin::Mutex<(u32, u32)> = spin::Mutex::new((0, 0));
pub(crate) fn swap() { SWAPS.fetch_add(1, Ordering::Relaxed); }
pub(crate) fn audio_gap(ns: u64) {
    AUDIO_GAP_US.fetch_max((ns / 1000).min(u32::MAX as u64) as u32, Ordering::Relaxed);
}
#[derive(Clone, Copy)]
pub(crate) enum Stage { Mmio, Read, StatusFence, OtherFence, QueueFull }
#[derive(Clone, Copy)]
struct Counter { calls: u64, ns: u64, max: u64 }
const EMPTY: Counter = Counter { calls: 0, ns: 0, max: 0 };
static COUNTERS: spin::Mutex<[Counter; 5]> = spin::Mutex::new([EMPTY; 5]);
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
        let mut counters = COUNTERS.lock();
        let counter = &mut counters[stage as usize];
        counter.calls += 1;
        counter.ns += ns;
        counter.max = counter.max.max(ns);
    }
}
pub(crate) fn reset() {
    SWAPS.store(0, Ordering::Relaxed);
    AUDIO_GAP_US.store(0, Ordering::Relaxed);
    *AUDIO_BASE.lock() = super::sound::diagnostic_counts();
    *COUNTERS.lock() = [EMPTY; 5];
}
pub(crate) fn print() {
    let (underruns, spikes) = super::sound::diagnostic_counts();
    let (old_underruns, old_spikes) = *AUDIO_BASE.lock();
    crate::compact_println!("[voodoo-prof] swaps={} audio_gap_us={} underruns={} rate_spikes={}",
        SWAPS.load(Ordering::Relaxed), AUDIO_GAP_US.load(Ordering::Relaxed),
        underruns.wrapping_sub(old_underruns), spikes.wrapping_sub(old_spikes));
    let counters = *COUNTERS.lock();
    for (name, counter) in ["mmio", "read", "status-fence", "other-fence", "queue-full"].into_iter().zip(counters) {
        crate::compact_println!("[voodoo-prof] {} calls={} ns={} max_ns={}",
            name, counter.calls, counter.ns, counter.max);
    }
}
