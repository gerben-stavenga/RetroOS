//! Shared software random generator and interrupt-timing entropy pool.
//!
//! HMAC-DRBG/SHA-256 (SP 800-90A section 10.1.2). Drivers supply entropy;
//! personalities and protocols only call `fill`. No clock-only seed or guest
//! scheduler PRNG fallback. Timing entropy accounting is a heuristic, not a
//! validated entropy source: injected/predictable input cannot provide secrecy.
use hmac::{Hmac, KeyInit, Mac};
use sha2::{Digest, Sha256};
use spin::Mutex;

#[derive(Debug, PartialEq, Eq)]
pub struct Unavailable;

/// A source must fill the whole buffer with independent entropy or return an
/// error. Called outside the pool lock; it must not recurse into `fill`.
pub type EntropySource = fn(&mut [u8]) -> Result<(), Unavailable>;
static SOURCE: Mutex<EntropySource> = Mutex::new(super::drivers::rdrand::fill);
static POOL: Mutex<Pool> = Mutex::new(Pool::new());
const RESEED_BYTES: usize = 1024 * 1024;

/// Install a platform/device entropy source. The software generator is shared
/// regardless of the source. Existing state is retained until reseeded.
pub fn install_source(source: EntropySource) {
    *SOURCE.lock() = source;
}

/// Seed/reseed from trusted entropy: at least 256 unpredictable bits plus
/// 128 bits of nonce/entropy. Callers must not pass a timestamp or fixed seed.
pub fn seed(entropy: &[u8; 48]) {
    POOL.lock().seed(entropy);
}

/// Whether secure consumers can currently generate output without a new seed.
pub fn ready() -> bool {
    let pool = POOL.lock();
    pool.generator.is_some() && pool.generated < RESEED_BYTES
}

/// Fill with software-generated random bytes. Before seeding, or when a
/// reseed is overdue, leave the destination untouched and return Unavailable.
pub fn fill(bytes: &mut [u8]) -> Result<(), Unavailable> {
    if bytes.is_empty() {
        return Ok(());
    }
    // Bound one request so it cannot use up the reseed budget part-way through.
    if bytes.len() > 65536 {
        return Err(Unavailable);
    }
    if !ready() {
        let source = *SOURCE.lock();
        let mut entropy = [0; 48];
        let result = source(&mut entropy);
        if result.is_ok() {
            seed(&entropy);
        }
        entropy.fill(0);
    }
    POOL.lock().fill(bytes)
}

struct Generator {
    key: [u8; 32],
    value: [u8; 32],
}
impl Generator {
    fn new(seed: &[u8]) -> Self {
        let mut this = Self {
            key: [0; 32],
            value: [1; 32],
        };
        this.update(seed);
        this
    }
    fn mac(key: &[u8; 32], parts: &[&[u8]]) -> [u8; 32] {
        let mut mac = Hmac::<Sha256>::new_from_slice(key).unwrap();
        for part in parts {
            mac.update(part);
        }
        mac.finalize().into_bytes().into()
    }
    fn update(&mut self, data: &[u8]) {
        self.key = Self::mac(&self.key, &[&self.value, &[0], data]);
        self.value = Self::mac(&self.key, &[&self.value]);
        if !data.is_empty() {
            self.key = Self::mac(&self.key, &[&self.value, &[1], data]);
            self.value = Self::mac(&self.key, &[&self.value]);
        }
    }
    fn fill(&mut self, bytes: &mut [u8]) {
        for chunk in bytes.chunks_mut(32) {
            self.value = Self::mac(&self.key, &[&self.value]);
            chunk.copy_from_slice(&self.value[..chunk.len()]);
        }
        self.update(&[]);
    }
}

#[derive(Clone, Copy)]
struct Timing {
    last: u64,
    delta: i128,
    delta2: i128,
    samples: u8,
}
impl Timing {
    const fn new() -> Self {
        Self {
            last: 0,
            delta: 0,
            delta2: 0,
            samples: 0,
        }
    }
    fn sample(&mut self, now: u64) -> bool {
        if now <= self.last {
            return false;
        }
        let delta = i128::from(now - self.last);
        let delta2 = delta - self.delta;
        let delta3 = delta2 - self.delta2;
        let credit = self.samples >= 3 && delta2 != 0 && delta3 != 0;
        self.last = now;
        self.delta = delta;
        self.delta2 = delta2;
        self.samples = self.samples.saturating_add(1);
        credit
    }
}
struct Pool {
    generator: Option<Generator>,
    generated: usize,
    mixed: [u8; 32],
    credited: u16,
    timings: [Timing; 18],
    keys: [bool; 128],
    buttons: u8,
}
impl Pool {
    const fn new() -> Self {
        Self {
            generator: None,
            generated: 0,
            mixed: [0; 32],
            credited: 0,
            timings: [Timing::new(); 18],
            keys: [false; 128],
            buttons: 0,
        }
    }
    fn seed(&mut self, entropy: &[u8; 48]) {
        match &mut self.generator {
            Some(generator) => generator.update(entropy),
            None => self.generator = Some(Generator::new(entropy)),
        }
        self.generated = 0;
    }
    fn fill(&mut self, bytes: &mut [u8]) -> Result<(), Unavailable> {
        if self.generated >= RESEED_BYTES {
            return Err(Unavailable);
        }
        self.generator.as_mut().ok_or(Unavailable)?.fill(bytes);
        self.generated += bytes.len();
        Ok(())
    }
    fn event(&mut self, event: &crate::Irq, now: u64) -> bool {
        match *event {
            crate::Irq::Key(sc) if sc < 0xe0 => {
                let index = usize::from(sc & 0x7f);
                let was_down = self.keys[index];
                self.keys[index] = sc & 0x80 == 0;
                sc & 0x80 == 0 && !was_down && self.input(0, now, &[sc])
            }
            crate::Irq::Mouse { dx, dy, buttons } => {
                let changed = dx != 0 || dy != 0 || buttons != self.buttons;
                self.buttons = buttons;
                changed && self.input(1, now, &[dx as u8, dy as u8, buttons])
            }
            // Legacy IDE completion IRQs have their own timing histories.
            // Unknown/shared device lines and MSI vectors are mixed without
            // credit: they may be periodic audio or externally controlled NICs.
            crate::Irq::Hw(irq) if matches!(irq, 14 | 15) => {
                self.input(2 + usize::from(irq), now, &[])
            }
            crate::Irq::Hw(0) => false,
            crate::Irq::Hw(irq) => self.mix(irq.wrapping_add(2), now, &[], false),
            crate::Irq::Msi(source) => self.mix(source.wrapping_add(128), now, &[], false),
            _ => false,
        }
    }

    fn input(&mut self, source: usize, now: u64, data: &[u8]) -> bool {
        let credit = self.timings[source].sample(now);
        self.mix(source as u8, now, data, credit)
    }

    fn mix(&mut self, source: u8, now: u64, data: &[u8], credit: bool) -> bool {
        let mut hash = Sha256::new();
        hash.update(self.mixed);
        hash.update([source]);
        hash.update(now.to_le_bytes());
        hash.update(data);
        self.mixed = hash.finalize().into();
        // At most one estimated bit per irregular eligible event. Contents of
        // keys/mouse packets are mixed but never counted as secret bits.
        if credit {
            self.credited += 1;
        }
        if self.credited < 256 {
            return false;
        }
        let mut entropy = [0; 48];
        entropy[..32].copy_from_slice(&self.mixed);
        let nonce = Sha256::digest(self.mixed);
        entropy[32..].copy_from_slice(&nonce[..16]);
        let was_ready = self.generator.is_some();
        self.seed(&entropy);
        entropy.fill(0);
        self.credited = 0;
        !was_ready
    }
}

/// Consume the timestamp captured by the backend at interrupt entry. Never
/// replace it with drain time: queued events can have very different arrivals.
/// Hashing happens here in the event loop, outside the interrupt handler.
/// Typematic, releases, and periodic clock interrupts earn no entropy credit.
pub fn interrupt_event(event: &crate::Irq, timestamp_ns: u64) {
    if matches!(event, crate::Irq::Hw(0)) {
        return;
    }
    let seeded = POOL.lock().event(event, timestamp_ns);
    if seeded {
        crate::compact_println!("random: seeded from interrupt timing");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    // Independent Python hashlib/hmac reference, two consecutive requests.
    #[test]
    fn hmac_drbg_reference_vector() {
        let mut seed = [0; 48];
        for (i, byte) in seed.iter_mut().enumerate() {
            *byte = i as u8;
        }
        let mut generator = Generator::new(&seed);
        let mut actual = [0; 128];
        generator.fill(&mut actual[..64]);
        generator.fill(&mut actual[64..]);
        assert_eq!(
            actual,
            [
                15, 251, 128, 135, 90, 62, 144, 34, 164, 148, 26, 63, 161, 176, 211, 97, 29, 241,
                78, 28, 246, 81, 167, 60, 233, 34, 155, 159, 58, 213, 104, 135, 104, 4, 40, 132,
                87, 16, 40, 142, 164, 57, 28, 166, 242, 29, 248, 205, 136, 183, 178, 122, 141, 252,
                22, 85, 149, 64, 115, 151, 89, 72, 12, 22, 202, 200, 73, 11, 169, 178, 63, 252, 22,
                241, 79, 155, 5, 212, 42, 219, 171, 194, 249, 185, 107, 42, 190, 37, 97, 36, 4, 80,
                205, 211, 139, 82, 185, 156, 35, 32, 24, 25, 106, 0, 5, 145, 21, 103, 158, 235,
                231, 160, 8, 209, 177, 119, 130, 233, 26, 247, 53, 124, 254, 218, 114, 65, 95, 228
            ]
        );
    }
    #[test]
    fn unseeded_and_reseed_required_leave_destination_untouched() {
        let mut pool = Pool::new();
        let mut bytes = [0xa5; 8];
        assert_eq!(pool.fill(&mut bytes), Err(Unavailable));
        assert_eq!(bytes, [0xa5; 8]);
        pool.seed(&[7; 48]);
        pool.generated = RESEED_BYTES;
        assert_eq!(pool.fill(&mut bytes), Err(Unavailable));
        assert_eq!(bytes, [0xa5; 8]);
    }
    #[test]
    fn typematic_releases_and_timer_interrupts_earn_no_credit() {
        let mut pool = Pool::new();
        let mut now = 0;
        for i in 1..1000u64 {
            now += i * i + 1;
            pool.event(&crate::Irq::Key(0x1e), now);
            pool.event(&crate::Irq::Hw(0), now + 1);
        }
        assert_eq!(pool.credited, 0);
        for i in 1..1000u64 {
            now += i * i + 1;
            pool.event(&crate::Irq::Key(0x9e), now);
            pool.event(&crate::Irq::Key(0xe0), now + 1);
        }
        assert_eq!(pool.credited, 0);
        assert!(pool.generator.is_none());
    }
    #[test]
    fn keyboard_and_mouse_can_each_seed_without_hardware() {
        for mouse in [false, true] {
            let mut pool = Pool::new();
            let mut now = 0;
            for i in 1..=259u64 {
                now += i * i + 1;
                if mouse {
                    pool.event(
                        &crate::Irq::Mouse {
                            dx: 1,
                            dy: 0,
                            buttons: 0,
                        },
                        now,
                    );
                } else {
                    pool.event(&crate::Irq::Key(0x1e), now);
                    pool.event(&crate::Irq::Key(0x9e), now + 1);
                }
            }
            assert!(pool.generator.is_some());
            let mut bytes = [0; 32];
            pool.fill(&mut bytes).unwrap();
            assert_ne!(bytes, [0; 32]);
        }
    }
    #[test]
    fn regular_or_repeated_timestamps_do_not_seed() {
        let mut pool = Pool::new();
        for i in 1..2000 {
            pool.input(0, i * 100, &[0x1e]);
        }
        assert!(pool.generator.is_none());
        assert_eq!(pool.credited, 0);
        for _ in 0..2000 {
            pool.input(0, 200000, &[0x1e]);
        }
        assert_eq!(pool.credited, 0);
    }
    #[test]
    fn irregular_legacy_disk_interrupts_seed_but_shared_irqs_do_not() {
        for event in [
            crate::Irq::Hw(0),
            crate::Irq::Hw(8),
            crate::Irq::Hw(11),
            crate::Irq::Msi(0),
            crate::Irq::Hw(14),
            crate::Irq::Hw(15),
        ] {
            let mut pool = Pool::new();
            let mut now = 0;
            for i in 1..=259u64 {
                now += i * i + 1;
                pool.event(&event, now);
            }
            assert_eq!(
                pool.generator.is_some(),
                matches!(event, crate::Irq::Hw(14 | 15))
            );
        }
    }
    #[test]
    fn regular_disk_interrupts_earn_no_credit_and_sources_are_separate() {
        let mut pool = Pool::new();
        for i in 1..1000u64 {
            // Interleaving lines must not manufacture entropy from two regular streams.
            pool.event(&crate::Irq::Hw(14), i * 100);
            pool.event(&crate::Irq::Hw(15), i * 100 + 37);
        }
        assert_eq!(pool.credited, 0);
        assert!(pool.generator.is_none());
    }
    #[test]
    fn irregular_input_seeds_and_reseeds() {
        let mut pool = Pool::new();
        let mut now = 0;
        for i in 1..=258u64 {
            now += i * i + 1;
            pool.input(0, now, &[0x1e]);
        }
        assert!(pool.generator.is_none());
        now += 259 * 259 + 1;
        assert!(pool.input(0, now, &[0x1e]));
        let mut bytes = [0; 32];
        pool.fill(&mut bytes).unwrap();
        assert_ne!(bytes, [0; 32]);
        pool.seed(&[9; 48]);
        let mut reseeded = [0; 32];
        pool.fill(&mut reseeded).unwrap();
        assert_ne!(bytes, reseeded);
    }
}
