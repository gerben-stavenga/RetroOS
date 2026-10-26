//! The device's register storage. The guest and scanout access the same cells;
//! no renderer publication, spinlock, or mutable slice aliases these bytes.
use alloc::sync::Arc;
use core::sync::atomic::{AtomicU8, Ordering};

pub struct Byte(AtomicU8);
impl Byte {
    pub fn new(value: u8) -> Self { Self(AtomicU8::new(value)) }
    #[inline] pub fn get(&self) -> u8 { self.0.load(Ordering::Relaxed) }
    #[inline] pub fn set(&self, value: u8) { self.0.store(value, Ordering::Relaxed); }
}
#[repr(transparent)]
pub struct Bytes<const N: usize>([AtomicU8; N]);
impl<const N: usize> Bytes<N> {
    pub fn new(values: [u8; N]) -> Self { Self(values.map(AtomicU8::new)) }
    #[inline] pub fn get(&self, index: usize) -> u8 { self.0[index].load(Ordering::Relaxed) }
    #[inline] pub fn set(&self, index: usize, value: u8) { self.0[index].store(value, Ordering::Relaxed); }
    pub fn read(&self) -> [u8; N] { core::array::from_fn(|i| self.get(i)) }
    pub fn write(&self, values: [u8; N]) { self.write_range(0, &values); }
    pub fn write_range(&self, start: usize, values: &[u8]) {
        assert!(start <= N && values.len() <= N - start);
        for (i, value) in values.iter().enumerate() { self.set(start + i, *value); }
    }
}

pub struct Registers {
    pub misc_output: Byte,
    pub feature_ctl: Byte,
    pub cga_mode_ctl: Byte,
    pub cga_color_select: Byte,
    pub seq: Bytes<5>,
    pub crtc: Bytes<25>,
    pub gc: Bytes<9>,
    pub ac: Bytes<21>,
    pub dac: Bytes<768>,
    pub dac_mask: Byte,
}
/// Cloning a saved process creates an independent device. Scanout explicitly
/// shares the original register file with `share`, retaining its lifetime.
pub struct RegisterFile(Arc<Registers>);
impl Default for RegisterFile {
    fn default() -> Self { Self::allocate(None) }
}
impl Clone for RegisterFile {
    fn clone(&self) -> Self { Self::allocate(Some(&self.0)) }
}
impl RegisterFile {
    fn allocate(source: Option<&Registers>) -> Self {
        let mut allocation = Arc::<Registers>::new_uninit();
        let p = Arc::get_mut(&mut allocation).unwrap().as_mut_ptr();
        // Initialize the final allocation in place: cloning a DOS device must
        // not put a second 768-byte DAC image on the kernel's fork/exec stack.
        unsafe {
            macro_rules! byte {
                ($field:ident, $default:expr) => {
                    core::ptr::addr_of_mut!((*p).$field).write(Byte::new(
                        source.map_or($default, |s| s.$field.get())));
                };
            }
            macro_rules! bytes {
                ($field:ident, $n:expr, $default:expr) => {
                    let dst = core::ptr::addr_of_mut!((*p).$field).cast::<AtomicU8>();
                    for i in 0..$n {
                        dst.add(i).write(AtomicU8::new(source.map_or_else(
                            || ($default)(i), |s| s.$field.get(i))));
                    }
                };
            }
            byte!(misc_output, 0); byte!(feature_ctl, 0);
            byte!(cga_mode_ctl, 0); byte!(cga_color_select, 0); byte!(dac_mask, 255);
            bytes!(seq, 5, |_| 0); bytes!(crtc, 25, |_| 0);
            bytes!(gc, 9, |i| if i == 8 { 255 } else { 0 });
            bytes!(ac, 21, |i| if i == 16 { 8 } else { 0 });
            bytes!(dac, 768, |_| 0);
            if source.is_none() {
                // Exclusive, not yet published: non-atomic initialization is
                // valid here. AtomicU8 has the size and alignment of u8.
                let palette = &mut *core::ptr::addr_of_mut!((*p).dac).cast::<[u8; 768]>();
                crate::fill_fallback_palette(palette);
            }
            Self(allocation.assume_init())
        }
    }
    pub fn share(&self) -> Self { Self(self.0.clone()) }
    pub fn same_device(&self, other: &Self) -> bool { Arc::ptr_eq(&self.0, &other.0) }
}
impl core::ops::Deref for RegisterFile {
    type Target = Registers;
    fn deref(&self) -> &Registers { &self.0 }
}
