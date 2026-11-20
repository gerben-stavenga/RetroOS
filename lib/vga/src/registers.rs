//! Shared storage ownership for the VGA model and scanout.
use alloc::sync::Arc;
use core::sync::atomic::AtomicU8;
pub use planar::{Byte, Bytes, Word, Dword, Registers};

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
            core::ptr::addr_of_mut!((*p).profile).write(planar::Profile::new());
            byte!(enabled, 1); byte!(profile_enabled, 0);
            byte!(seq_index, 0); byte!(gc_index, 0); byte!(latches_valid, 1);
            bytes!(latches, 4, |_| 0);
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
