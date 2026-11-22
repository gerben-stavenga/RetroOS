//! Caller-owned saved user page-directory entries.
pub struct AddressSpace(pub(crate) [u32; 768]);
impl AddressSpace {
    pub const fn empty() -> Self { Self([0; 768]) }
}
impl Default for AddressSpace {
    fn default() -> Self { Self::empty() }
}
