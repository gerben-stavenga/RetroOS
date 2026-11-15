//! Caller-owned saved user page-directory entries.
pub struct RootPageTable(pub(crate) [u32; 768]);
impl RootPageTable {
    pub const fn empty() -> Self { Self([0; 768]) }
}
impl Default for RootPageTable {
    fn default() -> Self { Self::empty() }
}
