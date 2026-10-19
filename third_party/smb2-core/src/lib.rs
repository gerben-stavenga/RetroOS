//! SMB2/3 wire types and NTLM/SPNEGO adapted from vdavid/smb2.
#![no_std]
#[macro_use]
extern crate alloc;
pub mod auth;
pub mod client;
pub mod msg;
pub mod mfsymlink;
pub mod name;
pub mod pack;
pub mod types;
#[derive(Clone, Debug)]
pub enum Error {
    InvalidData(alloc::string::String),
    Transport,
    Timeout,
    Authentication,
    Signature,
    Status(u32),
    Unavailable,
}
impl Error {
    pub fn invalid_data(s: impl Into<alloc::string::String>) -> Self {
        Self::InvalidData(s.into())
    }
}
impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{:?}", self)
    }
}
pub type Result<T> = core::result::Result<T, Error>;
pub mod error {
    pub use crate::{Error, Result};
}
