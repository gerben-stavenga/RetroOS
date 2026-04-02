//! Init process for RetroOS
//!
//! Execs DOS Navigator. Respawns if it exits.

#![no_std]
#![no_main]

#[unsafe(no_mangle)]
pub fn main(_args: &[&str]) {
    crt::print("RetroOS init\n");

    crt::exec("DN/DN.COM", &["DN.COM"]);
}
