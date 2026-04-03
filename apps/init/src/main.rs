//! Init process for RetroOS
//!
//! Execs DOS Navigator. Respawns if it exits.

#![no_std]
#![no_main]

#[unsafe(no_mangle)]
pub fn main(_args: &[&str]) {
    crt::print("RetroOS init\n");

    let pid = crt::fork();
    if pid == 0 {
        crt::exec("stress.elf", &["stress.elf", "4"]);
        crt::print("exec stress.elf failed\n");
        crt::exit(1);
    }
    crt::waitpid(pid);

    crt::exec("DN/DN.COM", &["DN.COM"]);
}
