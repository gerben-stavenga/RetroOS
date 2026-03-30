//! Init process for RetroOS
//!
//! Execs Norton Commander. Respawns if it exits.

#![no_std]
#![no_main]

#[unsafe(no_mangle)]
pub fn main(_args: &[&str]) {
    crt::print("RetroOS init\n");

    let pid = crt::fork();
    if pid == 0 {
        crt::exec("DOOM/DOOM.EXE", &["DOOM/DOOM.EXE"]);
        crt::exit(1);
    }
    crt::waitpid(pid);
    crt::print("init: DOOM exited\n");
    loop { crt::yield_cpu(); }
}
