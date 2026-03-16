//! RetroOS shell
//!
//! For now, runs the stress test.

#![no_std]
#![no_main]

#[unsafe(no_mangle)]
pub fn main(_args: &[&str]) {
    crt::print("RetroOS shell\n");

    crt::print("Running stress test...\n");
    let pid = crt::fork();
    if pid == 0 {
        crt::exec("stress.elf", &["stress.elf", "3"]);
        crt::print("shell: exec stress failed\n");
        crt::exit(1);
    }
    crt::waitpid(pid);
    crt::print("Stress test done.\n");
}
