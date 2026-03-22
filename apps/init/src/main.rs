//! Init process for RetroOS
//!
//! Execs the shell. Respawns if it exits.

#![no_std]
#![no_main]

#[unsafe(no_mangle)]
pub fn main(_args: &[&str]) {
    crt::print("RetroOS init\n");

    loop {
        let pid = crt::fork();
        crt::print("pid=");
        crt::print_num(pid);
        crt::print("\n");
        if pid == 0 {
            crt::print("child: exec NC\n");
            crt::exec("NC.EXE", &["NC.EXE"]);
            // Fallback to shell if NC fails
            crt::exec("shell.elf", &["shell.elf"]);
            crt::exit(1);
        }
        crt::print("parent: waitpid\n");
        crt::waitpid(pid);
        crt::print("init: shell exited, respawning\n");
    }
}
