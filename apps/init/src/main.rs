//! Init process for RetroOS
//!
//! Execs Norton Commander. Respawns if it exits.

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
            crt::print("child: exec NC.EXE\n");
            crt::exec("NC.EXE", &["NC.EXE"]);
            crt::exit(1);
        }
        crt::print("parent: waitpid\n");
        crt::waitpid(pid);
        crt::print("init: NC exited, respawning\n");
    }
}
