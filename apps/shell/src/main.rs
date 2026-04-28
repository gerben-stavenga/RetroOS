use std::os::unix::process::CommandExt;
use std::process::Command;

fn main() {
    // Replace ourselves with busybox-ash. argv[0]="sh" makes busybox's
    // standalone-shell applet dispatch pick the sh applet directly.
    let err = Command::new("/bin/busybox").arg0("sh").exec();
    eprintln!("shell.elf: failed to exec /bin/busybox: {}", err);
}
