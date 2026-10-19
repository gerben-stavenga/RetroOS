use std::{
    env,
    io::{self, Write},
    process::Command,
};

fn bytes(size: usize, offset: usize) -> Vec<u8> {
    (0..size)
        .map(|index| ((index + offset) % 251) as u8)
        .collect()
}
fn main() {
    let args: Vec<_> = env::args().collect();
    if args.get(1).map(String::as_str) == Some("child") {
        let size = args[2].parse().unwrap();
        io::stdout().write_all(&bytes(size, 0)).unwrap();
        io::stderr().write_all(&bytes(size, 17)).unwrap();
        std::process::exit(17);
    }
    for size in [31, 128 * 1024] {
        let output = Command::new(env::current_exe().unwrap())
            .args(["child", &size.to_string()])
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(17));
        assert_eq!(output.stdout.len(), size, "stdout length");
        assert_eq!(output.stderr.len(), size, "stderr length");
        assert_eq!(output.stdout, bytes(size, 0));
        assert_eq!(output.stderr, bytes(size, 17));
        eprintln!("RUST PROCESS OUTPUT PASS: {size} bytes per stream");
    }
}
