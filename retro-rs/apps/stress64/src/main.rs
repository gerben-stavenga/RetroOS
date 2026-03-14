#![no_std]
#![no_main]

/// 64-bit stress test: fork a binary tree to depth, alternating 64/32-bit execs.

#[unsafe(no_mangle)]
pub fn main(args: &[&str]) {
    let depth = if args.len() > 1 { crt::parse_int(args[1]) } else { 0 };
    stress(depth);
}

fn stress(depth: i32) {
    crt::print("s64 depth=");
    crt::print_num(depth);
    crt::print("\n");

    if depth <= 0 {
        return;
    }

    // Fork child 1: stays 64-bit, recurses
    let pid1 = crt::fork();
    if pid1 == 0 {
        stress(depth - 1);
        crt::exit(0);
    }

    // Fork child 2: exec into 32-bit stress test with decremented depth
    let pid2 = crt::fork();
    if pid2 == 0 {
        let mut buf = [0u8; 12];
        let depth_str = crt::format_int(depth - 1, &mut buf);
        crt::exec("stress.elf", &["stress.elf", depth_str]);
        crt::print("exec stress failed\n");
        crt::exit(1);
    }

    crt::wait_all();
}
