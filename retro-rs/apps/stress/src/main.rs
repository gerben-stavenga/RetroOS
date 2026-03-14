#![no_std]
#![no_main]

/// 32-bit stress test: fork a binary tree to depth, alternating 32/64-bit execs.

#[unsafe(no_mangle)]
pub fn main(args: &[&str]) {
    let depth = if args.len() > 1 { crt::parse_int(args[1]) } else { 0 };
    stress(depth);
}

fn stress(depth: i32) {
    crt::print("s32 depth=");
    crt::print_num(depth);
    crt::print("\n");

    if depth <= 0 {
        return;
    }

    // Fork child 1: stays 32-bit, recurses
    let pid1 = crt::fork();
    if pid1 == 0 {
        stress(depth - 1);
        crt::exit(0);
    }

    // Fork child 2: exec into 64-bit stress test with decremented depth
    let pid2 = crt::fork();
    if pid2 == 0 {
        let mut buf = [0u8; 12];
        let depth_str = crt::format_int(depth - 1, &mut buf);
        crt::exec("stress64.elf", &["stress64.elf", depth_str]);
        crt::print("exec stress64 failed\n");
        crt::exit(1);
    }

    crt::wait_all();
}
