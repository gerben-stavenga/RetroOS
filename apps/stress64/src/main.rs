#![no_std]
#![no_main]

/// 64-bit stress test: fork a binary tree to depth, alternating 64/32-bit execs.
/// Verifies COW by filling pages with a marker before fork and checking after.

/// 4 pages of memory for COW verification
const CHECK_WORDS: usize = 4 * 4096 / 8;
static mut MEM_CHECK: [u64; CHECK_WORDS] = [0; CHECK_WORDS];

fn fill_pages(marker: u64) {
    let base = unsafe { &raw mut MEM_CHECK } as *mut u64;
    for i in 0..CHECK_WORDS {
        unsafe { core::ptr::write_volatile(base.add(i), marker); }
    }
}

fn check_pages(marker: u64) {
    let base = unsafe { &raw const MEM_CHECK } as *const u64;
    for i in 0..CHECK_WORDS {
        let val = unsafe { core::ptr::read_volatile(base.add(i)) };
        if val != marker {
            crt::print("FAIL: mem[");
            crt::print_num(i as i32);
            crt::print("] = ");
            crt::print_num(val as i32);
            crt::print(" expected ");
            crt::print_num(marker as i32);
            crt::print("\n");
            crt::exit(2);
        }
    }
}

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

    // Fill pages with depth-unique marker before forking
    let marker = depth as u64 | 0xDEAD_BEEF_0000_0000;
    fill_pages(marker);

    // Fork child 1: stays 64-bit, recurses (gets COW copy, will overwrite in recursive stress)
    let pid1 = crt::fork();
    if pid1 == 0 {
        stress(depth - 1);
        crt::exit(0);
    }

    // Fork child 2: exec into 32-bit stress test (gets COW copy, exec frees it)
    let pid2 = crt::fork();
    if pid2 == 0 {
        let mut buf = [0u8; 12];
        let depth_str = crt::format_int(depth - 1, &mut buf);
        crt::exec("stress.elf", &["stress.elf", depth_str]);
        crt::print("exec stress failed\n");
        crt::exit(1);
    }

    crt::wait_all();

    // Verify our pages survived children's COW writes and exec
    check_pages(marker);
}
