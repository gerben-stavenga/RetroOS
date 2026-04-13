use std::io::Write;

/// Raw Linux x86_64 fork via syscall
fn fork() -> i64 {
    let ret: i64;
    unsafe { std::arch::asm!(
        "syscall",
        inout("rax") 57i64 => ret, // __NR_fork
        out("rcx") _,
        out("r11") _,
        options(nostack),
    ); }
    ret
}

/// Raw Linux x86_64 waitpid(-1, &status, 0)
fn wait_all() {
    loop {
        let mut status: i32 = 0;
        let ret: i64;
        unsafe { std::arch::asm!(
            "syscall",
            inout("rax") 61i64 => ret, // __NR_wait4
            in("rdi") -1i64,
            in("rsi") &mut status as *mut i32,
            in("rdx") 0i64,
            in("r10") 0i64, // rusage = NULL
            out("rcx") _,
            out("r11") _,
            options(nostack),
        ); }
        if ret < 0 { break; }
    }
}

/// Raw Linux x86_64 execve
fn exec(path: &str, argv: &[*const u8]) {
    let path_bytes = path.as_bytes();
    let mut buf = [0u8; 128];
    buf[..path_bytes.len()].copy_from_slice(path_bytes);
    // buf is null-terminated (zeroed)
    unsafe { std::arch::asm!(
        "syscall",
        in("rax") 59i64, // __NR_execve
        in("rdi") buf.as_ptr(),
        in("rsi") argv.as_ptr(),
        in("rdx") core::ptr::null::<u8>(),
        out("rcx") _,
        out("r11") _,
        options(nostack),
    ); }
}

/// 4 pages of memory for COW verification
const CHECK_WORDS: usize = 4 * 4096 / 8;
static mut MEM_CHECK: [u64; CHECK_WORDS] = [0; CHECK_WORDS];

fn fill_pages(marker: u64) {
    let base = &raw mut MEM_CHECK as *mut u64;
    for i in 0..CHECK_WORDS {
        unsafe { core::ptr::write_volatile(base.add(i), marker); }
    }
}

fn check_pages(marker: u64) {
    let base = &raw const MEM_CHECK as *const u64;
    for i in 0..CHECK_WORDS {
        let val = unsafe { core::ptr::read_volatile(base.add(i)) };
        if val != marker {
            eprintln!("FAIL: mem[{}] = {:#x} expected {:#x}", i, val, marker);
            std::process::exit(2);
        }
    }
}

fn stress(depth: i32) {
    print!("s64 depth={}\n", depth);
    std::io::stdout().flush().ok();

    if depth <= 0 { return; }

    let marker = depth as u64 | 0xDEAD_BEEF_0000_0000;
    fill_pages(marker);

    // Fork child 1: recurse in 64-bit
    let pid1 = fork();
    if pid1 == 0 {
        stress(depth - 1);
        std::process::exit(0);
    }

    // Fork child 2: exec 32-bit stress test
    let pid2 = fork();
    if pid2 == 0 {
        let depth_str = format!("{}\0", depth - 1);
        let path = b"stress.elf\0";
        let argv: [*const u8; 3] = [path.as_ptr(), depth_str.as_ptr(), core::ptr::null()];
        exec("stress.elf", &argv);
        eprintln!("exec stress.elf failed");
        std::process::exit(1);
    }

    // Fork child 3: exec DOS HELLO.COM
    let pid3 = fork();
    if pid3 == 0 {
        let path = b"HELLO.COM\0";
        let argv: [*const u8; 2] = [path.as_ptr(), core::ptr::null()];
        exec("HELLO.COM", &argv);
        eprintln!("exec HELLO.COM failed");
        std::process::exit(1);
    }

    wait_all();

    // Verify our pages survived children's COW writes and exec
    check_pages(marker);
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let depth = if args.len() > 1 {
        args[1].parse().unwrap_or(3)
    } else {
        3
    };
    stress(depth);
    println!("stress64 OK");
}
