use std::io::Write;

/// Raw Linux i386 fork via INT 0x80
fn fork() -> i32 {
    let ret: i32;
    unsafe { std::arch::asm!(
        "int 0x80",
        inout("eax") 2i32 => ret, // __NR_fork
        out("ebx") _,
        out("ecx") _,
        out("edx") _,
        options(nostack),
    ); }
    ret
}

/// Raw Linux i386 waitpid(-1, &status, 0)
fn wait_all() {
    loop {
        let mut status: i32 = 0;
        let ret: i32;
        unsafe { std::arch::asm!(
            "int 0x80",
            inout("eax") 7i32 => ret, // __NR_waitpid
            in("ebx") -1i32,
            in("ecx") &mut status as *mut i32,
            in("edx") 0i32,
            options(nostack),
        ); }
        if ret < 0 { break; }
    }
}

/// 4 pages of memory for COW verification
const CHECK_WORDS: usize = 4 * 4096 / 4;
static mut MEM_CHECK: [u32; CHECK_WORDS] = [0; CHECK_WORDS];

fn fill_pages(marker: u32) {
    let base = &raw mut MEM_CHECK as *mut u32;
    for i in 0..CHECK_WORDS {
        unsafe { core::ptr::write_volatile(base.add(i), marker); }
    }
}

fn check_pages(marker: u32) {
    let base = &raw const MEM_CHECK as *const u32;
    for i in 0..CHECK_WORDS {
        let val = unsafe { core::ptr::read_volatile(base.add(i)) };
        if val != marker {
            eprintln!("FAIL: mem[{}] = {:#x} expected {:#x}", i, val, marker);
            std::process::exit(2);
        }
    }
}

fn stress(depth: i32) {
    print!("s32 depth={}\n", depth);
    std::io::stdout().flush().ok();

    if depth <= 0 { return; }

    let marker = depth as u32 | 0xDEAD_0000;
    fill_pages(marker);

    // Fork child 1: recurse
    let pid1 = fork();
    if pid1 == 0 {
        stress(depth - 1);
        std::process::exit(0);
    }

    // Fork child 2: just exit
    let pid2 = fork();
    if pid2 == 0 {
        std::process::exit(0);
    }

    wait_all();

    // Verify our pages survived children's COW writes
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
    println!("stress OK");
}
