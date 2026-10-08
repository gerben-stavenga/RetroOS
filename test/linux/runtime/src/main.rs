use std::{
    cell::Cell,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};
thread_local! { static MARKER: Cell<u64> = const { Cell::new(13) }; }
#[repr(C, packed)]
#[derive(Clone, Copy)]
struct Event {
    events: u32,
    data: u64,
}
unsafe extern "C" {
    fn epoll_create1(flags: i32) -> i32;
    fn eventfd(init: u32, flags: i32) -> i32;
    fn epoll_ctl(ep: i32, op: i32, fd: i32, event: *const Event) -> i32;
    fn epoll_wait(ep: i32, events: *mut Event, max: i32, timeout: i32) -> i32;
    fn read(fd: i32, ptr: *mut u64, size: usize) -> isize;
    fn write(fd: i32, ptr: *const u64, size: usize) -> isize;
    fn close(fd: i32) -> i32;
    fn fcntl(fd: i32, cmd: i32, value: i32) -> i32;
    fn prctl(option: i32, name: *mut u8) -> i32;
    fn poll(ptr: *mut u8, count: usize, timeout: i32) -> i32;
}
fn main() {
    assert_eq!(MARKER.with(Cell::get), 13);
    MARKER.with(|m| m.set(17));
    let mut parent_name = *b"parent-thread-name-too-long\0";
    unsafe {
        assert_eq!(prctl(15, parent_name.as_mut_ptr()), 0);
    }
    let mut name = [0; 16];
    unsafe {
        assert_eq!(prctl(16, name.as_mut_ptr()), 0);
    }
    assert_eq!(&name, b"parent-thread-n\0");
    let shared = Arc::new(AtomicU64::new(0));
    unsafe {
        let original = epoll_create1(0x80000);
        let ep = fcntl(original, 1030, 3);
        assert!(original >= 0 && ep >= 0);
        assert_eq!(close(original), 0); // Duplicate must preserve the interest list.
        let fd = eventfd(0, 0x80800);
        assert!(fd >= 0);
        let mut event = Event {
            events: 1 | (1 << 31) | (1 << 30),
            data: 0x1234_5678_9abc_def0,
        };
        assert_eq!(epoll_ctl(ep, 1, fd, &event), 0);
        let clone = shared.clone();
        let worker = std::thread::spawn(move || {
            let mut name = [0; 16];
            assert_eq!(prctl(16, name.as_mut_ptr()), 0);
            assert_eq!(&name, b"parent-thread-n\0");
            let mut worker_name = *b"worker\0";
            assert_eq!(prctl(15, worker_name.as_mut_ptr()), 0);
            assert_eq!(MARKER.with(Cell::get), 13); // PT_TLS initialized independently.
            MARKER.with(|m| m.set(29));
            // sched_yield uses the shared Linux thread scheduler, preserving
            // this worker's TLS while another context gets to run.
            for _ in 0..20 {
                std::thread::yield_now();
                assert_eq!(MARKER.with(Cell::get), 29);
            }
            std::thread::sleep(Duration::from_millis(20));
            clone.store(37, Ordering::Release);
            assert_eq!(write(fd, &2, 8), 8);
            MARKER.with(Cell::get)
        });
        let mut delivered = Event { events: 0, data: 0 };
        assert_eq!(epoll_wait(ep, &mut delivered, 1, 3000), 1);
        let data = delivered.data;
        let expected = event.data;
        assert_eq!(data, expected);
        let mut counter = 0;
        assert_eq!(read(fd, &mut counter, 8), 8);
        assert_eq!(counter, 2);
        assert_eq!(shared.load(Ordering::Acquire), 37);
        assert_eq!(worker.join().unwrap(), 29);
        assert_eq!(MARKER.with(Cell::get), 17);
        let mut name = [0; 16];
        assert_eq!(prctl(16, name.as_mut_ptr()), 0);
        assert_eq!(&name, b"parent-thread-n\0");
        assert_eq!(write(fd, &1, 8), 8);
        assert_eq!(epoll_wait(ep, &mut delivered, 1, 0), 0); // EPOLLONESHOT disabled it.
        event.events = 1 | (1 << 31);
        assert_eq!(epoll_ctl(ep, 3, fd, &event), 0);
        assert_eq!(epoll_wait(ep, &mut delivered, 1, 0), 1);
        assert_eq!(read(fd, &mut counter, 8), 8);
        assert_eq!(counter, 1);
        assert_eq!(read(fd, &mut counter, 8), -1); // Empty EFD_NONBLOCK reports EAGAIN.
        assert_eq!(write(fd, &1, 8), 8);
        assert_eq!(epoll_wait(ep, &mut delivered, 1, 0), 1);
        // Linux eventfd produces another edge on write even if left unread.
        assert_eq!(write(fd, &1, 8), 8);
        assert_eq!(epoll_wait(ep, &mut delivered, 1, 0), 1);
        assert_eq!(read(fd, &mut counter, 8), 8);
        assert_eq!(counter, 2);
        let second = eventfd(1, 0x80800);
        event.data = 2;
        assert_eq!(epoll_ctl(ep, 1, second, &event), 0);
        assert_eq!(write(fd, &1, 8), 8);
        // maxevents=1 must leave the second edge queued for the next wait.
        assert_eq!(epoll_wait(ep, &mut delivered, 1, 0), 1);
        assert_eq!(epoll_wait(ep, &mut delivered, 1, 0), 1);
        let tag = delivered.data;
        assert_eq!(tag, 2);
        assert_eq!(close(second), 0);
        assert_eq!(close(fd), 0);
        assert_eq!(close(ep), 0);
        let start = Instant::now();
        assert_eq!(poll(std::ptr::null_mut(), 0, 10), 0);
        assert!(start.elapsed() >= Duration::from_millis(10));
    }
    std::fs::create_dir("probe").unwrap();
    std::fs::write("probe/file.txt", b"Linux runtime works").unwrap();
    assert_eq!(
        std::fs::read("probe/file.txt").unwrap(),
        b"Linux runtime works"
    );
    std::fs::rename("probe/file.txt", "probe/moved.txt").unwrap();
    assert_eq!(
        std::fs::read("probe/moved.txt").unwrap(),
        b"Linux runtime works"
    );
    std::fs::remove_file("probe/moved.txt").unwrap();
    std::fs::remove_dir("probe").unwrap();
    // Terminal capability probes must finish instead of stealing later keys.
    use std::io::Write;
    print!("\x1b[5n");
    std::io::stdout().flush().unwrap();
    let mut reply = 0u64;
    unsafe {
        assert_eq!(read(0, &mut reply, 4), 4);
    }
    assert_eq!(&reply.to_le_bytes()[..4], b"\x1b[0n");
    for _ in 0..300 {
        assert_eq!(std::thread::spawn(|| 42).join().unwrap(), 42);
    }
    // Rust's pre_exec launch uses fork + SOCK_SEQPACKET and CLOEXEC EOF.
    use std::os::unix::process::CommandExt;
    let mut command = std::process::Command::new("/TEST.COM");
    command.arg("hello world");
    unsafe {
        command.pre_exec(|| Ok(()));
    }
    assert_eq!(command.status().unwrap().code(), Some(37));
    let mut missing = std::process::Command::new("/MISSING.EXE");
    unsafe {
        missing.pre_exec(|| Ok(()));
    }
    assert_eq!(missing.status().unwrap_err().raw_os_error(), Some(2));
    println!("LINUX RUNTIME PASS");
}
