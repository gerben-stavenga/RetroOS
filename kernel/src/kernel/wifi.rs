//! Shared native Wi-Fi lifecycle and diagnostics, independent of guest ABI.
use crate::kernel::drivers::wcn785x;
use crate::kernel::vfs::{self, DirEntry, Filesystem, Vnode};
use alloc::boxed::Box;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};
pub mod scan;

/// Native radio lifecycle, shared by guest personalities and chip drivers.
pub trait Radio: Send {
    fn poll(&mut self);
    fn scan(&mut self) -> Result<(), i32> {
        Err(-95)
    }
}
static DEVICE: spin::Mutex<Option<Box<dyn Radio>>> = spin::Mutex::new(None);
static STATUS: Status = Status(spin::Mutex::new(Vec::new()));
struct Status(spin::Mutex<Vec<u8>>);
static SCAN: spin::Mutex<scan::Survey> = spin::Mutex::new(scan::Survey::new());
static SCAN_REQUEST: AtomicBool = AtomicBool::new(false);

pub fn scan_begin() {
    SCAN.lock().begin();
}
pub fn scan_phase(phase: scan::Phase) {
    SCAN.lock().phase = phase;
    match phase {
        scan::Phase::Running => crate::compact_println!("WiFi: passive scan started"),
        scan::Phase::Complete => {
            let text = SCAN.lock().text();
            crate::compact_println!("WiFi: {}", text.as_str());
        }
        scan::Phase::Failed(reason) => {
            crate::compact_println!("WiFi: scan failed reason={}", reason);
            let text = SCAN.lock().text();
            crate::compact_println!("WiFi: {}", text.as_str());
        }
        _ => {}
    }
}
pub fn scan_observe(network: scan::Network) {
    SCAN.lock().observe(network);
}

fn status_text() -> Vec<u8> {
    let mut text = STATUS.0.lock().clone();
    text.extend_from_slice(SCAN.lock().text().as_bytes());
    text
}

pub fn report(message: &str) {
    crate::compact_println!("WiFi: {}", message);
    *STATUS.0.lock() = [message.as_bytes(), b"\n"].concat();
}
pub fn init<A: crate::Arch>(machine: &mut A) {
    report("no supported native radio detected");
    vfs::mount(b"wificonfig/", &STATUS);
    vfs::hide_mount(b"wificonfig/");
    vfs::bind(b"proc/wifi", b"wificonfig/status");
    let c_root = crate::kernel::dos::c_root();
    if !c_root.is_empty() {
        let path = [c_root, b"proc/wifi"].concat();
        vfs::bind(
            alloc::boxed::Box::leak(path.into_boxed_slice()),
            b"wificonfig/status",
        );
    }
    // Driver selection is the only place the service names a chipset.
    *DEVICE.lock() = wcn785x::probe(machine).map(|radio| Box::new(radio) as Box<dyn Radio>);
    SCAN_REQUEST.store(DEVICE.lock().is_some(), Ordering::Release);
}
pub fn poll() {
    if let Some(device) = DEVICE.lock().as_mut() {
        device.poll();
        if SCAN_REQUEST.swap(false, Ordering::AcqRel)
            && let Err(error) = device.scan()
        {
            crate::compact_println!("WiFi: scan request rejected: {}", error);
        }
    }
}

/// Persist a radio's binary diagnostics on C:, preserving earlier dumps.
pub fn save_dump<A: crate::Arch>(machine: &mut A, bytes: &[u8]) -> Result<Vec<u8>, i32> {
    use crate::kernel::thread::{FdKind, MAX_FDS};
    let root = crate::kernel::dos::c_root();
    if root.is_empty() {
        return Err(-2);
    }
    let mut root = root.to_vec();
    if !root.ends_with(b"/") {
        root.push(b'/');
    }
    let path = (1..=9999)
        .find_map(|index| {
            let path = [
                root.as_slice(),
                alloc::format!("WIFI{:04}.DMP", index).as_bytes(),
            ]
            .concat();
            vfs::stat(&path, false).is_none().then_some(path)
        })
        .ok_or(-28)?;
    let mut fds = [FdKind::None; MAX_FDS];
    let fd = vfs::create(&path, &mut fds);
    if fd < 0 {
        return Err(fd);
    }
    let result = (|| {
        let mut offset = 0;
        while offset < bytes.len() {
            let end = (offset + 65536).min(bytes.len());
            let written = vfs::write(machine, fd, &bytes[offset..end], &fds);
            if written <= 0 {
                return Err(if written == 0 { -5 } else { written });
            }
            offset += written as usize;
        }
        let status = vfs::flush(fd, &fds);
        if status < 0 {
            return Err(status);
        }
        Ok(())
    })();
    let status = vfs::close(fd, &mut fds);
    result.and(if status < 0 { Err(status) } else { Ok(path) })
}
impl Filesystem for Status {
    fn supports_create(&self) -> bool {
        true
    }
    fn create(&self, path: &[u8]) -> Option<Vnode> {
        self.open(path)
    }
    fn open(&self, path: &[u8]) -> Option<Vnode> {
        (path == b"status").then(|| Vnode {
            handle: 1,
            size: status_text().len() as u32,
            mode: 0o644,
        })
    }
    fn read(&self, _: u64, offset: u32, out: &mut [u8], _: u32) -> i32 {
        let text = status_text();
        let start = (offset as usize).min(text.len());
        let count = out.len().min(text.len() - start);
        out[..count].copy_from_slice(&text[start..start + count]);
        count as i32
    }
    fn write(&self, _: u64, _: u32, bytes: &[u8]) -> i32 {
        let command = bytes.trim_ascii();
        if command.is_empty() {
            return bytes.len() as i32;
        }
        if command != b"scan" {
            return -22;
        }
        if DEVICE.lock().is_none() {
            return -19;
        }
        if matches!(
            SCAN.lock().phase,
            scan::Phase::Starting | scan::Phase::Running
        ) || SCAN_REQUEST.swap(true, Ordering::AcqRel)
        {
            return -16;
        }
        bytes.len() as i32
    }
    fn dir_exists(&self, path: &[u8]) -> bool {
        path.is_empty()
    }
    fn readdir(&self, _: &[u8], _: u64, _: &mut Vec<DirEntry>, _: usize) -> Option<u64> {
        None
    }
}
