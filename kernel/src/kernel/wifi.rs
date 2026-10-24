//! Shared native Wi-Fi lifecycle and diagnostics, independent of guest ABI.
use crate::kernel::drivers::wcn785x;
use crate::kernel::vfs::{self, DirEntry, Filesystem, Vnode};
use alloc::boxed::Box;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};
pub mod auth;
pub mod config;
pub mod link;
pub mod scan;
static CONNECTION: spin::Mutex<Manager> = spin::Mutex::new(Manager::new());
static EVENTS: spin::Mutex<alloc::collections::VecDeque<link::Event>> =
    spin::Mutex::new(alloc::collections::VecDeque::new());
pub fn configure(profile: Option<config::Profile>) {
    CONNECTION.lock().profile = profile;
}
pub fn event(event: link::Event) {
    let mut events = EVENTS.lock();
    if events.len() < 128 {
        events.push_back(event);
    } else {
        events.clear();
        events.push_back(link::Event::Disconnected);
    }
}
struct Manager {
    profile: Option<config::Profile>,
    connection: Option<link::Connection>,
    retry: u64,
    last: Option<link::Phase>,
}
impl Manager {
    const fn new() -> Self {
        Self {
            profile: None,
            connection: None,
            retry: 0,
            last: None,
        }
    }
    fn poll(&mut self, device: &mut dyn Radio) {
        let now = crate::kernel::portio::now_ns();
        let mut actions = Vec::new();
        if let Some(connection) = &mut self.connection {
            while let Some(event) = EVENTS.lock().pop_front() {
                actions.extend(connection.event(event, now));
            }
            actions.extend(connection.tick(now));
            if connection.phase == link::Phase::Idle {
                self.connection = None;
                self.last = None;
                self.retry = now + 5_000_000_000;
                SCAN_REQUEST.store(true, Ordering::Release);
            }
        } else {
            EVENTS.lock().clear();
            if now >= self.retry && self.profile.as_ref().is_some_and(|p| p.auto_connect) {
                let profile = self.profile.as_ref().unwrap();
                let survey = SCAN.lock();
                if matches!(survey.phase, scan::Phase::Failed(_) | scan::Phase::Idle) {
                    self.retry = now + 15_000_000_000;
                    SCAN_REQUEST.store(true, Ordering::Release);
                }
                if matches!(survey.phase, scan::Phase::Complete) {
                    let found = survey
                        .networks
                        .iter()
                        .filter(|n| n.ssid == profile.ssid)
                        .filter(|n| {
                            auth::Security::negotiate(&n.rsn).is_ok()
                                && link::legacy_rates(n).is_ok()
                        })
                        .max_by_key(|n| n.signal_dbm)
                        .cloned();
                    drop(survey);
                    if let Some(network) = found {
                        let mut nonce = [0; 32];
                        if let Some(mac) = device.mac_address()
                            && crate::kernel::random::fill(&mut nonce).is_ok()
                            && let Ok(pmk) = profile.pmk()
                            && let Ok(connection) =
                                link::Connection::new(network, mac, pmk, nonce, now)
                        {
                            actions.push(connection.first());
                            self.connection = Some(connection);
                        } else {
                            report("waiting for secure random source and radio");
                            self.retry = now + 5_000_000_000;
                        }
                    } else {
                        report("configured network absent or unsupported security; retrying scan");
                        self.retry = now + 15_000_000_000;
                        SCAN_REQUEST.store(true, Ordering::Release);
                    }
                }
            }
        }
        for action in actions {
            if let Err(error) = device.action(action) {
                crate::compact_println!("WiFi: station action failed: {}", error);
                if let Some(c) = &mut self.connection {
                    for a in c.fail(now) {
                        let _ = device.action(a);
                    }
                }
                break;
            }
        }
        if let Some(c) = &self.connection
            && self.last != Some(c.phase)
        {
            self.last = Some(c.phase);
            report(c.status());
        }
    }
}

/// Native radio lifecycle, shared by guest personalities and chip drivers.
pub trait Radio: Send {
    fn poll(&mut self);
    fn transmit(&mut self, _frame: &[u8]) -> bool {
        false
    }
    fn mac_address(&self) -> Option<[u8; 6]> {
        None
    }
    fn action(&mut self, _action: link::Action) -> Result<(), i32> {
        Err(-95)
    }
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
    let mut text = if let Some(connection) = CONNECTION.lock().connection.as_ref() {
        [connection.status().as_bytes(), b"\n"].concat()
    } else {
        STATUS.0.lock().clone()
    };
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
    let mut attach = None;
    if let Some(device) = DEVICE.lock().as_mut() {
        device.poll();
        CONNECTION.lock().poll(device.as_mut());
        let connected = CONNECTION
            .lock()
            .connection
            .as_ref()
            .is_some_and(|c| c.phase == link::Phase::Connected);
        let mut ethernet = ETHERNET.lock();
        if !connected {
            ethernet.rx.clear();
            ethernet.tx.clear();
        }
        ethernet.connected = connected;
        if connected && !ethernet.attached {
            ethernet.attached = true;
            attach = device.mac_address();
        }
        if connected {
            for _ in 0..16 {
                let Some(frame) = ethernet.tx.front() else {
                    break;
                };
                if !device.transmit(frame) {
                    break;
                }
                ethernet.tx.pop_front();
            }
        }
        drop(ethernet);
        if CONNECTION.lock().connection.is_none()
            && SCAN_REQUEST.swap(false, Ordering::AcqRel)
            && let Err(error) = device.scan()
        {
            crate::compact_println!("WiFi: scan request rejected: {}", error);
        }
    }
    if let Some(mac) = attach {
        crate::kernel::net::install_wifi(Box::new(Adapter(mac)));
    }
}
struct Ethernet {
    rx: alloc::collections::VecDeque<Vec<u8>>,
    tx: alloc::collections::VecDeque<Vec<u8>>,
    connected: bool,
    attached: bool,
}
static ETHERNET: spin::Mutex<Ethernet> = spin::Mutex::new(Ethernet {
    rx: alloc::collections::VecDeque::new(),
    tx: alloc::collections::VecDeque::new(),
    connected: false,
    attached: false,
});
pub fn ethernet_receive(frame: Vec<u8>) {
    let mut q = ETHERNET.lock();
    if q.connected && q.rx.len() < 64 {
        q.rx.push_back(frame);
    }
}
struct Adapter([u8; 6]);
impl crate::kernel::net::EthernetDevice for Adapter {
    fn mac_address(&self) -> [u8; 6] {
        self.0
    }
    fn receive(&mut self) -> Option<Vec<u8>> {
        ETHERNET.lock().rx.pop_front()
    }
    fn can_transmit(&mut self) -> bool {
        let q = ETHERNET.lock();
        q.connected && q.tx.len() < 64
    }
    fn transmit(&mut self, frame: &[u8]) -> bool {
        let mut q = ETHERNET.lock();
        if !q.connected || q.tx.len() >= 64 {
            return false;
        }
        q.tx.push_back(frame.to_vec());
        true
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
    fn content_version(&self, _: u64) -> Result<Option<crate::kernel::vfs::ContentVersion>, i32> {
        Ok(None)
    }

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
        if CONNECTION.lock().connection.is_some() {
            return -16;
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
