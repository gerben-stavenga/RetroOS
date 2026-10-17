//! Volatile resolver configuration from DHCP. An existing user file wins.
use crate::kernel::vfs::{self, DirEntry, Filesystem, Vnode};
use alloc::vec::Vec;
use smoltcp::wire::Ipv4Address;

struct Resolver(spin::Mutex<Vec<u8>>);
static RESOLVER: Resolver = Resolver(spin::Mutex::new(Vec::new()));

pub fn mount() {
    if let Some(file) = vfs::open_backing(b"etc/resolv.conf") {
        file.close();
        return;
    }
    vfs::mount(b"netconfig/", &RESOLVER);
    vfs::hide_mount(b"netconfig/");
    vfs::bind(b"etc/resolv.conf", b"netconfig/resolv.conf");
}

pub fn update(servers: &[Ipv4Address]) {
    let mut text = Vec::new();
    for server in servers {
        let a = server.octets();
        text.extend_from_slice(
            alloc::format!("nameserver {}.{}.{}.{}\n", a[0], a[1], a[2], a[3]).as_bytes(),
        );
    }
    *RESOLVER.0.lock() = text;
}

impl Filesystem for Resolver {
    fn open(&self, path: &[u8]) -> Option<Vnode> {
        path.eq_ignore_ascii_case(b"resolv.conf").then(|| Vnode {
            handle: 1,
            size: self.0.lock().len() as u32,
            mode: 0o444,
        })
    }
    fn read(&self, _: u64, offset: u32, out: &mut [u8], _: u32) -> i32 {
        let bytes = self.0.lock();
        let offset = (offset as usize).min(bytes.len());
        let count = out.len().min(bytes.len() - offset);
        out[..count].copy_from_slice(&bytes[offset..offset + count]);
        count as i32
    }
    fn write(&self, _: u64, _: u32, _: &[u8]) -> i32 {
        -30
    }
    fn dir_exists(&self, path: &[u8]) -> bool {
        path.is_empty()
    }
    fn readdir(&self, _: &[u8], _: u64, _: &mut Vec<DirEntry>, _: usize) -> Option<u64> {
        None
    }
}
