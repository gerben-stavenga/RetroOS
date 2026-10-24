//! Volatile DHCP resolver; direct user DNS servers take precedence.
//! Linux loopback DNS stubs need a daemon absent from the native kernel.
use crate::kernel::vfs::{self, DirEntry, Filesystem, Vnode};
use alloc::vec::Vec;
use smoltcp::wire::Ipv4Address;

struct Resolver(spin::Mutex<Vec<u8>>);
static RESOLVER: Resolver = Resolver(spin::Mutex::new(Vec::new()));

/// Keep a configured non-loopback resolver. Empty configurations and local
/// stubs (systemd-resolved, dnsmasq, etc.) cannot resolve on the native stack.
fn direct_resolver(bytes: &[u8]) -> bool {
    bytes.split(|b| *b == b'\n').any(|line| {
        let line = line
            .split(|b| matches!(b, b'#' | b';'))
            .next()
            .unwrap_or_default();
        let mut words = line
            .split(u8::is_ascii_whitespace)
            .filter(|w| !w.is_empty());
        if words.next() != Some(b"nameserver".as_slice()) {
            return false;
        }
        let Some(address) = words.next() else {
            return false;
        };
        !(address.starts_with(b"127.") || address == b"::1" || address == b"0:0:0:0:0:0:0:1")
    })
}
pub fn mount() {
    if let Some(file) = vfs::open_backing(b"etc/resolv.conf") {
        let mut bytes = [0; 4096];
        let keep = {
            let _serial = vfs::serialize_fs();
            let n = file.read_at(0, &mut bytes);
            let keep =
                file.size() > bytes.len() as u32 || n > 0 && direct_resolver(&bytes[..n as usize]);
            file.close();
            keep
        };
        if keep {
            crate::compact_println!("Network: keeping configured DNS resolver");
            return;
        }
    }
    vfs::mount(b"netconfig/", &RESOLVER);
    vfs::hide_mount(b"netconfig/");
    vfs::bind(b"etc/resolv.conf", b"netconfig/resolv.conf");
    crate::compact_println!("Network: using DHCP DNS resolver (no usable direct resolver)");
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
    fn content_version(&self, _: u64) -> Result<Option<crate::kernel::vfs::ContentVersion>, i32> {
        Ok(None)
    }

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

#[cfg(test)]
mod tests {
    use super::direct_resolver;
    #[test]
    fn linux_daemon_stubs_and_empty_configuration_need_dhcp_dns() {
        for value in [
            b"".as_slice(),
            b"# nameserver 8.8.8.8\n",
            b"nameserver 127.0.0.53\noptions edns0 trust-ad\n",
            b"nameserver 127.0.0.1\nnameserver ::1\n",
            b"nameserver 0:0:0:0:0:0:0:1\n",
        ] {
            assert!(!direct_resolver(value));
        }
    }
    #[test]
    fn explicitly_configured_network_dns_is_preserved() {
        for value in [
            b"nameserver 192.168.1.254\n".as_slice(),
            b"  nameserver\t9.9.9.9 # manual\n",
            b"nameserver 127.0.0.53\nnameserver 10.0.0.1\n",
            b"nameserver 2001:db8::53\n",
        ] {
            assert!(direct_resolver(value));
        }
    }
}
