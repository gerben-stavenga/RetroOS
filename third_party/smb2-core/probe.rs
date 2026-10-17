//! Host-side integration probe for the freestanding protocol implementation.
use smb2_core::{
    Error, Result,
    auth::ntlm::NtlmCredentials,
    client::{Client, Transport},
    msg::create::CreateDisposition,
};
use std::{
    io::{Read, Write},
    net::TcpStream,
};
struct Tcp(TcpStream);
impl Transport for Tcp {
    fn send_all(&mut self, b: &[u8]) -> Result<()> {
        self.0.write_all(b).map_err(|_| Error::Transport)
    }
    fn receive_exact(&mut self, b: &mut [u8]) -> Result<()> {
        self.0.read_exact(b).map_err(|_| Error::Transport)
    }
}
fn entropy(b: &mut [u8]) -> Result<()> {
    std::fs::File::open("/dev/urandom")
        .unwrap()
        .read_exact(b)
        .map_err(|_| Error::Unavailable)
}
fn time() -> u64 {
    (std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + 11_644_473_600)
        * 10_000_000
}
fn main() {
    let address = std::env::var("SMB_ADDRESS").unwrap_or("127.0.0.1:1445".into());
    let username = std::env::var("SMB_USERNAME").expect("set SMB_USERNAME");
    let password = std::env::var("SMB_PASSWORD").expect("set SMB_PASSWORD");
    let stream = TcpStream::connect(address).unwrap();
    stream
        .set_read_timeout(Some(std::time::Duration::from_secs(5)))
        .unwrap();
    let mut c = Client::connect(
        Tcp(stream),
        "127.0.0.1",
        "share",
        NtlmCredentials {
            username,
            password,
            domain: String::new(),
        },
        entropy,
        time,
    )
    .expect("signed SMB connect");
    let file = c
        .open(
            "probe.txt",
            0x0013_019f,
            CreateDisposition::FileOverwriteIf,
            0x40,
        )
        .unwrap();
    assert_eq!(c.write(file.file_id, 0, b"RetroOS SMB2\n").unwrap(), 13);
    assert_eq!(c.read(file.file_id, 0, 100).unwrap(), b"RetroOS SMB2\n");
    c.flush(file.file_id).unwrap();
    c.close(file.file_id).unwrap();
    println!("PASS: authenticated signed SMB2 create/write/read/flush/close");
}
