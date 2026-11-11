//! Process identity files backed by RetroOS tasks, never by the host's /proc.
use crate::kernel::{
    thread,
    vfs::{DirEntry, Filesystem, Meta, Vnode},
};
use alloc::{collections::BTreeMap, format, string::String, vec::Vec};
use core::fmt::Write;
use spin::Mutex;

#[derive(Clone, Copy)]
struct Info {
    pid: i32,
    parent: i32,
    comm: [u8; 16],
    state: u8,
    start: u64,
}
#[derive(Default)]
struct Snapshot {
    current: i32,
    tasks: Vec<Info>,
    boot_time: Option<u64>,
}
struct Files {
    next: u64,
    bytes: BTreeMap<u64, Vec<u8>>,
}
pub struct ProcessFs {
    tasks: Mutex<Snapshot>,
    files: Mutex<Files>,
}
pub static PROCESSES: ProcessFs = ProcessFs {
    tasks: Mutex::new(Snapshot {
        current: 0,
        tasks: Vec::new(),
        boot_time: None,
    }),
    files: Mutex::new(Files {
        next: 1,
        bytes: BTreeMap::new(),
    }),
};

fn split(path: &[u8]) -> (&[u8], &[u8]) {
    match path.iter().position(|&c| c == b'/') {
        Some(at) => (&path[..at], &path[at + 1..]),
        None => (path, b""),
    }
}
fn numeric(path: &[u8]) -> Option<i32> {
    if path.is_empty() || !path.iter().all(u8::is_ascii_digit) {
        return None;
    }
    path.iter().try_fold(0i32, |n, c| {
        n.checked_mul(10)?.checked_add(i32::from(c - b'0'))
    })
}
fn stat_text(info: Info) -> Vec<u8> {
    let name = &info.comm[..info.comm.iter().position(|&c| c == 0).unwrap_or(16)];
    let mut text = format!(
        "{} ({}) {}",
        info.pid,
        String::from_utf8_lossy(name),
        info.state as char
    );
    for field in 4..=52 {
        let value: i128 = match field {
            4 => i128::from(info.parent.max(1)),
            5 | 6 => i128::from(info.pid),
            8 => -1,
            20 => 1,
            22 => i128::from(info.start),
            25 => i128::from(u64::MAX),
            _ => 0,
        };
        let _ = write!(text, " {}", value);
    }
    text.push('\n');
    text.into_bytes()
}
impl ProcessFs {
    pub fn publish<A: crate::Arch>(&self, threads: &[thread::Thread<A>], current: usize, ticks: u64) {
        let mut snapshot = self.tasks.lock();
        // Keep the wall-clock boot epoch stable as the RTC advances. Linux
        // procps combines this with each task's USER_HZ start time for lstart.
        if snapshot.boot_time.is_none() {
            snapshot.boot_time = crate::kernel::clock::rtc_unix_timestamp()
                .map(|now| u64::from(now).saturating_sub(ticks / 1000));
        }
        snapshot.current = current as i32;
        snapshot.tasks.clear();
        snapshot.tasks.extend(
            threads
                .iter()
                .filter(|t| t.kernel.state != thread::ThreadState::Unused)
                .map(|t| Info {
                    pid: t.kernel.tid,
                    parent: t.kernel.parent_tid,
                    comm: t.kernel.comm,
                    state: match t.kernel.state {
                        thread::ThreadState::Zombie => b'Z',
                        thread::ThreadState::Blocked => b'S',
                        _ => b'R',
                    },
                    start: t.kernel.time / 10, // Linux USER_HZ=100; kernel birth times are milliseconds.
                }),
        );
    }
    fn info(&self, name: &[u8]) -> Option<Info> {
        let snapshot = self.tasks.lock();
        let pid = if matches!(name, b"self" | b"thread-self") {
            snapshot.current
        } else {
            numeric(name)?
        };
        snapshot.tasks.iter().find(|i| i.pid == pid).copied()
    }
}
impl Filesystem for ProcessFs {
    fn dynamic_directory(&self, path: &[u8]) -> bool { path.is_empty() }
    fn format_name(&self) -> &'static str {
        "processes"
    }
    fn exclusive_path(&self, path: &[u8]) -> bool {
        let (name, rest) = split(path);
        path == b"stat" || (!name.is_empty() && name.iter().all(u8::is_ascii_digit))
            || matches!(name, b"self" | b"thread-self") && matches!(rest, b"" | b"stat")
    }
    fn open(&self, path: &[u8]) -> Option<Vnode> {
        let bytes = if path == b"stat" {
            // libproc2 requires the aggregate and per-CPU headers even for
            // a btime-only query. Execution is on the BSP; CPU accounting is
            // currently unavailable (zero), as in per-process stat fields.
            // Never import the host's counters or boot epoch through a union.
            format!("cpu 0 0 0 0 0 0 0 0 0 0\ncpu0 0 0 0 0 0 0 0 0 0 0\nbtime {}\n",
                self.tasks.lock().boot_time?).into_bytes()
        } else {
            let (name, rest) = split(path);
            if rest != b"stat" { return None; }
            stat_text(self.info(name)?)
        };
        let mut files = self.files.lock();
        let handle = files.next;
        files.next = handle.checked_add(1)?;
        let size = bytes.len() as u32;
        files.bytes.insert(handle, bytes);
        Some(Vnode {
            handle,
            size,
            mode: 0o100444,
        })
    }
    fn file_identity(&self, handle: u64) -> Option<u64> {
        Some(handle)
    }
    fn read(&self, handle: u64, offset: u32, out: &mut [u8], _size: u32) -> i32 {
        let files = self.files.lock();
        let Some(bytes) = files.bytes.get(&handle) else {
            return -9;
        };
        let start = (offset as usize).min(bytes.len());
        let count = out.len().min(bytes.len() - start);
        out[..count].copy_from_slice(&bytes[start..start + count]);
        count as i32
    }
    fn clunk(&self, handle: u64) -> i32 {
        self.files.lock().bytes.remove(&handle);
        0
    }
    fn write(&self, _handle: u64, _offset: u32, _bytes: &[u8]) -> i32 {
        -30
    }
    fn dir_exists(&self, path: &[u8]) -> bool {
        path.is_empty() || !path.contains(&b'/') && self.info(path).is_some()
    }
    fn meta(&self, path: &[u8]) -> Option<Meta> {
        Some(Meta {
            uid: 0,
            gid: 0,
            mode: if self.dir_exists(path) {
                0o40555
            } else {
                let (name, rest) = split(path);
                if path != b"stat" && (rest != b"stat" || self.info(name).is_none()) {
                    return None;
                }
                0o100444
            },
        })
    }
    fn readdir(
        &self,
        path: &[u8],
        cookie: u64,
        out: &mut Vec<DirEntry>,
        max: usize,
    ) -> Option<u64> {
        let names = if path.is_empty() {
            let mut names = self.tasks
                .lock()
                .tasks
                .iter()
                .map(|i| format!("{}", i.pid).into_bytes())
                .collect::<Vec<_>>();
            names.push(b"stat".to_vec());
            names
        } else if self.info(path).is_some() {
            alloc::vec![b"stat".to_vec()]
        } else {
            return None;
        };
        let start = cookie as usize;
        for name in names.iter().skip(start).take(max) {
            out.push(DirEntry {
                name: name.clone(),
                name_len: name.len(),
                short_name: None,
                size: 0,
                is_dir: path.is_empty() && name != b"stat",
                is_symlink: false,
                mode: if path.is_empty() && name != b"stat" { 0o40555 } else { 0o100444 },
                dos_attributes: None,
                mtime: 0,
                node: 0,
                mount_idx: 0,
            });
        }
        (start.saturating_add(max) < names.len()).then_some(start.saturating_add(max) as u64)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn stat_start_time_is_field_22_and_numeric_misses_never_fall_through() {
        let text = stat_text(Info {
            pid: 7,
            parent: 3,
            comm: *b"name with )     ",
            state: b'S',
            start: 123456,
        });
        let text = core::str::from_utf8(&text).unwrap();
        let (_, fields) = text.rsplit_once(") ").unwrap();
        assert_eq!(fields.split_whitespace().nth(19), Some("123456"));
        assert_eq!(fields.split_whitespace().count(), 50);
        assert!(PROCESSES.exclusive_path(b"9999999999999999/stat"));
        assert!(PROCESSES.exclusive_path(b"7/stat"));
        assert!(!PROCESSES.exclusive_path(b"sys/kernel/random/boot_id"));
        assert!(!PROCESSES.exclusive_path(b"self/fd"));
    }
}
