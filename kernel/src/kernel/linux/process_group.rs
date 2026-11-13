//! POSIX process groups and sessions. Bookkeeping is independent of live roots.
use super::thread::MAX_THREADS;
#[derive(Clone, Copy)]
struct Process { present: bool, parent: i32, group: i32, session: i32, execed: bool }
const EMPTY: Process = Process { present: false, parent: -1, group: 0, session: 0, execed: false };
static PROCESSES: spin::Mutex<[Process; MAX_THREADS]> = spin::Mutex::new([EMPTY; MAX_THREADS]);

/// Reserve IDs while any member still names that group/session, even after its
/// leader was reaped. Reusing such an ID would make group-directed kill ambiguous.
pub(crate) fn reserved(pid: usize) -> bool {
    PROCESSES.lock().iter().any(|p| p.present && (p.group == pid as i32 || p.session == pid as i32))
}
pub(crate) fn create(pid: usize, parent: i32) {
    let mut all = PROCESSES.lock();
    let inherited = usize::try_from(parent).ok().and_then(|id| all.get(id)).copied().filter(|p| p.present);
    let (group, session) = inherited.map_or((pid as i32, pid as i32), |p| (p.group, p.session));
    all[pid] = Process { present: true, parent, group, session, execed: false };
}
pub(crate) fn exec(pid: i32) { PROCESSES.lock()[pid as usize].execed = true; }
pub(crate) fn reparent(pid: usize, parent: i32) { PROCESSES.lock()[pid].parent = parent; }
pub(crate) fn reap(pid: usize) { PROCESSES.lock()[pid] = EMPTY; }
pub(crate) fn group(pid: i32) -> i32 { lookup(pid, false) }
pub(crate) fn session(pid: i32) -> i32 { lookup(pid, true) }
fn lookup(pid: i32, session: bool) -> i32 {
    let all = PROCESSES.lock();
    match usize::try_from(pid).ok().and_then(|id| all.get(id)).filter(|p| p.present) {
        Some(p) => if session { p.session } else { p.group },
        None => -3,
    }
}
pub(crate) fn setsid(pid: i32) -> i32 {
    let mut all = PROCESSES.lock();
    if all.iter().any(|p| p.present && p.group == pid) { return -1; }
    let p = &mut all[pid as usize];
    p.group = pid; p.session = pid;
    pid
}
pub(crate) fn setpgid(caller: i32, pid: i32, group: i32) -> i32 {
    if pid < 0 || group < 0 { return -22; }
    let pid = if pid == 0 { caller } else { pid };
    let group = if group == 0 { pid } else { group };
    let mut all = PROCESSES.lock();
    let Some(target) = all.get(pid as usize).copied().filter(|p| p.present) else { return -3; };
    if pid != caller && target.parent != caller { return -3; }
    if pid != caller && target.execed { return -13; }
    let caller_session = all[caller as usize].session;
    if target.session != caller_session || target.session == pid { return -1; }
    if group != pid && !all.iter().any(|p| p.present && p.group == group && p.session == caller_session) { return -1; }
    all[pid as usize].group = group;
    0
}
