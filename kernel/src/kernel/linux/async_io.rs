//! Linux shared-address-space threads and asynchronous descriptor waits.
//! Contexts share the process's mappings and fd table, just as Win32 threads
//! do. Scheduling at syscall/IRQ boundaries preserves each context's TLS and
//! floating-point state. These are process resources, never host OS threads.
use super::*;
use alloc::{
    boxed::Box,
    rc::{Rc, Weak},
    vec::Vec,
};
use core::cell::{Cell, RefCell};
const IDLE: usize = 0x7ff6_0000;
const FIRST_FD: i32 = 1024;
#[derive(Clone, Copy)]
enum Wait {
    Ready,
    Futex(usize, u32, u64),
    Epoll(i32, usize, usize, u64),
    Sleep(u64),
    Poll(usize, usize, u64),
    Read(u8, usize, usize),
    Socket(i32, usize, usize),
    Exited,
}
struct Context {
    regs: Regs,
    fx: Box<dyn core::any::Any>,
    id: i32,
    comm: [u8; 16],
    clear_tid: usize,
    wait: Wait,
}
#[derive(Clone)]
struct Watch {
    fd: i32,
    events: u32,
    data: u64,
    last: u32,
    enabled: bool,
}
struct SocketEnd {
    packets: RefCell<alloc::collections::VecDeque<Vec<u8>>>,
    peer: RefCell<Weak<SocketEnd>>,
    packet_mode: bool,
    nonblock: Cell<bool>,
}
#[derive(Clone)]
enum Descriptor {
    Socket(Rc<SocketEnd>),
    Event {
        count: Rc<Cell<u64>>,
        semaphore: bool,
    },
    Epoll(Rc<RefCell<Vec<Watch>>>),
}
#[derive(Default)]
pub(super) struct State {
    contexts: Vec<Context>,
    next_thread: u32,
    active: usize,
    idle: bool,
    idle_mapped: bool,
    descriptors: Vec<Option<Descriptor>>,
    nonblock: u64,
    handles: Vec<Option<usize>>,
    cloexec: Vec<bool>,
}
fn ensure<A: crate::Arch>(
    machine: &mut A,
    kt: &thread::KernelThread<A>,
    s: &mut State,
    regs: &Regs,
) {
    if !s.contexts.is_empty() {
        return;
    }
    s.contexts.push(Context {
        regs: *regs,
        fx: Box::new(machine.clean_fx_template()),
        id: kt.tid,
        comm: kt.comm,
        clear_tid: 0,
        wait: Wait::Ready,
    });
    s.next_thread = 1;
    // Idle in the process's own space so interrupts and wakeups keep working.
    if !s.idle_mapped {
        machine.copy_to(IDLE, &[0xb8, 24, 0, 0, 0, 0x0f, 0x05, 0xeb, 0xf7]);
        machine.set_page_flags(IDLE / 4096, 1, false, true);
        s.idle_mapped = true;
    }
}
fn alloc_fd(s: &mut State, d: Descriptor) -> i32 {
    let object = s.descriptors.len();
    s.descriptors.push(Some(d));
    duplicate(s, object, FIRST_FD)
}
fn alloc_fd_cloexec(s: &mut State, descriptor: Descriptor, cloexec: bool) -> i32 {
    let fd = alloc_fd(s, descriptor);
    s.cloexec[(fd - FIRST_FD) as usize] = cloexec;
    fd
}
fn duplicate(s: &mut State, object: usize, min: i32) -> i32 {
    let start = (min.max(FIRST_FD) - FIRST_FD) as usize;
    if start > 65536 {
        return -EINVAL;
    }
    if s.handles.len() < start {
        s.handles.resize(start, None);
    }
    let i = (start..s.handles.len())
        .find(|&i| s.handles[i].is_none())
        .unwrap_or(s.handles.len());
    if i == s.handles.len() {
        s.handles.push(Some(object));
    } else {
        s.handles[i] = Some(object);
    }
    s.cloexec.resize(s.handles.len(), false);
    s.cloexec[i] = false;
    FIRST_FD + i as i32
}
fn object(s: &State, fd: i32) -> Option<usize> {
    *s.handles.get((fd - FIRST_FD) as usize)?
}
fn descriptor(s: &State, fd: i32) -> Option<&Descriptor> {
    s.descriptors.get(object(s, fd)?)?.as_ref()
}
fn deadline<A: crate::Arch>(machine: &A, ms: i32) -> u64 {
    if ms < 0 {
        u64::MAX
    } else {
        machine.now().saturating_add(ms as u64 * 1_000_000)
    }
}
fn ready<A: crate::Arch>(kt: &thread::KernelThread<A>, s: &State, fd: i32) -> u32 {
    if let Some(Descriptor::Event { count, .. }) = descriptor(s, fd) {
        return u32::from(count.get() > 0) | if count.get() < u64::MAX - 1 { 4 } else { 0 };
    }
    if let Some(Descriptor::Socket(end)) = descriptor(s, fd) {
        return u32::from(!end.packets.borrow().is_empty())
            | if end.peer.borrow().upgrade().is_some() {
                4
            } else {
                16
            };
    }
    if fd < 0 || fd as usize >= thread::MAX_FDS {
        return 0;
    }
    match kt.fds[fd as usize] {
        FdKind::PipeRead(i) => {
            if crate::kernel::kpipe::has_data(i) {
                1
            } else if !crate::kernel::kpipe::has_writers(i) {
                16
            } else {
                0
            }
        }
        FdKind::ConsoleOut | FdKind::PipeWrite(_) => 4,
        FdKind::Vfs(_) | FdKind::Dir { .. } => 5,
        _ => 0,
    }
}
fn poll<A: crate::Arch>(
    machine: &mut A,
    kt: &thread::KernelThread<A>,
    s: &State,
    ptr: usize,
    count: usize,
) -> i32 {
    let mut n = 0;
    for i in 0..count {
        let fd = machine.read::<i32>(ptr + i * 8);
        let requested = machine.read::<u16>(ptr + i * 8 + 4) as u32;
        let bits = if fd < 0 {
            0
        } else if descriptor(s, fd).is_none()
            && (fd as usize >= thread::MAX_FDS || kt.fds[fd as usize].is_none())
        {
            32
        } else {
            ready(kt, s, fd) & (requested | 0x18)
        };
        machine.write::<u16>(ptr + i * 8 + 6, bits as u16);
        n += i32::from(bits != 0);
    }
    n
}
fn epoll<A: crate::Arch>(
    machine: &mut A,
    kt: &thread::KernelThread<A>,
    s: &mut State,
    fd: i32,
    out: usize,
    max: usize,
) -> i32 {
    let Some(Descriptor::Epoll(watches)) = descriptor(s, fd) else {
        return -EBADF;
    };
    let events: Vec<u32> = watches
        .borrow()
        .iter()
        .map(|w| ready(kt, s, w.fd))
        .collect();
    let object_index = object(s, fd).unwrap();
    let Some(Some(Descriptor::Epoll(watches))) = s.descriptors.get_mut(object_index) else {
        unreachable!()
    };
    let mut watches = watches.borrow_mut();
    let mut n = 0;
    for (w, bits) in watches.iter_mut().zip(events) {
        let bits = bits & (w.events | 0x18);
        let deliver = if w.events & (1 << 31) != 0 {
            bits & !w.last
        } else {
            bits
        };
        if n < max || deliver == 0 {
            w.last = bits;
        }
        if w.enabled && deliver != 0 && n < max {
            machine.write::<u32>(out + n * 12, deliver);
            machine.write::<u64>(out + n * 12 + 4, w.data);
            n += 1;
            if w.events & (1 << 30) != 0 {
                w.enabled = false;
            }
        }
    }
    n as i32
}
fn reset_edge(s: &mut State, fd: i32) {
    let aliases: Vec<i32> = if let Some(index) = object(s, fd) {
        s.handles
            .iter()
            .enumerate()
            .filter_map(|(i, h)| (*h == Some(index)).then_some(FIRST_FD + i as i32))
            .collect()
    } else {
        alloc::vec![fd]
    };
    for d in &mut s.descriptors {
        if let Some(Descriptor::Epoll(ws)) = d {
            for w in ws.borrow_mut().iter_mut() {
                if aliases.contains(&w.fd) {
                    w.last = 0;
                }
            }
        }
    }
}
pub(super) fn call<A: crate::Arch>(
    machine: &mut A,
    kt: &mut thread::KernelThread<A>,
    linux: &mut LinuxState,
    regs: &mut Regs,
    nr: u32,
    a: &Args,
) -> Option<SyscallResult> {
    // Only the x86-64 syscall ABI is handled here.
    let s = &mut linux.async_io;
    let fd = a.a0 as i32;
    let ret = match nr {
        // These threads are scheduled inside one kernel process. A global
        // Yield would resume its launcher instead, and bypass schedule()'s
        // wait handling. Return normally so the shared-context scheduler
        // chooses another runnable thread (or polls the idle context).
        24 if !s.contexts.is_empty() => 0,
        53 => {
            let kind = a.a1 & !(0x80000 | 0x800);
            if a.a0 != 1 || !matches!(kind, 1 | 5) || a.a2 != 0 {
                -EINVAL
            } else {
                let make = || {
                    Rc::new(SocketEnd {
                        packets: Default::default(),
                        peer: Default::default(),
                        packet_mode: kind == 5,
                        nonblock: Cell::new(a.a1 & 0x800 != 0),
                    })
                };
                let one = make();
                let two = make();
                *one.peer.borrow_mut() = Rc::downgrade(&two);
                *two.peer.borrow_mut() = Rc::downgrade(&one);
                let one = alloc_fd(s, Descriptor::Socket(one));
                let two = alloc_fd(s, Descriptor::Socket(two));
                for fd in [one, two] {
                    let index = (fd - FIRST_FD) as usize;
                    s.cloexec.resize(s.handles.len(), false);
                    s.cloexec[index] = a.a1 & 0x80000 != 0;
                }
                machine.write::<i32>(a.a3 as usize, one);
                machine.write::<i32>(a.a3 as usize + 4, two);
                0
            }
        }
        0 | 1 | 44 | 45 if matches!(descriptor(s, fd), Some(Descriptor::Socket(_))) => {
            if matches!(nr, 0 | 45) {
                let end = match descriptor(s, fd).unwrap() {
                    Descriptor::Socket(end) => end.clone(),
                    _ => unreachable!(),
                };
                match socket_read(machine, &end, a.a1 as usize, a.a2 as usize) {
                    Some(n) => n,
                    None if end.nonblock.get() || (nr == 45 && a.a3 & 0x40 != 0) => -11,
                    None => {
                        ensure(machine, kt, s, regs);
                        s.contexts[s.active].wait = Wait::Socket(fd, a.a1 as usize, a.a2 as usize);
                        0
                    }
                }
            } else {
                let peer = match descriptor(s, fd).unwrap() {
                    Descriptor::Socket(end) => end.peer.borrow().upgrade(),
                    _ => unreachable!(),
                };
                if let Some(peer) = peer {
                    let mut data = alloc::vec![0; a.a2 as usize];
                    machine.copy_from(a.a1 as usize, &mut data);
                    if !data.is_empty() {
                        peer.packets.borrow_mut().push_back(data);
                    }
                    a.a2 as i32
                } else {
                    -EPIPE
                }
            }
        }
        291 => {
            if a.a0 & !0x80000 != 0 {
                -EINVAL
            } else {
                alloc_fd_cloexec(
                    s,
                    Descriptor::Epoll(Default::default()),
                    a.a0 & 0x80000 != 0,
                )
            }
        }
        290 => {
            if a.a1 & !(0x80000 | 0x800 | 1) != 0 {
                -EINVAL
            } else {
                alloc_fd_cloexec(
                    s,
                    Descriptor::Event {
                        count: Rc::new(Cell::new(a.a0 as u32 as u64)),
                        semaphore: a.a1 & 1 != 0,
                    },
                    a.a1 & 0x80000 != 0,
                )
            }
        }
        233 => {
            let watched = a.a2 as i32;
            if descriptor(s, fd).is_none() {
                -EBADF
            } else if watched == fd {
                -EINVAL
            } else if descriptor(s, watched).is_none()
                && (watched < 0
                    || watched as usize >= thread::MAX_FDS
                    || kt.fds[watched as usize].is_none())
            {
                -EBADF
            } else {
                let ptr = a.a3 as usize;
                let event = if a.a1 != 2 {
                    (machine.read::<u32>(ptr), machine.read::<u64>(ptr + 4))
                } else {
                    (0, 0)
                };
                let object_index = object(s, fd).unwrap();
                match s.descriptors[object_index].as_mut().unwrap() {
                    Descriptor::Epoll(ws) => {
                        let mut ws = ws.borrow_mut();
                        let i = ws.iter().position(|w| w.fd == watched);
                        match (a.a1, i) {
                            (1, None) => {
                                ws.push(Watch {
                                    fd: watched,
                                    events: event.0,
                                    data: event.1,
                                    last: 0,
                                    enabled: true,
                                });
                                0
                            }
                            (1, Some(_)) => -17,
                            (2, Some(i)) => {
                                ws.remove(i);
                                0
                            }
                            (3, Some(i)) => {
                                ws[i].events = event.0;
                                ws[i].data = event.1;
                                ws[i].enabled = true;
                                ws[i].last = 0;
                                0
                            }
                            (2 | 3, None) => -ENOENT,
                            _ => -EINVAL,
                        }
                    }
                    _ => -EINVAL,
                }
            }
        }
        7 => {
            if a.a1 > 4096 {
                -EINVAL
            } else {
                let n = poll(machine, kt, s, a.a0 as usize, a.a1 as usize);
                if n == 0 && a.a2 as i32 != 0 {
                    ensure(machine, kt, s, regs);
                    s.contexts[s.active].wait =
                        Wait::Poll(a.a0 as usize, a.a1 as usize, deadline(machine, a.a2 as i32));
                }
                n
            }
        }
        232 | 281 => {
            if a.a2 == 0 || a.a2 > i32::MAX as u64 {
                -EINVAL
            } else {
                let n = epoll(machine, kt, s, fd, a.a1 as usize, a.a2 as usize);
                if n == 0 && a.a3 as i32 != 0 {
                    ensure(machine, kt, s, regs);
                    s.contexts[s.active].wait = Wait::Epoll(
                        fd,
                        a.a1 as usize,
                        a.a2 as usize,
                        deadline(machine, a.a3 as i32),
                    );
                }
                n
            }
        }
        0 | 1 if descriptor(s, fd).is_some() => {
            if a.a2 < 8 {
                -EINVAL
            } else {
                let i = object(s, fd).unwrap();
                match s.descriptors[i].as_mut().unwrap() {
                    Descriptor::Event { count, semaphore } if nr == 0 => {
                        if count.get() == 0 {
                            -11
                        } else {
                            let value = if *semaphore { 1 } else { count.get() };
                            count.set(count.get() - value);
                            machine.write::<u64>(a.a1 as usize, value);
                            reset_edge(s, fd);
                            8
                        }
                    }
                    Descriptor::Event { count, .. } => {
                        let value = machine.read::<u64>(a.a1 as usize);
                        if value == u64::MAX {
                            -EINVAL
                        } else if value >= u64::MAX - count.get() {
                            -11
                        } else {
                            count.set(count.get() + value);
                            // eventfd writes notify epoll even while the counter
                            // is already readable (Mio leaves its waker unread).
                            reset_edge(s, fd);
                            8
                        }
                    }
                    _ => -EINVAL,
                }
            }
        }
        3 if descriptor(s, fd).is_some() => {
            close_virtual(s, fd);
            0
        }
        72 if descriptor(s, fd).is_some() => match a.a1 {
            0 | 1030 => {
                let i = object(s, fd).unwrap();
                let new = duplicate(s, i, a.a2 as i32);
                if new >= FIRST_FD {
                    s.cloexec.resize(s.handles.len(), false);
                    s.cloexec[(new - FIRST_FD) as usize] = a.a1 == 1030;
                }
                new
            }
            1 => i32::from(
                s.cloexec
                    .get((fd - FIRST_FD) as usize)
                    .copied()
                    .unwrap_or(false),
            ),
            2 => {
                s.cloexec.resize(s.handles.len(), false);
                s.cloexec[(fd - FIRST_FD) as usize] = a.a2 & 1 != 0;
                0
            }
            4 => {
                if let Some(Descriptor::Socket(end)) = descriptor(s, fd) {
                    end.nonblock.set(a.a2 & 0x800 != 0);
                }
                0
            }
            3 => {
                if let Some(Descriptor::Socket(end)) = descriptor(s, fd) {
                    2 | if end.nonblock.get() { 0x800 } else { 0 }
                } else {
                    0x802
                }
            }
            _ => -EINVAL,
        },
        72 if fd >= 0 && (fd as usize) < thread::MAX_FDS && a.a1 == 4 => {
            if a.a2 & 0x800 != 0 {
                s.nonblock |= 1u64 << fd;
            } else {
                s.nonblock &= !(1u64 << fd);
            }
            0
        }
        0 if fd >= 0 && (fd as usize) < thread::MAX_FDS && !s.contexts.is_empty() => {
            if let FdKind::PipeRead(i) = kt.fds[fd as usize] {
                let mut data = alloc::vec![0; a.a2 as usize];
                let n = crate::kernel::kpipe::read(i, &mut data);
                if n == 0 && crate::kernel::kpipe::has_writers(i) {
                    if s.nonblock & (1u64 << fd) != 0 {
                        -11
                    } else {
                        s.contexts[s.active].wait = Wait::Read(i, a.a1 as usize, a.a2 as usize);
                        0
                    }
                } else {
                    machine.copy_to(a.a1 as usize, &data[..n]);
                    reset_edge(s, fd);
                    n as i32
                }
            } else {
                return None;
            }
        }
        56 if a.a0 & 0x100 != 0 => {
            // CLONE_VM threads require shared files, signal handlers and group.
            const SHARED: u64 = 0x100 | 0x200 | 0x400 | 0x800 | 0x10000;
            const OPTIONAL: u64 = 0x40000 | 0x80000 | 0x100000 | 0x200000 | 0x400000 | 0x1000000;
            if a.a0 & SHARED != SHARED || a.a0 & !(SHARED | OPTIONAL) != 0 || a.a1 == 0 {
                -EINVAL
            } else {
                ensure(machine, kt, s, regs);
                let reuse = s
                    .contexts
                    .iter()
                    .position(|c| matches!(c.wait, Wait::Exited));
                if (reuse.is_none() && s.contexts.len() >= 256) || s.next_thread >= 65536 {
                    return Some(SyscallResult::val(-11)); // EAGAIN: thread limit.
                }
                let id = (((kt.tid as u32) << 16) | s.next_thread) as i32;
                s.next_thread += 1;
                let mut child = *regs;
                child.rax = 0;
                child.frame.rsp = a.a1;
                if a.a0 & 0x80000 != 0 {
                    child.fs = a.a4;
                }
                if a.a0 & 0x100000 != 0 {
                    machine.write::<i32>(a.a2 as usize, id);
                }
                if a.a0 & 0x1000000 != 0 {
                    machine.write::<i32>(a.a3 as usize, id);
                }
                let mut snapshot = machine.clean_fx_template();
                machine.switch_fx(&mut snapshot);
                let inherited_fx = snapshot;
                machine.switch_fx(&mut snapshot);
                let context = Context {
                    regs: child,
                    fx: Box::new(inherited_fx),
                    id,
                    comm: s.contexts[s.active].comm,
                    clear_tid: if a.a0 & 0x200000 != 0 {
                        a.a3 as usize
                    } else {
                        0
                    },
                    wait: Wait::Ready,
                };
                if let Some(index) = reuse {
                    s.contexts[index] = context;
                } else {
                    s.contexts.push(context);
                }
                id
            }
        }
        157 => match a.a0 {
            15 | 16 if a.a1 == 0 => -EFAULT,
            15 => {
                ensure(machine, kt, s, regs);
                let mut name = [0; 16];
                for (i, slot) in name.iter_mut().take(15).enumerate() {
                    *slot = machine.read::<u8>(a.a1 as usize + i);
                    if *slot == 0 {
                        break;
                    }
                }
                s.contexts[s.active].comm = name;
                if s.active == 0 {
                    kt.comm = name;
                }
                0
            }
            16 => {
                let mut name = if s.contexts.is_empty() {
                    kt.comm
                } else {
                    s.contexts[s.active].comm
                };
                name[15] = 0;
                machine.copy_to(a.a1 as usize, &name);
                0
            }
            _ => -EINVAL,
        },
        186 => {
            if s.contexts.is_empty() {
                kt.tid
            } else {
                s.contexts[s.active].id
            }
        }
        218 => {
            ensure(machine, kt, s, regs);
            s.contexts[s.active].clear_tid = a.a0 as usize;
            s.contexts[s.active].id
        }
        60 if !s.contexts.is_empty() => {
            let c = &mut s.contexts[s.active];
            if c.clear_tid != 0 {
                machine.write::<u32>(c.clear_tid, 0);
            }
            c.wait = Wait::Exited;
            if s.contexts.iter().all(|c| matches!(c.wait, Wait::Exited)) {
                return Some(SyscallResult::act(
                    0,
                    thread::KernelAction::Exit(a.a0 as i32),
                ));
            }
            0
        }
        202 => {
            let op = a.a1 as u32 & 0x7f;
            match op {
                0 | 9 => {
                    if machine.read::<u32>(a.a0 as usize) != a.a2 as u32 {
                        -11
                    } else {
                        ensure(machine, kt, s, regs);
                        let until = if a.a3 == 0 {
                            u64::MAX
                        } else {
                            let sec = machine.read::<u64>(a.a3 as usize);
                            let ns = machine.read::<u64>(a.a3 as usize + 8);
                            let time = sec.saturating_mul(1_000_000_000).saturating_add(ns);
                            if op == 9 {
                                time
                            } else {
                                machine.now().saturating_add(time)
                            }
                        };
                        s.contexts[s.active].wait = Wait::Futex(a.a0 as usize, a.a2 as u32, until);
                        0
                    }
                }
                1 | 10 => {
                    let mut n = 0;
                    for c in &mut s.contexts {
                        if matches!(c.wait, Wait::Futex(addr, _, _) if addr == a.a0 as usize)
                            && n < a.a2
                        {
                            c.wait = Wait::Ready;
                            c.regs.rax = 0;
                            n += 1;
                        }
                    }
                    n as i32
                }
                _ => -ENOSYS,
            }
        }
        35 | 230 => {
            ensure(machine, kt, s, regs);
            let ptr = if nr == 35 { a.a0 } else { a.a2 } as usize;
            let ns = machine
                .read::<u64>(ptr)
                .saturating_mul(1_000_000_000)
                .saturating_add(machine.read::<u64>(ptr + 8));
            s.contexts[s.active].wait = Wait::Sleep(if nr == 230 && a.a1 & 1 != 0 {
                ns
            } else {
                machine.now().saturating_add(ns)
            });
            0
        }
        228 | 96 => {
            let out = if nr == 96 { a.a0 } else { a.a1 } as usize;
            let ns = machine.now();
            machine.write::<u64>(out, ns / 1_000_000_000);
            machine.write::<u64>(
                out + 8,
                if nr == 96 {
                    ns % 1_000_000_000 / 1000
                } else {
                    ns % 1_000_000_000
                },
            );
            0
        }
        204 => {
            if a.a1 < 8 {
                -EINVAL
            } else {
                machine.zero(a.a2 as usize, a.a1 as usize);
                machine.write::<u64>(a.a2 as usize, 1);
                8
            }
        }
        // No guest signals are delivered yet, but musl needs to register its
        // per-thread alternate stack. Do not claim previous stack contents.
        131 => {
            if a.a1 != 0 {
                machine.zero(a.a1 as usize, 24);
                machine.write::<u32>(a.a1 as usize + 8, 2);
            }
            0
        }
        _ => return None,
    };
    Some(SyscallResult::val(ret))
}
pub(super) fn schedule<A: crate::Arch>(
    machine: &mut A,
    kt: &thread::KernelThread<A>,
    linux: &mut LinuxState,
    regs: &mut Regs,
) {
    if regs.mode() != crate::UserMode::Mode64 {
        return;
    }
    let s = &mut linux.async_io;
    if s.contexts.is_empty() {
        return;
    }
    if !s.idle {
        s.contexts[s.active].regs = *regs;
    }
    let now = machine.now();
    for i in 0..s.contexts.len() {
        let result = match s.contexts[i].wait {
            Wait::Futex(addr, val, end) => {
                if machine.read::<u32>(addr) != val {
                    Some(0)
                } else if now >= end {
                    Some(-110)
                } else {
                    None
                }
            }
            Wait::Epoll(fd, out, max, end) => {
                let n = epoll(machine, kt, s, fd, out, max);
                if n != 0 || now >= end { Some(n) } else { None }
            }
            Wait::Sleep(end) if now >= end => Some(0),
            Wait::Poll(ptr, count, end) => {
                let n = poll(machine, kt, s, ptr, count);
                if n != 0 || now >= end { Some(n) } else { None }
            }
            Wait::Socket(fd, out, count) => match descriptor(s, fd) {
                Some(Descriptor::Socket(end)) => socket_read(machine, end, out, count),
                _ => Some(-EBADF),
            },
            Wait::Read(pipe, out, count) => {
                let mut data = alloc::vec![0; count];
                let n = crate::kernel::kpipe::read(pipe, &mut data);
                if n > 0 || !crate::kernel::kpipe::has_writers(pipe) {
                    machine.copy_to(out, &data[..n]);
                    Some(n as i32)
                } else {
                    None
                }
            }
            _ => None,
        };
        if let Some(result) = result {
            s.contexts[i].regs.rax = result as i64 as u64;
            s.contexts[i].wait = Wait::Ready;
        }
    }
    let next = (1..=s.contexts.len())
        .map(|n| (s.active + n) % s.contexts.len())
        .find(|&i| matches!(s.contexts[i].wait, Wait::Ready));
    if let Some(next) = next {
        if next != s.active {
            let mut fx = *s.contexts[next].fx.downcast_ref::<A::Fx>().unwrap();
            machine.switch_fx(&mut fx);
            *s.contexts[s.active].fx.downcast_mut::<A::Fx>().unwrap() = fx;
        }
        s.active = next;
        s.idle = false;
        *regs = s.contexts[next].regs;
    } else {
        s.idle = true;
        regs.frame.rip = IDLE as u64;
    }
}

fn socket_read<A: crate::Arch>(
    machine: &mut A,
    end: &SocketEnd,
    out: usize,
    count: usize,
) -> Option<i32> {
    if count == 0 {
        return Some(0);
    }
    let mut packets = end.packets.borrow_mut();
    if let Some(mut packet) = packets.pop_front() {
        let n = count.min(packet.len());
        machine.copy_to(out, &packet[..n]);
        if !end.packet_mode && n < packet.len() {
            packet.drain(..n);
            packets.push_front(packet);
        }
        Some(n as i32)
    } else if end.peer.borrow().upgrade().is_none() {
        Some(0)
    } else {
        None
    }
}
fn close_virtual(s: &mut State, fd: i32) {
    if let Some(i) = object(s, fd) {
        s.handles[(fd - FIRST_FD) as usize] = None;
        if !s.handles.contains(&Some(i)) {
            s.descriptors[i] = None;
        }
    }
}
pub(super) fn close_cloexec(s: &mut State) {
    for i in 0..s.cloexec.len() {
        if s.cloexec[i] {
            close_virtual(s, FIRST_FD + i as i32);
            s.cloexec[i] = false;
        }
    }
}
pub(super) fn fork_state(s: &State) -> State {
    State {
        descriptors: s.descriptors.clone(),
        handles: s.handles.clone(),
        cloexec: s.cloexec.clone(),
        nonblock: s.nonblock,
        idle_mapped: s.idle_mapped,
        ..State::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn fork_shares_socket_endpoints_and_exec_closes_only_cloexec_handles() {
        let make = || {
            Rc::new(SocketEnd {
                packets: Default::default(),
                peer: Default::default(),
                packet_mode: true,
                nonblock: Cell::new(false),
            })
        };
        let input = make();
        let output = make();
        *input.peer.borrow_mut() = Rc::downgrade(&output);
        *output.peer.borrow_mut() = Rc::downgrade(&input);
        let input_weak = Rc::downgrade(&input);
        let output_weak = Rc::downgrade(&output);
        let mut parent = State {
            idle_mapped: true,
            ..State::default()
        };
        let r = alloc_fd(&mut parent, Descriptor::Socket(input));
        let w = alloc_fd(&mut parent, Descriptor::Socket(output));
        parent.cloexec[(w - FIRST_FD) as usize] = true;
        let mut child = fork_state(&parent);
        assert!(child.idle_mapped);
        assert!(!exec_state(&parent).idle_mapped);
        close_virtual(&mut child, r);
        close_virtual(&mut parent, w);
        assert!(output_weak.upgrade().is_some());
        close_cloexec(&mut child);
        assert!(output_weak.upgrade().is_none());
        assert!(input_weak.upgrade().is_some());
        // Reusing a descriptor number must clear the former CLOEXEC flag.
        let fd = alloc_fd(
            &mut child,
            Descriptor::Event {
                count: Rc::new(Cell::new(0)),
                semaphore: false,
            },
        );
        assert!(!child.cloexec[(fd - FIRST_FD) as usize]);
    }
    #[test]
    fn fork_shares_eventfd_counter() {
        let count = Rc::new(Cell::new(1));
        let mut parent = State::default();
        let fd = alloc_fd(
            &mut parent,
            Descriptor::Event {
                count: count.clone(),
                semaphore: false,
            },
        );
        let child = fork_state(&parent);
        if let Some(Descriptor::Event { count, .. }) = descriptor(&child, fd) {
            count.set(7);
        } else {
            panic!("missing inherited eventfd");
        }
        assert_eq!(count.get(), 7);
    }
}

pub(super) fn exec_state(s: &State) -> State {
    let mut inherited = fork_state(s);
    inherited.idle_mapped = false; // exec discarded the old address space.
    inherited
}
