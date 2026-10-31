//! Boot-session shared storage. Guest views do not own these physical pages.
use super::*;

// Wine 11's session header contains 32744 user entries of 32 bytes each.
// The session exists for the lifetime of the kernel, including when no app has a view.
const SIZE: u32 = 1024 * 1024;
struct Arena {
    header: usize,
    chunks: Vec<usize>,
    next: u64,
    free: Vec<u64>,
    users: Vec<(u16, bool)>,
}
static BACKING: spin::Mutex<Arena> = spin::Mutex::new(Arena {
    header: 0,
    chunks: Vec::new(),
    next: SIZE as u64,
    free: Vec::new(),
    users: Vec::new(),
});
pub(super) fn allocate_object<A: crate::Arch>(machine: &mut A, id: u64) -> u64 {
    let mut arena = BACKING.lock();
    let offset = if let Some(o) = arena.free.pop() {
        o
    } else {
        let o = arena.next;
        arena.next += 8192;
        o
    };
    let index = (offset - SIZE as u64) as usize / 65536;
    while arena.chunks.len() <= index {
        arena
            .chunks
            .push(machine.alloc_shared_pages(16).as_ptr() as usize);
    }
    let ptr = (arena.chunks[index] + (offset as usize % 65536)) as *mut u8;
    // Preserve the seqlock generation across reuse so cached locators notice it.
    unsafe {
        let version = begin_write(ptr);
        core::ptr::write_bytes(ptr.add(8), 0, 8184);
        core::ptr::write_volatile(ptr.add(8) as *mut u64, id);
        end_write(ptr, version);
    }
    offset
}
pub(super) fn release_object(offset: u64) {
    let mut arena = BACKING.lock();
    let ptr = (arena.chunks[(offset - SIZE as u64) as usize / 65536] + offset as usize % 65536)
        as *mut u8;
    unsafe {
        let version = begin_write(ptr);
        core::ptr::write_volatile(ptr.add(8) as *mut u64, 0);
        end_write(ptr, version);
    }
    arena.free.push(offset);
}
#[derive(Default)]
pub(super) struct State {
    handles: Vec<bool>,
    views: Vec<u32>,
}

pub(super) fn call<A: crate::Arch>(
    machine: &mut A,
    state: &mut WindowsState,
    args: [u32; 6],
) -> u32 {
    let [op, handle, offset, size, flags, out] = args;
    if op == 0 {
        let slot = state
            .session
            .handles
            .iter()
            .position(|h| !*h)
            .unwrap_or(state.session.handles.len());
        if slot == state.session.handles.len() {
            state.session.handles.push(true);
        } else {
            state.session.handles[slot] = true;
        }
        machine.write::<u32>(out as usize, 0x73000000 | slot as u32 * 4);
        return 0;
    }
    if op == 3 {
        let Some(i) = state.session.views.iter().position(|&base| base == handle) else {
            return 0xc0000019;
        };
        memory::call(machine, state, Api::MemoryRelease, handle, 0, 1);
        state.session.views.swap_remove(i);
        return 0;
    }
    let Some(slot) = handle
        .checked_sub(0x73000000)
        .filter(|h| h % 4 == 0)
        .map(|h| h as usize / 4)
        .filter(|&i| state.session.handles.get(i) == Some(&true))
    else {
        return 0xc0000008;
    };
    if op == 2 {
        state.session.handles[slot] = false;
        return 0;
    }
    if op != 1 || offset & 65535 != 0 || flags != 2 {
        return 0xc000000d;
    }
    let mut backing = BACKING.lock();
    let (pointer, available) = if offset < SIZE {
        if backing.header == 0 {
            backing.header = machine.alloc_shared_pages(SIZE as usize / 4096).as_ptr() as usize;
        }
        (backing.header + offset as usize, SIZE - offset)
    } else {
        let Some(&ptr) = backing.chunks.get((offset - SIZE) as usize / 65536) else {
            return 0xc000001f;
        };
        (ptr, 65536)
    };
    let length = if size == 0 {
        available
    } else {
        let Some(n) = size
            .checked_add(4095)
            .map(|n| n & !4095)
            .filter(|&n| n <= available)
        else {
            return 0xc000001f;
        };
        n
    };
    let requested = machine.read::<u32>(out as usize);
    let base = memory::call(machine, state, Api::MemoryReserve, requested, length, 0);
    if base == 0 {
        return 0xc0000018;
    }
    let pointer = core::ptr::NonNull::new(pointer as *mut u8).unwrap();
    // The boot session owns the allocation permanently. Read-only guest aliases
    // are removed with the view/address space; they never free the allocation.
    unsafe {
        machine.map_shared_pages(base as usize / 4096, pointer, length as usize / 4096);
    }
    machine.set_page_flags(base as usize / 4096, length as usize / 4096, false, false);
    memory::adopt_shared(state, base, 0);
    state.session.views.push(base);
    machine.write::<u32>(out as usize, base);
    machine.write::<u32>(out as usize + 4, length);
    0
}

/// Update a live shared record while advancing the generation observed by Wine.
pub(super) fn write_object(offset: u64, data: &[u8]) {
    write_object_part(offset, 0, data);
}
pub(super) fn write_object_part(offset: u64, start: usize, data: &[u8]) {
    assert!(start <= 8176 && data.len() <= 8176 - start);
    let arena = BACKING.lock();
    let ptr = (arena.chunks[(offset - SIZE as u64) as usize / 65536] + offset as usize % 65536)
        as *mut u8;
    unsafe {
        let version = begin_write(ptr);
        core::ptr::copy_nonoverlapping(data.as_ptr(), ptr.add(16 + start), data.len());
        end_write(ptr, version);
    }
}

// Writers hold BACKING. Publish an odd low word before changing either the
// payload or the high word, then release the final even low word. This keeps
// Wine's 64-bit seqlock layout without requiring AtomicU64 on the i686 kernel.
unsafe fn begin_write(ptr: *mut u8) -> u32 {
    unsafe {
        (&*(ptr as *const core::sync::atomic::AtomicU32))
            .fetch_add(1, core::sync::atomic::Ordering::AcqRel)
    }
}
unsafe fn end_write(ptr: *mut u8, previous: u32) {
    unsafe {
        if previous == u32::MAX - 1 {
            let high = ptr.add(4) as *mut u32;
            core::ptr::write_volatile(high, core::ptr::read_volatile(high).wrapping_add(1));
        }
        (&*(ptr as *const core::sync::atomic::AtomicU32)).store(
            previous.wrapping_add(2),
            core::sync::atomic::Ordering::Release,
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn shared_sequence_carries_into_high_word_before_even_publication() {
        let mut words = [u32::MAX as u64 - 1, 0];
        let ptr = words.as_mut_ptr() as *mut u8;
        unsafe {
            let version = begin_write(ptr);
            assert_eq!(words[0], u32::MAX as u64);
            end_write(ptr, version);
        }
        assert_eq!(words[0], 1u64 << 32);
    }
}

// USER handles refer to session slots, independently of process object handles.
// Publish uniq last, and invalidate it before reusing any locator fields.
pub(super) fn allocate_user<A: crate::Arch>(
    machine: &mut A,
    id: u64,
    offset: u64,
    kind: u16,
    owner: [u32; 2],
) -> Option<u32> {
    use core::sync::atomic::{AtomicU32, Ordering};
    let mut arena = BACKING.lock();
    let i = arena
        .users
        .iter()
        .position(|u| !u.1)
        .unwrap_or(arena.users.len());
    if i >= 32744 {
        return None;
    }
    if arena.header == 0 {
        arena.header = machine.alloc_shared_pages(SIZE as usize / 4096).as_ptr() as usize;
    }
    if i == arena.users.len() {
        arena.users.push((0, false));
    }
    let generation = match arena.users[i].0.wrapping_add(1) {
        0 | 0xffff => 1,
        n => n,
    };
    arena.users[i] = (generation, true);
    let ptr = (arena.header + i * 32) as *mut u8;
    unsafe {
        core::ptr::write_volatile(ptr as *mut u64, offset);
        core::ptr::write_volatile(ptr.add(8) as *mut u32, owner[0]);
        core::ptr::write_volatile(ptr.add(12) as *mut u32, owner[1]);
        core::ptr::write_volatile(ptr.add(16) as *mut u64, id);
        (&*(ptr.add(24) as *const AtomicU32)).store(
            u32::from(kind) | ((generation as u32) << 16),
            Ordering::Release,
        );
    }
    Some(0x20 + (i as u32 * 2) | ((generation as u32) << 16))
}
pub(super) fn release_user(handle: u32) {
    use core::sync::atomic::{AtomicU32, Ordering};
    let mut arena = BACKING.lock();
    let i = ((handle & 0xffff) - 0x20) as usize / 2;
    assert_eq!(arena.users[i], ((handle >> 16) as u16, true));
    unsafe {
        (&*((arena.header + i * 32 + 24) as *const AtomicU32)).store(0, Ordering::Release);
    }
    arena.users[i].1 = false;
}
