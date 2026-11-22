// Single-core PAE model for two adjacent user leaves under resident, unchanged
// parents that permit user reads, writes and fetches. User translations are
// non-global and NXE is enabled.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Leaf {
    frame: u64,
    present: bool,
    user: bool,
    writable: bool,
    executable: bool,
}

impl Leaf {
    const EMPTY: Self = Self {
        frame: 0,
        present: false,
        user: false,
        writable: false,
        executable: false,
    };

    fn arbitrary(frame: u64) -> Self {
        Self {
            frame,
            present: kani::any(),
            user: kani::any(),
            writable: kani::any(),
            executable: kani::any(),
        }
    }

    fn user_access(self, access: Access) -> Option<u64> {
        let allowed = self.present && self.user && match access {
            Access::Read => true,
            Access::Write => self.writable,
            Access::Fetch => self.executable,
        };
        allowed.then_some(self.frame)
    }
}

#[derive(Clone, Copy)]
enum Access {
    Read,
    Write,
    Fetch,
}

struct Cpu {
    leaves: [Leaf; 2],
    tlb: [Option<Leaf>; 2],
    displaced: [Option<u64>; 2],
    fail_at: usize,
    in_mapping_call: bool,
}

impl Cpu {
    fn access(&self, slot: usize, use_cache: bool, access: Access) -> Option<u64> {
        assert!(!self.in_mapping_call);
        let cached = if use_cache { self.tlb[slot] } else { None };
        cached.unwrap_or(self.leaves[slot]).user_access(access)
    }
}

static mut CPU: Cpu = Cpu {
    leaves: [Leaf::EMPTY; 2],
    tlb: [None; 2],
    displaced: [None; 2],
    fail_at: 2,
    in_mapping_call: false,
};

// Contracts for the modeled boundaries. The wrapper, batch logic, and
// sync-then-flush ordering are compiled from the real arch-metal source.
type PageEntry = Leaf;

#[derive(Clone, Copy)]
struct UserPage(usize);

impl UserPage {
    fn offset(self, count: usize) -> Result<Self, MappingError> {
        self.0.checked_add(count)
            .filter(|&index| index < 2)
            .map(Self)
            .ok_or(MappingError::InvalidAddress)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum MappingError {
    InvalidAddress,
    NeedPages,
}

#[derive(Debug, PartialEq, Eq)]
struct MappingFailure {
    completed: usize,
    error: MappingError,
}

struct PagingGuard;

impl PagingGuard {
    fn lock() -> Self {
        unsafe {
            assert!(!CPU.in_mapping_call);
            CPU.in_mapping_call = true;
        }
        Self
    }
}

impl Drop for PagingGuard {
    fn drop(&mut self) {
        unsafe { CPU.in_mapping_call = false; }
    }
}

fn replace_page(page: UserPage, incoming: PageEntry) -> Result<(), MappingError> {
    let cpu = unsafe { &mut *(&raw mut CPU) };
    assert!(cpu.in_mapping_call);
    if page.0 == cpu.fail_at {
        return Err(MappingError::NeedPages);
    }
    let old = std::mem::replace(&mut cpu.leaves[page.0], incoming);
    // The initial present frames have one owner and no other aliases.
    cpu.displaced[page.0] = old.present.then_some(old.frame);
    // A PTE store leaves a cached translation intact.
    Ok(())
}

fn sync_hw_pdpt() {
    // Unchanged parents are already synchronized.
}

mod x86 {
    pub fn flush_tlb() {
        unsafe {
            assert!(super::CPU.in_mapping_call);
            (&raw mut super::CPU.tlb).write([None; 2]);
        }
    }
}

#[kani::proof]
#[kani::unwind(4)]
fn replacement_returns_with_no_stale_user_translations() {
    let old = [Leaf::arbitrary(32), Leaf::arbitrary(33)];
    let new = [Leaf::arbitrary(34), Leaf::arbitrary(35)];
    let fail_at: usize = kani::any();
    kani::assume(fail_at <= 2);
    let cached = old.map(|leaf| (leaf.present && kani::any()).then_some(leaf));
    unsafe {
        (&raw mut CPU).write(Cpu {
            leaves: old,
            tlb: cached,
            displaced: [None; 2],
            fail_at,
            in_mapping_call: false,
        });
    }

    let mut args = Replace { page: UserPage(0), entries: &new, result: Ok(()) };
    replace_mappings(&mut args);

    let expected_result = if fail_at == 2 {
        Ok(())
    } else {
        Err(MappingFailure { completed: fail_at, error: MappingError::NeedPages })
    };
    assert_eq!(args.result, expected_result);
    let cpu = unsafe { &*(&raw const CPU) };
    let slot: usize = kani::any();
    kani::assume(slot < 2);
    let expected = if slot < fail_at { new[slot] } else { old[slot] };
    let displaced = (slot < fail_at && old[slot].present).then_some(old[slot].frame);
    assert_eq!(cpu.leaves[slot], expected);
    assert_eq!(cpu.displaced[slot], displaced);

    let access = match kani::any::<u8>() {
        0 => Access::Read,
        1 => Access::Write,
        _ => Access::Fetch,
    };
    let translated = cpu.access(slot, kani::any(), access);
    assert_eq!(translated, expected.user_access(access));
    if let Some(frame) = translated {
        assert_ne!(Some(frame), cpu.displaced[0]);
        assert_ne!(Some(frame), cpu.displaced[1]);
    }
}
