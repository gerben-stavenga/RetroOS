// A single present path through 32-bit PAE: PDPTE -> PD -> PT -> data.
// Keep the real Rust fork and sharing loops. Physical copies, faults, frame
// counters and CR3 reloads have explicit contracts in this model.

const FRAMES: usize = 7; // Three initial frames, three donations, and the null frame.
const OLD_PD: usize = 1;
const OLD_PT: usize = 2;
const OLD_DATA: usize = 3;

#[derive(Clone, Copy, Default)]
struct Slot(u64);

impl Entry for Slot {
    const ADDR_MASK: u64 = 0x000f_ffff_ffff_f000;

    fn raw(&self) -> u64 { self.0 }
    fn set_raw(&mut self, value: u64) { self.0 = value; }
}

struct Cpu {
    refs: [u8; FRAMES],
    children: [Slot; FRAMES],
    data: [u8; FRAMES],
    next_frame: usize,
    cached: Option<(usize, bool)>,
}

static mut CPU: Cpu = Cpu {
    refs: [0; FRAMES],
    children: [Slot(0); FRAMES],
    data: [0; FRAMES],
    next_frame: OLD_DATA + 1,
    cached: None,
};

fn root_base() -> usize { 0 }
fn recursive_idx() -> usize { 1 }
fn nx_enabled() -> bool { true }

#[derive(PartialEq, Eq)]
enum CpuMode { Pae }
fn cpu_mode() -> CpuMode { CpuMode::Pae }

fn invalidate_tlb() { unsafe { CPU.cached = None; } }
fn flush_tlb() { invalidate_tlb(); }

fn replace_entry<E: Entry>(slot: &mut E, incoming: E) -> E {
    std::mem::replace(slot, incoming)
}

mod memory {
    pub fn inc_shared_count(frame: u64) -> bool {
        unsafe {
            let refs = &mut (*(&raw mut super::CPU)).refs[frame as usize];
            assert!(*refs > 0 && *refs < 254);
            *refs += 1;
        }
        true
    }
}

fn drop_ref(frame: usize) -> bool {
    unsafe {
        let refs = &mut (*(&raw mut CPU)).refs[frame];
        assert!(*refs > 0);
        *refs -= 1;
        *refs == 0
    }
}

fn take_donation() -> usize {
    unsafe {
        let frame = CPU.next_frame;
        assert!(frame < FRAMES && CPU.refs[frame] == 0);
        CPU.next_frame += 1;
        CPU.refs[frame] = 1;
        frame
    }
}

fn split_table<E: Entry>(mut parent: E) -> E {
    let frame = parent.page() as usize;
    let refs = unsafe { CPU.refs[frame] };
    if refs > 1 {
        let new = take_donation();
        let mut source = [unsafe { CPU.children[frame] }];
        let mut dest = [Slot::default()];
        share_and_copy(&mut source, &mut dest);
        unsafe {
            CPU.children[frame] = source[0];
            CPU.children[new] = dest[0];
        }
        assert!(!drop_ref(frame));
        parent.set_raw((parent.raw() & !E::ADDR_MASK) | ((new as u64) << 12));
    }
    parent.set_hw_writable(true);
    invalidate_tlb();
    parent
}

fn cow_entry<E: Entry>(entries: &mut [E], index: usize) {
    // The fork only COWs the directory reached by a PDPTE here.
    entries[index] = split_table(entries[index]);
}

fn translate(root: Slot) -> (usize, bool) {
    unsafe {
        if let Some(cached) = CPU.cached {
            if kani::any() { return cached; }
        }
        let pde = CPU.children[root.page() as usize];
        let pte = CPU.children[pde.page() as usize];
        assert!(root.present() && pde.present() && pte.present());
        assert!(pde.user() && pte.user());
        // The PAE PDPTE's software writable bit has no hardware effect.
        let translation = (pte.page() as usize, pde.hw_writable() && pte.hw_writable());
        CPU.cached = Some(translation);
        translation
    }
}

fn write(root: Slot, value: u8) {
    let (mut frame, writable) = translate(root);
    if !writable {
        let pd = root.page() as usize;
        let pde = split_table(unsafe { CPU.children[pd] });
        let pt = pde.page() as usize;
        let mut pte = unsafe { CPU.children[pt] };
        frame = pte.page() as usize;
        assert!(pte.writable());
        if unsafe { CPU.refs[frame] } > 1 {
            let new = take_donation();
            unsafe { CPU.data[new] = CPU.data[frame]; }
            assert!(!drop_ref(frame));
            frame = new;
            pte.set_raw((pte.raw() & !Slot::ADDR_MASK) | ((frame as u64) << 12));
        }
        pte.set_hw_writable(true);
        unsafe {
            CPU.children[pd] = pde;
            CPU.children[pt] = pte;
        }
        invalidate_tlb();
        assert_eq!(translate(root), (frame, true));
    }
    unsafe { CPU.data[frame] = value; }
}

fn read(root: Slot) -> u8 {
    let (frame, _) = translate(root);
    unsafe { CPU.data[frame] }
}

fn release(entry: Slot, level: u8) {
    let frame = entry.page() as usize;
    if drop_ref(frame) && level > 0 {
        release(unsafe { CPU.children[frame] }, level - 1);
    }
}

fn assert_refs(roots: &[Slot]) {
    let mut expected = [0; FRAMES];
    let mut visited_pd = [false; FRAMES];
    let mut visited_pt = [false; FRAMES];
    for root in roots {
        let pd = root.page() as usize;
        expected[pd] += 1;
        if visited_pd[pd] { continue; }
        visited_pd[pd] = true;
        let pt = unsafe { CPU.children[pd] }.page() as usize;
        expected[pt] += 1;
        if visited_pt[pt] { continue; }
        visited_pt[pt] = true;
        let frame = unsafe { CPU.children[pt] }.page() as usize;
        expected[frame] += 1;
    }
    assert_eq!(unsafe { CPU.refs }, expected);
}

#[kani::proof]
#[kani::unwind(12)]
fn pae_fork_isolates_the_first_write_in_both_orders() {
    let original: u8 = kani::any();
    let first_value: u8 = kani::any();
    let second_value: u8 = kani::any();
    let mut parent = [Slot::new(OLD_PD as u64, true, true)];
    let mut child = [Slot::default()];
    unsafe {
        CPU.data[OLD_DATA] = original;
        CPU.children[OLD_PD] = Slot::new(OLD_PT as u64, true, true);
        CPU.children[OLD_PT] = Slot::new(OLD_DATA as u64, true, true);
        CPU.refs[OLD_PD] = 1;
        CPU.refs[OLD_PT] = 1;
        CPU.refs[OLD_DATA] = 1;
        CPU.cached = Some((OLD_DATA, true));
    }

    fork_generic(&mut parent, &mut child);
    let roots = [parent[0], child[0]];
    assert_refs(&roots);
    assert_eq!(translate(parent[0]), (OLD_DATA, false));
    invalidate_tlb(); // Switch to the child's root.
    assert_eq!(translate(child[0]), (OLD_DATA, false));

    let (first, second) = if kani::any() { (parent[0], child[0]) } else { (child[0], parent[0]) };
    invalidate_tlb();
    assert_eq!(read(first), original);
    write(first, first_value);
    assert_eq!(read(first), first_value);
    assert_refs(&roots);

    invalidate_tlb();
    assert_eq!(read(second), original);
    write(second, second_value);
    assert_eq!(read(second), second_value);
    assert_refs(&roots);
    assert_eq!(unsafe { CPU.next_frame }, FRAMES);

    invalidate_tlb();
    assert_eq!(read(first), first_value);
    // Teardown can happen in either order, independently of the write order.
    let (discarded, survivor, survivor_value) = if kani::any() {
        (first, second, second_value)
    } else { (second, first, first_value) };
    invalidate_tlb();
    release(discarded, 2);
    assert_refs(&[survivor]);
    assert_eq!(read(survivor), survivor_value);
    invalidate_tlb();
    release(survivor, 2);
    assert_refs(&[]);
}
