//! Private anonymous ranges eligible for demand-zero page reclamation.
use super::*;

#[derive(Clone, Default)]
pub(super) struct Anonymous { ranges: alloc::vec::Vec<(usize, usize)> }

impl Anonymous {
    pub fn contains(&self, start: usize, end: usize) -> bool {
        self.ranges.iter().any(|&(lo, hi)| lo <= start && end <= hi)
    }

    pub fn remove(&mut self, start: usize, end: usize) {
        if start >= end { return; }
        let mut index = 0;
        while index < self.ranges.len() {
            let (lo, hi) = self.ranges[index];
            if hi <= start || lo >= end { index += 1; continue; }
            if lo < start && hi > end {
                self.ranges[index] = (lo, start);
                self.ranges.insert(index + 1, (end, hi));
                break;
            } else if lo < start {
                self.ranges[index].1 = start;
                index += 1;
            } else if hi > end {
                self.ranges[index].0 = end;
                break;
            } else {
                self.ranges.remove(index);
            }
        }
    }

    pub fn add(&mut self, start: usize, end: usize) {
        if start >= end { return; }
        self.remove(start, end);
        self.ranges.push((start, end));
        self.ranges.sort_unstable();
        let mut index = 0;
        while index + 1 < self.ranges.len() {
            if self.ranges[index].1 >= self.ranges[index + 1].0 {
                self.ranges[index].1 = self.ranges[index].1.max(self.ranges[index + 1].1);
                self.ranges.remove(index + 1);
            } else { index += 1; }
        }
    }
}

pub(super) fn call<A: crate::Arch>(machine: &mut A, linux: &LinuxState, a: &Args) -> SyscallResult {
    if a.a0 & 4095 != 0 { return SyscallResult::val(-EINVAL); }
    let Some(end) = a.a0.checked_add(a.a1).and_then(|n| n.checked_add(4095))
        .map(|n| n & !4095).filter(|end| *end <= 0xc0000000)
        else { return SyscallResult::val(-EINVAL); };
    match a.a2 {
        // Access, merging, huge-page and dump hints do not change contents.
        // This kernel does not merge pages, allocate THPs or produce core dumps.
        0..=3 | 12..=17 => SyscallResult::val(0),
        4 | 8 => {
            if a.a1 == 0 { return SyscallResult::val(0); }
            let (start, end) = (a.a0 as usize, end as usize);
            if !linux.anonymous_mappings.contains(start, end) { return SyscallResult::val(-EINVAL); }
            if a.a2 == 4 {
                // Drop only this address space's frames. Fork siblings retain
                // their COW references; a later access gets a fresh zero page.
                machine.unmap_range(start / 4096, (end - start) / 4096);
            }
            // MADV_FREE is lazy: retaining contents until pressure is valid.
            SyscallResult::val(0)
        }
        // Fork inheritance and hole punching require additional semantics.
        _ => SyscallResult::val(-EINVAL),
    }
}

#[cfg(test)]
mod tests {
    use super::Anonymous;
    #[test]
    fn replacement_and_partial_unmap_exclude_files_and_holes() {
        let mut ranges = Anonymous::default();
        ranges.add(4096, 16384);
        ranges.remove(8192, 12288);
        assert!(ranges.contains(4096, 8192));
        assert!(!ranges.contains(4096, 16384));
        assert!(!ranges.contains(8192, 12288));
        assert!(ranges.contains(12288, 16384));
        ranges.add(8192, 12288);
        assert!(ranges.contains(4096, 16384));
        ranges.remove(0, 8192);
        ranges.remove(12288, 20480);
        assert_eq!(ranges.ranges, [(8192, 12288)]);
        let mut forked = ranges.clone();
        forked.remove(0, usize::MAX);
        assert!(ranges.contains(8192, 12288));
        assert!(!forked.contains(8192, 12288));
    }
}
