//! Intrusive address-ordered AVL index of free extents. Each subtree records
//! its largest extent, so ordinary aligned allocations skip undersized holes.
//! Nodes live in free memory; maintaining the index never allocates.
use core::ptr::NonNull;
use super::align_up;

type Link = Option<NonNull<FreeBlock>>;

pub(super) struct FreeBlock {
    pub size: usize,
    // Also used by the bounded exact-size caches while outside this tree.
    pub next: Link,
    right: Link,
    height: usize,
    largest: usize,
}
impl FreeBlock {
    pub fn new(size: usize, next: Link) -> Self {
        Self { size, next, right: None, height: 1, largest: size }
    }
}
const HEADER: usize = core::mem::size_of::<FreeBlock>();

pub(super) struct FreeTree { root: Link }
impl FreeTree {
    pub const fn new() -> Self { Self { root: None } }

    /// The caller supplies a nonoverlapping, writable free extent. Only its
    /// surviving header must remain backed after page reclamation.
    pub fn insert_coalescing(&mut self, address: usize, size: usize) -> (usize, usize) {
        if size < HEADER { return (address, 0); }
        let (mut before, mut after, mut cursor) = (None, None, self.root);
        while let Some(node) = cursor {
            unsafe {
                if (node.as_ptr() as usize) < address {
                    before = Some(node); cursor = node.as_ref().right;
                } else {
                    after = Some(node); cursor = node.as_ref().next;
                }
            }
        }
        let (mut start, mut length) = (address, size);
        unsafe {
            if let Some(previous) = before {
                let end = previous.as_ptr() as usize + previous.as_ref().size;
                debug_assert!(end <= address, "overlapping heap free");
                if end == address {
                    start = previous.as_ptr() as usize;
                    length += previous.as_ref().size;
                    self.root = remove(self.root, start);
                }
            }
            if let Some(next) = after {
                let end = address + size;
                debug_assert!(end <= next.as_ptr() as usize, "overlapping heap free");
                if end == next.as_ptr() as usize {
                    length += next.as_ref().size;
                    self.root = remove(self.root, next.as_ptr() as usize);
                }
            }
            self.insert(start, length);
        }
        (start, length)
    }

    pub fn allocate(&mut self, size: usize, align: usize) -> Option<usize> {
        let (block, address) = unsafe { find(self.root, size, align)? };
        unsafe {
            let start = block.as_ptr() as usize;
            let length = block.as_ref().size;
            self.root = remove(self.root, start);
            let prefix = address - start;
            let suffix = length - prefix - size;
            if prefix >= HEADER { self.insert(start, prefix); }
            if suffix >= HEADER { self.insert(address + size, suffix); }
        }
        Some(address)
    }

    unsafe fn insert(&mut self, address: usize, size: usize) {
        let node = unsafe { NonNull::new_unchecked(address as *mut FreeBlock) };
        unsafe {
            node.as_ptr().write(FreeBlock::new(size, None));
            self.root = insert(self.root, node);
        }
    }
}

// All links below point to disjoint free extents whose headers remain mapped.
// Tree surgery preserves node addresses: keys are the physical header locations,
// so deletion moves links, never a successor's key/value into another header.
unsafe fn height(node: Link) -> usize { unsafe { node.map_or(0, |n| n.as_ref().height) } }
unsafe fn largest(node: Link) -> usize { unsafe { node.map_or(0, |n| n.as_ref().largest) } }
unsafe fn update(mut node: NonNull<FreeBlock>) {
    unsafe {
        let n = node.as_mut();
        n.height = 1 + height(n.next).max(height(n.right));
        n.largest = n.size.max(largest(n.next)).max(largest(n.right));
    }
}
unsafe fn rotate_left(mut root: NonNull<FreeBlock>) -> NonNull<FreeBlock> {
    unsafe {
        let mut next = root.as_ref().right.unwrap();
        root.as_mut().right = next.as_ref().next;
        next.as_mut().next = Some(root);
        update(root); update(next); next
    }
}
unsafe fn rotate_right(mut root: NonNull<FreeBlock>) -> NonNull<FreeBlock> {
    unsafe {
        let mut next = root.as_ref().next.unwrap();
        root.as_mut().next = next.as_ref().right;
        next.as_mut().right = Some(root);
        update(root); update(next); next
    }
}
unsafe fn balance(mut root: NonNull<FreeBlock>) -> NonNull<FreeBlock> {
    unsafe {
        update(root);
        let (left, right) = (root.as_ref().next, root.as_ref().right);
        if height(left) > height(right) + 1 {
            let l = left.unwrap();
            if height(l.as_ref().right) > height(l.as_ref().next) {
                root.as_mut().next = Some(rotate_left(l));
            }
            return rotate_right(root);
        }
        if height(right) > height(left) + 1 {
            let r = right.unwrap();
            if height(r.as_ref().next) > height(r.as_ref().right) {
                root.as_mut().right = Some(rotate_right(r));
            }
            return rotate_left(root);
        }
        root
    }
}
unsafe fn insert(root: Link, node: NonNull<FreeBlock>) -> Link {
    let Some(mut root) = root else { return Some(node); };
    unsafe {
        debug_assert_ne!(root, node);
        if node.as_ptr() < root.as_ptr() {
            root.as_mut().next = insert(root.as_ref().next, node);
        } else {
            root.as_mut().right = insert(root.as_ref().right, node);
        }
        Some(balance(root))
    }
}
unsafe fn take_first(mut root: NonNull<FreeBlock>) -> (Link, NonNull<FreeBlock>) {
    unsafe {
        let Some(left) = root.as_ref().next else { return (root.as_ref().right, root); };
        let (new_left, first) = take_first(left);
        root.as_mut().next = new_left;
        (Some(balance(root)), first)
    }
}
unsafe fn remove(root: Link, address: usize) -> Link {
    let mut root = root?;
    unsafe {
        let key = root.as_ptr() as usize;
        if address < key {
            root.as_mut().next = remove(root.as_ref().next, address);
        } else if address > key {
            root.as_mut().right = remove(root.as_ref().right, address);
        } else {
            let left = root.as_ref().next;
            let Some(right) = root.as_ref().right else { return left; };
            let (new_right, mut successor) = take_first(right);
            successor.as_mut().next = left;
            successor.as_mut().right = new_right;
            return Some(balance(successor));
        }
        Some(balance(root))
    }
}
unsafe fn find(root: Link, size: usize, align: usize) -> Option<(NonNull<FreeBlock>, usize)> {
    let root = root?;
    unsafe {
        let node = root.as_ref();
        if node.largest < size { return None; }
        if let Some(found) = find(node.next, size, align) { return Some(found); }
        let start = root.as_ptr() as usize;
        let mut address = align_up(start, align);
        if address != start && address - start < HEADER { address = align_up(start + HEADER, align); }
        if address.checked_sub(start)?.checked_add(size)? <= node.size { return Some((root, address)); }
        find(node.right, size, align)
    }
}
