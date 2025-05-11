//
// Created by gerben stavenga on 6/24/23.
//

#ifndef OS_PAGING_H
#define OS_PAGING_H

#include <cstdint>

#include "boot/boot.h"
#include "entry.h"
#include "src/freestanding/utils.h"

// There is a wonderful property of the x86 paging system, namely that all "page tables" at all levels are similar in
// size and structure. On 32bit the address space is divided into 4kb pages, with each page table fitting exactly in
// a page itself, giving 1024 entries of 4 bytes each. This leads to 1024^2 * 4kb = 4gb of address space matching
// the 32 bit address space perfectly. The easiest way of visualizing is to think of the address space instead of
// addressing bytes but addressing native machine words. This means 4gb = 2^30 4-byte machine words and 30 factors as
// 3 * 10, so we need 3 levels (page, page table(pt), page dir(pd)) each of 1024 4-byte words. On 64 bit this nice coincidence
// doesn't work anymore, indeed 2^64 bytes = 2^61 8-byte machine words, and 61 is prime. Instead AMD restricted the
// address space to 48 bits, which gives 2^45 8-byte machine words and 45 factors as 9 * 5, leading to 5 levels
// page, pt, pd, page dir pointer table(pdpt), page map level 4(pml4) each of 512 8-byte machine words.
//
// Anyway, given that we have a hierarchy of page tables that are all the same size and the same structure, we can
// think of them as having N levels, each of 2^M entries. Level 0 are the machine words, level 1 the pages and
// level N is the root page, ie. for 32bit N = 3 and M = 10, for 64 bit N = 5 and M = 9. Now an operating system
// must manipulate the content of the page tables, which requires that some of the pages at level 1 are in fact pages
// that are page table or higher level nodes, a back edge in tree. An operating system must keep track of this whole
// structure and the back edges, which could be a lot of bookkeeping. Due to the nice structure of the page tables we can
// point the first (or one any) entry of the root page to itself. This means that the low end of the address space
// [0, N^(L-1)) is covered by the root interpreted as root of a tree one layer less deep. This pattern continues to
// the next level where the root covers the addresses [0, N^(L-2)) as a tree two layers less deep. With finally
// [0, N) being the page of the root dir entries and [0, 1) being the physical address of the root page itself.
//
// This means that by just setting root[0] = phys_addr(root) we mapped all page tables at all levels in the virtual
// space and not only that, but also we mapped them at easily computable virtual addresses. This is technique is
// called recursive paging. Note we use first entry as it makes for the easiest explanation, in practice we often want
// the low range of memory available for user space, so we'd use the last entry, but this is not material. If we
// furthermore split the virtual address space in two ranges a privileged range and a user range, we have to set
// the U/S bit for each page properly. In our example we would have [0, kUserSpaceBase) privileged and
// [kUserSpaceBase, N^L) for user space. It is most convenient to choose kUserSpaceBase aligned to N^(L-1) so that
// only the root has a split between privileged and user space and all other nodes are entirely privileged
// or entirely user space. This means we can set the U/S bit of all non-root nodes to 1 relying only on the root node
// to set the proper access rights.
//
// So what to do on a page fault. Well it's either the user accessing space outside of it's allocation (sigsegv) or
// it's either the user or kernel accessing space that is not currently not mapped (swapped/COW). For now we will
// not do write protection or allocation and just allow user address everything in userspace.
//
/*
void page_fault(uintptr_t fault_addr, int error) {
    if ((error & kUser) && fault_addr < kUserSpaceBase) {
        // sigsegv
    } else {
        auto pt_entry = fault_addr / kPageSize;
        bool is_user_page = pt >= (kUserSpaceBase / kWordSize / (N^(L-1));
        // allocate page
        int page = AllocatePhysPage();
        (PageEntry*)(0)[pt_entry] = MakePageEntry(page, is_user_page);
    }
}
*/

// Simple 32bit paging gives pd -> pt -> page (3 * 10 + 2 = 32 bits)
// [0xFFC00000, 0x100000000) is covered by pd as pt and is array of all pt pages.
// [0xFFFFF000, 0x100000000) is covered by pd as page and is array of all pd pages.

// Higher level paging
// pml4 -> pdpt -> pd -> pt -> page  (5 * 9 + 3 = 48 bits)
// pml4 0x1FF points to itself, so [0xFF8000000000, 0x1000000000000) is covered by pml4 as pdpt.
// [0xFFFFB0000000, 0x1000000000000) is covered by pml4 as pd and is array of all pd.
// [0xFFFFFFE00000, 0x1000000000000) is covered by pml4 as pt and is array of all pdpt pages.
// [0xFFFFFFFFF000, 0x1000000000000) is covered by pml4 as page and is array of the pml4 entries

// Linear memory layout
// [0, 0x10000) null page (not present)
// [0x10000, kKernelBase) user space (mapping dep
// [kKernelBase, kLowMemBase) kernel space (fixed mapping)
// [kLowMemBase, kCurPageTab) 1 mb mapped to physical [0, 1mb)
// [kCurPageTab, 0x100000000) 4 mb of 1m page tables entries covering the 4gb address space
// [kCurPageDir, 0x100000000) page table covering [0xFFC00000, 0x100000000) and simultaneous page dir

constexpr uintptr_t kKernelBase = 0xE0000000;  // 512mb of kernel address space
constexpr uintptr_t kLowMemBase = 0xFF700000;  // 1mb of low memory mapped to physical [0, 1mb)
constexpr uintptr_t kForkPageTab = 0xFF800000; // 4mb of page tables for a separate address space
constexpr uintptr_t kCurPageTab = 0xFFC00000;  // 4mb of page table entries covering the 4gb address space
constexpr uintptr_t kCurPageDir = 0xFFFFF000;  // last page is the page dir and simultaneous page table covering [0xFFC00000, 0x100000000)

constexpr uintptr_t kPageSize = 4096;
constexpr uintptr_t kNumPageEntries = kPageSize / sizeof(uintptr_t);
constexpr uintptr_t kNumPages = 1 << 20;   // 4GB address space has 1M 4K pages

constexpr auto kKernelPageDirIdx = kKernelBase / kPageSize / kNumPageEntries;

struct PageEntry {
    constexpr PageEntry() = default;
    constexpr PageEntry(uintptr_t data) : data(data) {}
    constexpr PageEntry(uintptr_t page, bool read_write, bool user_super, bool cow)
        : data(kPresent | (read_write ? kReadWrite : 0) | (user_super ? kUserSuper : 0) | (cow ? kCow : 0) | (page * kPage)) { }

    bool IsPresent() const { return data & kPresent; }
    bool IsReadWrite() const { return data & kReadWrite; }
    bool IsUserSuper() const { return data & kUserSuper; }
    bool IsAccessed() const { return data & kAccessed; }
    bool IsDirty() const { return data & kDirty; }
    bool IsCow() const { return data & kCow; }
    uintptr_t Page() const { return data / kPage; }
    uintptr_t AsUInt() const { return data; }

    enum {
        kPresent = 1,
        kReadWrite = 1 << 1,
        kUserSuper = 1 << 2,
        kAccessed = 1 << 5,
        kDirty = 1 << 6,
        kCow = 1 << 9,
        kPage = 1 << 12,
    };

    uintptr_t data = 0;
} __attribute__((packed));

static_assert(sizeof(PageEntry) == sizeof(uintptr_t));

inline bool IsZero(const PageEntry& e) {
    return e.AsUInt() == 0;
}

inline char* PageEntryPrinter(char* pos, BufferedOStream& out, const ValuePrinter& value) {
    auto entry = PageEntry(value.n);
    if (entry.IsPresent()) {
        return print(pos, out, "{{r/w: {}, u/s: {}, cow {}, page: {}}}", entry.IsReadWrite(), entry.IsUserSuper(), entry.IsCow(), Hex(entry.Page()));
    } else {
        return print(pos, out, "{{Page not present}}");
    }
}

inline ValuePrinter MakeValuePrinter(const PageEntry& e) {
    ValuePrinter res;
    res.n = e.AsUInt();
    res.print = PageEntryPrinter;
    return res;
}

struct PageTable {
    PageEntry entries[kNumPageEntries];
};

struct alignas(kPageSize) KernelPages {
    PageTable pdir;  // The directory of kernel/init process
    PageTable ptab;  // The page table mapping the kernel binary
    PageTable kernel_low_mem_base;  // page table just below the page table addresses
    PageTable scratch;
    PageTable zero_page;
};

extern KernelPages kernel_pages;

static_assert(sizeof(PageTable) == kPageSize);

inline uintptr_t AsLinear(const void* p) {
    return reinterpret_cast<uintptr_t>(p);
}

inline uintptr_t PageIdx(const void* p) {
    return AsLinear(p) / kPageSize;
}

inline uintptr_t ParentPageIdx(std::uintptr_t page_idx) {
    return kNumPages - 1 - (kNumPages - 1 - page_idx) / kNumPageEntries;
}

inline uintptr_t ChildPageIdx(std::uintptr_t root_idx, unsigned idx) {
    return kNumPages - (kNumPages - root_idx) * kNumPageEntries + idx;
}

inline PageEntry& GetPageEntry(uintptr_t page_idx) {
    return reinterpret_cast<PageEntry*>(kCurPageTab)[page_idx];
}

inline uintptr_t PhysicalPage(std::uintptr_t page_idx) {
    return GetPageEntry(page_idx).Page();
} 

inline uintptr_t PhysicalPage(const void* p) {
    return PhysicalPage(PageIdx(p));
} 

inline PageTable& GetCurrentDir() {
    return *reinterpret_cast<PageTable*>(kCurPageDir);
}

inline uintptr_t CurrentCR3() {
    return *reinterpret_cast<uint32_t*>(-4) & -kPageSize;
}

inline uintptr_t GetPageIndex(const void* p) {
    return AsLinear(p) / kPageSize;
}

void InitPaging(int kernel_low, int kernel_high, const BootData* boot_data);
void EnablePaging(KernelPages* kpages, uintptr_t phys_address, int read_only);

void* AllocPages(int npages);

//PageTable* CreatePageDir();
void SwitchPageDirAndFreeOld(PageTable* new_dir, PageTable* old_dir);

PageTable* ForkCurrent();

void SwitchPageDir(PageTable* new_dir);

void page_fault(Regs* regs);

void* malloc(std::size_t size);
void free(void* ptr);

#endif //OS_PAGING_H
