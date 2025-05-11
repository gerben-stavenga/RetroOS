//
// Created by gerben stavenga on 6/25/23.
//

#include "paging.h"

#include "src/kernel/kassert.h"
#include "x86_inst.h"
#include "src/freestanding/utils.h"
#include "irq.h"
#include "thread.h"

#include "src/kernel/thread.h"

/***
 * How does forking work. When forking the whole address space is duplicated. This is done
 * lazily by marking all pages copy-on-write (COW). Each page has a ref-count counting how
 * many address spaces point to this page. If the `ref-count == 1` only one address space
 * includes this page and thus it's safe to make it writeable.
 * 
 * A page can be in the following states
 * 1. Read/write and ref-count == 1
 * 2. Read-only and ref-count == 1
 * 3. Read-only and ref-count > 1
 * 4. Read-only (COW) and ref-count == 1
 * 5. Read-only (COW) and ref-count > 1
 * 
 * State 1, 3 and 5 are logically writeable pages. However states 4 and 5 will page fault.
 * State 4 can trivially move to state 1
 * State 5 make a copy, decrease ref-count and make copied page state 1
 * 
 * States 2 and 3 are pure read-only by choice of user. Typically code section will be marked read-only
 * by default by the kernel, but the user can change write permissions of it's address space.
 * If read-only is changed to writeable we have
 * State 2 -> 1
 * State 3 -> 5
 * 
 * Similarly marking read-write page read-only
 * State 1 -> State 2
 * State 4 -> State 2
 * State 5 -> State 3
 * 
 * Access control is done on the level of pages accessible to users. All kernel pages will be R/W
 * 
 * Address space overview, address space is divided
 * [0 .. 2^16)  nullptr protection (not present)
 * [2^16 .. kKernelBase) user space
 * [kKernelBase  .. kLowMemBase) kernel space
 * [kLowMemBase .. kPageTable) mapped to phys [0 .. 1mb)
 * [kPageTable .. 2^32) page tables
 * 
 * We need protection against user access for [kKernelBase .. 2^32) by not marking U/S for addresses
 * in that range. One can mark U/S either on page tables or page dir, we choose to establish a simple
 * invariant. For all page table entries U/S = 1 and for page dir entry U/S = 0 for the kernel space
 * part. This together with recursive page tables make only page entries at the top have U/S 0.
*/

constexpr int kMaxPages = 32768;  // 128 MB

KernelPages kernel_pages;

// A map of physical page => shared count.
uint8_t available[kMaxPages];
// Bit map of available "pages" in kernel address space
constexpr auto kNumKernelPages = (kLowMemBase - kKernelBase) / kPageSize;
uint32_t avail_bitmap[kNumKernelPages / 32];

constexpr int kNumPageDirs = 1024;
PageTable* page_dirs[kNumPageDirs];
int num_page_dirs = kNumPageDirs;
int free_pages = 0;

PageEntry ZeroPageEntry(bool user, bool cow) {
    return PageEntry(PhysicalPage(&kernel_pages.zero_page), 0, user, cow);
}

inline void FlushTLB() {
    X86_set_cr3(CurrentCR3());
}

NOINLINE
void IncSharedCount(int page) {
    assert(available[page] < 255) << page;
    available[page]++;
}

int FreePhysPage(int page) {
    assert(available[page] > 0) << page;
    if (available[page] == 1) {
        free_pages++;
    }
    return available[page]--;
}

int AllocPhysPage() {
    for (int i = 0; i < kMaxPages; i++) {
        if (available[i] == 0) {
            IncSharedCount(i);
            free_pages--;
            return i;
        }
    }
    panic("No free pages");
    return -1;
}

void MarkUsed(unsigned low, unsigned high) {
    for (; low < high; low++) available[low] = -1;
}

PageTable* AllocPageDir(std::uintptr_t page_idx) {
    if (num_page_dirs == 0) return nullptr;
    auto pt = page_dirs[--num_page_dirs];
    assert(pt);
    GetPageEntry(PageIdx(pt)) = PageEntry(page_idx, 1, 0, 0);
    return pt;
}

void FreeKernelPage(PageTable* p) {
    assert(num_page_dirs < kNumPageDirs);
    page_dirs[num_page_dirs++] = p;
}

void RecurseFreePages(uintptr_t page_idx) {
    auto& e = GetPageEntry(page_idx);
    assert(e.IsPresent()) << e;
    if (page_idx >= kCurPageTab / kPageSize) {
        auto p = reinterpret_cast<PageTable*>(page_idx * kPageSize);
        for (int i = 0; i < kNumPageEntries; i++) {
            if (p->entries[i].IsPresent() && p->entries[i].IsUserSuper()) {
                RecurseFreePages(ChildPageIdx(page_idx, i));
            }
        }
    }
    FreePhysPage(e.Page());
}

void DumpTable(PageTable* tables, std::uintptr_t page_idx) {
    constexpr auto kStart = kCurPageTab / kPageSize;
    if (page_idx >= kStart) {
        auto page = page_idx - kStart;
        auto src = &tables[page];
        // It's a page table page, we copy them all
        for (int i = 0; i < kNumPageEntries; i++) {
            auto& e = src->entries[i];
            if (e.IsPresent()) {
                auto child = ChildPageIdx(page_idx, i);
                if (child < page_idx) DumpTable(tables, child);
            }
        }
        kprint("Page {}\n", Hex(page));
        for (unsigned i = 0; i < kNumPageEntries; i++) {
            auto& e = src->entries[i];
            if (e.IsPresent()) {
                kprint("Idx {}@{} (page {}) -> {}\n", i,  Hex((page_idx * kNumPageEntries + i) * kPageSize), ChildPageIdx(page_idx, i), e);
            }
        }
    }
}

// Allocate a page and recursively copies pagetables page_idx and below in the hierachy.
// Returns the physical page of root page table
__attribute__((noinline))
std::uintptr_t RecursivelyCopyPageTable(std::uintptr_t page_idx) {
    auto src = reinterpret_cast<PageTable*>(page_idx * kPageSize);
    if (page_idx >= kCurPageTab / kPageSize) {
        auto dst = reinterpret_cast<PageTable*>(kForkPageTab) + page_idx - (kCurPageTab / kPageSize);
        // It's a page table page, we copy them all
        for (int i = 0; i < kNumPageEntries; i++) {
            auto& e = src->entries[i];
            if (e.IsPresent() && e.IsUserSuper()) {
                auto child = ChildPageIdx(page_idx, i);
                auto child_page = RecursivelyCopyPageTable(ChildPageIdx(page_idx, i));
                // Copy tables
                dst->entries[i] = PageEntry(child_page, e.IsReadWrite(), e.IsUserSuper(), e.IsCow());
            } else {
                dst->entries[i] = e;
            }
        }
        return PhysicalPage(dst);
    } else {
        // A user space page, increase ref count and mark COW
        auto& e = GetPageEntry(page_idx);
        IncSharedCount(e.Page());
        if (e.IsReadWrite()) {
            e.data |= e.kCow;
            e.data &= ~e.kReadWrite;
        }
        return e.Page();
    }
}

// Attribute to force the linker to not drop the function
__attribute__((used))
PageTable* ForkCurrent() {
    kprint("Free pages {} free kernel pages {}\n", free_pages, num_page_dirs);
    // Establish recursive pages
    auto pt = AllocPageDir(RecursivelyCopyPageTable(kNumPages - 1));
    kprint("Root pdir page {}\n", PhysicalPage(pt));
    // Re-establish recursive pages
    pt->entries[kNumPageEntries - 1] = PageEntry(PhysicalPage(pt), 1, 0, 0);
    pt->entries[kNumPageEntries - 2] = 0;
    if (0) {
        FlushTLB();
        DumpTable(reinterpret_cast<PageTable*>(kCurPageTab), kNumPages - 1);
        kprint("Forked\n");
        DumpTable(reinterpret_cast<PageTable*>(kForkPageTab), kNumPages - 1);
    }
    auto pe = PageEntry();
    swap(GetCurrentDir().entries[kNumPageEntries - 2], pe);
    FlushTLB();
    FreePhysPage(pe.Page());
    return pt;
}

PageTable* SwitchFreshPageDirAndFreeOld(PageTable* old_dir) {
    auto pd = AllocPageDir(AllocPhysPage());
    auto user_space = kKernelBase / kPageSize / kNumPageEntries;
    memcpy(pd->entries + user_space, GetCurrentDir().entries + user_space, kPageSize - user_space * sizeof(PageEntry));
    // Re-establish recursive pages
    pd->entries[kNumPageEntries - 1] = PageEntry(PhysicalPage(pd), 1, 0, 0);
    assert(pd->entries[kNumPageEntries - 2].AsUInt() == 0);
    SwitchPageDirAndFreeOld(pd, old_dir);
    return pd;
}

void SwitchPageDirAndFreeOld(PageTable* new_dir, PageTable* old_dir) {
    assert(CurrentCR3() != PhysicalPage(new_dir) * kPageSize);
    assert(CurrentCR3() == PhysicalPage(old_dir) * kPageSize);

    RecurseFreePages(kNumPages - 1);
    FreeKernelPage(old_dir);
    SwitchPageDir(new_dir);
}

void SwitchPageDir(PageTable* new_dir) {
    assert(new_dir != nullptr);
    // We must keep the kernel addresses mapped identically (except the recursive pagedir entry)
    auto size = (kNumPageEntries - 1 - kKernelPageDirIdx) * sizeof(PageEntry);
    memcpy(new_dir->entries + kKernelPageDirIdx, GetCurrentDir().entries + kKernelPageDirIdx, size);
    X86_set_cr3(PhysicalPage(new_dir) * kPageSize);
}

extern uint8_t kernel_stack[4096];

void page_fault(Regs* regs) {
    auto error = regs->err_code;

    // X86 defined page fault error codes
    const bool page_present = error & 1;
    const bool is_write = error & 2;
    const bool is_user = error & 4;

    auto fault_address = X86_load_cr2();
    auto page_index = fault_address / kPageSize;

    auto& page_entry = GetPageEntry(page_index);

    struct Printer {
        ValuePrinter MakeValuePrinter() const {
            ValuePrinter p;
            p.p = this;
            p.print = &print_page_fault;
            return p;
        }

        static char* print_page_fault(char* pos, BufferedOStream& out, const ValuePrinter& value) {
            auto p = static_cast<const Printer*>(value.p);

            auto error = p->regs->err_code;
            const bool page_present = error & 1;
            const bool is_write = error & 2;
            const bool is_user = error & 4;
            return print(pos, out, "page fault @{} present {} write {} user {} from ip@{}", Hex(p->fault_address), page_present, is_write, is_user, Hex(p->regs->eip));
        }
        Regs* regs;
        std::uintptr_t fault_address;
    };

    Printer pf_printer{regs, fault_address};

    if (page_index == 1022) {
        kprint("PF {}\n", pf_printer);
        StackTrace();
    }
    if (0) {
        if (page_present) {
            kprint("Page fault @{} present {} write {} user {} page {}\n", Hex(fault_address), page_present, is_write, is_user, page_entry);
        } else {
            kprint("Page fault @{} present {} write {} user {}\n", Hex(fault_address), page_present, is_write, is_user);
        }
        // StackTrace();
    }

    // Address space is divided as [nullptr protection, user space, kernel space]
    constexpr uintptr_t kNullLimit = 0x10000;
    if (fault_address < kNullLimit) {
        assert(is_user) << pf_printer;
        // Null pointer dereference
        StackTrace();
        return SegvCurrentThread(regs, fault_address);
    }
    if (is_user && fault_address >= kKernelBase) {
        // User mode tried to access kernel memory
        assert(false) << pf_printer << *regs;
        return SegvCurrentThread(regs, fault_address);
    }
    // We know now that it's not a permission issue.

    bool is_u_s = page_index < kNumPages - kNumPageEntries + kKernelPageDirIdx;

    if (page_present) {
        // The page is present, but we got a page fault. This means it must be a write to read only, 
        // because it's not a privilege issue as we already checked the bounds.
        assert(is_write) << pf_printer;
        // kprint("Parent page {}\n", *GetPageEntry(GetPageIndex(&page_entry)));
        assert(!page_entry.IsReadWrite()) << pf_printer;
        if (page_entry.IsCow()) {
            int phys_page_index = page_entry.Page();
            // kprint("COW page fault @{} page {} #{}\n", Hex(fault_address), phys_page_index, available[phys_page_index]);
            if (available[phys_page_index] == 1) {
                // Page is not shared, we can just make it writable.
                // kprint("COW page is not shared making r/w\n");
                page_entry.data |= PageEntry::kReadWrite;
                page_entry.data &= ~PageEntry::kCow;
                FlushTLB();
            } else {
                if (phys_page_index != PhysicalPage(&kernel_pages.zero_page)) {
                    FreePhysPage(phys_page_index);
                }
                // kprint("COW page is shared making copy\n");
                // Page was meant to writable. We need to copy it.
                auto page_ptr = reinterpret_cast<void *>(fault_address & -kPageSize);
                memcpy(&kernel_pages.scratch, page_ptr, kPageSize);
                int phys_page = AllocPhysPage();
                if (phys_page == -1) panic("OOM");
                page_entry = PageEntry(phys_page, 1, is_u_s, 0);
                FlushTLB();
                memcpy(page_ptr, &kernel_pages.scratch, kPageSize);
            }
        } else {
            assert(is_user) << pf_printer;  // Kernel should never try to write to read only page.
            SegvCurrentThread(regs, fault_address);
        }
    } else {
        //kprint("Page not present\n");
        if (false /*&& !IsZero(page_entry)*/) {
            panic("Swapping not implemented yet\n");
        } else {
            //kprint("Zero page cow @{} {}\n", Hex(fault_address), page_index - (kNumPages - kNumPageEntries));
            // StackTrace();
            // This assignment may itself page fault
            page_entry = ZeroPageEntry(is_u_s, true);
            FlushTLB();
        }
    }
}

extern "C" char _end[];

void InitPaging(int kernel_low, int kernel_high, const BootData* boot_data) {
    // Remove the identity mapping
    kernel_pages.pdir.entries[0] = kernel_pages.pdir.entries[1];
    // Don't map pages not used.
    for (int i = kernel_high - kernel_low; i < kNumPageEntries; i++) {
        kernel_pages.ptab.entries[i] = 0;
    }
    FlushTLB();

    for (unsigned i = 0; i < array_size(available); i++) {
        assert(available[i] == 0);
    }
    memset(available, -1, sizeof(available));
    for (int i = 0; i < boot_data->mmap_count; i++) {
        auto& mmap = boot_data->mmap_entries[i];
        if (mmap.type != 1) continue;
        auto start = (mmap.base + kPageSize - 1) / kPageSize;
        auto end = (mmap.base + mmap.length) / kPageSize;
        kprint("Available memory {} - {} ({} pages)\n", Hex(mmap.base), Hex(mmap.base + mmap.length), end - start);
        start = min<int>(start, kMaxPages);
        end = min<int>(end, kMaxPages);
        if (start < end) memset(available + start, 0, (end - start) * sizeof(available[0]));
        free_pages += end - start;
    }

    // Mark free pages in kernel address space
    for (int i = 0; i < kernel_high - kernel_low; i++) {
        avail_bitmap[i / 32] |= 1 << (i % 32);
    }

    if (!CheckA20()) {
        // So far we only used < 1MB memory, so nothing is fucked yet as we haven't encountered aliased mem.
        // We can simply continue by marking all pages at an odd 1MB segment unavailable, this halves the available
        // memory.
        kprint("A20 disabled! Compensating but losing half the memory");
        constexpr auto kPagesPerMB = (1 << 20) / kPageSize;
        for (int i = kPagesPerMB; i < kMaxPages; i += 2 * kPagesPerMB) {
            MarkUsed(i, min(kMaxPages, int(i + kPagesPerMB)));
        }
    }

    MarkUsed(0, 1);  // zero page is used by bios

    // Mark pages where kernel is loaded as used
    kprint("Kernel pages {} {}\n", kernel_low, kernel_high);
    MarkUsed(kernel_low, kernel_high);
    free_pages -= kernel_high - kernel_low;

    kprint("Free pages {}\n", free_pages);

    // Initialize list of free page dirs
    for (int i = 0; i < kNumPageDirs; i++) {
        page_dirs[i] = (PageTable*)(kLowMemBase) - i - 1;
    }

    auto heap_start = ((uintptr_t)_end + 7) & -8;
    kprint("Reserving {} with size {} as heap\n", (void*)heap_start, kLowMemBase - kNumPageDirs * kPageSize - heap_start);
    InitializeAllocator((void*)heap_start, kLowMemBase - kNumPageDirs * kPageSize - heap_start);
}

// Note: this function cannot access any global variables as it is called before the kernel is paged at the correct
// address
void EnablePaging(KernelPages* kpages, uintptr_t phys_address, int read_only) {
    // Identity map the lowest 4mb and
    // Map 4mb starting at the start of the kernel into kernel mem
    auto& id_map = kpages->scratch;
    auto& kernel_ptab = kpages->ptab;
    auto& kernel_pdir = kpages->pdir;
    // assert((read_only & (kPageSize - 1)) == 0);

    auto GetPageIdx = [](const void* p) { return AsLinear(p) / kPageSize; };

    for (unsigned i = 0; i < 1024; i++) {
        id_map.entries[i] = PageEntry(i, 1, 0, 0);
        bool read_write = i >= read_only / kPageSize;
        kernel_ptab.entries[i] = PageEntry(i + phys_address / kPageSize, read_write, 0, 0);
    }

    // Paging is not enabled so physical address == linear address
    // Identity map the first 4mb (page dir idx 0)
    kernel_pdir.entries[0] = PageEntry(AsLinear(&id_map) / kPageSize, 1, 0, 0);
    // Map the kernel at kKernelBase (k)
    kernel_pdir.entries[kKernelPageDirIdx] = PageEntry(GetPageIdx(&kernel_ptab), 1, 0, 0);
    kernel_pdir.entries[kNumPageEntries - 3] = PageEntry(GetPageIdx(&kpages->kernel_low_mem_base), 1, 0, 0);
    // Recursive page tables
    kernel_pdir.entries[kNumPageEntries - 1] = PageEntry(GetPageIdx(&kernel_pdir), 1, 0, 0);

    X86_set_cr3(AsLinear(&kernel_pdir));

    // Enable paging and Write Protect bit
    asm volatile (
            "mov %%cr0, %%eax\n\t"
            "or $0x80010000, %%eax\n\t"
            "mov %%eax, %%cr0\n\t"
            :::"ax");

    // Map first MB into the end of kernel space.
    for (int i = 0; i < 256; i++) GetPageEntry(kLowMemBase / kPageSize + i) = PageEntry(i, 1, 0, 0);
    FlushTLB();
}

