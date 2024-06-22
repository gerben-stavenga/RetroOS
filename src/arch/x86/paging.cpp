//
// Created by gerben stavenga on 6/25/23.
//

#include "paging.h"

#include "kassert.h"
#include "x86_inst.h"
#include "src/freestanding/utils.h"
#include "irq.h"

uintptr_t kernel_free_pages_low;
uintptr_t kernel_free_pages_high;
uintptr_t kernel_temp_page;
void* kernel_temp_page_ptr;

// page_tables[0] is the kernel page table
// page_tables[2] maps the first 1mb
// page_tables[3] is the kernel page directory
// page_tables[4] is the zero page
PageTable page_tables[5];

constexpr int kMaxPages = 32768;  // 128 MB

// A map of physical page => shared count.
uint8_t available[kMaxPages];

PageEntry ZeroPageEntry(bool user, bool cow) {
    return PageEntry(PhysAddress(zero_page) / kPageSize, 0, user, cow);
}

inline void FlushTLB() {
    X86_set_cr3(CurrentCR3());
}

void IncSharedCount(int page) {
    kassert(available[page] < 255);
    available[page]++;
}

void FreePhysPage(int page) {
    kassert(available[page] > 0);
    available[page]--;
}

int AllocPhysPage() {
    for (int i = 0; i < kMaxPages; i++) {
        if (available[i] == 0) {
            IncSharedCount(i);
            return i;
        }
    }
    return -1;
}

void MarkUsed(unsigned low, unsigned high) {
    for (; low < high; low++) available[low] = -1;
}

// Add npages to the current address space
void* AllocPages(int npages) {
    // First 64kb of linear address space we leave unmapped, for null exception
    unsigned i;
    for (i = 16; i < kKernelBase / kPageSize - npages + 1; i++) {
        if (!GetPageEntry(i)->IsPresent()) break;
    }
    if (i >= kKernelBase / kPageSize - npages + 1) return nullptr;
    void* res = reinterpret_cast<void*>(uintptr_t{i} * kPageSize);
    for (int j = 0; j < npages; j++) *GetPageEntry(i + j) = ZeroPageEntry(true, true);
    FlushTLB();
    return res;
}

void InitializePageDir(PageTable* page_dir) {
    auto kt_page = PhysAddress(page_tables) / kPageSize;
    memset(page_dir, 0, kPageSize);
    page_dir->entries[kKernelBase / kPageSize / kNumPageEntries] = PageEntry(kt_page, 1, 0, 0);
    page_dir->entries[kNumPageEntries - 2] = PageEntry(PhysAddress(page_tables + 2) / kPageSize, 1, 0, 0);
    page_dir->entries[kNumPageEntries - 1] = PageEntry(PhysAddress(page_dir) / kPageSize, 1, 0, 0);
}

void RecurseMarkCOW(uintptr_t page, int depth) {
    if (depth >= 2) return;
    auto& e = *GetPageEntry(page);
    if (e.IsPresent()) {
        for (int i = 0; i < kNumPageEntries; i++) {
            RecurseMarkCOW(kNumPages - (kNumPages - page) * kNumPageEntries + i, depth + 1);
        }
        kprint("Mark page {} at depth {}\n", page, depth);
        IncSharedCount(e.Page());
        if (e.IsReadWrite()) {
            e.data &= ~e.kReadWrite;
            e.data |= e.kCow;
        } else {
            // Already read-only, COW or not no need to copy
        }
    }
}

void RecurseFreePages(uintptr_t page, int depth) {
    if (depth >= 2) return;
    auto& e = *GetPageEntry(page);
    if (e.IsPresent()) {
        for (int i = 0; i < kNumPageEntries; i++) {
            RecurseFreePages(kNumPages - (kNumPages - page) * kNumPageEntries + i, depth + 1);
        }
        FreePhysPage(e.Page());
    }
}

PageTable* CreatePageDir() {
    for (unsigned i = 0; i < kNumPageEntries - 256; i++) {
        if (page_tables[2].entries[i].AsUInt() == 0) {
            int phys = AllocPhysPage();
            if (phys < 0) return nullptr;
            page_tables[2].entries[i] = PageEntry(phys, 1, 1, 0);
            FlushTLB();
            return reinterpret_cast<PageTable*>(kLowMemBase - (kNumPageEntries - 256 - i) * kPageSize);
        }
    }
    return nullptr;
}

PageTable* ForkCurrent() {
    auto page_dir = CreatePageDir();
    if (!page_dir) return nullptr;
    for (int i = 0; i < kKernelBase / kPageSize / kNumPageEntries; i++) {
        RecurseMarkCOW(kNumPages - kNumPageEntries + i, 0);
    }
    FlushTLB();
    memcpy(page_dir, GetCurrentDir(), kPageSize);
    page_dir->entries[kNumPageEntries - 1] = PageEntry(PhysAddress(page_dir) / kPageSize, 1, 0, 0);
    return static_cast<PageTable*>(page_dir);
}

void DestroyPageDir(const PageTable* p) {
    auto cr3 = CurrentCR3();
    auto this_page = PhysAddress(p);
    kassert(cr3 != this_page);

    for (unsigned i = 0; i < kKernelBase / kPageSize / kNumPageEntries; i++) {
        RecurseFreePages(kNumPages - kNumPageEntries + i, 0);
    }
    FreePhysPage(GetPageEntry(kNumPages - 1)->Page());

    X86_set_cr3(cr3);
    FlushTLB();
}

void SwitchPageDir(PageTable* new_dir) {
    // We must keep the kernel addresses mapped identically
    auto kernel_entries = kKernelBase / kPageSize / kNumPageEntries;
    memcpy(new_dir->entries + kernel_entries, GetCurrentDir() + kernel_entries, (kNumPageEntries - kernel_entries - 1) * sizeof(PageEntry));
    X86_set_cr3(PhysAddress(new_dir));
    FlushTLB();
}

void segv(Regs* regs) {
    (void)regs;  // silence unused warning
    // TODO send sigsegv
    panic("Seg fault, user outside allocation\n");
}

extern uint8_t kernel_stack[4096];

void page_fault(Regs* regs) {
    constexpr uintptr_t kPresent = 1; (void)kPresent;
    constexpr uintptr_t kWrite = 2;
    constexpr uintptr_t kUser = 4;

    auto error = regs->err_code;
    auto fault_address = X86_load_cr2();
    auto page_index = fault_address / kPageSize;

    // kprint("Page fault error {} @{} coming from @{}:{} stack: {}\n", error, Hex(fault_address), Hex(regs->cs), Hex(regs->eip), s);
    // kprint("eax {} ebx {} ecx {} edx {} esi {} edi {} ebp {}\n", Hex(regs->eax), Hex(regs->ebx), Hex(regs->ecx), Hex(regs->edx), Hex(regs->esi), Hex(regs->edi), Hex(regs->ebp));
    // WaitKeypress();
    auto& page_entry = *GetPageEntry(page_index);

    constexpr uintptr_t kNullLimit = 0x10000;
    if (fault_address < kNullLimit) {
        kprint("Page fault error {} @{} coming from @{}:{} stack: {}\n", error, Hex(fault_address), Hex(regs->cs), Hex(regs->eip), Hex(regs->esp));
        kassert(error & kUser);
        // Null pointer dereference
        return segv(regs);
    }
    if ((error & kUser) && fault_address >= kKernelBase) {
        // User mode tried to access kernel memory
        return segv(regs);
    }

    constexpr auto kPrivilegedEntry = kKernelBase / kPageSize / kNumPageEntries;
    bool is_user = page_index < kNumPages - kNumPageEntries + kPrivilegedEntry;

    if (error & kPresent) {
        //kprint("Page fault error {} @{} coming from @{}:{} stack: {}\n", error, Hex(fault_address), Hex(regs->cs), Hex(regs->eip), Hex(regs->esp));
        //kprint("Page {} {}\n", page_index, page_entry);
        //kprint("Parent page {}:{} {}\n", page_index / kNumPageEntries, page_index % kNumPageEntries, *GetPageEntry(page_index / kNumPageEntries + kNumPages - kNumPageEntries));
        // The page is present, but we got a page fault. This means it must be a write to read only, because it's not
        // a privilege issue as we already checked the bounds.
        kassert(error & kWrite);
        kassert(!page_entry.IsReadWrite());
        if (page_entry.IsCow()) {
            int phys_page_index = page_entry.Page();
            kprint("COW page fault @{} page {} #{}\n", Hex(fault_address), phys_page_index, available[phys_page_index]);
            kassert(available[phys_page_index] > 0 || phys_page_index == PhysAddress(zero_page) / kPageSize);
            if (available[phys_page_index] == 1) {
                // Page is not shared, we can just make it writable.
                kprint("COW page is not shared making r/w\n");
                page_entry.data |= PageEntry::kReadWrite;
                page_entry.data &= ~PageEntry::kCow;
            } else {
                kprint("COW page is shared making copy\n");
                // Page was meant to writable. We need to copy it.
                *GetPageEntry(kernel_temp_page) = page_entry;
                int phys_page = AllocPhysPage();
                if (phys_page == -1) panic("OOM");
                page_entry = PageEntry(phys_page, 1, is_user, 0);
                FlushTLB();
                memcpy(reinterpret_cast<void *>(fault_address & -kPageSize), kernel_temp_page_ptr, kPageSize);
                if (fault_address >= kCurPageTab) FlushTLB();
                //kprint("COW page {} {} done\n", page_index, page_entry);
            }
        } else {
            kassert(error & kUser);  // Kernel should never try to write to read only page.
            segv(regs);
        }
    } else {
        //kprint("Page not present\n");
        if (false /*&& !IsZero(page_entry)*/) {
            panic("Swapping not implemented yet\n");
        } else {
            kprint("Zero page cow @{}\n", Hex(fault_address));
            page_entry = ZeroPageEntry(is_user, true);
            FlushTLB();
        }
    }
}

void InitPaging(int kernel_low, int kernel_high, int ramdisk_low, int ramdisk_high, const BootData* boot_data) {
    for (unsigned i = 0; i < array_size(available); i++) {
        kassert(available[i] == 0);
    }
    memset(available, -1, sizeof(available));
    int free_pages = 0;
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

    kprint("ramdisk pages {} {}\n", ramdisk_low, ramdisk_high);
    MarkUsed(ramdisk_low, ramdisk_high);
    free_pages -= ramdisk_high - ramdisk_low;

    if (kernel_high >= ramdisk_low) {
        kprint("Ramdisk overlaps kernel\n");
        terminate(-1);
    }

    kprint("Free mem {}\n", free_pages * kPageSize);

    // We are done with the identity mapping, make zero page zero
    memset(zero_page, 0, kPageSize);
    kernel_free_pages_low = kKernelBase / kPageSize + kernel_high - kernel_low;
    kernel_free_pages_high = kLowMemBase / kPageSize;

    kernel_temp_page = kernel_free_pages_low++;
    kernel_temp_page_ptr = reinterpret_cast<void*>(kernel_temp_page * kPageSize);

    // Make page dir as it should be
    InitializePageDir(page_tables + 3);

    FlushTLB();
}

// Note: this function cannot access any global variables as it is called before the kernel is paged at the correct
// address
void EnablePaging(PageTable* ptables, uintptr_t phys_address) {
    // Identity map the lowest 4mb, we use the zero-page to store the mapping as we don't use it yet
    // Map 4mb starting at the start of the kernel into kernel mem
    for (unsigned i = 0; i < 1024; i++) {
        ptables[4].entries[i] = PageEntry(i, 1, 0, 0);
        ptables[0].entries[i] = PageEntry(i + phys_address / kPageSize, 1, 0, 0);
    }

    // Paging is not enabled so physical address == linear address
    auto AsPhysical = [](const void* ptr) { return AsLinear(ptr); };

    // Identity map the first 4mb
    ptables[3].entries[0] = PageEntry(AsPhysical(ptables + 4) / kPageSize, 1, 0, 0);
    // Map 4mb from the start of the loaded kernel into the kernel mem.
    ptables[3].entries[kKernelBase / kPageSize / kNumPageEntries] = PageEntry(AsPhysical(ptables + 0) / kPageSize, 1, 0, 0);
    // Put a page at the end of kernel space before the page table space
    ptables[3].entries[kNumPageEntries - 2] = PageEntry(AsPhysical(ptables + 2) / kPageSize, 1, 0, 0);
    // Use recursive page table trick to map the page tables into themselves
    ptables[3].entries[kNumPageEntries - 1] = PageEntry(AsPhysical(ptables + 3) / kPageSize, 1, 0, 0);

    for (int i = 0; i < 4; i++) ptables[3].entries[i + kNumPageEntries - 4] = PageEntry(AsPhysical(ptables + i) / kPageSize, 1, 0, 0);

    X86_set_cr3(AsPhysical(ptables + 3));

    // Enable paging and Write Protect bit
    asm volatile (
            "mov %%cr0, %%eax\n\t"
            "or $0x80010000, %%eax\n\t"
            "mov %%eax, %%cr0\n\t"
            :::"ax");

    // Map first MB into the end of kernel space.
    for (int i = 0; i < 256; i++) *GetPageEntry(kLowMemBase / kPageSize + i) = PageEntry(i,1,0, 0);
    FlushTLB();
}
