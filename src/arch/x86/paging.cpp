//
// Created by gerben stavenga on 6/25/23.
//

#include "paging.h"

#include "kassert.h"
#include "x86_inst.h"
#include "src/freestanding/utils.h"
#include "irq.h"

PageTable page_tables[5];
constexpr PageTable* zero_page = page_tables + 4;

uint32_t available[kNumWords];  // 128KB bit mask

PageEntry ZeroPageEntry(bool user, bool cow) {
    return PageEntry(PhysAddress(zero_page) / kPageSize, 0, user, cow);
}

inline void FlushTLB() {
    LoadPageDir(CurrentCR3());
}

int AllocPhysPage() {
    for (int i = 0; i < kNumWords; i++) {
        if (available[i] != uint32_t (-1)) {
            int j = 0;
            while (available[i] & (1 << j)) j++;
            available[i] |= 1 << j;
            return i * 32 + j;
        }
    }
    return -1;
}

void FreePhysPage(unsigned page) {
    available[page / 32] &= ~(uint32_t{1} << (page & 31));
}

void MarkUsed(unsigned low, unsigned high) {
    if (low < (high & -32)) {
        available[low / 32] |= -(1 << (low & 31));
        if (high & 31) available[high / 32] |= (1 << (high & 31)) - 1;
        low = (low + 32) & -32;
        high &= -32;
        for (; low < high; low += 32) available[low / 32] = -1;
    } else {
        available[low / 32] |= ((1 << (high & 31)) - 1) & -(1 << (low & 31));
    }
}

// Add npages to the current address space
void* AllocPages(int npages) {
    // First 64kb of linear address space we leave unmapped, for null exception
    unsigned i;
    for (i = 16; i < kKernelBase / kPageSize - npages + 1; i++) {
        if (!GetPageEntry(i)->IsPresent()) break;
    }
    if (i == kKernelBase / kPageSize - npages + 1) return nullptr;
    void* res = reinterpret_cast<void*>(uintptr_t{i} * kPageSize);
    for (int j = 0; j < npages; j++) *GetPageEntry(i + j) = ZeroPageEntry(true, true);
    FlushTLB();
    for (int j = 15; j < 20; j++) kprint("Page {} {}\n", j, *GetPageEntry(j));
    return res;
}

void SwitchPageDir(PageTable* new_dir) {
    LoadPageDir(PhysAddress(new_dir));
}
/*
void ForkProcess(PageTable* page_dir) {
    for (int i = 0; i < kNumPageEntries - 4; i++) {
        page_dir->entries[i] = GetCurrentDir()[i];
        page_dir->entries[i].read_write = 0;


        if (page_dir->entries[i].present) {
            auto page = AllocPhysPage();
            auto& e = page_dir->entries[i];
            auto& new_e = GetPageEntry(page);
            *new_e = e;
            new_e->offset = page;
            FlushTLB();
        }
    }
}
*/
void InitializePageDir(PageTable* page_dir) {
    auto kt_page = PhysAddress(page_tables) / kPageSize;
    memset(page_dir, 0, kPageSize);
    for (int i = 0; i < 3; i++) {
        page_dir->entries[i + kNumPageEntries - 4] = PageEntry(kt_page + i, 1, 0, 0);
    }
    page_dir->entries[kNumPageEntries - 1] = PageEntry(PhysAddress(page_dir) / kPageSize, 1, 0, 0);
}
#if 0
void RecurseMarkCOW(int page) {
    /*
     * A process has different types of pages
     *  - read-only pages  (this can just be shared)
     *  - read-only that are COPY-ON-WRITE (this needs to be copied)
     *  - read-write pages (this can be made COW and shared)
     */
    auto& e = GetPageEntry(page);
    if (e.IsPresent()) {
        if (e.IsWritable()) {
            e.SetWritable(false);
            e.SetCOW(true);
        } else if (e.IsCOW()) {
            // Copy
            e.SetWritable();
        }
    }
            e.SetCOW();
        } else {

            e.SetWritable();
        }
    }
}

void Fork(PageTable* page_dir) {
    InitializePageDir(page_dir);
    for (int i = 0; i < kNumPageEntries - 4; i++) {
        RecurseMarkCOW(kNumPages - kNumPageEntries + i);
        page_dir->entries[i] = GetCurrentDir()[i];
    }
}
#endif
PageTable* CreatePageDir() {
    auto zp_address = PhysAddress(zero_page);
    for (unsigned i = 0; i < kNumPageEntries - 256; i++) {
        if (page_tables[2].entries[i].Page() == zp_address >> 12) {
            auto p = reinterpret_cast<PageTable*>((kNumPageEntries - 2) * kNumPageEntries * kPageSize + i * kPageSize);
            InitializePageDir(p);
            return p;
        }
    }
    return nullptr;
}

void DestroyPageDir(const PageTable* p) {
    auto cr3 = CurrentCR3();
    auto this_page = PhysAddress(p);
    if (cr3 != this_page) {
        LoadPageDir(this_page);
    } else {
        // We are destroying the current page dir, so we need to switch to the task 0 one.
        cr3 = PhysAddress(page_tables + 3);
    }
    for (unsigned i = 16; i < kKernelBase / kPageSize; i++) {
        if (!GetPageEntry(i)->IsPresent()) break;
        unsigned page = GetPageEntry(i)->Page();
        if (page == PhysAddress(zero_page) / kPageSize) continue;
        FreePhysPage(page);
    }

    LoadPageDir(cr3);
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
    auto fault_address = LoadPageFaultAddress();
    auto page_index = fault_address / kPageSize;

    auto s = reinterpret_cast<const uint8_t*>(regs) - kernel_stack;
    // kprint("Page fault error {} @{} coming from @{}:{} stack: {}\n", error, Hex(fault_address), Hex(regs->cs), Hex(regs->eip), s);
    // kprint("eax {} ebx {} ecx {} edx {} esi {} edi {} ebp {}\n", Hex(regs->eax), Hex(regs->ebx), Hex(regs->ecx), Hex(regs->edx), Hex(regs->esi), Hex(regs->edi), Hex(regs->ebp));
    // WaitKeypress();
    auto& page_entry = *GetPageEntry(page_index);

    constexpr uintptr_t kNullLimit = 0x10000;
    if (fault_address < kNullLimit) {
        kassert(error & kUser);
        // Null pointer dereference
        return segv(regs);
    }
    if ((error & kUser) && fault_address >= kKernelBase) {
        // User mode tried to access kernel memory
        return segv(regs);
    }

    constexpr auto kPrivilegedEntry = kKernelBase / kPageSize / kNumPageEntries;
    bool is_user = page_index < (kNumPages - kPrivilegedEntry);

    if (error & kPresent) {
        //kprint("Page info {}\n", page_entry);
        // The page is present, but we got a page fault. This means it must be a write to read only, because it's not
        // a privilege issue as we already checked the bounds.
        kassert(error & kWrite);
        kassert(!page_entry.IsReadWrite());
        if (page_entry.IsCow()) {
            // Page was meant to writable. We need to copy it.
            uint8_t tmp[kPageSize];  // NEED A LOT OF STACK FOR THIS
            memcpy(tmp, reinterpret_cast<void*>(fault_address & -kPageSize), kPageSize);
            int phys_page = AllocPhysPage();
            if (phys_page == -1) panic("OOM");
            page_entry = PageEntry(phys_page, 1, is_user, 0);
            FlushTLB();
            memcpy(reinterpret_cast<void*>(fault_address & -kPageSize), tmp, kPageSize);
            if (fault_address >= kCurPageTab) FlushTLB();
            //kprint("Page copy done {}\n", page_entry);
        } else {
            kassert(error & kUser);  // Kernel should never try to write to read only page.
            segv(regs);
        }
    } else {
        //kprint("Page not present\n");
        if (false && !IsZero(page_entry)) {
            panic("Swapping not implemented yet\n");
        } else {
            auto zp = ZeroPageEntry(is_user, true);
            page_entry = zp;
            FlushTLB();
            //kprint("Put COW zero page entry {}\n", page_entry);
        }
    }
}

void InitPaging(int kernel_low, int kernel_high, int ramdisk_low, int ramdisk_high) {
    for (unsigned i = 0; i < array_size(available); i++) {
        kassert(available[i] == 0);
    }

    if (!CheckA20()) {
        // So far we only used < 1MB memory, so nothing is fucked yet as we haven't encountered aliased mem.
        // We can simply continue by marking all pages at an odd 1MB segment unavailable, this halves the available
        // memory.
        kprint("A20 disabled! Compensating but losing half the memory");
        constexpr int kWordsPerMB = (1 << 20) / kPageSize / 32;
        for (int i = 0; i < kNumWords; i += 2 * kWordsPerMB) {
            memset(available + i + kWordsPerMB, -1, sizeof(uint32_t) * kWordsPerMB);
        }
    }

    MarkUsed(0, 1);  // zero page is used by bios

    // Mark pages where kernel is loaded as used
    kprint("Kernel pages {} {}\n", kernel_low, kernel_high);
    MarkUsed(kernel_low, kernel_high);

    kprint("ramdisk pages {} {}\n", ramdisk_low, ramdisk_high);
    MarkUsed(ramdisk_low, ramdisk_high);

    if (kernel_high >= ramdisk_low) {
        kprint("Ramdisk overlaps kernel\n");
        terminate();
    }

    // Mark extended bios area + UMB used
    int umb_low = (uintptr_t{*reinterpret_cast<uint16_t*>(kLowMemBase + 0x40e)} << 4) / kPageSize;
    int umb_high = 0x100000 / kPageSize;
    MarkUsed(umb_low, umb_high);

    // We are done with the identity mapping, make zero page zero
    memset(zero_page, 0, kPageSize);
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

    ptables[3].entries[0] = PageEntry(AsPhysical(ptables + 4) / kPageSize, 1, 0, 0);
    for (int i = 0; i < 4; i++) ptables[3].entries[i + kNumPageEntries - 4] = PageEntry(AsPhysical(ptables + i) / kPageSize, 1, 0, 0);

    LoadPageDir(AsPhysical(ptables + 3));

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
