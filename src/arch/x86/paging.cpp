//
// Created by gerben stavenga on 6/25/23.
//

#include "paging.h"

#include "kassert.h"
#include "x86_inst.h"
#include "src/freestanding/utils.h"

PageTable page_tables[5];
constexpr PageTable* zero_page = page_tables + 4;

uint32_t available[kNumWords];  // 128KB bit mask

PageEntry ZeroPageEntry(bool user) {
    return MakePageEntry(PhysAddress(zero_page), 1, 0, user);
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
        if (!GetPageEntry(i)->present) break;
    }
    if (i == kKernelBase / kPageSize - npages + 1) return nullptr;
    void* res = reinterpret_cast<void*>(uintptr_t{i} * kPageSize);
    for (int j = 0; j < npages; j++, i++) *GetPageEntry(i) = ZeroPageEntry(true);
    FlushTLB();
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
    auto kt_address = PhysAddress(page_tables);
    for (unsigned i = 0; i < kNumPageEntries - 4; i++) {
        page_dir->entries[i] = ZeroPageEntry(true);
    }
    for (int i = 0; i < 3; i++) {
        page_dir->entries[i + kNumPageEntries - 4] = MakePageEntry(kt_address + i * kPageSize, 1, 1, 0);
    }
    page_dir->entries[kNumPageEntries - 1] = MakePageEntry(PhysAddress(page_dir), 1, 1, 0);
}

PageTable* CreatePageDir() {
    auto zp_address = PhysAddress(zero_page);
    for (unsigned i = 0; i < kNumPageEntries - 256; i++) {
        if (page_tables[2].entries[i].offset == zp_address >> 12) {
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
        if (!GetPageEntry(i)->present) break;
        unsigned page = GetPageEntry(i)->offset;
        if (page == PhysAddress(zero_page) / kPageSize) continue;
        FreePhysPage(page);
    }

    LoadPageDir(cr3);
}

void page_fault(Regs* regs) {
    constexpr uintptr_t kPresent = 1; (void)kPresent;
    constexpr uintptr_t kWrite = 2;
    constexpr uintptr_t kUser = 4;

    auto error = regs->err_code;
    auto fault_address = LoadPageFaultAddress();
    int page_index = fault_address >> 12;

    kprint("Page fault at {} coming from {}:{}\n", Hex(fault_address), Hex(regs->cs), Hex(regs->eip));
    if (fault_address < kKernelBase) {
        auto page_entry = *GetPageEntry(page_index);
        if (!page_entry.present) {
            // A bug-free kernel will not address memory outside of the allocation of the user
            kassert(error & kUser);
            panic("Seg fault, user outside allocation {}\n", Hex(fault_address));
        }
        kprint("{} {}\n", page_entry, error);
        kassert(error & kPresent);
        // kprint("{} {}\n", page_entry, error);
        kassert(error & kWrite);
        // Must be write to zero-page
        int page = AllocPhysPage();
        if (page == -1) panic("OOM");
        *GetPageEntry(page_index) = MakePageEntry(uintptr_t(page) * kPageSize, 1, 1, 1);
        FlushTLB();
        memset(reinterpret_cast<void*>(fault_address & -kPageSize), 0, kPageSize);
        FlushTLB();
        return;
    }
    if (error & kUser) {
        panic("Seg fault, user addresses kernel space");
    }
    // The whole kernel mem area is readable by the kernel, so this must be a write
    kassert(error & kWrite);  // The whole area is always readable (COW)

    // Fault occurred in kernel space by the kernel
    if (fault_address >= kCurPageTab) {
        // The whole page_dir is present and readable, due to initialization with zero-page.
        // Kernel tried to access a non-existing page table
        int page = AllocPhysPage();
        if (page == -1) panic("OOM");
        auto page_dir_entry = (fault_address >> 12) & 1023;
        bool user_space = fault_address < kCurPageTab + (kKernelBase / kPageSize) * 4;
        GetCurrentDir()[page_dir_entry] = MakePageEntry(uintptr_t(page) * kPageSize, 1, 1, user_space);
        FlushTLB();
        memset(reinterpret_cast<void*>(fault_address & -kPageSize), 0, kPageSize);
        FlushTLB();
        return;
    }
    if (fault_address >= kKernelBase + (8 << 20)) {
        int page = AllocPhysPage();
        if (page == -1) panic("OOM");
        *GetPageEntry(page_index) = MakePageEntry(uintptr_t(page) * kPageSize, 1, 1, 0);
        return;
    }
    panic("Failure in kernel address {}\n", reinterpret_cast<void*>(fault_address));
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

    // Mark extended bios area + UMB used
    int umb_low = (uintptr_t{*reinterpret_cast<uint16_t*>(kLowMemBase + 0x40e)} << 4) / kPageSize;
    int umb_high = 0x100000 / kPageSize;
    MarkUsed(umb_low, umb_high);

    // We are done with the identity mapping, make zero page zero
    memset(zero_page, 0, kPageSize);
    // Make page dir as it should be
    InitializePageDir(page_tables + 3);
    // Use COW for rest of kernel space
    for (unsigned i = kNumPages - 3 * kNumPageEntries; i < kNumPages - kNumPageEntries - 256; i++) {
        *GetPageEntry(i) = ZeroPageEntry(false);
    }

    FlushTLB();
}

// Note: this function cannot access any global variables as it is called before the kernel is paged at the correct
// address
void EnablePaging(PageTable* ptables, uintptr_t phys_address) {
    // Identity map the lowest 4mb, we use the zero-page to store the mapping as we don't use it yet
    // Map 4mb starting at the start of the kernel into kernel mem
    for (unsigned i = 0; i < 1024; i++) {
        ptables[4].entries[i] = MakePageEntry(i * kPageSize, 1, 1, 0);
        ptables[0].entries[i] = MakePageEntry(i * kPageSize + phys_address, 1, 1, 0);
    }

    ptables[3].entries[0] = MakePageEntry(Cast(ptables + 4), 1, 1, 0);
    for (int i = 0; i < 4; i++) ptables[3].entries[i + kNumPageEntries - 4] = MakePageEntry(Cast(ptables + i), 1, 1, 0);

    LoadPageDir(Cast(ptables + 3));

    // Enable paging and Write Protect bit
    asm volatile (
            "mov %%cr0, %%eax\n\t"
            "or $0x80010000, %%eax\n\t"
            "mov %%eax, %%cr0\n\t"
            :::"ax");

    // Map first MB into the end of kernel space.
    for (int i = 0; i < 256; i++) *GetPageEntry(kLowMemBase / kPageSize + i) = MakePageEntry(i * kPageSize,1,1,0);
    FlushTLB();
}
