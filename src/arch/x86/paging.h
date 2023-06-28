//
// Created by gerben stavenga on 6/24/23.
//

#ifndef OS_PAGING_H
#define OS_PAGING_H

#include <stdint.h>

#include "entry.h"
#include "src/freestanding/utils.h"

// Linear memory layout
// [0, 0x1000) null page (not present)
// [0x1000, 0xFF000000) user space (mapping dep
// [0xFF000000, 0xFFB00000) 15 mb kernel space (fixed mapping)
// [0xFFB00000, 0xFFC00000) 1 mb mapped to physical [0, 1mb)
// [0xFFC00000, 0x100000000) 4 mb of 1m page tables entries covering the 4gb address space
// [0xFFFFF000, 0x100000000) page table covering [0xFFC00000, 0x100000000) and simultaneous page dir

constexpr uintptr_t kKernelBase = 0xFF000000;
constexpr uintptr_t kLowMemBase = 0xFFB00000;
constexpr uintptr_t kCurPageTab = 0xFFC00000;
constexpr uintptr_t kCurPageDir = 0xFFFFF000;

constexpr unsigned kPageSize = 4096;
constexpr unsigned kNumPageEntries = kPageSize / sizeof(uint32_t);
constexpr int kNumPages = 1 << 20;   // 4GB address space has 1M 4K pages
constexpr int kNumWords = kNumPages / 32;

struct PageEntry {
    uint32_t present : 1;
    uint32_t read_write : 1;
    uint32_t user_super : 1;
    uint32_t zero1 : 2;
    uint32_t accessed : 1;
    uint32_t dirty : 1;
    uint32_t zero2 : 2;
    uint32_t available : 3;
    uint32_t offset : 20;
} __attribute__((packed));

inline void print_val(BufferedOStream& out, const PageEntry& e) {
    print_buf(out, "{{p: {}, r/w: {}, u/s: {}, offset: {}}}", e.present, e.read_write, e.user_super, e.offset);
}

struct alignas(kPageSize) PageTable {
PageEntry entries[kNumPageEntries];
};

static_assert(sizeof(PageTable) == kPageSize);

inline uintptr_t Cast(const void* p) {
    return reinterpret_cast<uintptr_t>(p);
}

inline PageEntry* GetCurrentDir() {
    return reinterpret_cast<PageEntry*>(kCurPageDir);
}

inline uintptr_t CurrentCR3() {
    return *reinterpret_cast<uint32_t*>(-4) & -kPageSize;
}

inline uintptr_t PhysAddress(const void* p) {
    uintptr_t linear = reinterpret_cast<uintptr_t>(p);
    return (reinterpret_cast<const uint32_t*>(0xFFC00000)[linear >> 12] & -kPageSize) + (linear & (kPageSize - 1));
}

inline PageEntry* GetPageEntry(int page) {
    return reinterpret_cast<PageEntry*>(kCurPageTab) + page;
}

inline constexpr PageEntry MakePageEntry(uintptr_t address, bool present, bool read_write, bool user_super) {
    return PageEntry{present, read_write, user_super, 0, 0, 0, 0, 0, address >> 12};
}

void InitPaging(int kernel_low, int kernel_high, int ramdisk_low, int ramdisk_high);
void EnablePaging(PageTable* ptables, uintptr_t phys_address);

void* AllocPages(int npages);

PageTable* CreatePageDir();
void DestroyPageDir(const PageTable* p);

void SwitchPageDir(PageTable* new_dir);

void page_fault(Regs* regs);

#endif //OS_PAGING_H
