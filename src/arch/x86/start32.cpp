//
// Created by gerben stavenga on 6/5/23.
//
#include <stdint.h>
#include <stddef.h>

#include "src/freestanding/utils.h"
#include "descriptors.h"
#include "irq.h"
#include "kassert.h"
#include "paging.h"
#include "x86_inst.h"

struct Screen {
    int cursor_x, cursor_y;

    void ClearScreen() {
        uint16_t *video = reinterpret_cast<uint16_t *>(kLowMemBase + 0xB8000);
        memset(video, 0, 80 * 25 * 2);
        cursor_x = cursor_y = 0;
    }

    void Put(char c) {
        uint16_t* video = reinterpret_cast<uint16_t *>(kLowMemBase + 0xB8000);
        if (c == '\n') {
            cursor_x = 0;
            cursor_y++;
        } else {
            video[cursor_y * 80 + cursor_x] = 0x700 | c;
            cursor_x++;
        }
        if (cursor_x == 80) {
            cursor_x = 0;
            cursor_y++;
        }
        if (cursor_y == 25) {
            memmove(video, video + 80, 80 * 24 * 2);
            memset(video + 80 * 24, 0, 80 * 2);
            cursor_y = 24;
        }
    }
};

constinit Screen screen;

void KernelOutput::Push(string_view str) {
    Screen tmp = screen;
    for (char c : str) {
        tmp.Put(c);
    }
    screen = tmp;
}

constinit KernelOutput kout;

NOINLINE [[noreturn]] void hlt() {
    while (true) hlt_inst();
}

NOINLINE [[noreturn]] void panic_assert(string_view cond_str, string_view file, int line) {
    kprint("Kernel assert: Condition \"{}\" failed at {}:{}.\n", cond_str, file, line);
    hlt();
}

extern PageTable page_tables[];

extern "C" uint8_t _start[];
extern "C" uint8_t _edata[];
extern "C" uint8_t _end[];

// This is a subtle function. The bootloader loads the kernel at some arbitrary physical address with unpaged
// memory, the kernel is compiled/linked expecting to be loaded at kKernelBase. When enabling paging the page tables
// can map the linear address at kKernelBase to the physical address where it's loaded, after which the code can
// execute at the right address. However this code is called before paging is enabled, so we have to be careful because
// access of globals will be at the wrong physical address. We compensate by passing in `delta` to offset the address
// of globals to the correct physical address. After paging is enabled we should switch to the right stack and right
// ip, this must be done in asm and will be handled in entry.asm. This function returns the address of the stack.
extern "C" void* PrepareKernel() {
    static uint8_t init_stack[1024 * 4];

    constexpr uintptr_t kCallOffset = 5;  // 5 bytes for call instruction
    auto phys_address = reinterpret_cast<uintptr_t>(__builtin_extract_return_addr(__builtin_return_address(0))) - kCallOffset;

    if ((phys_address & (kPageSize - 1)) != 0 || reinterpret_cast<uintptr_t>(_start) != kKernelBase) {
        // The loaded kernel must be page aligned, linked at kKernelBase
        hlt();
    }
    memset(reinterpret_cast<uint8_t*>(phys_address) + (_edata - _start), 0, _end - _edata);  // Zero bss

    auto delta = Cast(page_tables) - Cast(_start);
    auto ptables = reinterpret_cast<PageTable*>(phys_address) + (delta / kPageSize);

    EnablePaging(ptables, phys_address);

    return init_stack + sizeof(init_stack);
}

void* ramdisk;
size_t ramdisk_size;

// alignas(alignof(RamUSTARReader)) uint8_t fs[sizeof(RamUSTARReader)];
constinit RamUSTARReader fs(nullptr, 0);

void InitFS(uintptr_t phys, size_t size) {
    ramdisk = reinterpret_cast<void*>(kLowMemBase + phys);
    ramdisk_size = size;
}

size_t Open(const char* path) {
    fs = RamUSTARReader(static_cast<const char*>(ramdisk), ramdisk_size);
    return fs.FindFile(path);
}

void ReadFile(void* dst, size_t size) {
    fs.ReadFile(dst, size);
}

extern "C" void KernelInit(int pos, uintptr_t ramdisk, int ramdisk_size) {
    screen.cursor_x = pos & 0xFF;
    screen.cursor_y = (pos >> 8) & 0xFF;

    auto ip = GetIP();
    kprint("Entering main kernel\nStack at {} and ip {} at phys address {}\n", &pos, ip, reinterpret_cast<void*>(PhysAddress(ip)));

    int kernel_low = PhysAddress(_start) / kPageSize;
    int kernel_high = (PhysAddress(_end) + kPageSize - 1) / kPageSize;
    InitPaging(kernel_low, kernel_high, ramdisk / kPageSize, (ramdisk + ramdisk_size + kPageSize - 1) / kPageSize);

    SetupDescriptorTables();

    RemapInterrupts();
    EnableIRQ();

    InitFS(ramdisk, ramdisk_size);

    auto size = Open("src/arch/x86/init");
    auto dst = AllocPages((size + 65536 * 4 + kPageSize - 1) / kPageSize);
    ReadFile(dst, size);

    kprint("Boot succeeded {} {} {}\n", size, dst, Hex(*reinterpret_cast<uintptr_t*>(dst)));

    // Move to init
    asm volatile(
            "push $0\n\t"  // We make a call from ring 0 which does not push old stack, so we push dummy values
            "push $0\n\t"
            "int $0x80\n\t"::"a" (0), "d" (dst));
}
