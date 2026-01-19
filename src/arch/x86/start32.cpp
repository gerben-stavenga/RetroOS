//
// Created by gerben stavenga on 6/5/23.
//
#include <cstdint>
#include <cstddef>

#include "boot/boot.h"
#include "src/freestanding/utils.h"
#include "descriptors.h"
#include "irq.h"
#include "paging.h"
#include "x86_inst.h"
#include "drv/hdd.h"

#include "src/kernel/startup.h"
#include "src/kernel/kassert.h"

struct Screen {
    int cursor_x = 0, cursor_y = 0;

    void ClearScreen() {
        uint16_t *video = reinterpret_cast<uint16_t *>(kLowMemBase + 0xB8000);
        std::memset(video, 0, 80 * 25 * 2);
        cursor_x = cursor_y = 0;
    }

    void Put(char c) {
        X86_outb(0xe9, c);  // qemu console output when run "--debugcon stdio"
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
            std::memmove(video, video + 80, 80 * 24 * 2);
            std::memset(video + 80 * 24, 0, 80 * 2);
            cursor_y = 24;
        }
    }
};

constinit Screen screen;

void StdFlush(int fd, std::string_view str) {
    Screen tmp = screen;
    for (char c : str) {
        tmp.Put(c);
    }
    screen = tmp;
}

NOINLINE [[noreturn]] void Exit(int) {
    StackTrace();
    while (true) X86_hlt();
}

extern "C" uint8_t _start[];
extern "C" uint8_t _data[];
extern "C" uint8_t _edata[];
extern "C" uint8_t _end[];

[[noreturn]] void KernelInit(const BootData* boot_data) {
    screen.cursor_x = boot_data->cursor_pos & 0xFF;
    screen.cursor_y = (boot_data->cursor_pos >> 8) & 0xFF;

    SetupDescriptorTables();

    RemapInterrupts();
    X86_sti();

    int kernel_low = PhysicalPage(_start);
    int kernel_high = PhysicalPage(_end + kPageSize - 1);

    InitPaging(kernel_low, kernel_high, boot_data);

    Startup(boot_data->start_sector, &kernel_pages.pdir);
}

extern "C"
[[noreturn]]
void SwitchStack(void* stack, void* func);

// This is a subtle function. The bootloader loads the kernel at some arbitrary physical address with unpaged
// memory, the kernel is compiled/linked expecting to be loaded at kKernelBase. When enabling paging the page tables
// can map the linear address at kKernelBase to the physical address where it's loaded, after which the code can
// execute at the right address. However this code is called before paging is enabled, so we have to be careful because
// access of globals will be at the wrong physical address. We compensate by passing in `delta` to offset the address
// of globals to the correct physical address. After paging is enabled we should switch to the right stack and right
// ip, this must be done in asm and will be handled in entry.asm. This function returns the address of the stack.
__attribute__((section(".entry")))
[[noreturn]] void PrepareKernel(const BootData* boot_data) {
    auto phys_address = reinterpret_cast<uintptr_t>(boot_data->kernel);
    if ((phys_address & (kPageSize - 1)) != 0 || reinterpret_cast<uintptr_t>(_start) != kKernelBase) {
        // The loaded kernel must be page aligned, linked at kKernelBase
        Exit(-1);
    }

    auto delta = phys_address - AsLinear(_start);
    auto adjust = [delta](auto* ptr) { return reinterpret_cast<decltype(ptr)>(reinterpret_cast<uintptr_t>(ptr) + delta); };

    // Need to do this as not to override pages 
    std::memset(adjust(_edata), 0, _end - _edata);  // Zero bss

    auto kpages = adjust(&kernel_pages);
    EnablePaging(kpages, phys_address, _data - _start);

    ((uint32_t*)(kernel_stack + sizeof(kernel_stack)))[-1] = reinterpret_cast<uintptr_t>(boot_data) + kLowMemBase;
    SwitchStack(kernel_stack + sizeof(kernel_stack) - 4, reinterpret_cast<void*>(KernelInit));
}
