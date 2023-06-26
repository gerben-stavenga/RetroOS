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
        uint16_t *video = reinterpret_cast<uint16_t *>(kLowMemBase + 0xB8000);
        if (c == '\n') {
            cursor_x = 0;
            cursor_y++;
            if (cursor_y == 25) {
                memmove(video, video + 80, 80 * 24 * 2);
                memset(video + 80 * 24, 0, 80 * 2);
                cursor_y = 24;
            }
        } else {
            if (cursor_x < 80) {
                video[cursor_y * 80 + cursor_x] = 0x700 | c;
            }
            cursor_x++;
        }
    }
};

Screen screen;

void KernelOutput::Push(string_view str) {
    for (char c : str) {
        screen.Put(c);
    }
}

KernelOutput kout;

NOINLINE [[noreturn]] void hlt() {
    while (true) hlt_inst();
}

NOINLINE [[noreturn]] void panic_assert(string_view cond_str, string_view file, int line) {
    kprint("Kernel assert: Condition \"{}\" failed at {}:{}.\n", cond_str, file, line);
    hlt();
}
/*
extern uint8_t _start[];
extern uint8_t ret_address[];
extern "C" void* PrepareKernel() {
    auto tmp = reinterpret_cast<uintptr_t>(__builtin_extract_return_addr(__builtin_return_address(0))) - reinterpret_cast<uintptr_t>(ret_address);
    tmp += reinterpret_cast<uintptr_t>(_start);
    EnablePaging(tmp);
    return kernel_stack + sizeof(kernel_stack);
}
*/
extern "C" void KernelInit(int pos) {
    screen.cursor_x = pos & 0xFF;
    screen.cursor_y = (pos >> 8) & 0xFF;

    auto ip = GetIP();
    kprint("Entering main kernel\nStack at {} and ip {} at phys address {}\n", &pos, ip, reinterpret_cast<void*>(PhysAddress(ip)));
    InitPaging();

    RemapInterrupts();
    SetupDescriptorTables();
    EnableIRQ();

    kprint("Boot succeeded\n");

    if (1) {
        auto p = static_cast<uint32_t *>(AllocPages(3));
        kprint("Got memory: {}\n", p);

        for (int i = 15; i < 20; i += 1) {
            kprint("Page {} loaded {}\n", i, *GetPageEntry(i));
        }

        kprint("Read {}\n", p[0]);

        p[0] = 10;

        kprint("Read {}\n", p[0]);

        for (int i = 15; i < 20; i += 1) {
            kprint("Page {} loaded {}\n", i, *GetPageEntry(i));
        }

        auto newp = CreatePageDir();
        kprint("Got page at {}\n", newp);

        SwitchPageDir(newp);

        for (int i = 15; i < 20; i += 1) {
            kprint("Page {} loaded {}\n", i, *GetPageEntry(i));
        }

        auto q = static_cast<uint32_t *>(AllocPages(3));
        kprint("Got memory: {}\n", q);

        for (int i = 15; i < 20; i += 1) {
            kprint("Page {} loaded {}\n", i, *GetPageEntry(i));
        }

        kprint("Read {}\n", q[0]);

        q[0] = 20;

        kprint("Read {}\n", q[0]);

        for (int i = 15; i < 20; i += 1) {
            kprint("Page {} loaded {}\n", i, *GetPageEntry(i));
        }

        DestroyPageDir(newp);

        // SwitchPageDir(page_tables + 3);

        kprint("Read {}\n", p[0]);
    }

    // *reinterpret_cast<uint32_t volatile*>(0x10);
    hlt();
}
