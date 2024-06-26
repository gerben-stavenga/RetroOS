//
// Created by gerben stavenga on 6/5/23.
//
#include <cstdint>
#include <cstddef>

#include "boot/boot.h"
#include "src/freestanding/utils.h"
#include "descriptors.h"
#include "irq.h"
#include "kassert.h"
#include "paging.h"
#include "thread.h"
#include "x86_inst.h"

struct Screen {
    int cursor_x = 0, cursor_y = 0;

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

struct KernelOutput : public OutputStream {
    void Push(std::string_view str) override;

    Screen screen_;
};

void KernelOutput::Push(std::string_view str) {
    Screen tmp = screen_;
    for (char c : str) {
        tmp.Put(c);
    }
    screen_ = tmp;
}

constinit KernelOutput kout;

NOINLINE [[noreturn]] void terminate(int) {
    while (true) X86_hlt();
}

extern PageTable page_tables[];

extern "C" uint8_t _start[];
extern "C" uint8_t _edata[];
extern "C" uint8_t _end[];

extern uint8_t kernel_stack[4096 * 16];

// This is a subtle function. The bootloader loads the kernel at some arbitrary physical address with unpaged
// memory, the kernel is compiled/linked expecting to be loaded at kKernelBase. When enabling paging the page tables
// can map the linear address at kKernelBase to the physical address where it's loaded, after which the code can
// execute at the right address. However this code is called before paging is enabled, so we have to be careful because
// access of globals will be at the wrong physical address. We compensate by passing in `delta` to offset the address
// of globals to the correct physical address. After paging is enabled we should switch to the right stack and right
// ip, this must be done in asm and will be handled in entry.asm. This function returns the address of the stack.
extern "C" void* PrepareKernel(const BootData* boot_data) {
    auto phys_address = reinterpret_cast<uintptr_t>(boot_data->kernel);
    if ((phys_address & (kPageSize - 1)) != 0 || reinterpret_cast<uintptr_t>(_start) != kKernelBase) {
        // The loaded kernel must be page aligned, linked at kKernelBase
        terminate(-1);
    }

    auto delta = phys_address - AsLinear(_start);
    auto adjust = [delta](auto* ptr) { return reinterpret_cast<decltype(ptr)>(reinterpret_cast<uintptr_t>(ptr) + delta); };

    // Need to do this as not to override pages 
    memset(adjust(_edata), 0, _end - _edata);  // Zero bss

    auto ptables = adjust(page_tables);
    EnablePaging(ptables, phys_address);

    return kernel_stack + sizeof(kernel_stack);
}

void* ramdisk;
std::size_t ramdisk_size;

class RamUSTARReader : public USTARReader {
public:
    constexpr RamUSTARReader(const char* data, std::size_t size) : data_(data), size_(size) {}

    bool ReadBlocks(std::size_t block, int n, void *buf) override {
        //kprint("ReadBlocks from {} at block {} n {} to {}\n", (void*)data_, block_, n, buf);
        if ((block + n) * 512 > size_) return false;
        memcpy(buf, data_ + block * 512, n * 512);
        return true;
    }

private:
    const char* data_;
    std::size_t size_;
};

// alignas(alignof(RamUSTARReader)) uint8_t fs[sizeof(RamUSTARReader)];
constinit RamUSTARReader fs(nullptr, 0);

void InitFS(uintptr_t phys, std::size_t size) {
    ramdisk = reinterpret_cast<void*>(kLowMemBase + phys);
    ramdisk_size = size;
}

std::size_t Open(std::string_view path) {
    fs = RamUSTARReader(static_cast<const char*>(ramdisk), ramdisk_size);
    return fs.FindFile(path);
}

void ReadFile(void* dst, std::size_t size) {
    fs.ReadFile(dst, size);
}

extern "C" [[noreturn]] void KernelInit(const BootData* boot_data) {
    kout.screen_.cursor_x = boot_data->cursor_pos & 0xFF;
    kout.screen_.cursor_y = (boot_data->cursor_pos >> 8) & 0xFF;

    uintptr_t ramdisk = PhysAddress(boot_data->ramdisk);
    std::size_t ramdisk_size = boot_data->ramdisk_size;

    int kernel_low = PhysAddress(_start) / kPageSize;
    int kernel_high = (PhysAddress(_end) + kPageSize - 1) / kPageSize;
    InitPaging(kernel_low, kernel_high, ramdisk / kPageSize, (ramdisk + ramdisk_size + kPageSize - 1) / kPageSize, boot_data);

    SetupDescriptorTables();

    RemapInterrupts();
    X86_sti();

    InitFS(ramdisk, ramdisk_size);

    std::string_view filename = "src/arch/x86/init.bin";
    auto size = Open(filename);
    if (size == SIZE_MAX) {
        kprint("Failed to load {}\n", filename);
        terminate(-1);
    }
    auto dst = reinterpret_cast<void*>(0x10000);
    ReadFile(dst, size);
    char md5_out[16];
    md5(std::string_view(static_cast<const char*>(dst), size), md5_out);
    auto init_stack = reinterpret_cast<uintptr_t>(kKernelBase);

    kprint("Boot succeeded!\nLoaded {} of size {} with md5 {} at {}\nMoving to userspace\n", filename, size, Hex(std::string_view(md5_out, 16)), dst);

    auto thread = CreateThread(nullptr, kernel_page_dir, true);
    thread->cpu_state.eip = reinterpret_cast<uintptr_t>(dst);
    thread->cpu_state.esp = init_stack;

    ExitToThread(thread);
}
