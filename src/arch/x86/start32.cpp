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
#include "drv/hdd.h"

struct Screen {
    int cursor_x = 0, cursor_y = 0;

    void ClearScreen() {
        uint16_t *video = reinterpret_cast<uint16_t *>(kLowMemBase + 0xB8000);
        memset(video, 0, 80 * 25 * 2);
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

PanicStream GetPanicStream(const char* str, const char* file, int line) {
    return PanicStream(kout, str, file, line);
}

std::size_t symbol_size;
char *symbol_map;

void StackTrace() {
    StackTrace(kout, {symbol_map, symbol_size});
}

NOINLINE [[noreturn]] void exit(int) {
    StackTrace(kout, {symbol_map, symbol_size});
    while (true) X86_hlt();
}

extern "C" uint8_t _start[];
extern "C" uint8_t _data[];
extern "C" uint8_t _edata[];
extern "C" uint8_t _end[];

class RamUSTARReader : public USTARReader {
public:
    constexpr RamUSTARReader(unsigned start) : start_(start) {}

    bool ReadBlocks(std::size_t block, int n, void *buf) override {
        ReadSectors(start_ + block, n, buf);
        return true;
    }

private:
    unsigned start_;
};

RamUSTARReader fs(0);

void InitFS(unsigned start) {
    fs = RamUSTARReader(start);
}

std::size_t Open(std::string_view path) {
    return fs.FindFile(path);
}

void ReadFile(void* dst, std::size_t size) {
    fs.ReadFile(dst, size);
}

void ReadSectors(unsigned lba, unsigned count, void* p);

extern "C" [[noreturn]] void KernelInit(const BootData* boot_data) {
    kout.screen_.cursor_x = boot_data->cursor_pos & 0xFF;
    kout.screen_.cursor_y = (boot_data->cursor_pos >> 8) & 0xFF;

    SetupDescriptorTables();

    RemapInterrupts();
    X86_sti();

    int kernel_low = PhysicalPage(_start);
    int kernel_high = PhysicalPage(_end + kPageSize - 1);

    InitPaging(kernel_low, kernel_high, boot_data);

    kprint("Initializing disk {}\n", boot_data->start_sector);
    InitFS(boot_data->start_sector);

    auto ssize = Open("system.map");
    auto smap = (char*)malloc(ssize);
    ReadFile(smap, ssize);
    symbol_map = smap;
    symbol_size = ssize;

    std::string_view filename = "src/arch/x86/init.elf";
    auto size = Open(filename);
    if (size == SIZE_MAX) {
        kprint("Failed to load {}\n", filename);
        exit(-1);
    }
    char* buf = (char*)malloc(size);
    assert(buf != nullptr);
    ReadFile(buf, size);
    char md5_out[16];
    md5(std::string_view(buf, size), md5_out);
    kprint("init.elf md5 {} {}\n", size, Hex(std::string_view{md5_out, 16}));
    auto dst = LoadElf({buf, size}, +[](uintptr_t address, std::size_t sz, int type) { 
        kprint("Map @{} size {} of type {}\n", Hex(address), sz, type);
        memset(reinterpret_cast<void*>(address), 0, sz);
        return reinterpret_cast<void*>(address); 
    });
    free(buf);

    auto init_stack = reinterpret_cast<uintptr_t>(kKernelBase);
    kprint("Boot succeeded!\nLoaded {} of size {} with md5 {} at {}\nMoving to userspace\n", filename, size, Hex(std::string_view(md5_out, 16)), dst);

    auto thread = CreateThread(nullptr, &kernel_pages.pdir, true);
    thread->cpu_state.eip = reinterpret_cast<uintptr_t>(dst);
    thread->cpu_state.esp = init_stack;

    ExitToThread(thread);
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
        exit(-1);
    }

    auto delta = phys_address - AsLinear(_start);
    auto adjust = [delta](auto* ptr) { return reinterpret_cast<decltype(ptr)>(reinterpret_cast<uintptr_t>(ptr) + delta); };

    // Need to do this as not to override pages 
    memset(adjust(_edata), 0, _end - _edata);  // Zero bss

    auto kpages = adjust(&kernel_pages);
    EnablePaging(kpages, phys_address, _data - _start);

    ((uint32_t*)(kernel_stack + sizeof(kernel_stack)))[-1] = reinterpret_cast<uintptr_t>(boot_data) + kLowMemBase;
    SwitchStack(kernel_stack + sizeof(kernel_stack) - 4, reinterpret_cast<void*>(KernelInit));
}
