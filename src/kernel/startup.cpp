//
// Created by gerben stavenga on 6/5/23.
//
#include <cstdint>
#include <cstddef>

#include "src/freestanding/utils.h"
#include "src/kernel/kassert.h"
#include "src/kernel/thread.h"
#include "src/arch/x86/drv/hdd.h"


std::size_t symbol_size;
char *symbol_map;

void StackTrace() {
    StackTrace(std_out, {symbol_map, symbol_size});
}


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

[[noreturn]] void Startup(unsigned start_sector, PageTable* page_dir) {
    kprint("Initializing disk {}\n", start_sector);
    InitFS(start_sector);

    kprint("Initializing symbol map\n");
    auto ssize = Open("src/arch/x86/kernel.map");
    auto smap = (char*)malloc(ssize);
    ReadFile(smap, ssize);
    symbol_map = smap;
    symbol_size = ssize;

    kprint("Loading init.elf\n");
    std::string_view filename = "src/arch/x86/init.elf";
    auto size = Open(filename);
    if (size == SIZE_MAX) {
        panic("Failed to load {}\n", filename);
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

    kprint("Boot succeeded!\nLoaded {} of size {} with md5 {} at {}\nMoving to userspace\n", filename, size, Hex(std::string_view(md5_out, 16)), dst);

    auto thread = CreateThread(nullptr, page_dir, true);
    InitializeProcessThread(thread, dst);

    ExitToThread(thread);
}
