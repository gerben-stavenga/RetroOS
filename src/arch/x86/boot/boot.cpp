//
// Created by gerben stavenga on 6/11/23.
//
#include "boot.h"

#include "src/freestanding/utils.h"
#include "src/arch/x86/x86_inst.h"

struct Regs {
    uint32_t ax;
    uint32_t bx;
    uint32_t cx;
    uint32_t dx;
    uint32_t si;
    uint32_t di;
    uint32_t bp;
    uint16_t ds;
    uint16_t es;
} __attribute__((packed));

extern Regs regs;

// Call an interrupt function and returns the flag status
extern "C" int __attribute__((no_caller_saved_registers)) generate_real_interrupt(int interrupt);

inline int GetCursor() {
    regs.ax = 0x300;
    regs.bx = 0;
    generate_real_interrupt(0x10);
    return regs.dx;
}

inline void PutChar(char c) {
    if (c == '\n') PutChar(13);
    regs.ax = 0xe00 | c;
    regs.bx = 7;
    generate_real_interrupt(0x10);
    X86_outb(0xe9, c);  // qemu console output when run "--debugcon stdio"
}

struct Out : public OutputStream {
    void Push(std::string_view str) override {
        for (char c : str) {
            PutChar(c);
        }
    }
};

Out out;

[[noreturn]] inline void Halt() {
    while (true) X86_hlt();    
}

NOINLINE [[noreturn]] void exit(int exit_code) {
    print(out, "Panic! Exit code {}", exit_code);
    Halt();
}

inline int min(unsigned a, unsigned b) { return a < b ? a : b; }

__attribute__((__always_inline__))
inline bool read_disk(int drive, unsigned lba, uint16_t count, void* buffer) {
    auto address = reinterpret_cast<uintptr_t>(buffer);
    struct __attribute__((packed)) {
        char size;
        char null;
        uint16_t count;
        uint16_t off;
        uint16_t seg;
        uint64_t lba;
    } packet = { 16, 0, count, static_cast<uint16_t>(address & 0xF), 
                static_cast<uint16_t>(address >> 4), lba };
    // Use int 13 to read disk
    regs.ax = 0x4200;
    regs.ds = 0;
    regs.si = reinterpret_cast<uintptr_t>(&packet);
    regs.dx = drive;
    auto flags = generate_real_interrupt(0x13);
    return (flags & 1) == 0;
}

int CreateMemMap(MMapEntry *entries, int max_entries) {
    int count = 0;
    regs.es = 0;
    regs.bx = 0;
    constexpr uint32_t smap_id = 0x534d4150;  // Ascii 'SMAP'
    while (count < max_entries) {
        entries[count].acpi = 1;
        regs.ax = 0xe820;
        regs.cx = 24;
        regs.dx = smap_id;
        regs.di = reinterpret_cast<uintptr_t>(&entries[count]);
        int flags = generate_real_interrupt(0x15);
        if (regs.ax != smap_id) {
            return -1;
        }
        if ((flags & 1) != 0) {
            if (count == 0) {
                return -1;
            } else {
                break;
            }
        }
        if (!(entries[count].acpi & 1)) {
            // ignore
        } else {
            count++;
        }
        if (regs.bx == 0) break;
    }
    sort(entries, entries + count, [](const auto &a, const auto &b) { return a.base < b.base; });
    return count;
}

class TarFSReader : public USTARReader {
public:
    TarFSReader(int drive, int lba) : drive_(drive), lba_(lba) {}

private:
    bool ReadBlocks(std::size_t block, int n, void *buffer) override {
        if (!read_disk(drive_, lba_ + block, n, buffer)) {
            print(out, "Failed {}\n", Hex{regs.ax});
            return false;
        }
        return true;
    }

    int drive_;
    int lba_;
};

static void EnableA20() {
    if (CheckA20()) return;
    regs.ax = 0x2401;
    generate_real_interrupt(0x15);
    // Hang if not
    while (!CheckA20());
}

extern char _start[], _edata[], _end[];
[[noreturn]] void FullBootLoader(int drive) {
    memset(_edata, 0, _end - _edata);
    print(out, "Booting from drive: {}\n", char(drive >= 0x80 ? 'c' + drive - 0x80 : 'a' + drive));
    print(out, "Loader size: {}\n", _edata - _start);
    print(out, "Extended BIOS at {}\n", Hex(uintptr_t(*reinterpret_cast<uint16_t*>(0x40E)) << 4));
    EnableA20();
    print(out, "A20 enabled\n");
    unsigned fs_lba = (reinterpret_cast<uintptr_t >(_edata) - reinterpret_cast<uintptr_t >(_start) + 511) / 512;
    TarFSReader tar(drive, fs_lba);
    auto size = tar.FindFile("kernel.md5");
    if (size != 16) {
        print(out, "md5 file not found or invalid size {}", size);
        exit(-1);
    }
    char expected_md5[16];
    tar.ReadFile(expected_md5, 16);

    size = tar.FindFile("src/arch/x86/kernel.bin");
    if (size == -1) {
        print(out, "kernel not found");
        exit(-1);
    }
    auto const buffer = reinterpret_cast<char*>((0x7C00 + _end - _start + 0xFFF) & -0x1000);
    tar.ReadFile(buffer, size);
    print(out, "Loaded kernel at {} {}\n", (void*)buffer, size);

    char md5_out[16];
    md5(std::string_view(buffer, size), md5_out);
    if (std::string_view(expected_md5, 16) != std::string_view(md5_out, 16)) {
        print(out, "Error md5 checksum of kernel of size {} mismatch! Expected {} got {}\n",
            size, Hex(std::string_view(expected_md5, 16)), Hex(std::string_view(md5_out, 16)));
        exit(-1);
    }
    print(out, "Kernel loaded .. starting kernel\n");
    BootData boot_data;
    boot_data.kernel = buffer;
    boot_data.cursor_pos = GetCursor();
    boot_data.start_sector = fs_lba;
    boot_data.mmap_count = CreateMemMap(boot_data.mmap_entries, array_size(boot_data.mmap_entries));
    typedef void (*Kernel)(BootData*);
    ((Kernel)(buffer))(&boot_data);
    __builtin_unreachable();
}

// Master boot record code (must fit the 512 byte limit)
__attribute__((always_inline))
inline void Print(std::string_view str) {
    regs.ax = 0x300;
    regs.bx = 0;
    generate_real_interrupt(0x10);
    regs.ax = 0x1301;
    regs.bx = 7;
    regs.cx = str.size();
    regs.es = 0;
    regs.bp = reinterpret_cast<uintptr_t>(str.data());
    generate_real_interrupt(0x10);
}

extern "C"
char start_msg[15];

extern "C" __attribute__((noinline, fastcall, section(".boot")))
[[noreturn]] void BootLoader(int /* dummy */, int drive) {
    Print({start_msg, 15});
    auto nsectors = (reinterpret_cast<uintptr_t>(_edata) - reinterpret_cast<uintptr_t>(_start) - 1) / 512;
    if (read_disk(drive, 1, nsectors, reinterpret_cast<void*>(0x7C00 + 512))) {
        FullBootLoader(drive);
    } else {
        Halt();
    }
}
