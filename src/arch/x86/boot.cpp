//
// Created by gerben stavenga on 6/11/23.
//
#include "boot.h"

#include "src/freestanding/utils.h"
#include "x86_inst.h"

constexpr int kKernelSize = 30;

struct Regs {
    uint32_t ax;
    uint32_t bx;
    uint32_t cx;
    uint32_t dx;
    uint32_t si;
    uint32_t di;
    uint32_t bp;
    uint32_t flags;
    uint16_t ds;
    uint16_t es;
} __attribute__((packed));

Regs regs;

extern "C" void generate_real_interrupt(int interrupt);

NOINLINE [[noreturn]] void terminate(int) {
    while (true) hlt_inst();
}

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
}


inline void Print(string_view str) {
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

struct Out : public OutputStream {
    void Push(string_view str) override {
        for (char c : str) {
            PutChar(c);
        }
    }
};

inline int min(unsigned a, unsigned b) { return a < b ? a : b; }

__attribute__((__always_inline__)) inline bool read_sectors(int drive, unsigned sector, unsigned head, unsigned cylinder, unsigned nsectors, uintptr_t address) {
    // Use int 13 to read disk
    regs.es = address >> 4;
    regs.bx = address & 0xF;

    regs.ax = 0x0200 + nsectors;
    regs.cx = (cylinder << 8) | (sector + 1) | ((cylinder >> 2) & 0xC0);
    regs.dx = (head << 8) | drive;
    generate_real_interrupt(0x13);
    return (regs.flags & 1) == 0;
}

bool read_disk(int drive, unsigned lba, unsigned count, void *buffer) {
    unsigned sectors_per_track;
    unsigned num_heads;

    if ((drive & 0x80)) {
        regs.ax = 0x800;
        regs.dx = drive;
        generate_real_interrupt(0x13);
        if ((regs.flags & 1) != 0) {
            return false;
        }
        sectors_per_track = regs.cx & 0x3F;
        num_heads = ((regs.dx >> 8) & 0xFF) + 1;
    } else {
        // Should probe
        sectors_per_track = 18;
        num_heads = 2;
    }

    // Use int 13 to read disk
    auto address = reinterpret_cast<uintptr_t>(buffer);
    while (count > 0) {
        unsigned sector = lba % sectors_per_track;
        unsigned head = lba / sectors_per_track;
        int cylinder = head / num_heads;
        head = head % num_heads;

        unsigned nsectors = min(count, min(127, sectors_per_track * num_heads - sector));

        if(!read_sectors(drive, sector, head, cylinder, nsectors, address)) return false;

        lba += nsectors;
        address += 512 * nsectors;
        count -= nsectors;
    }
    return true;
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
        generate_real_interrupt(0x15);
        if (regs.ax != smap_id) {
            return -1;
        }
        if ((regs.flags & 1) != 0) {
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
    TarFSReader(int drive, int lba) : USTARReader(lba), drive_(drive) {}

private:
    bool ReadBlocks(int n, void *buffer) override {
        if (!read_disk(drive_, block_, n, buffer)) return false;
        block_ += n;
        return true;
    }

    int drive_;
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
    void* const buffer = reinterpret_cast<void*>(0x1000);
    Out out;
    print(out, "Booting from drive: {}\n", char(drive >= 0x80 ? 'c' + drive - 0x80 : 'a' + drive));
    print(out, "Loader size: {}\n", _edata - _start);
    print(out, "Extended BIOS at {}\n", Hex(uintptr_t(*reinterpret_cast<uint16_t*>(0x40E)) << 4));
    EnableA20();
    print(out, "A20 enabled\n");
    unsigned fs_lba = (reinterpret_cast<uintptr_t >(_edata) - reinterpret_cast<uintptr_t >(_start) + 511) / 512;
    TarFSReader tar(drive, fs_lba);
    char* ramdisk = reinterpret_cast<char*>(0x80000);
    char* load_address = ramdisk;
    size_t size = 0;
    bool found = false;
    while ((size = tar.ReadHeader(load_address)) != SIZE_MAX) {
        string_view filename{load_address};
        print(out, "filename {} size {}\n", filename, size);

        load_address += 512;
        tar.ReadFile(load_address, size);
        if (filename == "src/arch/x86/kernel.bin") {
            char md5_out[16];
            md5(string_view(load_address, size), md5_out);
            print(out, "Loading {} of size {} with md5 {} at physical address {}\n", filename, size, Hex(string_view(md5_out, 16)), buffer);
            memcpy(buffer, load_address, size);
            found = true;
        }
        load_address += (size + 511) & -512;
    }
    if (!found) {
        print(out, "Kernel not found\n");
        terminate(-1);
    }
    print(out, "Kernel loaded .. starting kernel\n");
    BootData boot_data;
    boot_data.kernel = buffer;
    boot_data.cursor_pos = GetCursor();
    boot_data.ramdisk = ramdisk;
    boot_data.ramdisk_size = load_address - ramdisk;
    boot_data.mmap_count = CreateMemMap(boot_data.mmap_entries, array_size(boot_data.mmap_entries));
    typedef void (__attribute__((fastcall))*Kernel)(BootData*);
    ((Kernel)(buffer))(&boot_data);
    __builtin_unreachable();
}

extern "C"
char start_msg[];

extern "C" __attribute__((noinline, fastcall, section(".boot")))
[[noreturn]] void BootLoader(int /* dummy */, int drive) {
    Print({start_msg, 16});
    auto nsectors = (reinterpret_cast<uintptr_t>(_edata) - reinterpret_cast<uintptr_t>(_start) - 1) / 512;
    read_sectors(drive, 1, 0, 0, nsectors, 0x7C00 + 512);
    FullBootLoader(drive);
}
