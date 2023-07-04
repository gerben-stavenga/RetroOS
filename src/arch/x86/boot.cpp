//
// Created by gerben stavenga on 6/11/23.
//

#include <stdint.h>

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

struct BootData {
    int cursor_pos;
    void* ramdisk;
    int ramdisk_size;
};

BootData boot_data;

extern "C" void generate_real_interrupt(int interrupt);

NOINLINE [[noreturn]] void terminate() {
    while (true) hlt_inst();
}

struct Out : public OutputStream {
    void Push(string_view str) {
        for (char c : str) {
            put(c);
        }
    }

    void put(char c) {
        if (c == '\n') put(13);
        regs.ax = 0xe00 | c;
        regs.bx = 7;
        generate_real_interrupt(0x10);
    }

    int GetCursor() {
        regs.ax = 0x300;
        regs.bx = 0;
        generate_real_interrupt(0x10);
        return regs.dx;
    }
};

inline int min(unsigned a, unsigned b) { return a < b ? a : b; }

__attribute__((noinline)) bool read_disk(int drive, unsigned lba, unsigned count, void *buffer) {
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

        regs.es = address >> 4;
        regs.bx = address & 0xF;

        regs.ax = 0x0200 + nsectors;
        regs.cx = (cylinder << 8) | (sector + 1) | ((cylinder >> 2) & 0xC0);
        regs.dx = (head << 8) | drive;
        generate_real_interrupt(0x13);
        if ((regs.flags & 1) != 0) {
            return false;
        }
        lba += nsectors;
        address += 512 * nsectors;
        count -= nsectors;
    }
    return true;
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
extern "C" void BootLoader(void* buffer, int drive) {
    Out out;
    print(out, "Booting from drive: {}\n", char(drive >= 0x80 ? 'c' + drive - 0x80 : 'a' + drive));
    print(out, "Loader size: {}\n", _edata - _start);
    print(out, "Extended BIOS at {}\n", reinterpret_cast<void*>(static_cast<uintptr_t>(*reinterpret_cast<uint16_t*>(0x40E)) << 4));
    EnableA20();
    print(out, "A20 enabled\n");
    unsigned kernel_lba = (reinterpret_cast<uintptr_t >(_edata) - reinterpret_cast<uintptr_t >(_start) + 511) / 512;
    TarFSReader tar(drive, kernel_lba);
    char* ramdisk = reinterpret_cast<char*>(0x80000);
    char * load_address = ramdisk;
    size_t size = 0;
    bool found = false;
    while ((size = tar.ReadHeader(load_address)) != SIZE_MAX) {
        string_view filename{load_address};
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
        terminate();
    }
    boot_data.cursor_pos = out.GetCursor();
    boot_data.ramdisk = ramdisk;
    boot_data.ramdisk_size = load_address - ramdisk;
}
