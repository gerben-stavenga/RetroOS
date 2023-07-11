//
// Created by gerben stavenga on 7/8/23.
//

#ifndef OS_BOOT_H
#define OS_BOOT_H

#include <stdint.h>

struct MMapEntry {
    uint64_t base;
    uint64_t length;
    uint32_t type;
    uint32_t acpi;
} __attribute__((packed));

struct BootData {
    void* kernel;
    void* ramdisk;
    intptr_t ramdisk_size;
    int cursor_pos;
    int mmap_count;
    MMapEntry mmap_entries[32];
};

#endif //OS_BOOT_H
