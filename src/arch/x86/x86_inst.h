//
// Created by gerben stavenga on 6/18/23.
//

#ifndef OS_X86_INST_H
#define OS_X86_INST_H

#include <stddef.h>

struct DescriptorPtr {
    uint16_t limit;
    const void* base;
} __attribute__((packed));

inline void LoadGDT(void* base, size_t size) {
    DescriptorPtr ptr = {static_cast<uint16_t>(size - 1), base};
    asm volatile ("lgdt %0\n\t"::"m"(ptr));
}

inline void LoadIDT(void* base, size_t size) {
    DescriptorPtr ptr = {static_cast<uint16_t>(size - 1), base};
    asm volatile ("lidt %0\n\t"::"m"(ptr));
}

inline void LoadTR(int selector) {
    asm volatile ("ltr %w0\n\t"::"r" (selector));
}

// This is the physical address, pointers in the kernel refer
// to linear address.
inline void LoadPageDir(uintptr_t page) {
    asm volatile ("mov %0, %%cr3\n\t"::"r"(page):"memory");
}

inline void outb(uint16_t port, uint8_t data) {
    asm volatile("outb %0, %1" : : "a"(data), "d"(port));
}

inline uint8_t inb(uint16_t port) {
    uint8_t data;
    asm volatile("inb %1, %0" : "=a"(data) : "d"(port));
    return data;
}

inline void EnableIRQ() {
    asm volatile ("sti\n\t");
}

inline void DisableIRQ() {
    asm volatile ("cli\n\t");
}

inline void hlt_inst() {
    asm volatile("hlt\n\t");
}

inline uintptr_t LoadPageFaultAddress() {
    uintptr_t address;
    asm ("mov %%cr2, %0":"=r"(address));
    return address;
}

inline const void* GetIP() {
    uintptr_t res;
    asm volatile(
            "call 1f\n\t"
            "1:\n\t"
            "pop %0\n\t"
            : "=r"(res));
    return reinterpret_cast<const void*>(res);
}

inline bool CheckA20() {
    volatile uint32_t tmp = 0xDEADBEEF;
    uint32_t volatile* a20_aliased = reinterpret_cast<uint32_t *>(reinterpret_cast<uintptr_t>(&tmp) ^ 0x100000);
    if (tmp != *a20_aliased) return true;
    tmp = 0xCAFEBABE;
    return tmp != *a20_aliased;
}

#endif //OS_X86_INST_H
