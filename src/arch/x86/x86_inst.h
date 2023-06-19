//
// Created by gerben stavenga on 6/18/23.
//

#ifndef OS_X86_INST_H
#define OS_X86_INST_H

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

// This is the physical address, pointers in the kernel refer
// to linear address.
inline void LoadPageDir(uintptr_t page) {
    asm volatile ("mov %0, %%cr3\n\t"::"r"(page));
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

inline const void* GetIP() {
    uintptr_t res;
    asm volatile(
            "call 1f\n\t"
            "1:\n\t"
            "pop %0\n\t"
            : "=r"(res));
    return reinterpret_cast<const void*>(res);
}

#endif //OS_X86_INST_H
