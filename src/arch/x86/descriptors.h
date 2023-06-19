//
// Created by gerben stavenga on 6/17/23.
//

#ifndef OS_DESCRIPTORS_H
#define OS_DESCRIPTORS_H

struct DescriptorEntry {
    uint32_t limit : 16;
    uint32_t base : 24;
    uint32_t access: 1;  // set by processor on accessing segment
    uint32_t rw: 1;
    uint32_t dc: 1;
    uint32_t ex: 1;
    uint32_t special: 1;
    uint32_t dpl: 2;
    uint32_t present: 1;
    uint32_t limit_high: 4;
    uint32_t reserved: 2;
    uint32_t big: 1;
    uint32_t granularity: 1;
    uint32_t base_high: 8;    
} __attribute__((packed));

static_assert(sizeof(DescriptorEntry) == 8);

constexpr DescriptorEntry MakeSegDesc(bool is_32bit, bool is_code, int dpl) {
    return DescriptorEntry {
        0xFFFF,  // limit
        0,  // base
        0,  // access
        1,  // rw
        0,  // dc
        is_code, // executable
        1,  // special
        static_cast<uint16_t>(dpl),
        1,  // present
        is_32bit ? 0xFu : 0u,
        0,  // reserved
        is_32bit,  // 32 bit (operand size for cs)
        is_32bit,  // granularity of limit
        0,  // base high
    };
}

constexpr DescriptorEntry MakeTSSDescriptor(void* ptr) {
    uintptr_t base = reinterpret_cast<uintptr_t>(ptr);
    return DescriptorEntry {
            103,  // limit
            base,
            1,  // access
            0,  // busy
            0,  // dc
            1, // executable
            0,  // special is zero
            0,  // dpl (only kernel can do task switch)
            1,  // present
            0,  // limit high
            0,  // reserved
            0,  // 32 bit (operand size for cs)
            0,  // granularity of limit
            base >> 24,  // base high
    };
}

struct IdtEntry {
    uint16_t offset_low;
    uint16_t selector;
    uint16_t reserved : 8;
    uint16_t gate_type: 5;
    uint16_t dpl: 2;
    uint16_t present: 1;
    uint16_t offset_high;
} __attribute__((packed));

// We only use interrupt gates (which additionally clears IF) and enable interrupts manually
// depending on the logic
constexpr IdtEntry MakeInterruptGate(void* ptr, uint16_t dpl) {
    auto base = reinterpret_cast<uintptr_t>(ptr);
    auto offset_low = static_cast<uint16_t>(base);
    auto offset_high = static_cast<uint16_t>(base >> 16);
    return IdtEntry{offset_low, 0x8, 0, 0xE, dpl, 1, offset_high};
}

#endif //OS_DESCRIPTORS_H
