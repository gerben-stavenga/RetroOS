//
// Created by gerben stavenga on 6/17/23.
//

#ifndef OS_DESCRIPTORS_H
#define OS_DESCRIPTORS_H

#include <cstdint>

constexpr int kKernelCS = 0x8;
constexpr int kKernelDS = 0x10;
constexpr int kUserCS = 0x18;
constexpr int kUserDS = 0x20;
constexpr int kTSS = 0x28;
constexpr int kKernelCS64 = 0x30;
constexpr int kKernelDS64 = 0x40;


void SetupDescriptorTables();

extern uint8_t kernel_stack[4096 * 32];

#endif //OS_DESCRIPTORS_H
