#include "src/arch/x86/x86_inst.h"
#include "src/kernel/kassert.h"
#include "src/freestanding/utils.h"

enum {
    kDataRW = 0,
    kErrorR = 1,
    kFeaturesW = 1,
    kSectorCountRW = 2,
    kLBA_0_7RW = 3,
    kLBA_8_15RW = 4,
    kLBA_16_23RW = 5,
    kLBA_24_27_FlagsRW = 6,
    kStatusR = 7,
    kCommandW = 7,
};

void WaitDiskReady(int port) {
  while((X86_inb(port + kStatusR) & 0xC0) != 0x40);
}

void ReadSectors(unsigned lba, unsigned count, void* buffer) {
    assert(lba + count <= (1 << 28));

    constexpr int kPort = 0x1F0;
    int slave = 0;

    auto p = static_cast<uint16_t*>(buffer);
    while (count > 0) {
        int c = min(count, 256u);
        WaitDiskReady(kPort);
        X86_outb(kPort + kLBA_24_27_FlagsRW, (lba >> 24) | 0xE0 | (slave << 4));
        X86_outb(kPort + kFeaturesW, 0); // ?
        X86_outb(kPort + kSectorCountRW, c);  // 0 means 256
        X86_outb(kPort + kLBA_0_7RW, lba);
        X86_outb(kPort + kLBA_8_15RW, lba >> 8);
        X86_outb(kPort + kLBA_16_23RW, lba >> 16);
        X86_outb(kPort + kCommandW, 0x20);  // Read sectors

        count -= c;
        lba += c;

        do {
            WaitDiskReady(kPort);
            for (int i = 0; i < 256; i++) p[i] = X86_inw(kPort + kDataRW);
            p += 256;
        } while (--c);
    }
}
