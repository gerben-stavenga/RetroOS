CC := i386-elf-g++
LD := i386-elf-ld
AS := nasm

CFLAGS := -ffreestanding -O2 -Wall -Wextra -fno-exceptions -fno-rtti -std=c++17

BOOT_BIN := src/arch/x86/boot.bin
ARCH_OBJ := src/arch/x86/entry.o src/arch/x86/start32.o

ALL_OBJ := src/arch/x86/start32.o

include $(ALL_OBJ:.o=.d)

%.o: %.asm
	$(AS) -f elf $< -o $@

%.bin: %.asm
	$(AS) -f bin $< -o $@

%.o: %.cpp
	$(CC) $(CFLAGS) -c $< -o $@

%.d: %.cpp
	./depend.sh $(@D) $(CFLAGS) $< > $@

%.d: depend.sh

src/arch/x86/kernel.bin: $(ARCH_OBJ)
	i386-elf-ld -Ttext=0x1000 $(ARCH_OBJ) --oformat binary -o $@

IMAGE_DEPS := src/arch/x86/boot.bin src/arch/x86/kernel.bin
image: $(IMAGE_DEPS)
	cat $(IMAGE_DEPS) > image
	truncate -s 16M image
