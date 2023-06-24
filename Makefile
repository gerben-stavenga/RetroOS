CC := i386-elf-g++
LD := i386-elf-ld
AS := nasm

CFLAGS := -ffreestanding -O2 -Wall -Wextra -fno-exceptions -fno-rtti -std=c++17 -I .

BOOTLOADER_OBJ := src/arch/x86/boot.o
KERNEL_OBJ := src/arch/x86/start32.o

ALL_OBJ := $(BOOTLOADER_OBJ) $(KERNEL_OBJ)

include $(ALL_OBJ:.o=.d)

%.o: %.asm
	$(AS) -f elf $< -o $@

%.o: %.cpp Makefile
	$(CC) $(CFLAGS) -c $< -o $@

%.d: %.cpp
	./depend.sh $(@D) $(CFLAGS) $< > $@

%.d: depend.sh

src/arch/x86/bootloader.bin: src/arch/x86/boot.ld src/arch/x86/mbr.o $(BOOTLOADER_OBJ)
	i386-elf-ld -T $^ --oformat binary -o $@

src/arch/x86/bootloader_padded.bin: src/arch/x86/bootloader.bin
	cp $^ $@
	truncate -s 2560 $@

src/arch/x86/kernel.bin: src/arch/x86/kernel.ld src/arch/x86/entry.o $(KERNEL_OBJ)
	i386-elf-ld -T $^ --oformat binary -o $@

IMAGE_DEPS := src/arch/x86/bootloader_padded.bin src/arch/x86/kernel.bin
image: $(IMAGE_DEPS)
	cat $(IMAGE_DEPS) > image
	truncate -s 16M image
