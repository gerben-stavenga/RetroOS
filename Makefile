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

%.bin: %.asm
	$(AS) -f bin $< -o $@

%.o: %.cpp Makefile
	$(CC) $(CFLAGS) -c $< -o $@

%.d: %.cpp
	./depend.sh $(@D) $(CFLAGS) $< > $@

%.d: depend.sh

src/arch/x86/bootloader.bin: src/arch/x86/boot_entry.o $(BOOTLOADER_OBJ)
	i386-elf-ld -Ttext=0x7e00 $^ --oformat binary -o $@

src/arch/x86/bootloader_padded.bin: src/arch/x86/bootloader.bin
	cp $^ $@
	truncate -s 2560 $@

src/arch/x86/kernel.bin: src/arch/x86/entry.o $(KERNEL_OBJ)
	i386-elf-ld -Ttext=0xFF000000 $^ --oformat binary -o $@

IMAGE_DEPS := src/arch/x86/mbr.bin src/arch/x86/bootloader_padded.bin src/arch/x86/kernel.bin
image: $(IMAGE_DEPS)
	cat $(IMAGE_DEPS) > image
	truncate -s 16M image
