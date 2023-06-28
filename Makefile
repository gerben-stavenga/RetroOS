CC := i386-elf-g++
LD := i386-elf-ld
AS := nasm

CFLAGS := -O2 -Wall -Wextra -ffreestanding -fno-exceptions -fno-rtti -fomit-frame-pointer -std=c++20 -I .

BOOTLOADER_OBJ := src/arch/x86/boot.o
KERNEL_OBJ := src/arch/x86/start32.o src/arch/x86/paging.o src/arch/x86/descriptors.o src/arch/x86/traps.o src/arch/x86/irq.o

ALL_OBJ := $(BOOTLOADER_OBJ) $(KERNEL_OBJ)

include $(ALL_OBJ:.o=.d)

%.o: %.asm
	$(AS) -f elf $< -o $@

%.o: %.cpp
	$(CC) $(CFLAGS) -c $< -o $@

%.d: %.cpp
	./depend.sh $(@D) $(CFLAGS) $< > $@

%.d: depend.sh

%.bin: %.elf
	i386-elf-objcopy -O binary $< $@

src/freestanding/freestanding.a: src/freestanding/utils.o
	i386-elf-ar rcs $@ $^

src/libc/libc.a: src/libc/libc.o
	i386-elf-ar rcs $@ $^

src/arch/x86/bootloader.elf: src/arch/x86/boot.ld src/arch/x86/mbr.o $(BOOTLOADER_OBJ) src/freestanding/freestanding.a
	i386-elf-ld -T $^ -o $@

src/arch/x86/bootloader_padded.bin: align.py src/arch/x86/bootloader.bin
	./$^ > $@

src/arch/x86/kernel.elf: src/arch/x86/kernel.ld src/arch/x86/entry.o $(KERNEL_OBJ) src/freestanding/freestanding.a
	i386-elf-ld -T $^ -o $@

src/arch/x86/init: src/libc/crt0.o src/arch/x86/init.o src/libc/libc.a src/freestanding/freestanding.a
	i386-elf-ld -Ttext=0x10000 --oformat=binary $^ -o $@

fs.tar: src/arch/x86/kernel.bin src/arch/x86/init depend.sh
	tar -cf fs.tar $^

IMAGE_DEPS := src/arch/x86/bootloader_padded.bin fs.tar
image: $(IMAGE_DEPS)
	cat $(IMAGE_DEPS) > image
	truncate -s 16M image
