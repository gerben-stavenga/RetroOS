CC := i686-elf-g++
LD := i686-elf-g++
AR := i686-elf-ar
AS := nasm

# no-red-zone is needed because in kernel mode, the stack is nested due to interrupts not switching to a new stack
CFLAGS := -Os -Wall -Wextra -ffreestanding -fno-exceptions -fno-rtti -fomit-frame-pointer -fno-common -mno-red-zone -std=c++20 -I .
LDFLAGS := $(CFLAGS) -nostdlib -lgcc

BOOTLOADER_OBJ := src/arch/x86/boot.o
KERNEL_OBJ := src/arch/x86/start32.o src/arch/x86/paging.o src/arch/x86/descriptors.o src/arch/x86/traps.o src/arch/x86/irq.o src/arch/x86/thread.o
FREESTANDING_OBJ := src/freestanding/utils.o
LIBC_OBJ := src/libc/libc.o
INIT_OBJ := src/arch/x86/init.o

ALL_OBJ := $(BOOTLOADER_OBJ) $(KERNEL_OBJ) $(FREESTANDING_OBJ) $(LIBC_OBJ) $(INIT_OBJ)

include $(ALL_OBJ:.o=.d)

%.o: %.asm
	$(AS) -f elf $< -o $@

%.o: %.cpp %.d Makefile
	$(CC) $(CFLAGS) -c $< -o $@

%.d: %.cpp depend.sh
	./depend.sh $(@D) $(CFLAGS) $< > $@

%.bin: %.elf
	i386-elf-objcopy -O binary $< $@

src/freestanding/freestanding.a: src/freestanding/utils.o
	$(AR) rcs $@ $^

src/libc/libc.a: src/libc/libc.o
	$(AR) rcs $@ $^

src/arch/x86/bootloader.elf: src/arch/x86/boot.ld src/arch/x86/mbr.o $(BOOTLOADER_OBJ) src/freestanding/freestanding.a
	$(LD) -T $^ -o $@ $(LDFLAGS)

src/arch/x86/kernel.elf: src/arch/x86/kernel.ld src/arch/x86/entry.o $(KERNEL_OBJ) src/freestanding/freestanding.a
	$(LD) -T $^ -o $@ $(LDFLAGS)

src/arch/x86/init.elf: src/libc/crt0.o src/arch/x86/init.o src/libc/libc.a src/freestanding/freestanding.a
	$(LD) -Ttext=0x10000 $^ -o $@ $(LDFLAGS)

# tar is used to create a filesystem image, it naturally blocks files to 512 bytes which matches the sector size
fs.tar: src/arch/x86/bootloader.bin src/arch/x86/kernel.bin src/arch/x86/init.bin depend.sh
	tar -cf fs.tar $^

# the first file in the tar is the bootloader, so we need to skip the first 512 bytes which is the tar header for
# the bootloader so that the MBR is correctly filled with the first 512 bytes of bootloader.bin
# NOTE: tail is 1-indexed, so this strips the first 512 bytes
image: fs.tar
	tail -c +513 $< > image
	truncate -s 16M image
