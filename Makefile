CC := clang++
LD := ld
AR := ar
AS := nasm
OBJCOPY := i686-linux-gnu-objcopy

# no-red-zone is needed because in kernel mode, the stack is nested due to interrupts not switching to a new stack
CFLAGS := -O2 -Wall -Wextra -m32 -march=i386 -ffreestanding -fbuiltin -fno-exceptions -fno-rtti -fomit-frame-pointer -fno-common -fno-pie -fcf-protection=none -fno-asynchronous-unwind-tables -mno-red-zone -std=c++20 -I .
LDFLAGS := -melf_i386 -nostdlib -no-pie

BOOTLOADER_OBJ := build/src/arch/x86/boot/boot.o
KERNEL_OBJ := build/src/arch/x86/start32.o build/src/arch/x86/paging.o build/src/arch/x86/descriptors.o build/src/arch/x86/traps.o build/src/arch/x86/irq.o build/src/arch/x86/thread.o
FREESTANDING_OBJ := build/src/freestanding/utils.o
LIBC_OBJ := build/src/libc/libc.o
INIT_OBJ := build/src/arch/x86/init.o

ALL_OBJ := $(BOOTLOADER_OBJ) $(KERNEL_OBJ) $(FREESTANDING_OBJ) $(LIBC_OBJ) $(INIT_OBJ)

include $(ALL_OBJ:.o=.d)

build/%.o: %.asm
	mkdir -p $(@D)
	$(AS) -f elf $< -o $@

build/%.o: %.cpp build/%.d Makefile
	mkdir -p $(@D)
	$(CC) $(CFLAGS) -c $< -o $@

build/%.d: %.cpp depend.sh
	mkdir -p $(@D)
	./depend.sh $(@D) $(CFLAGS) $< > $@

%.bin: %.elf
	mkdir -p $(@D)
	$(OBJCOPY) --remove-section .note* -O binary $< $@

build/src/freestanding/freestanding.a: $(FREESTANDING_OBJ)
	mkdir -p $(@D)
	$(AR) rcs $@ $^

build/src/libc/libc.a: $(LIBC_OBJ)
	mkdir -p $(@D)
	$(AR) rcs $@ $^

build/src/arch/x86/bootloader.elf: src/arch/x86/boot/boot.ld build/src/arch/x86/boot/mbr.o $(BOOTLOADER_OBJ) build/src/freestanding/freestanding.a
	mkdir -p $(@D)
	$(LD) -T $^ -o $@ $(LDFLAGS)

build/src/arch/x86/kernel.elf: src/arch/x86/kernel.ld build/src/arch/x86/entry.o $(KERNEL_OBJ) build/src/freestanding/freestanding.a
	mkdir -p $(@D)
	$(LD) -T $^ -o $@ $(LDFLAGS)

build/src/arch/x86/init.elf: build/src/libc/crt0.o $(INIT_OBJ) build/src/libc/libc.a build/src/freestanding/freestanding.a
	mkdir -p $(@D)
	$(LD) --image-base-= 0x10000 $^ -o $@ $(LDFLAGS)

build/kernel.md5: build/src/arch/x86/kernel.bin
	md5sum $< | xxd -r -p > $@

# tar is used to create a filesystem image, it naturally blocks files to 512 bytes which matches the sector size
build/fs.tar: build/src/arch/x86/bootloader.bin build/kernel.md5 build/src/arch/x86/kernel.bin build/src/arch/x86/init.bin
	tar -cf $@ -C build $(^:build/%=%)

# the first file in the tar is the bootloader, so we need to skip the first 512 bytes which is the tar header for
# the bootloader so that the MBR is correctly filled with the first 512 bytes of bootloader.bin
# NOTE: tail is 1-indexed, so this strips the first 512 bytes
build/image: build/fs.tar
	tail -c +513 $< > $@
	truncate -s 16M $@
