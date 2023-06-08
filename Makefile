CC := i386-elf-g++
LD := i386-elf-ld
AS := nasm

CFLAGS := -ffreestanding -O2 -Wall -Wextra -fno-exceptions -fno-rtti -std=c++17

SRC :=  src/start32.cpp src/main.cpp
ASM_SRC := src/entry.asm src/boot.asm src/interrupt.asm
CPP_OBJ := $(SRC:.cpp=.o)

include $(CPP_OBJ:.o=.d)

%.o: %.asm
	$(AS) -f elf $< -o $@

%.o: %.cpp
	$(CC) $(CFLAGS) -c $< -o $@

%.d: %.cpp
	./depend.sh $@ $(CFLAGS) $< > $@
%.d: depend.sh

boot.bin: src/boot.asm
	nasm -f bin src/boot.asm -o $@

kernel.bin: src/entry.o src/start32.o
	i386-elf-ld -Ttext=0x1000 src/entry.o src/start32.o --oformat binary -o $@

image: boot.bin kernel.bin
	cat boot.bin kernel.bin  > image
	truncate -s 16M image
