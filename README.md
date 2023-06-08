# RetroOS
Learn basic os construction

## Building and running
- install nativeos/i386-elf-toolchain for i386 cross compiler.
- install nasm for asm parts.
- install qemu for 386 emulation
- make image to build the boot image with kernel
- qemu-system-i386 image to run the emulation

## Goals of project
The goal is to write a small and readable example OS, at the cost of performance. This translates
into the following design choices 
1) Absolute minimal amount of asm code.
2) Minimal amount of c++ code that requires platform and compiler
specific logic, ie. calling convention or CPU dependent structures.
3) Cleanly separate the project in a pure c++ part (kernel) that conforms to
the c++ language standard, implementing the logic of operating system,
and a small platform/compiler dependent layer (arch) that contains a
super thin layer of asm.
4) Develop a functional interface between kernel and arch,
that allows seamless portability to other platforms/compilers.

Minimize the use of #define/#if macros, instead rely on generics or
interfaces and build dependencies to provide customizability.

## Non-goals

Given the above it's good to specifically cite some of the non-goals
1) Performance. We do want to write simple and performant code but 
not to the point it adds code, complexity, more asm. It's not meant
as a production OS.
2) Ideas like micro-kernels are a non-goal in this project. Those
ideas would only play a role in as much it helps simplicity and 
understandability of the kernel. Not because of security and
stability concerns.
3) Device drivers. To get a working kernel we need to support
keyboard, screen, mouse and hard disks. This detracts from the goals
of kernel. In real world setting device drivers are arguably the
biggest part of the OS, we use good'ol bios to short cut this.
