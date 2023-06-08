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

## System assumptions

Although we want to separate kernel and arch, there are of course
still some (high level) platform assumptions. The assumptions are
1) The system is a byte-addressable random-access von Neumann 
machine, with a flat memory model.
2) There is paging at some arch specified granularity.
3) Interrupts / traps for external events or errors.
4The usual keyboard, screen, and storage are attached. Where
keyboard can be modelled as an incoming stream of characters, the
screen can be modelled by a rectangular 2d array of characters/pixels
and the storage can be modelled as 1d array of blocks, each of a
fixed size bytes. 

These are eminently reasonable and practical assumptions to target for
a portable OS.

## System calls

The end goal is to be able to support a reasonable subset of libc,
enough to get useful set of gnu coreutils and compiler working.
The classic milestone would be self-hosting.

## High level design

### Arch

Arch consist of a few components, namely
- A very platform specific booting part, mostly pure asm.
- Syscall / interrupt part, very thin asm layer + platform
dependent c++ code servicing the interrupts and translating them
to proper kernel calls.
- Timer, keyboard, screen and hard disk drivers. We keep this part
as small as possible.
- Paging manager.
- OS ABI (platform specific mechanism how user land interacts with kernel)

### Kernel

Kernel implements the high-level operating system, that users
interact with. 
- Memory manager
- Process manager
- File system (abstracts hard disk and keyboard)
- Timers, screen
- OS API (what functionality the OS provides)

### Meta

To facilitate development and testability it should be possible to
implement arch on top of the kernel OS API. Which means one should be
able to build the OS that runs inside it's own OS. This would
be another self-hosting milestone. The other arch implementation
would be against the linux (posix) API allowing development of
kernel on linux / macos as a regular user application.

### Directory structure

- arch
  - x86 - actual operating system.
  - um - user mode, implemented on top of the OS API.
  - linux - implemented on top of linux.
- kernel - the pure standard c++ kernel implementation.
- libc - implementation of libc on the OS API (this should allow self-hosting).