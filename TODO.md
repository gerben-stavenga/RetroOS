* Move to PAE page tables
* Support 64bit long mode (with 32 bit kernel running in compat mode)
* Load kernel in elf format in boot loader (use segment wrapping to load high) and jump to _start
* Enable CPU switching between legacy PAE mode and compatibility mode and vice versa
* Load elf symbols (both kernel and apps) for full annotated stack traces
* Add VM86 monitor for legacy 32 bit mode
* Add dos + dpmi + xms + ems api support
* Support linux 32 bit/64 bit syscalls
* Add sound card drivers
* Add VFS + ext3 fs support
* Emulate GUS/SB
* Give dos apps permission to much video ports (mode x) and save/load video settings
