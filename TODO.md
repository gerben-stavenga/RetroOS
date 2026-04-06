# DOS Game Compatibility — Bug Sprint

## Keen4
- [ ] Keyboard input: keypresses and releases sometimes missed, causing Keen to run continuously in one direction
- [ ] Startup screen has some graphical corruption

## Prince of Persia
- [ ] Demo loop runs fine, but no keyboard input detected at all

## Wolf3D
- [ ] Doesn't boot yet

## Memory Management
- [ ] XMS (Extended Memory Specification) support
- [ ] EMS (Expanded Memory Specification) support
- [ ] VCPI (Virtual Control Program Interface) support
- [ ] DPMI (DOS Protected Mode Interface) support

## Architecture
- [ ] Hardware-enforced isolation: shrink Ring 1 segment limits to exclude Ring 0/Arch region (long-term)
- [ ] VGA / COW interaction: investigate "hello.com output appears one run late" symptom. Current theory: VM86 BIOS writes via user virt 0xA0000/0xB8000 get COW'd to private pages on fork (RESERVED phys_mm status only guards refcount, not the cow_entry alloc/copy path). CACHE_DISABLE-skip fix applied in `share_and_copy` (paging2.rs) — needs empirical verification, and decide whether to also short-circuit RESERVED in `cow_entry` as belt-and-braces.
