# Contributors

RetroOS is written by Gerben Stavenga. The people below have contributed
changes that are part of the tree; thank you.

## István Nagy (<https://github.com/nistvan86>)

**DPMI physical address mapping — `INT 31h AX=0800h` / `AX=0801h`.**

Protected-mode DOS programs map a VESA linear framebuffer by asking DPMI to
translate its physical address. RetroOS answered `0800h` by clearing carry and
echoing the address straight back, so a client received a physical address that
was neither mapped nor even inside the user half of the address space, and
faulted on the first write to it. Under QEMU with SeaBIOS reporting the LFB at
`0xFD000000`, Duke Nukem 3D in an 800x600 SVGA mode died with

    fault rip=0x6229f1 addr=0xfd000000 err=0x6      (user write, non-present)
    SEGV in thread 1 at 0xfd000000

His implementation maps the requested physical range into a dedicated
downward-growing window (`PHYS_MAP_TOP`), preserving the caller's sub-page
offset in the linear address it returns, and records each mapping so `0801h`
can release it by the exact address that was handed out. Pages are mapped
cache-disabled and flagged as externally owned, so device memory is never
returned to the page allocator. Mappings are released when the client exits and
when a nested `EXEC` replaces the DPMI state, and the two new page flags are
named in `arch-abi` rather than open-coded as raw PTE bits.

He also diagnosed the palette failure that accompanies it, which turned out not
to be ours: see the `VGABIOS_ROM` note in `run.sh`.
