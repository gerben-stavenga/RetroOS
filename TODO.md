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


# Memory Layout

## Legacy

Page size is 4kb with 32 bit pointer entries means we have 1024 entries per page, and two level hierachy.

PD (Page directory of 10 bits = 1024 entries)   ->  PT (Page table of 10 bits = 1024 entries)  -> Page (12 bits = 4kb)

## Legacy with PAE (physical address extension)

With PAE a 32 bit computer can access more than 4gb memory, due to page table entries being 64 bit. However a single
address space is still limited to 4gb. However different processes that each live in their own address space can together
access more than 4gb memory.

PDPT (page directory pointer table, 2 bits 4 entries)
PD (page directory 9 bits, 512 entries)
PT (page table 9 bits, 512 entries)
Page (12 bits)

## Long mode (64 bit)

In long mode with 64 bit registers the address space is widened to 48 bits (256 TB). This is done by adding another
layer in the page hierarchy and enlarging PDPT to full page. 

PML4 (page map level 4, 9 bits)
PDPT (page directory pointer table, 9 bits)
PD (page directory 9 bits, 512 entries)
PT (page table 9 bits, 512 entries)
Page (12 bits)

# Recursive paging

In order to access the memory pages backing the page tables, those pages itself have to be present somewhere in the page tables.
The most elegant way to acomplish this is to make one entry of the root page point to itself. Because the format of each level
of the page hierarchy is a valid page structure. Addresses that have a bit pattern that cause the recursive entry to be traversed
one or more times will reach a page that is used as the backing page of one of the page table pages.

It's easy to get confused. So the best way is write formulas. The linear addresses of the page tables will some consecutive range
in the address space, starting with the prefix of the recursive entry in the root page table. This means that the address space
reserved by the page tables will be total_address_size / num_page_entries. 

For legacy this is 4gb/1024 = 4mb, for PAE this is 4gb/512 = 8mb and for LM it is 256TB/512 = 512gb.

There is some misinformation on OSDEV that for PAE, recursive pages would occupy 1gb of the address space. Because the PDPT is
4 entries. This is not true, when PDPT is interpreted as a PD due to the recursive entry we can use the remaining 508 entries
of the page as entries of a normal page directory.

# Mixing legacy PAE and long mode

Long mode has 32 bit compatibility mode that runs 32 bit application code fine, however it does not support V86 mode anymore.
The goal of retro os is to support natively all modes, in a modern OS. So we want to run 16 bit dos code natively which 
requires switching back to legacy mode. This suggest a 32 bit kernel that supports 16, 32, 64 bit app code. By taking care 
we keep the kernel address spaces identical between legacy PAE and long mode. 

Using recursive pages for PDPT we have only one good option, the page table address range should be in higher half memory and
only 0xC0000000 makes sense, if we want to give user space 3GB address space. If we place the PDPT at start bits of a
page then the address range for the page tables is 0xC000.0000-0xC080.0000.

We need the first 4GB address space in LM to be the same. This means that the first entry of PML4 points to PDPT page. We do
want our 32 bit kernel to manipulate PML4, so we can add at entry 4 of PDPT a link back to PML4. This means we get access

