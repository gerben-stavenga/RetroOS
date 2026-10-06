# Win16 personality modules

These are real 16-bit Windows 3.x NE DLLs. Open Watcom links their OMF gate
objects with the module names and ordinal export tables expected by Win16
applications. Each exported entry is the same two-byte `INT 83h` ABI boundary
used by RetroOS's Win32 facade DLLs; the kernel owns the implementation.

The normal image installs the modules in `C:\WINDOWS\SYSTEM`. The NE loader
loads each imported module, maps its segments behind LDT selectors, resolves
the requested export ordinal, and patches the application's chained 16:16
relocations to the exported selector and offset.

The modules intentionally contain no Microsoft code.
