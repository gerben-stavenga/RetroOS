# DPMI exception routing

Run `python3 test/dpmi_rm_exception.py` from the repository root. Set
`ENGINE=kvm` to exercise the KVM backend. The guest checks the DOS date
probe used to detect DESQview, a real-mode INT 6 hook called through DPMI
0301h, and a protected-mode exception handler installed through 0203h.

## NDN DPMI32 smoke test

The NDN distribution in `apps-boot/NDN-D32` is packaged under
`C:\RETROOS\NDN-D32` on the read-only runtime volume. Its plugin loader
opens DLLs with read/write access (INT 21h AX=716Ch, BX=0042h, falling
back to AX=3D42h). Running there produces a `Cannot load module ...
DESCSS.DLL` dialog; dismissing that dialog can also crash this NDN build.

Copy the entire directory, including its subdirectories, to the writable
data disk as `C:\NDN-D32`. Run `C:\NDN-D32\NDN.COM` from that directory.
In a native QEMU smoke test, this loads all three plugin DLLs and reaches
the file panels without the module error. Test with a private data disk
or a snapshot; do not edit the disk image while another VM is using it.

The startup probe intentionally executes an illegal instruction. Its
real-mode INT 6 hook must receive the fault, even when NDN has installed
a protected-mode DPMI 0203h handler. Treating that real-mode segment as a
protected-mode selector crashes startup before the panels appear.
