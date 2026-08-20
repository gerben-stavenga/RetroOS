# OS/2 personality tests

`hello/hello.c` is a normal Open Watcom C program linked with the standard
OS/2 runtime. It exercises the LX loader, Watcom startup, DLL imports and
`DOSCALLS` dispatch before printing through `stdio`.

Build the LX programs and compatibility DLLs hermetically with Bazel:

```sh
bazelisk build \
  //apps/os2/doscalls:doscalls_dll \
  //test/os2/hello:hello_lx
```

The DLL exports are two-byte `INT 82h` gates at their canonical OS/2 ordinals. No function returns inside the
DLL: the Rust OS/2 personality consumes the application return address and
finishes the call.

The packaged DOS filesystem installs the shared OS/2 runtime and C smoke test
at `C:\OS2\DLL\DOSCALLS.DLL` and `C:\OS2\APPS\HELLO.EXE`. DOS and OS/2
therefore see the same drive and directory tree.

Expected output includes `Hello from Open Watcom C`. `watcom_io/watcom_io.c` is the
normal Open Watcom CRT acceptance test (`C:\OS2\APPS\WATCIO.EXE`): it creates, writes, seeks, reads and
closes `C:\OS2\APPS\WATCOM.TXT`, then prints the verified contents.

Bazel downloads a pinned official Linux-hosted Open Watcom snapshot and
cross-compiles the tests to OS/2; no system-wide compiler installation is needed:

```sh
bazelisk build //test/os2/hello:hello_lx
```

Both programs link the normal runtime and therefore use the real Watcom entry
point and OS/2 calling convention. `watcom_io` additionally exercises memory
services and OS/2 file handles.
