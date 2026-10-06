# OS/2 personality tests

`hello/hello.c` is a normal Open Watcom C program linked with the standard
OS/2 runtime. It exercises the LX loader, Watcom startup, DLL imports and
`DOSCALLS` dispatch before printing through `stdio`.

Build the LX programs and compatibility DLLs hermetically with Bazel:

```sh
bazelisk build \
  //lib/os2/doscalls:doscalls_dll \
  //test/os2/hello:hello_lx
```

The DLL exports are two-byte `INT 82h` gates at their canonical OS/2 ordinals. No function returns inside the
DLL: the Rust OS/2 personality consumes the application return address and
finishes the call.

The packaged DOS filesystem installs the shared OS/2 runtime and C smoke test
at `C:\RETROOS\OS2\DLL\DOSCALLS.DLL` and `C:\OS2\APPS\HELLO.EXE`. DOS and OS/2
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

`pm_smoke/pm_smoke.c` is the first native Presentation Manager acceptance
program. It creates a PM window, paints through `WinFillRect`, and remains in
its PM message loop. Run `C:\OS2\APPS\PMSMOKE.EXE`; use the F12 monitor to
switch away from or terminate it.

## Runtime regression

```sh
ENGINE=tcg python3 test/os2_runtime.py
ENGINE=kvm python3 test/os2_runtime.py
```

This runs the normal Watcom CRT tests and `runtime/runtime.c`. The latter
checks DLL initialization and exported calls, named shared memory, committed
memory protection and execution from LX data pages, current directories, file reads/writes and metadata,
directory searches, 16-bit VIO/KBD calls, and timed waits. `PROBE.DLL` reads
memory created by its caller during its actual `_DLL_InitTerm` callback.

The LX parser tests cover both EXEPACK page encodings, malformed compressed
streams, relocation source lists, selector-only records, and alias flags.
The compressed-page token layout was checked against
[lxLite's decoder](https://github.com/bitwiseworks/lxlite/blob/master/src/os2exe.pas)
and the [IBM LX specification](https://komh.github.io/os2books/os2tk45/lxref.htm).

NDN's OS/2 distribution is an additional manual acceptance check: run
`NDN-O32\NDN.EXE` with its accompanying `NDNPMAPI.DLL` and language files.
The loader calls the real DLL initializer and uses the same filesystem as
DOS. VIO text is presented through the compositor, and 16-bit keyboard/video
calls translate selector-based pointers and stack frames.
Readable LX object pages remain executable through the flat code selector,
matching classic OS/2's x86 paging behavior. This supports Pascal runtime
trampolines stored in data objects even when RetroOS itself uses NX protection.

Workplace Shell object operations, network services, and device IOCTLs remain
unsupported; these entrypoints report failure. The compatibility DLL sources
are system libraries under `lib/os2/`, and their implementations are under
`kernel/src/kernel/os2/`.
