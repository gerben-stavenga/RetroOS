# Win32 personality tests

These are normal 32-bit Windows console programs compiled and linked with the
Open Watcom C runtime. `HELLO.EXE` covers PE loading, Watcom startup and stdout.
`WATCIO.EXE` creates, writes, seeks, reads and closes
`C:\WINDOWS\APPS\WATCOM.TXT` before printing the verified contents.

RetroOS ships the PE replacement DLLs at `C:\RETROOS\WINDOWS\SYSTEM32` with the
matched boot runtime, even when C: is a separate data disk. Their exports are
two-byte `INT 83h` gates; Win32 API
semantics live in the Rust Windows personality.
The Win32 `GetEnvironmentStrings` API now exposes values parsed from
`C:\CONFIG\CONFIG.SYS`, including optional `HOME` and `MCHOME` settings.
`GetTempPathA` uses `TEMP` from that environment (default `C:\TEMP`).

The Win16 side follows the same boundary with real 16-bit NE facade modules
from `C:\RETROOS\WINDOWS\SYSTEM`. The NE loader resolves ordinal imports through those
modules' entry tables and patches 16:16 call sites to their `INT 83h` exports.
The original Windows 3.1 `WINMINE.EXE` is a local proprietary acceptance test
and is therefore not part of this repository.

```sh
bazelisk build \
  //lib/windows/kernel32:kernel32_dll \
  //lib/windows/user32:user32_dll \
  //lib/windows/win16:kernel_dll \
  //lib/windows/win16:user_dll \
  //lib/windows/win16:gdi_dll \
  //test/windows/hello:hello \
  //test/windows/watcom_io:watcom_io
```

## NDN and Win32 runtime regression

System DLL sources are under `lib/windows`. The optional GDIPLUS, IPHLPAPI,
MPR, NTDLL, OLE32, WININET, WSOCK32 and MSVCRT facades are packaged alongside
KERNEL32 and USER32. Unsupported desktop and network services report failure
so applications can disable those features.

The Win32 runtime supports PE string resources, signed file seeks, runtime
DLL imports and process initialization, named memory mappings for shared heaps,
executable page protection changes,
and cooperative threads sharing the process address space. Threads preserve
registers, floating point state, TEB, TLS and last error, with event, mutex,
critical section and sleep synchronization. ANSI message queues support NDN's
hidden window worker.

Run the focused regression on both hosted engines:

```sh
ENGINE=kvm python3 test/windows_threads.py
ENGINE=tcg python3 test/windows_threads.py
```

It executes a data-buffer thunk after `VirtualProtect`, checks protection
restoration, suspended threads, contended critical sections, sleep, auto-reset
events, TLS and floating point isolation, exit status, and a dynamically loaded
DLL whose exported function depends on `DllMain` having run. It also checks
named mappings shared by two views, as used by Virtual Pascal's runtime.

With a locally extracted NDN Windows distribution, also check import resolution for
SCRRES, DESCSS, NDNPASS and TETRIS:

```sh
NDN_DIR=/path/to/NDN-W32 ENGINE=kvm python3 test/windows_threads.py
```

The proprietary DLLs are copied into a temporary test drive and are not
included in the repository. The fixture skips their application-specific
DLL startup, which needs NDN's Virtual Pascal shared heap callbacks.
