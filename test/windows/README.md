# Win32 personality tests

These are normal 32-bit Windows console programs compiled and linked with the
Open Watcom C runtime. `HELLO.EXE` covers PE loading, Watcom startup and stdout.
`WATCIO.EXE` creates, writes, seeks, reads and closes
`C:\WINDOWS\APPS\WATCOM.TXT` before printing the verified contents.

RetroOS ships the PE replacement DLLs at `C:\RETROOS\WINDOWS\SYSTEM32` with the
matched boot runtime, even when C: is a separate data disk. Most exports are
two-byte `INT 83h` gates into the Rust Windows personality. USER32 also contains guest Rust code: `CreateWindowExA/W`,
`SendMessageA/W`, and `DispatchMessageA/W` call application window procedures
using the guest stack. Window allocation, procedure lookup and release remain
private kernel gates.
The Win32 `GetEnvironmentStrings` API now exposes values parsed from
`C:\RETROOS\RETROOS.INI`, including optional `HOME` and `MCHOME` settings.
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

## Guest-stack window callbacks

`CreateWindowExA/W` builds a `CREATESTRUCT` on its guest stack, calls
`WM_NCCREATE` and `WM_CREATE` synchronously, and handles rejected creation
before returning. Nested creation and message dispatch use ordinary guest
calls and returns, so no Rust continuation or kernel window-callback record
survives a call into application code. This does not implement a save-state
format; it keeps the pending call state in guest memory and CPU registers.

Run the callback regression with either hosted engine:

```sh
ENGINE=kvm python3 test/windows_callbacks.py
ENGINE=tcg python3 test/windows_callbacks.py
```

It checks ANSI and Unicode creation, `CREATESTRUCT` contents, class atoms,
creation rejection and cleanup, nested window creation and synchronous
messages, timer dispatch, and a thread blocking inside a callback while
another thread creates a window. A separate program loads USER32 at runtime
and checks its exported guest functions and private gates.

This is the basic creation/message path, not complete USER32 compatibility:
creation's full nonclient/positioning notifications, cross-process messaging,
and ANSI/Unicode message conversion remain unimplemented.

The Rust implementation is in `lib/windows/user32/user32.rs`, with pure
rectangle operations in `rect.rs`. A pinned Windows Rust core is used only
for `no_std` compilation; the DLL does not import the Windows Rust standard
library or a C runtime. `extern "system"` supplies the Win32 calling
convention, and the existing PE linker exports the normal undecorated API
names. NASM contains only kernel-entry gates. The same test also exercises
rectangle boundaries, aliasing, intersections, unions and subtraction, plus
`CallWindowProcA/W`.

The message fixture checks per-thread posted queues, window/child and message
filters, `PM_NOREMOVE`, `WM_QUIT`, deadline-based timers, timer replacement and
cancellation, and pending timer messages surviving cancellation. Cross-thread
`SendMessage` runs callbacks on their owning thread; a blocked sender services
incoming sends, including a nested call back from its receiver. `ReplyMessage`
can unblock the sender before the receiver returns. No USER state lock is held
across application callbacks.

The guest DLL owns queues and timers. `RetroReadEvent` transfers kernel input
and paint notifications, and subscribes existing KERNEL32 events for wakeups.
Waiting uses `WaitForSingleObject`, with the next matching timer as its timeout.
There is no fabricated timer on an empty queue or busy-polling message loop.
The kernel retains its separate Win16 message handling.
