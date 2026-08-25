# Win32 personality tests

These are normal 32-bit Windows console programs compiled and linked with the
Open Watcom C runtime. `HELLO.EXE` covers PE loading, Watcom startup and stdout.
`WATCIO.EXE` creates, writes, seeks, reads and closes
`C:\WINDOWS\APPS\WATCOM.TXT` before printing the verified contents.

RetroOS loads the ordinary PE replacement DLLs from
`C:\WINDOWS\SYSTEM32`. Their exports are two-byte `INT 83h` gates; Win32 API
semantics live in the Rust Windows personality.

The Win16 side follows the same boundary with real 16-bit NE facade modules
from `C:\WINDOWS\SYSTEM`. The NE loader resolves ordinal imports through those
modules' entry tables and patches 16:16 call sites to their `INT 83h` exports.
The original Windows 3.1 `WINMINE.EXE` is a local proprietary acceptance test
and is therefore not part of this repository.

```sh
bazelisk build \
  //apps/windows/kernel32:kernel32_dll \
  //apps/windows/user32:user32_dll \
  //apps/windows/win16:kernel_dll \
  //apps/windows/win16:user_dll \
  //apps/windows/win16:gdi_dll \
  //test/windows/hello:hello \
  //test/windows/watcom_io:watcom_io
```
