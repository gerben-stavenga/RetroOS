# Win32 personality tests

These are normal 32-bit Windows console programs compiled and linked with the
Open Watcom C runtime. `HELLO.EXE` covers PE loading, Watcom startup and stdout.
`WATCIO.EXE` creates, writes, seeks, reads and closes
`C:\WINDOWS\APPS\WATCOM.TXT` before printing the verified contents.

RetroOS loads the ordinary PE replacement DLLs from
`C:\WINDOWS\SYSTEM32`. Their exports are two-byte `INT 83h` gates; Win32 API
semantics live in the Rust Windows personality.

```sh
bazelisk build \
  //apps/windows/kernel32:kernel32_dll \
  //apps/windows/user32:user32_dll \
  //test/windows/hello:hello \
  //test/windows/watcom_io:watcom_io
```
