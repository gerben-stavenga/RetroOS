# dosrt — Rust-on-DOS via a shared ELF loader

Run ordinary `no_std` 32-bit Rust ELF programs as DOS apps under a DPMI host
(RetroOS's DOS personality first; stock DOS + CWSDPMI later). One shared
loader system-wide; per-app cost is a tiny stub + the app's own ELF.

## Three stages

```
app.exe = [ tc/asm MZ stub ] ++ [ payload ELF ]      (per app)
RLOADER.BIN  = pure-PM flat Rust loader              (one, shared, over //lib elf)
payload      = ordinary Rust no_std ELF              (per app; e.g. hello, later modplay)
```

### Control flow (linear — no returns)

1. **stub** (real mode, MZ EXE): finds `RLOADER.BIN` (env `RLOADER=`, else
   fixed path) and reads it into memory; `open`s its own `.EXE` (path-passing
   INT 21h is trivial in real mode); reserves a small transfer buffer in its
   own conventional memory; DPMI detect (INT 2Fh AX=1687) + enter PM.
2. A ~dozen-instruction **asm thunk** (Turbo C is real-mode-only, so the
   post-PM-entry handoff cannot be C) far-jumps to `RLOADER._start` (32-bit).
3. **RLOADER** (pure PM): `lseek`+`read` the payload ELF from the stub's open
   handle via DPMI `AX=0300` + the stub's conventional xfer buffer (no DPMI
   DOS-mem alloc needed — same process, the stub's memory *is* conventional);
   parse via `lib::elf`; `INT 31h AX=0501` alloc payload memory; copy
   PT_LOADs, zero BSS, apply relocs; far-jump payload entry. **Never returns,
   never frees itself** (≈KB resident; reclaimed with the process on exit).
4. **payload** runs; exits via INT 21h AH=4Ch → unwinds to DOS.

### Handoff contract (stub → RLOADER `_start`, 32-bit)

| reg | meaning |
|-----|---------|
| EBX | DOS file handle of the app `.EXE` (stub opened it) |
| ECX | byte offset of the appended payload ELF within the `.EXE` |
| EDX | DPMI INT 31h entry (0 if host reflects `int 0x31` directly) |
| ESI | real-mode `seg:off` of the stub's xfer buffer (seg<<16 | off) |
| EDI | xfer buffer length (bytes) |

RLOADER's PM INT-21h shim is **only** a bounce read loop (`lseek` is
register-only/plain-reflect; `read` uses `AX=0300` into the xfer buffer then
copies linear→payload). It is independent of any shim the payload needs at
runtime — no ABI coupling between RLOADER and payload.

## Bring-up order (RetroOS first)

1. `hello` payload + chain prove-out under RetroOS DOS personality.
2. Swap payload → MOD player (loads `INTRO.MOD`, SB DMA) once the chain is green.

## Status

SCAFFOLD. Structure + contract + skeletons are in place. Needs build bring-up:
- a freestanding `no_std` Rust **binary** ELF is new ground here (all existing
  `apps/` Rust is musl-Linux); the `retro.bzl` transition + `ld -T` genrule
  mirror the kernel pattern but must be iterated until it links.
- the DPMI real→PM enter sequence in `stub/stub.asm` and RLOADER's `AX=0300`
  read loop are written to the documented DPMI services
  (`kernel/src/kernel/dos/dpmi.rs`) but need on-target debugging.
