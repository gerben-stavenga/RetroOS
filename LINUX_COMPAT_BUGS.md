# Linux compatibility bugs found by running Claude Code on RetroOS

Claude Code 2.1.325 (a Bun 1.4.4 single-file binary, dynamically linked
x86-64) ran on RetroOS under the Linux personality twice on 2026-11-15, on a
kernel based on `c179d1e6`. Reads and network traffic worked from the start.
Every failure traced back to a place where RetroOS's Linux layer or
filesystems answer differently from Linux.

## Status

| Tool | Run 1 (`c179d1e6`) | Run 2 (+ `/proc/self/fd` fix) | Run 3 (current uncommitted tree) |
| --- | --- | --- | --- |
| Read | works | works | works |
| Write (new file) | ENOENT on create | works | works |
| Edit (existing file) | "String not found" | ENOENT on the final rename | works on FAT sessionfs and ext4 (bug B) |
| Bash | "tasks dir moved or linked" | `EBADF … posix_spawn '/bin/bash'` | works: git, pipes, rm (bug C) |

| Bug | Caused | State |
| --- | --- | --- |
| A. Paths below `/proc/self/fd/N` not resolved | Run 1: Write, Edit and Bash | fixed; confirmed on RetroOS in run 2 |
| B. FAT rename refuses an existing destination | Run 2: Edit | fixed; confirmed on RetroOS in run 3 |
| C. `socketpair` descriptors can't be subprocess stdio | Run 2: Bash | fixed; confirmed on RetroOS in run 3 |
| D. `statx` reports a different device from `stat` | nothing observed | fixed; QEMU-tested |
| E. `rt_sigaction` rejects pointers above 3 GiB | Run 3: `bazelisk` (Go) aborts "sigaction failed" | fixed in `e0494cbc`; confirmed on RetroOS in run 4 (bazelisk runs) |
| F. `timerfd_create` not implemented (ENOSYS) | Run 4: Bazel server (Netty epoll transport) exits 37 | fixed (uncommitted); QEMU-tested, not yet run on RetroOS |
| G. No loopback: `bind(127.0.0.1)` is EADDRNOTAVAIL | Run 4: Bazel gRPC server can't bind (with F worked around) | open |

Fixes A-D are committed in `ba20b53b`: `kernel/src/kernel/linux/{mod,proc_fd,socket,statfs,async_io,message}.rs`,
`kernel/src/kernel/{startup,vfs}.rs`, `kernel/src/kernel/fs/fat.rs`,
`kernel/src/kernel/net/local.rs`, `test/linux_proc_fd_probe.c`,
`test/linux_fd_metadata_probe.c`, `test/linux_unix_socket{.py,_probe.c}`,
and `test/linux_high_stack_probe.c`.

## Background that the diagnosis depends on

**Where files live on the laptop under RetroOS.** The repo and `~/.claude`
are on the laptop's ext4 root (BOOT.INI mount `linux`, `path=/`,
`access=rw`, `grant=/home/retroos`). `~/TEMP` and `/tmp` are not: they are
bound to `sessionfs` (`kernel/src/kernel/mount_config.rs:677-698`), a 32 MiB
RAM disk formatted as FAT and served by the FAT backend
(`kernel/src/kernel/fs/session.rs`). Claude Code's scratchpad and task
output live there, so they run on FAT semantics and vanish at reboot.
RetroOS sets `TMPDIR=<home>/TEMP` (`linux/environment.rs:63`).

**How Claude Code touches the filesystem.** From `strace -f` of headless
runs on Linux (`claude -p "..." --allowedTools Read,Edit,Bash`):

1. *Anchored paths.* It opens a parent directory as an `O_PATH` descriptor
   and then works through `/proc/self/fd/N/<name>`. Its error messages print
   the resolved real path, which hides this.
2. *Saving* (Write and Edit): create `<name>.tmp.<pid>.<hex>` with
   `O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC`, write it, then rename it
   over `<name>`. Edit also does `fchmod(fd, <original st_mode, type bits
   included>)` and `fsync` before closing. An inotify watch covers the
   directory.
3. *Bash's tasks directory:* `openat("/proc/self/fd/N/tasks",
   O_PATH|O_DIRECTORY|O_NOFOLLOW)`, then `readlink("/proc/self/fd/M")` must
   equal the expected path, then `statx`/`open` of
   `/proc/self/fd/M/<id>.output`.
4. *Spawning* (Bash, git, sh, ps): three `socketpair(AF_UNIX,
   SOCK_STREAM|SOCK_CLOEXEC)` for stdio, `vfork`, then in the child: reset
   signals, `dup2` the sockets onto 0/1/2, close the originals,
   `close_range(3, ~0, CLOSE_RANGE_CLOEXEC)`, `execve`.

**How to tell Claude Code is on RetroOS:** `OS Version: Linux 5.0.0` (the
host reports `7.0.0-43-generic`), a scratchpad under `~/TEMP`, and no
`/proc/version`.

## Bug A — paths below `/proc/self/fd/N` (FIXED)

**Symptoms (run 1):**

```
ENOENT: no such file or directory, open '/home/priv-gerben/project/RetroOS/LINUX_COMPAT_BUGS.md.tmp.4.6991781af43d'
String not found in file. Failed to apply edit.        (Edit, for text Read showed was present)
task output swap refused (tasks dir moved or linked): /home/priv-gerben/TEMP/claude-1001/-home-priv-gerben-project-RetroOS/35f766c4-4c44-439f-91ed-cc211044e9c8/tasks/bnnf7hnro.output. To recover: restart Claude Code with CLAUDE_CODE_TMPDIR set to a fresh directory; ...
```

**Cause:** RetroOS handled only a bare `/proc/self/fd/N`. For
`proc/self/fd/23/name`, `proc_fd::fd_path` saw a non-numeric descriptor name
and `open_pipe` returned ENOENT before the VFS was consulted. So:

- Write's temp-file create failed.
- Edit's read failed, so it searched no text.
- Bash's reopen of its tasks directory failed, which Claude Code reports as
  "moved or linked".

Read and the file-history snapshot use plain paths, so they worked.

**Fix:** the Linux `resolve_path` (`linux/mod.rs:943`) takes the
descriptor table. After normal resolution, `proc_fd::follow_directory_link`
(`linux/proc_fd.rs:63`) rewrites `proc/self/fd/N/rest` to
`<directory of N>/rest` when N is a directory descriptor, as Linux path walk
follows the link. The same applies under `proc/thread-self/fd/N` and
`dev/fd/N`. Every Linux path syscall goes through it: open, the stat family,
statx, rename, unlink/mkdir/rmdir, chmod, access, readlink, utimensat,
xattr, symlink, chdir, statfs, and Unix-socket bind/connect.

**Evidence:**

- `directory_links()` in `test/linux_proc_fd_probe.c` replays patterns 1–3
  (checks 210–226): create, rename, read, `/dev/fd` stat and unlink, plus
  Bash's `O_PATH|O_DIRECTORY` reopen, `readlink` and `statx`.
- The `c179d1e6` kernel fails at check 211 (the create). The fixed kernel
  passes on ext4 and SMB, 32- and 64-bit.
- In run 2 the tasks-directory check passed on RetroOS, and Write worked.

**Remaining gaps:**

- A path below a non-directory descriptor returns ENOENT; Linux returns
  ENOTDIR. Check 221 only requires failure.
- `execve` through `/proc/self/fd/N/name` isn't covered: exec resolves
  with `exec::resolve_path`, which has no descriptor table.

## Bug B — FAT rename over an existing file (FIXED)

**Symptom (run 2):** Write worked; Edit failed at its last step.

```
ENOENT: no such file or directory, rename '/home/priv-gerben/TEMP/claude-1001/-home-priv-gerben-project-RetroOS/35f766c4-4c44-439f-91ed-cc211044e9c8/scratchpad/write-test.md.tmp.4.e1f7856cf401' -> '/home/priv-gerben/TEMP/claude-1001/-home-priv-gerben-project-RetroOS/35f766c4-4c44-439f-91ed-cc211044e9c8/scratchpad/write-test.md'
```

**Cause:** the file was in `~/TEMP`, which is sessionfs, which is FAT.
rust-fatfs's `Dir::rename` refuses an existing destination
(`AlreadyExists`), and `FatFs::rename` (`fs/fat.rs:976`) reported every
error as -2 (ENOENT). Write's rename had no existing target, so it worked.
This affects every FAT mount, not only sessionfs.

**Fix:** when the destination exists, `FatFs::rename` removes it and
renames again. FAT has no atomic replace. The VFS reaches a backend with an
existing destination only for a POSIX replace, after `rename_inner`
(`vfs.rs:1767`) has checked type, emptiness and permission. Errors now map
to ENOENT, EEXIST, ENOTEMPTY or EIO.

**Evidence:**

- A QEMU replay of Edit's exact sequence (pattern 2) in `/tmp` gives
  `errno=2` on every replace with the old `fat.rs`. With the fix all ten
  variants pass, through plain paths and `/proc/self/fd`.
- Checks 227–234 in `test/linux_proc_fd_probe.c` replace `/tmp/saved` via a
  temp file. They pass on ext4 and SMB, 32- and 64-bit.
- Not yet confirmed by running Claude Code on RetroOS.

## Bug C — `socketpair` descriptors can't be subprocess stdio (FIXED)

**Symptom (run 2):** after the tasks-directory check passed:

```
EBADF: bad file descriptor, posix_spawn '/bin/bash'
```

**Cause:** RetroOS's `socketpair` (`linux/async_io.rs:373`) creates
in-process virtual sockets, numbered from 1024 (`FIRST_FD`). They live in
the process's `async_io` state, not its descriptor table.

- `async_io` doesn't handle `dup2`/`dup3`. The child's `dup2(sock, 0)`
  falls through to `sys_dup2` (`linux/mod.rs:3805`), which returns EBADF
  for `oldfd >= MAX_FDS` (1024). Bun reports the child's errno as the
  `posix_spawn` failure.
- The original diagnosis also implicated `close_virtual_fds`, but the current
  exec path uses `close_cloexec` and `exec_state`. The confirmed blocker is
  duplication into the ordinary descriptor table.

So no subprocess Claude Code starts can run on RetroOS: Bash, git and
helper shells all use this pattern (4).

The kernel already has real AF_UNIX byte streams (`kernel/net/local.rs`,
`FdKind::Socket`). They live in the normal descriptor table, are
reference-counted through `dup2`, and survive fork and exec. They lack a
connected-pair constructor and `SOCK_SEQPACKET`.

**Fix:** both `SOCK_STREAM` and `SOCK_SEQPACKET` socketpairs now use
`net::local::pair` and ordinary `FdKind::Socket` descriptors. The constructor
connects both endpoints under one lock, and failed descriptor allocation or
result-pointer validation releases both handles. The x86-64 syscall, i386
direct syscall, and i386 socketcall share the implementation. The former
virtual socket implementation has been removed from `async_io`.

Sequenced packets retain message boundaries, discard a truncated packet's
remainder, and support peek, nonblocking mode and zero-length messages.
Socketpairs use the existing reference counts, close-on-exec flags, credentials,
poll/epoll readiness and shutdown paths. Blocking socket syscalls now wait per
64-bit user context, allowing another pthread to supply data.

**Regression coverage:** `test/linux_unix_socket.py --bits 64` and `--bits 32`
exercise three socketpairs, `vfork`, `dup2` onto 0/1/2, closing originals,
`close_range(CLOSE_RANGE_CLOEXEC)`, and self-exec. The parent checks echoed
stdin, separate stderr, and EOF; the 64-bit case also checks edge-triggered
epoll. Additional checks cover packet boundaries, flags, peer credentials,
invalid result pointers and rollback when only one descriptor slot remains.
`test/linux_high_stack_probe.c` delays the writer to force a blocking socket
read while another pthread must continue running. Both ABI probes, the high-stack
pthread test and the 16-child parallel-process test pass in QEMU/KVM.
The VFS cache unit test now checks both no-replace failure and successful FAT
replacement, instead of expecting the old FAT replacement bug.

A live Claude Code rerun on the laptop is still pending.

## Bug D — `statx` device number differs from `stat` (FIXED)

Found while suspecting the tasks-directory check; it turned out not to be
that check's cause (bug A was). `write_stat64` reported device 1 while
`write_statx` left `stx_dev_major`/`stx_dev_minor` at 0, so the same object
looked like two devices depending on the call.

**Fix:** both now use the `VFS_DEV*` constants (`linux/mod.rs:3389`).

**Test:** `test/linux_fd_metadata_probe.c` checks
`makedev(stx_dev_major, stx_dev_minor) == st_dev`. It fails on `c179d1e6`
(line 27) and passes on the fix.

## Ruled out

| Suspect | For | How ruled out |
| --- | --- | --- |
| `statx`/`stat` device mismatch | tasks-dir check | real bug (D), but run 2 showed bug A was the cause |
| hashed inode numbers (`vfs.rs:398-412`) | tasks-dir check | the check never reached a stat comparison; bug A failed the open first |
| open flags, multi-dot temp names | Write ENOENT | 24 flag/name variants create fine in QEMU |
| the laptop's `grant=/home/retroos` policy | Write ENOENT | QEMU with the laptop's BOOT.INI: writes outside the grant work |
| `check_remove`'s `fs.meta` on ext4 | Edit rename ENOENT | QEMU: rename over existing works on ext4, with Edit's exact sequence |
| `fchmod` with type bits, `fsync`, inotify | Edit rename ENOENT | QEMU replay of all combinations passes on ext4 |
| descriptor tables per thread | Edit rename ENOENT | threads share one table (`async_io` contexts in one `KernelThread`) |

## Other observations

- **Clock resolution:** Node sees whole seconds on RetroOS. Every
  transcript timestamp from both runs ends in `.000Z`, and
  `.claude.json.backup.<ms>` names end in `000`. Check the sub-second
  fields of `clock_gettime`/`gettimeofday` (and the vDSO, if Bun uses it).
- `/proc/version` doesn't exist.
- The Read tool refusing `/proc/self/status` is the tool's own rule, not
  RetroOS.

## Test-suite notes

`test/linux_proc_fd.py` was already failing on `c179d1e6` before these
changes:

- Check 195 expected `setpgid(0,0) == 0`. Since `2b8c42d1` the probe leads
  its session, and RetroOS correctly returns EPERM, as Linux does. It now
  accepts either result (fixed).
- Check 129 (`ipc_roundtrips`, after all the new checks) expects
  consecutive children to get the same PID. It fails in most
  configurations; not investigated.

## Related gaps found by reading the code, not yet hit at runtime

In `kernel/src/kernel/linux/mod.rs` unless noted:

- `futex`: WAIT returns immediately and WAKE does nothing (`sys_futex`,
  line 3043).
- `nanosleep` doesn't sleep (line 2905).
- `pread64`/`pwrite64` reject offsets above 4 GiB, and `lseek` truncates
  to 32 bits (KERNEL_REVIEW.md finding 5).
- `arch_prctl(ARCH_SET_FS/GS)` doesn't check that the address is canonical
  (line 3699).
- A read-only user pointer passed to a syscall panics the kernel
  (KERNEL_REVIEW.md finding 1).

## Method that worked

On RetroOS, record the exact error and which tools still work. Write can
create new files even when Edit and Bash can't. Then on Linux:

1. Trace the same tool use with `strace -f -s 200 claude -p "..."
   --allowedTools ...`.
2. Replay the traced syscall sequence in a C probe.
3. Run the probe in QEMU with the laptop's BOOT.INI shape (root mount with
   `grant=/home/retroos`), and include `/tmp`, which is sessionfs.
4. Confirm the probe fails on the old kernel before trusting a fix.

## E. `rt_sigaction` rejects pointers above 3 GiB (fixed)

Run 3: `bazelisk build` dies at startup with `fatal error: sigaction failed`
(signal 1), so nothing Bazel-based runs on RetroOS. Go's heap starts at
`0xc000000000`, and the runtime passes a `sigaction` struct from there.
`signals.rs` (nr 13) validates `act`/`oldact` with `valid()` against
`USER_END = 0xc0000000` and goes through `machine.read`/`write`, so a
high-half pointer gets `EFAULT`. The fix is to validate and copy through
`high_memory::copy_from`/`copy_to`, the way `rt_sigprocmask` (nr 14)
already does; `sigaltstack` and the other `valid()` users in
`signals.rs` should get the same treatment.

**Fix:** every guest access in `signals.rs` goes through `high_memory`.
`valid()` uses `high_memory::range`; `rt_sigaction` copies `act`/`oldact`
as 32-byte blocks; delivery builds the whole frame in a kernel buffer and
copies it out once (SIGCHLD's `si_status` now goes in that buffer too), and
`rt_sigreturn` copies it back in the same way. `test/linux_high_stack_probe.c`
covers `sigaction` structs and an `SA_ONSTACK` delivery on a high-half
stack. A static `bazelisk version` booted under QEMU now runs to its own
"could not start Bazel" error. It also hits unimplemented syscall 434
(`pidfd_open`), which Go tolerates.

## Run 4 (`e0494cbc`): Bazel's server is the next wall

`bazelisk version` now gets as far as "Starting local Bazel server". The
server (Bazel's embedded Zulu JDK 21) dies before it writes `jvm.out`. To
see why, run the server by hand: its cmdline is
`<output_base>/server/cmdline`, NUL-separated, and argv[0] is
`bazel(RetroOS)`, so exec `<install_base>/embedded_tools/jdk/bin/java`
with the remaining arguments. `java -version` itself works.

### F. `timerfd_create` not implemented (fixed)

Netty's native epoll transport calls `timerfd_create` for every event loop.
The kernel has no timerfd at all (only eventfd, in `linux/async_io.rs`).
Netty needs create/settime/gettime, `read` returning the expiry count,
and epoll readiness on expiry. Workaround for further testing:
`bazelisk --host_jvm_args=-Dio.netty.transport.noNative=true ...`, which
makes Netty fall back to its NIO transport.

**Fix:** `linux/timerfd.rs` holds the timer model (deadline + interval; the
expiry count is derived from the clock on demand). `async_io.rs` adds the
`Timer` descriptor, syscalls 283/286/287, blocking and nonblocking `read`,
poll/epoll readiness, and wakes parked waiters at the next future expiry.
Edge-triggered epoll follows Linux: `settime` and `read` start a new edge,
and an unread periodic timer raises only one (native Linux confirmed that;
a per-tick edge was wrong). Netty re-arms its edge-triggered timerfd
without reading it, so the reset on `settime` is what keeps its event loop
running. Tests: unit tests in `timerfd.rs`; `test/linux_timerfd.py`, which
passes on native Linux and on RetroOS in QEMU.

### G. No loopback interface (open)

With F worked around, the gRPC server fails "Failed to bind to address
/127.0.0.1:0: Cannot assign requested address", and fails the same way on IPv6.
`net/stack.rs` `bind()` accepts only the unspecified address or the NIC's
single address (`n.address`), so 127.0.0.1 gets `AddressUnavailable`.
There is no loopback interface, so the Bazel client can't reach its server
even after `bind` succeeds.
