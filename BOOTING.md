# Booting RetroOS with GRUB

GRUB supplies the kernel and two ordinary configuration files: `BOOT.INI`
for bundle backing and mounts, and `RETROOS.INI` for user settings.

## CPU use

On a machine with at least two initialized CPUs, core 0 runs guests, device
commands and allocation. Core 1 runs audio mixing, VGA decoding, composition,
Voodoo rasterization and linear framebuffer presentation. Other CPUs remain
parked. The boot log reports `core 1: Media worker: audio and graphics ready`.
Single-core machines and hosted execution use the same operations inline.

Audio is a persistent service on core 1. It samples its own clock, advances
sources and feeds the physical output once per millisecond, including at
checkpoints within graphics work. Core 0 does not submit mixing jobs or wait
for a quantum. It processes device commands and delivers pending virtual IRQs.
Core 1 samples guest DMA through an arch read view while holding the same short
guest-memory gate as VGA. The view temporarily borrows the source CPU's user
page-table entries and restores the worker root before returning; it never
allocates or retains guest pointers. Sound-device state is protected at that boundary;
an unavailable device lock defers per-slice service without losing timer time.
The output log reports `core 1: sink: first frame played`.

Rendering is also a persistent service, paced at 70 Hz for virtual VGA and
60 Hz for Voodoo. Core 1 samples resident VGA memory into its own preallocated
scratch, then decodes, composes, scales and presents it. Core 0 publishes VGA
register changes, scene transactions and producer surface updates; it does not
construct a new frame for each refresh. The renderer retains background surfaces
and paints OSD text/rectangle commands into its own pixels. Every refresh still
renders the complete picture, including continuously changing screens.

A short memory gate excludes guest slices and kernel writes while core 1 samples
VRAM. A failed media read requests the next guest-slice boundary; core 0
hands over that brief copy window instead of immediately retaking the gate.
The gate is released before mixing, decoding, OSD painting or presentation. Mode
and owner changes invalidate old VRAM descriptors and fence output mapping changes.
Single-core linear output uses the same renderer inline. Banked BIOS presentation
remains on core 0. The log reports
`core 1: Video service: rendering at 70 Hz` for VGA.

Voodoo writes use an ordered, bounded command ring. A persistent device service
on core 1 drains bounded batches without guest ticks or graphics-job submissions.
Reads fence completed commands, and a full ring applies producer backpressure.
One-core Voodoo and audio use the same device/mixer routines inline.
Graphics checks audio between rows or small copy chunks. Worker callbacks use
resident kernel buffers and do not allocate, free pages or invoke BIOS calls.
Guest DMA access is limited to the guarded arch read view above. Core 0 allocates
resident source and output storage. Each job or
due service refreshes the worker's kernel root and TLB before accessing published
storage. Idle polling does not flush the TLB. The worker polls rather than
sleeping; PIT interrupts remain on core 0.

To exercise the dual-core paths:

```sh
python3 test/display_scaling.py --cpus 2 --kvm
python3 test/audio_steady.py --cpus 2 --kvm 10
python3 test/audio_steady.py --cpus 2 --kvm --effects-only 10
```

## DOS CPU speed

For games whose startup timing overflows on fast CPUs, add `cpu5` through
`cpu100` (in steps of 5) to their `RETROOS.INI` `[launch]` entry. For example:

```ini
[launch]
F22.EXE=repair cpu25
```

COMMAND.COM passes the limit with the launch policy, including batch and
LOADFIX launches. `cpu25` limits guest execution to roughly 25% duty; it does
not promise a particular MHz. Unlisted programs retain full speed. The default
configuration includes this F22 entry. Existing installations can add it after
updating both the kernel and COMMAND.COM.

For direct executable launches, `DOS_CPU_PERCENT=25` in `[environment]` supplies
the same policy; a `cpuN` launch flag overrides it. The valid range is 1–100;
missing or invalid environment values leave execution unlimited. CPU pacing
uses the monotonic clock independently of VGA, the OSD and rendering. The
event loop continues servicing input, audio and device clocks between guest
slices. Long host pauses do not accumulate unbounded pacing debt. This is a
compatibility speed control, not a host CPU-utilization limit: the kernel
continues polling services during the delay.

## Machine installation (ext4 or FAT)

```sh
tools/install_kernel.sh --prepare
# Review build/machine-install/<release>/BOOT.INI and grub.cfg
sudo tools/install_kernel.sh
```

The same installer accepts a FAT data volume without `--module`:

```sh
tools/install_kernel.sh --prepare --c-uuid=ABCD-1234 --copy-showcase
sudo tools/install_kernel.sh
```

Use the filesystem UUID of the data volume, not the EFI partition. A mounted
FAT volume can instead be selected with `--c-root=/mnt/data`. Nothing is
formatted. The installer remembers the prepared layout, so the installation
command needs no storage flags. The release bundle uses the same commands
with `./install.sh`.

FAT and ext4 use the same disk-backed C: layout. Both INIs live under
`C:\RETROOS`, and the matched runtime is versioned beneath
`C:\RETROOS\releases\<version>`. GRUB loads only the kernel and INIs;
RetroOS reads the runtime directly from the selected disk. Kernel files live
under `/boot/retroos/releases/<version>/` (or `--destination`). `/boot` may
be separate or Btrfs because only GRUB needs to read those kernel files.

On the default ext4 Linux-root installation, C: is `$HOME/DOS` and the
Linux filesystem supplies `/`, `/bin` and `/usr/bin`. A separate FAT or
ext4 data volume uses the bundled BusyBox root unless a Linux root is
explicitly selected with `--root-uuid`. The RetroOS C: tree is identical.
Unix command aliases use the same link manifest on both filesystems.

`BOOT.INI` also selects the Linux session home independently of C::

```ini
[session]
home=/home/alice
```

For a Linux-root installation, the installer uses the installing user's home
and mounts their `DOS` directory as C:. Settings physically live at
`/home/alice/DOS/RETROOS/RETROOS.INI`, visible as
`C:\RETROOS\RETROOS.INI`. Use `--c-root` to select another DOS directory.
On FAT, C: is the volume root, mounted at `/dos` in the bundled Linux namespace.
`home=/RETROOS/HOME` gives BusyBox a persistent home backed by FAT
`\RETROOS\HOME`; settings remain at FAT `\RETROOS\RETROOS.INI`.
The bundle supplies Unix commands, while `/tmp`, `/run`, `C:\TEMP`, and
`$HOME/TEMP` are RAM-backed. `[linux.environment]` in RETROOS.INI can still
override Linux environment defaults. Old BOOT.INI files without `[session]`
retain their previous home behavior; installation does not relocate old trees.

User settings and C: data persist in the persistent entry. Runtime edits use
a session overlay. Upgrades preserve existing user settings and extra mount
choices while updating the matched runtime path. Protected-disk edits remain
session-only. `--module` explicitly selects the RAM-core alternative; it is
also used when there is no supported disk C: or when `--image` supplies a
USB/ISO core.

## Clock settings

`RETROOS.INI` can interpret the hardware clock as UTC and present local time:

```ini
[clock]
rtc=utc
utc_offset=-07:00
```

`rtc=local` (the default) uses the hardware clock directly for local time.
`utc_offset` defaults to `+00:00` and accepts signed `HH:MM` offsets up to
14 hours, including partial hours. It also converts between local dates and
UTC filesystem timestamps. DOS/BIOS and Windows/OS/2 local time calls use
the local clock; Windows system time and Unix file timestamps use UTC.
The offset is fixed: update it yourself when daylight saving time changes.
Settings take effect after reboot and do not alter the hardware clock.

## QEMU with the live machine files

Configure the local live-files profile once, as your normal user:

```sh
python3 tools/qemu_live.py setup --root / --c-root /home/retroos
./run.sh qemu --kvm
```

With that profile present, QEMU KVM uses the host's live `/` read-only and
`/home/retroos` as writable C:, through authenticated, signed SMB2 over VirtIO.
It reads the same GNU programs, shared libraries, CA certificates and user
`RETROOS/RETROOS.INI` as the metal installation. C: writes and user-settings
edits are visible immediately on the host. Existing C: application symlinks
retain access to their targets with your Unix user's permissions.

Live-files QEMU defaults to 2 GiB RAM for native Linux applications, including
Codex's client and background server. Override this with emulator arguments,
for example `./run.sh qemu --kvm -- -m 4096`.

The launcher starts a private Samba process on loopback, with a random port
and fresh per-launch credentials. It reuses installed Samba tools or the
existing user-local RetroOS Samba tools. On Debian/Ubuntu, setup can extract
missing server utilities locally; their runtime libraries must be available.
The writable SMB session uses a subdirectory view of the host namespace so
normal server symlink handling can resolve C: links. The guest's `/` mount is
read-only. This shares live files; storage access is SMB rather than the ext4
backend used on metal, and QEMU still supplies virtual hardware.

No mounted host block device is attached. The only VM disk is a disposable
boot image containing the matched runtime and bootstrap INIs. It carries a
private copy of user settings while mounting the network filesystems; the
persistent user INI is exposed again once C: is mounted. The QEMU RTC base
follows the selected user's clock setting. The server and bootstrap copy are
removed when the VM exits; an unavailable root/C: share stops boot.

`--live-root` explicitly selects this profile. To use a separate persistent
disk instead, supply `--data-image build/data.bin`; this overrides the KVM
live-files default. `RETROOS_QEMU_LIVE_PROFILE` selects another profile JSON
with `root` and `c_root` directory paths. Run `python3 test/live_root.py` for
GNU userspace from the live root, DOS/Linux C: writes, application symlinks,
persistent settings, and rejection of writes through the root view.

`C:\RETROOS\SHELL.ELF` starts a Linux shell session. Linux entry supplies `PATH` with
`HOME/bin`, `/usr/local/bin`, `/usr/bin`, `/bin` and the sbin directories,
`TMPDIR=HOME/TEMP`, `SHELL=/bin/sh` and `TERM=linux`. HOME defaults to the C:
mount's Unix path; LANG follows the selected locale. Arguments such as `-i`,
`-c` or a script filename are forwarded to the selected shell. GNU `/bin/sh`
is used when available, with a BusyBox fallback for a missing or unsupported
default shell. Linux children inherit exactly the environment their parent
passes, including an explicitly empty environment.

Optional overrides go in the user INI, separately from DOS variables:

```ini
[linux.environment]
HOME=/home/retroos
# PATH=/home/retroos/bin:/usr/local/bin:/usr/bin:/bin
# CODEX_HOME=/home/retroos/.codex
```

Names are case-sensitive. Defaults fill missing values; explicit values are
preserved. Direct ELF launches (including RC started from DOS) receive these
defaults too, so their child shells search `HOME/bin` before the system npm
launchers. The kernel does not export DOS `[environment]` into Linux processes;
`SHELL.ELF` retains fallback defaults when launched with an explicit environment.
Run `python3 test/linux_codex.py --direct` to check native Codex discovery from
a shell started without `SHELL.ELF`.

`bazelisk test //tests:linux_dn_shell` exercises DN starting COMMAND.COM's
batch interpreter, which launches the interactive SHELL.ELF child. It boots
GNU sh, its loader, the runtime bundle, Linux root and C: from a private native
ext4/NVMe volume under UEFI with 32 GiB RAM and six CPUs. The probe types a
command, verifies its saved output, and checks diagnostic control after F12.
The script also supports `--kernel /path/to/kernel.elf` for comparisons and,
without `--native-root`, a read-only SMB tool root with native ext4 C:.

`python3 tools/try_self_build.py` attempts `//kernel:kernel` with Linux Bazel
inside QEMU/KVM running RetroOS. It shares sources/tools read-only and keeps
guest outputs in `build/ci/self-build/c`; `klog.txt` and `c/build.err` retain
diagnostics. The launcher's host build prepares the boot image only. Supply
`--install-base /path/to/existing/bazel/install` to skip slow runtime extraction
over SMB. `--bazel-command version` runs the full JVM-backed version command;
`--workspace`, `--bazel-arg` and `--env NAME=VALUE` support isolated build probes.
`--work-dir` selects a separate guest home and diagnostic directory. The default
full-build timeout is four hours, including boot-image preparation.
Directory `access(F_OK)`, modification timestamps, longer metadata paths and
SMB installation symlinks now work. Linux provides `getcpu`, the three legacy
x86-64 vsyscall entries, allocator-backed `sysinfo`, and resource-limit queries.
Limit changes that are not enforced return an error instead of silent success.
Linux processes with no runnable internal threads are blocked in the kernel;
the event loop polls their waits and resumes a ready thread. There is no
user-mode waiting stub or reserved executable page. The mapping allocator
avoids the loaded ELF interpreter and fixed mappings; large JVM reservations
previously collided with read-only code. Fixed mappings replace old user
pages before loading, preserving fork isolation. Anonymous reservations discard
old backing and supply zero pages on demand, so reserving a large JVM address
range does not allocate that much physical RAM. Run
`python3 test/linux_vsyscall.py` for both syscall ABIs, real legacy CALL/return
paths, system information, limits, mapping bounds and rejected invalid calls.
`python3 test/linux_runtime.py` covers sleeping threads and wakeups. Bazel 7.4.1
now completes `version` with its JIT enabled. The helper defaults to a
512 MiB heap, 64 MiB compressed class space and 64 MiB code cache; repeat
`--jvm-arg` to override JVM settings. The corrupt `String` class was caused
by SMB exposing its 32 KiB packet limit as a short regular-file read; reads
now collect multiple packets through EOF. `python3 test/linux_smb_read.py`
checks large reads, positioned reads, offsets and EOF through both Linux ABIs.
The same test checks persisted 8 MiB writes and multi-buffer `writev` output.
Regular-file `write`/`writev` stage at most 64 KiB of user memory at a time,
preserve short-write/error progress, and stop at a partial vector. SMB writes
span negotiated packets, so a large compiler output does not repeatedly copy
its entire remaining buffer for each 32 KiB sent.

Native thread switches now preserve XMM8–15 as well as XMM0–7. Linux x86-64
page faults can enter a registered SIGSEGV handler with a Linux signal frame,
alternate stack and per-thread mask; `rt_sigreturn` restores the user context
and floating-point state. `ITIMER_REAL` delivers SIGALRM using the same frames
and masks, including interrupting a sleeping process. CPU-accounting timers
and general signal sending are not yet implemented. Timers are checked when
a process runs or its blocked I/O is polled. Linux terminal peers receive
bounded CPU turns even while a helper remains runnable. `python3 test/linux_xmm_context.py` checks SIMD preservation and
`python3 test/linux_signal.py` checks fault recovery and rejected invalid
signal contexts. Working directories use the VFS path limit, missing
`readlink` paths return ENOENT, and `/proc/self/exe` exec stays absolute.
`python3 test/linux_glibc_fork.py` covers glibc worker-thread fork/exec with
large allocations and copy-on-write pages on ext4 and SMB, plus shared-memory
spawn, missing-executable error propagation, inherited environment and pipe
redirection. The vfork child owns the live address space while its parent
is suspended; exec/exit returns that space to the parent before child cleanup.
The same regression checks one-shot/repeating timers, blocked pending alarms,
invalid timevals, cleared timers after fork and retained timers after exec.

`python3 test/linux_bazel.py` runs native Bazel 7.4.1, Bash and `cat` inside
RetroOS, builds a genrule with a fresh declared input, recursively globs 96
nested directories, and verifies the output bytes and Git version stamp, retaining diagnostics in `build/ci/bazel-smoke`. It discovers the host's
extracted install base automatically; use
`--install-base /path/to/install` to select one explicitly. Linux supplies
`/proc/self/fd`, `/proc/thread-self/fd` and `/dev/fd` directory listings and
links from the guest process's own descriptors, including epoll/eventfd and
Unix socket descriptors. This prevents process-launch code from enumerating
the SMB server's `/proc/self/fd`, which disconnected its root share.
Pipe `fstat` reports FIFO metadata, matching the proc-fd view and allowing
Java's normal `jspawnhelper` path to validate its input pipe.
Blocked Linux processes lend the CPU to peers sharing their terminal; pending
I/O is polled with the receiving address space active. Child exit wakes only
matching waiters and reaps consumed waits after switching back. The proc-fd
test includes repeated fork/exec pipe round trips and nonzero child statuses.
`python3 test/linux_proc_fd.py` checks both Linux ABIs on ext4 and SMB.
A kernel device filesystem provides `/dev/null` above the shared root, so
shell redirection works even with a read-only SMB root. Its character-file
metadata and seek behavior pass through the shared VFS; discarded writes
leave its size zero. The proc-fd regression also checks null reads, writes,
seeks and path/descriptor stat.
Linux shebang exec resolves nested interpreters before replacing the process;
`python3 test/linux_script.py` checks arguments, environment and launch errors
on both filesystems and ABIs. `FIONREAD` reports unread pipe and socket bytes,
allowing Java to read process output without seeking a pipe. `FIONBIO`,
`fcntl` and `pipe2` share each pipe endpoint's nonblocking state across dup/fork.
Pipe queues grow without overwriting unread output and report allocation errors;
closing the last reader releases queued storage. `python3 test/linux_process_output.py`
checks Rust `Command::output()` with separate stdout/stderr, exact exit status,
and 128 KiB per stream. The proc-fd and
`python3 test/linux_epoll_network.py` tests cover unread-byte queries.

Linux ordinary descriptor capacity is 1024, with heap-backed tables and
multiword CLOEXEC/pselect masks. DOS retains its previous 64-handle allocation
and device sentinels. `close_range` supports closing and CLOEXEC marking across
ordinary and virtual async descriptors on both ABIs. Fork has a private table;
UNSHARE on a multi-context thread group returns EOPNOTSUPP until per-thread
file-table splitting exists. `//tests:linux_fd_limits` opens 192 files, uses
fds through 963, checks pselect across mask words, and repeats fork/exec cleanup
24 times per ABI. `python3 test/linux_code_mode_native.py` executes JavaScript
in the installed managed code-mode host on native ext4 with 96 inherited fds.

When DOS Navigator occupies PID 1, orphaned Linux helpers are adopted by a
surviving Linux ancestor in the same terminal, rather than by DN. Otherwise
the helper's exit can hand display ownership to DN while the shell and Codex
are still alive. The DN shell regression double-forks a helper before checking
interactive output and F12, covering this transition as well as shell launch.

Synchronous Linux file reads retain a scratch buffer of at most 64 KiB per
process. Reusing its backing avoids repeatedly demand-faulting and releasing
temporary buffers while hashing large executables. Larger requests may return
a short read. The file-cache regression checks changing request sizes, EOF,
and coherence with unflushed shared mappings through this path.
`python3 test/linux_codex_native_resume.py --resume latest --daemon --full-features`
profiles the current project's saved session using copied SQLite snapshots,
the installed managed daemon, and a native ext4/NVMe root. It types a draft
without submitting it. Omit `--daemon` to compare direct startup. This external
test needs saved login/package state; its guest state is private and temporary.

Metal KLOG0211 also exposed persistent log-flush stalls of 100–370 ms.
Timing that durable flush by appending its own stall warning dirtied the log
again after every slow flush, sustaining another flush each second while idle.
The log writer no longer emits its own timing message, and schedules its next
sync from completion. Actual new log bytes retain the normal durable sync path.


Directory identities grow as needed rather than limiting all processes to 32
open directories. The proc-fd test holds 48 directory descriptors open and
checks complete 300-entry listings on ext4 and SMB. Serial `trace fs` records
Linux filesystem metadata calls while excluding clock and futex noise.
The same regression creates and removes trees beyond 256 bytes and exercises
rename, chmod, symlink and unlinkat there. Path mutations use the VFS path
limit and reject overflow rather than silently changing a truncated path.

The helper defaults to `MALLOC_ARENA_MAX=2`, one loading thread, one globbing
thread (`--legacy_globbing_threads=1`) and one build job. Java uses its normal
process-spawn mechanism. This fits the existing low user window; Linux now has a 1024-descriptor
process table, Bazel's separate default globbing pool uses 100 threads.
The Rust distribution exposes named toolchain filegroups rather than exporting
every file, avoiding a recursive scan of its HTML documentation during analysis.
`--reuse-repositories /path/to/host/bazel/output-base/external` reads extracted
repository sources and toolchains from the host instead of unpacking archives
over SMB. Build outputs remain private in the guest's separate `cache-reused`
directory; this does not reuse host compilation outputs. A full RetroOS guest
build has not yet completed.
The first build is also too slow for practical use. A sampled compiler startup
spent over 99% of its time in the kernel, dominated by file-backed `mmap`.
An isolated QEMU/KVM startup probe measured 29 seconds for `rustc --version`
versus 0.44 seconds for `/bin/true`. File mappings eagerly read regions into
fresh pages; compiler launches repeatedly load Rust/LLVM libraries totaling
roughly 350 MB, and loader segment mappings can repeat those reads. Reusing
file-backed pages or loading them on demand remains performance work; passing
the genrule regression does not establish practical self-build speed.
`python3 test/linux_build_profile.py --native-ext4` isolates Python startup
and a fresh C compile/link/run with tools, libraries and outputs on a private
ext4/NVMe image. The fixture has no NIC, 32 GiB RAM, six CPUs and HDA audio.
A small syscall-only helper measures each child with CLOCK_MONOTONIC;
VM boot and the helper's own loading are excluded. Cumulative profiles and
outputs are retained under `build/ci/program-profile-ext4`. Add
`--codex-startup` for two native `codex --version` invocations in an isolated
home without login/session state (`build/ci/program-profile-codex-ext4`).

The native-ext4 Codex probe initially took about 6 and 5 seconds. Of about
4.9 seconds inside an executable-read phase, ext4/volume reads accounted for
only about 0.6 seconds. Large sequential reads were populating and evicting
4 KiB boxed pages in a 2 MiB cache for a roughly 284 MiB executable. Large
uncached spans now stream into the caller's buffer, stopping at any existing
cache page so mapped changes remain authoritative. Small reads and mapping
fills retain their cache behavior; content-version validation remains in place.
ELF and private mapping loaders use 64 KiB buffers. The updated probe measured
1621/1712 ms for Codex and 1200/1297 ms for C compile/link, respectively.
Compiler/linker loader traffic is roughly 130–140 MB, including repeated
libraries; eager loading and library sharing remain further performance work.
These isolated results do not establish full interactive Codex startup time on
physical hardware. Earlier SMB-root timings are not a model for metal ext4.

The full managed-daemon resume exposed a second streaming failure: an ELF
segment starting inside a previously cached 32 KiB run consumed that prefix,
then its remaining request fell below the 64 KiB streaming threshold. Cache
read-ahead extended past the request and seeded the same prefix in the next
chunk, so subsequent large reads kept allocating and evicting cache pages.
The streaming decision now uses the original request length, even after
consuming cached bytes. The regression primes a metadata prefix and then
checks eight consecutive 64 KiB reads: nine backend reads total and no cache
growth beyond the original metadata fill. It failed with 17 backend reads
before this correction. Existing cached and mapped pages remain authoritative.
In the full native-ext4 managed-daemon resume probe, the same 14,715 ELF
payload reads (963,726,638 bytes) fell from 14.11 s to 1.07 s. Cache insertion
fell from 974 MB to 35 MB across the measured workload. Resume readiness
after guest control became available improved from 41.72 s to 27.47 s;
host builds and VM preparation are excluded from that interval. This fixes
one measured cost and does not establish acceptable metal responsiveness.

The opt-in COM2 command `profile io` reports read allocation/fetch/copy,
file-mapping allocation/read/copy, ELF allocation/read/copy, and ext4/volume
read timing in nanoseconds. It also separates VFS lock acquisition and reads,
cache checking/misses/insertion, and executable seeks. Those stages nest and
must not be summed. Pipe waits/allocations and physical disk read/write/flush
timings are also reported. F12's profile dump includes the same I/O counters
in KLOG, allowing physical-machine capture without a COM2 connection.

A no-daemon native-ext4 resume measured 2,040 physical flushes taking 7.34 s,
versus 0.31 s for physical reads and 0.29 s for writes. Pipe allocation took
less than 1 ms. The ext4 journal uses five ordered durability barriers per
mutation; hundreds of small mutations therefore spend seconds waiting for
flush completion. This measurement retains the conservative journal policy.
The probe's `--existing-skills` option copies installed skills into its private
home. Before correcting directory-relative `openat`, that run reported 860
flushes / 3.21 s and readiness at 12.21 s. It is not a reliable successful
cleanup baseline: after the correction, startup performed 71 `unlinkat` calls,
made 2,545 flushes / 8.67 s and reached readiness at 20.17 s. Correctness exposes
additional mutation work. These QEMU timings do not account for the complete
reported metal delay: KLOG0214 contained no I/O profile, and the saved
application log also recorded a model-list timeout.
The comparison is saved in
`build/ci/codex-native-resume/storage-stall-comparison.json`.

`python3 test/linux_time_accounting.py` gates before a real fork/exec/wait
compile/link/run and compares private ext4 and SMB roots with the same tools,
32 GiB RAM and six CPUs. `profile totals` exposes cumulative exclusive cycle
categories and elapsed nanoseconds; idle sleep is separated from scheduler
work. The two gated build runs measured 2.416 s and 4.968 s, with only about
24 ms idle sleep on either backend. Reports include boundary overhead.

The full resume probe also gates before exec, so native loading cannot finish
before profiling starts. Use `--storage smb` for a private SMB root and
`--sample-interval 0` to disable periodic detailed dumps. Readiness now has its
own saved `ready-sample.json`, excluding the later typing check. The gated
comparison loaded the same 298,515,108 ELF bytes on both backends. One measured
pair took 19.54 s (ext4) and 26.04 s (SMB), including 2.28/1.77 s of diagnostic
serial handling. Ext4 spent 8.01 s in disk flushes. SMB spent 7.82 s receiving,
1.18 s verifying responses, 4.30 s allocating response buffers and 3.47 s
decoding reads. Kernel-mode page-fault handlers took 1.79/8.39 s respectively;
those costs overlap the allocation/decoding timings. User-mode faults took
2.53/2.56 s. Actual application instructions accounted for about 0.53/0.51 s.
These are measurements, not an allocator or durability change. The complete
exclusive ledger and nested detail are in
`build/ci/time-accounting/comparison.txt` and `comparison.json`. Nested stages
must not be summed. Physical-machine timings still require a metal capture.

The subsequent fixes target extra kernel work rather than seeded application
state. The heap retains at most 1 MiB of free backing (scaled down on small
machines) instead of releasing and faulting every temporary buffer again.
Tests poison evicted pages and check that live allocations and free-list
headers survive fragmentation. New ext4 objects receive initial permissions
and mtime in their creation transaction; unchanged metadata is not rewritten.
Single-page mappings invalidate that page rather than all translations, and
a first user write completes demand allocation in one fault instead of
installing a read-only zero page and faulting again.

With grouped journal writeback, the same profiled native-ext4 resume measured
6.42 s, down from 19.54 s. Physical flushes fell from about 2,400 to 178 and
flush time from 8.01 s to 0.77 s. A separate run with `--no-profile` reached
readiness in 6.94 s and accepted typing. This is still slower than the Linux
PTY baseline (1.82 s median, three runs); timings vary with flush/network and
terminal-detection latency. The no-profile result is an actual run, not a
subtraction of profiler costs. Boot and private-state preparation are excluded.

The later `/resume` investigation found repeated metadata work outside startup.
Linux ownership queries now use stable ext4 inode identities instead of walking
the pathname again after `stat`. File writes refresh cached inode sizes through
hard links and bind aliases; namespace edits invalidate affected directories and
aliases rather than every cached directory. Mount changes still invalidate all.
An ext4 allocation search remembers its last successful block/inode group,
wrapping across the entire filesystem when needed. Previously every newly
allocated block restarted at group zero, rescanning occupied groups.

`python3 test/linux_metadata.py --filled` checks a mostly allocated, valid ext4
image with thousands of block groups and runs `e2fsck` before and after. A 2 MiB
append and fsync measured 888 ms before the allocation hint and 164 ms afterward.
The separate 2,000-file stat walk measured 387 -> 63 ms; 200 stat calls interleaved
with unrelated writes measured 414 -> 87 ms. These are individual QEMU runs.
`//tests:unit_ext4_modern_image_test` also bounds exhausted-group descriptor reads
while extending a file, independently of wall-clock timing.

`test/linux_codex_native_resume.py --picker --filled --existing-skills
--full-features --sample-interval 0 --kernel /path/to/kernel.elf --label NAME`
uses copied saved rollouts and a populated native ext4/NVMe image. It separately
times startup, typing `/resume`, listing, and loading the selected session.
The explicit kernel uses a private UEFI boot copy. Matched profiled runs measured
8.30 -> 6.86 s for loading; volume read calls fell from 3,055,508 to 64,108.
Separate runs with profiling disabled measured 8.06 -> 6.56 s for loading.
Those runs still used serial screen polling; disabling counters did not remove
the UART sampling cost. The later QMP measurements below avoid that overhead.
The picker remained about 0.9 s. This does not establish the cause of the much
longer picker delay reported on metal. KLOG0215 contains no I/O profile.
For a physical capture, enable F12 -> Debug -> Profile before reproducing the
delay, then use Print profile; its counters are saved in KLOG.

A subsequent loading profile exposed a separate paging hot path: `cpu_mode()`
read CR4, executed two CPUID probes and read EFER whenever page-table helpers
asked for the current mode. Recursive walks and page faults asked repeatedly.
The mode is now per-core state, initialized by paging setup and updated from
the actual EFER result after every protected/compatibility transition. Legacy,
PAE and long-mode execution retain their existing page-table formats.
The isolated `test/linux_paging_timing.py` maps 64 MiB, first-writes every page,
checks the bytes and unmaps. First writes measured 872 -> 28 ms in QEMU/KVM;
the same host Linux probe measured about 24 ms. VM exits make repeated hardware
queries particularly expensive under KVM; physical timings still need a metal
run. No application data seeding or durability policy changes produce this gain.

The resume fixture's `--screen-transport qmp` obtains the terminal projection
address once with `screen memory`, then samples it through QEMU's debugger.
It avoids guest UART transmission of a whole hex screen on every sample.
This reduced the measured diagnostic interference before evaluating the paging
fix: the passive profiled baseline loaded in about 4.16 s, versus the previous
6.56 s serial-sampled result. With the mode cache the passive run loaded in
about 2.18 s; user fault-handler time fell from 760 to 20 ms. The raw profiles
and isolated benchmark are recorded under `build/ci/resume-investigation`.
The final comparison uses one frozen snapshot of all 118 rollouts, preserves
their date hierarchy, disables profiling and reads the screen through QMP:
session loading measured 3.97 -> 2.27 s, with typing verified on both kernels.
Release `65ea2d06c272` contains the mode cache; preparation is not installation.

A later command-tool investigation reproduced a separate lifecycle bug using
the installed `codex-exec-server` directly, without a model, network, or screen
polling. On kernel `65ea2d06c272`, a shell printed its marker and became a
zombie, while the helper still returned `exited=false` after the probe's
20-second deadline. Child exit woke blocking `wait4` callers but did not send
SIGCHLD to asynchronous child monitors. Their initial `waitpid(WNOHANG)` could
return zero, after which they received no notification to retry it.

Child exit now queues SIGCHLD after publishing the zombie, using the existing
masked signal delivery and wakeup path. The handler receives child PID, exit
reason and status. `//tests:linux_sigchld` forces an initially empty WNOHANG,
then tests a parent parked in poll, masked notification and later unmasking.
`//tests:linux_exec_server_native` drives initialize, process/start and
process/read against the installed helper on private native ext4/NVMe, checks
the output and final status, and compares direct shells on Linux. Pipe-backed
shells are covered; this fixture does not exercise PTYs or the complete
code-mode/app-server stack. It shuts down the helper by closing stdin because
the current kill syscall is still a no-op.
The final QEMU sample delivered the first marker in 12 ms, reported exit and
closed in 13 ms, and completed its RPC in 17 ms; before the fix the marker
arrived in 11 ms but completion was still absent at the 20-second deadline.
Release `c514aa22ab32` contains the SIGCHLD fix. It is prepared, not installed.

The code-mode crash in KLOG0214/KLOG0216 was reproduced separately with the
installed CLI's helper. After 11 successful JavaScript sessions it trapped at
the same `0x94de7e0` address. The preceding INT3 is V8's overflow check on a
`clock_gettime(CLOCK_MONOTONIC)` result. Time syscalls truncated high output
pointers to 32 bits, leaving a high-stack timespec unwritten while reporting
success. Time and entropy output now use checked full-width user copies.
The entropy service had also rejected high-stack `getrandom` calls with EFAULT,
which caused the Rust runtime worker to panic after the clock fix.

Asynchronous thread TID stores/clears, futex addresses and timeout buffers,
sleep buffers, pipe and virtual socket/eventfd buffers, signal masks and
alternate-stack queries now retain their full user addresses. These paths are
covered by `//tests:linux_high_stack`, which puts a real pthread on a high
stack and checks its startup, I/O, time/random calls and join. The focused
`//tests:linux_time_high` checks alias guards, cross-page writes and protected
high buffers. These changes do not implement every high-buffer Linux ABI.

A further malloc corruption was traced to `brk`: musl places a guard page
inside its existing heap, and our growth check treated that guard as a new
ceiling. A request from `0xc708000` to `0xc709000` returned `0xc706000`,
shrinking the recorded heap and allowing later mmap allocations to overwrite
live malloc metadata. `brk` now rejects failed growth without changing the
current break and ignores guards wholly inside the existing heap. The
`//tests:linux_brk` regression also checks collisions, invalid full-width
requests, preserved data and valid shrinking against Linux.

With these fixes, `//tests:linux_code_mode_stress` completes 24 distinct
JavaScript sessions and shuts down cleanly on private native ext4/NVMe.
Both installed CLI and managed-daemon helpers passed the 24-session run.
No model, network or screen polling is involved. Linux fatal logs now retain
full RIP/RSP and the executable path; native 64-bit general-protection faults
avoid the legacy instruction decoder, which truncates addresses.
Evidence and hashes are saved in `build/ci/code-mode-crash-report.json`.
Release `4e392b12f870` contains these fixes and the preceding SIGCHLD fix.
The full 13-target validation suite and Clippy passed; kernel unit tests,
code-mode stress and the expanded high-stack test passed again after the
final lint cleanup. The release is prepared, not installed; physical metal
verification is still needed.

`python3 test/linux_bazel_rust.py --compare-host` isolates this with a tiny
workspace: one genrule compiles a fresh Rust source and another runs the binary
and checks its output. It uses the same installed compiler and extracted Bazel
runtime on both systems, with separate output caches and no repository downloads.
Results and Bazel JSON profiles are retained in `build/ci/bazel-rust`;
`--compiler-timings` additionally enables nightly Rust's `-Ztime-passes` and
glibc's loader statistics. Bazel's reported elapsed time excludes VM boot;
the probe also records the full guest wall time separately.
An initial QEMU/KVM measurement took 112.2 seconds in RetroOS, including an
83.6-second compile action. A second run with compiler/loader diagnostics and
pre-extracted Bazel runtimes took 125.1 seconds versus 0.87 seconds on Linux;
its compile action took 96.8 seconds versus 0.075 seconds. Rust reported only
0.136 seconds in LLVM passes, but 37.8 seconds waiting for the linker.
A compiler-startup profile spent 99.8% of sampled time in the kernel,
dominated by `mmap`. A native loader trace of the same Rust distribution maps
about 499 MiB from its two Rust/LLVM shared libraries, including overlapping
segments. Our eager private mappings read these regions again for each process;
the 32 KiB SMB read cap further turns the loads into thousands of serialized
requests. This probe measures the bottleneck; it does not implement demand
paging or a reusable cache of private file-backed pages.
The existing runtime can remain read-only: Bazel ignores `EROFS` when
updating its directory's last-use timestamp. Returning `ENOSYS` for this
operation previously made that optional update fatal. The guest cache and
outputs remain writable. `python3 test/linux_timestamps.py` checks 32/64-bit
Linux stat layouts, file/directory descriptors, ext4 links, and persistent
SMB timestamp updates. Linux `utimensat` uses shared VFS mount policy and
backend updates, including `UTIME_NOW`, `UTIME_OMIT` and no-follow semantics.
Existing timestamps retain one-second precision; Linux `statx` reports
unsupported access/change timestamp reads as unavailable.

`madvise(MADV_DONTNEED)` discards private anonymous mmap/brk pages and restores
demand-zero contents without removing the mapping reservation. Fork siblings
retain their original COW contents. Range tracking follows fixed replacements,
partial unmaps, fork, vfork and anonymous remap growth; file/shared ranges are
rejected rather than zeroed. `MADV_FREE` retains pages lazily; non-destructive
access, merge, huge-page and core-dump hints are accepted without changing data.
Other operations, including fork inheritance changes, remain unsupported.
The proc-fd probe checks both ABIs on ext4 and SMB. Run
`python3 test/linux_node_gc.py` for repeated Node/V8 collections with fragmented
old-space pages; missing page-discard support caused V8's
`DiscardSystemPages` fatal assertion on metal.

Private file mappings currently use eager copies. Shared file mappings alias
kernel-owned VFS pages: overlapping mappings and forked processes see the same
RAM, regular reads overlay mapped bytes, and regular writes update those pages.
`msync`, `fsync` and final unmapping write modified pages back to the backend;
closing the original fd does not invalidate the mapping. Protection changes
retain page ownership flags so fork and cleanup cannot free kernel-owned RAM.
Mapping validation/backing reads happen before a shared `MAP_FIXED` replacement.
Mapped file shrinking, renaming/unlinking mapped files, remapping shared ranges
and whole pages beyond EOF are explicitly unsupported. Mapped shrinking,
including `O_TRUNC`, returns `EBUSY` pending SIGBUS support; rename/unlink also
return `EBUSY` until file identity can survive namespace changes.
These pages coordinate RetroOS processes, not concurrent external SMB clients.
Run `python3 test/linux_proc_fd.py` for private isolation, shared visibility,
fork, fd-close lifetime, overlapping offsets, partial unmap and persistence
through both Linux ABIs on ext4 and SMB. `python3 test/linux_rustc.py` compiles,
links and executes a native Rust program, checking its ELF header and output.

To expose the locally installed native Codex executable and seed its separate
RetroOS login, run as your Linux user:

```sh
python3 tools/setup_codex.py
```

This installs executable wrappers under `/home/retroos/bin` for Codex and its
code-mode helper, bypassing the npm Node launcher. The wrappers exec the real
package path so SMB symlink handling does not hide the installed package from
`/proc/self/exe` discovery. It copies saved CLI authentication
into a private `/home/retroos/.codex` only when no RetroOS login exists.
Existing login state is preserved. After installing the updated kernel and
runtime, start `SHELL.ELF` and run `codex --version` or `codex exec`.
The same setup is used with live QEMU files and the physical-machine root.

Interactive Codex 0.163.0 returned `Hello from interactive Codex on
RetroOS.` using the in-process server in the actual QEMU/KVM terminal,
with a prompt entered through the
guest keyboard and the assistant reply verified from the terminal grid.
From `SHELL.ELF`, the response-only configuration is:

```sh
codex --no-daemon --disable apps --disable shell_snapshot --disable plugins --disable remote_plugin
```

SQLite WAL startup requires shared file pages. Returning `ENODEV` for writable
shared mappings caused `SQLITE_IOERR_SHMMAP` (5386), which Codex described as a
damaged local database even for a fresh private home. Shared VFS mappings now
provide this capability without resetting saved databases or login state.
Both Codex modes get past database initialization. The editor appears while
the session is still loading; pressing Enter then can leave text in a draft
without starting a model request. Earlier response probes timed out for this
reason. Wait for the model/status footer before submitting; the interactive
test now waits for that readiness signal before typing.
Run `python3 test/linux_sqlite.py` for a focused native SQLite WAL test using
the host's `libsqlite3.so.0`: concurrent reader snapshots, writer commits,
checkpoint, reopen, and a host integrity check after the guest exits.

Run `python3 test/linux_codex_interactive.py` to reproduce the interactive
request with a private copy of saved authentication, a separate temporary home,
and live SMB files. It retains terminal text and a QEMU screenshot under
`build/ci/codex-interactive`, then removes the private login. The test invokes
the ordinary PATH wrapper. Add `--daemon` to test the background server; its
artifacts are under `build/ci/codex-interactive-daemon`.
These response-only probes disable Apps, shell snapshots, plugins and remote
plugins so auxiliary setup does not become part of the model-response check.

The code-mode helper needs three additional Linux behaviors: `setpgid(0, 0)`
must return zero, `wait4(WNOHANG)` must return immediately while the child is
alive, and `readv` must support its random-device reads. Returning the
process ID from `setpgid` made musl report a negative child PID as the spawn
error (for example, `os error -5`). File and pipe vectored reads now retain the
open description and iovec snapshot while blocked. Socket and virtual-descriptor
vectored reads remain unsupported; process groups still use the existing
per-process job model.

Run `python3 test/linux_code_mode_host.py` to check the installed helper without
a model request. `python3 test/linux_codex_interactive.py --tools` requests a
real command and checks its output file in a private VM home. That probe
explicitly bypasses the Codex process sandbox; `--tools-readonly` instead tests
the read-only sandbox by asking the command tool to read an unknown marker.
Neither option changes the normal installation's configuration.

The installed 0.163.0 helper now executes JavaScript in RetroOS:
`python3 test/linux_code_mode_host.py --runtime` passes the framed runtime
request and verifies `RUNTIME_PASS`. Add `--sessions 3` to check independent
V8 isolates; this also verifies smaller reservations fall back high when the
low window fills. Its V8 sandbox previously failed because
large virtual reservations exceeded the 3 GiB low user window. Long-mode
processes now have a sparse anonymous arena from 512 GiB to 128 TiB, using
PML4 entries 1 through 255. The compatibility kernel and its recursive aliases
retain PML4 entry 0; ordinary ELF images, stacks, libraries and small anonymous
allocations prefer the existing low window, with anonymous reservations
falling back high when it fills. Fixed low mappings and `MAP_32BIT` retain
their low-address constraint.

Large anonymous mappings and explicit high hints use full-width addresses.
Uniform nonpresent table entries reserve whole subtrees; protection changes
and first access expand only the necessary tables. Committed pages are
zero-filled on demand. Context switches preserve the high roots; fork uses
copy-on-write for tables and data, and exec/exit release their references.
High `mprotect`, `munmap`, `MADV_DONTNEED`, and `read`/`write` buffers use the
physical mapping window rather than truncating pointers in the 32-bit kernel.
Fault events and Linux signal frames retain the complete 64-bit fault address.
High file/shared mappings, high `mremap`, and general high pointers in the
remaining syscall interfaces are not implemented by this change.

Run `bazelisk test //tests:linux_high_memory //tests:linux_signal
//tests:linux_vsyscall` (on one shell line) for a 4 TiB reservation in a 256 MiB
VM, cross-page I/O, fork isolation, discard, protection/unmap faults, full-width
signal addresses, and existing low-address behavior. The JavaScript runtime
probe establishes V8 execution. The interactive `--tools` probe now reaches
the command tool and completes a real `printf`/`cat` command: it creates
`tool-result.txt`, verifies its contents from the host, and checks the assistant's
`CODEX_TOOL_PASS` reply in the guest terminal. The probe uses its private VM's
sandbox-bypass option; read-only sandbox operation is a separate check.

The default background server also needs `/proc/sys/kernel/random/boot_id`.
RetroOS supplies that file from a read-only kernel filesystem, including on
metal with an ext4 Linux root and no Linux `/proc` mounted. Its UUID is generated
once from the kernel entropy service, shared by all processes, and changes on
reboot. It does not expose the hosted Linux machine's boot ID. Run
`bazelisk test //tests:linux_boot_id` for partial reads, seek, fork/exec,
write rejection, and two independent boots. An older
kernel reporting `failed to read Linux boot ID` can bypass this requirement
with `codex --no-daemon` until the updated kernel is installed.

Physical-machine logs subsequently exposed two gaps that the original SMB,
pretrusted-project probe did not cover. The daemon reads field 22 of
`/proc/<pid>/stat` to identify its process lifetime. RetroOS now supplies that
file and `/proc/self/stat` from its own task table, with birth times in Linux
clock ticks that survive exec. Numeric process paths mask the backing root's
`/proc` entries, including absent PIDs, so hosted files cannot supply another
OS's process identity.

Saving project trust uses temporary-file replacement of the existing
`config.toml`. Linux `rename` and `renameat` now permit the backend's atomic
replacement instead of returning `EEXIST`. DOS rename retains its existing
no-replace policy. Destination metadata overrides are replaced with the
source's, and failed operations preserve the original. Replacing an open or
mapped destination currently returns `EBUSY` pending inode lifetime support.
No unlink-before-rename fallback is used.

`bazelisk test //tests:linux_persistence` exercises these paths on an ext4
root with fake backing `/proc` entries: live and exited process identities,
exec-stable start times, config replacement through both rename syscalls,
metadata transfer, and preservation on errors. The interactive probe's
`--untrusted` option creates a private Git project, uses default startup,
accepts the trust prompt, and verifies the saved project entry in its private
`config.toml`. A folder without a project marker skips trust onboarding.
`python3 test/linux_codex_interactive.py --untrusted` saved trust and
completed a live model request in QEMU with the in-process server. These checks
use a private home; physical hardware still needs the updated kernel installed.

Linux creation permissions also need native ext4 coverage: its previous
`mkdir` path ignored the requested mode and created directories as `0775`.
`mkdir`, `mkdirat`, and new regular files now apply their requested mode and
the process's `umask` (initially `0022`). Fork copies the mask and exec preserves
it. Directory descriptor metadata reflects the actual directory, and mode
changes update existing regular-file descriptors. This allows private socket
parents and temporary directories to retain `0700` without a later chmod.
Run `bazelisk test //tests:linux_permissions` for creation modes, temporary
files, directory `fstat`/`statx`, and mask inheritance. Regular-file `F_GETFL`
must report its actual access mode: reporting every file as read-only caused
libc's `mkstemp` -> `fdopen("w")` sequence to fail with `EINVAL`, matching
GNU sed's temporary-file failure on metal. `openat` also resolves relative
paths against its directory descriptor rather than the process cwd; ignoring
that descriptor broke opening child directories during recursive operations.
The permission probe covers both regressions, including relative creation and
removal through a directory fd.

The interactive probe's `--ext4-home` option keeps the private writable home
on an ext4 disk while exporting installed host tools over read-only SMB. It
checks saved trust after stopping the VM and reading back the private disk.
`--state-from /path/to/codex-home` seeds private database snapshots;
`--raw-state` also preserves copied WAL/shared-memory files. Neither option
writes to the source home. `--binary` and `--managed-daemon` permit separate
checks of the CLI executable and its managed server package. Codex 0.163.0
started and replied with both checkpointed and WAL-preserving state copies on
native ext4. Those runs selected the in-process server: command-line feature
switches excluded daemon startup even when `--daemon` was passed to the probe.
The corrected probe writes feature switches into its private config and requires
a freshly created daemon PID record before reporting a daemon-mode pass.
Previous daemon-mode success claims therefore do not establish background
server operation. The 0.167.0 CLI test did not reach startup readiness before
it was stopped, so that CLI version is not established by these checks.

The managed 0.167.0 server performs an NFS check with Linux `statfs` before
opening SQLite pools. Returning `ENOSYS` was fatal there: the server exited
with code 1, then its parent reported `failed to record pid-managed ...
startup` because that process was gone. RetroOS now implements native
`statfs`/`fstatfs`, plus both i386 layouts. Queries resolve the backing
filesystem and read-only mount flags; ext4 and FAT supply live allocation
counts, and virtual/network backends identify their filesystem type without
inventing capacity. Run `bazelisk test //tests:linux_statfs` for both ABIs,
path/descriptor queries, allocation changes, read-only flags and errno checks.
The interactive probe accepts `--memory 32768 --storage nvme --ext4-home`
to exercise large RAM and the native NVMe driver rather than IDE/SMB defaults.

After SQLite initialization the daemon needs pathname Unix stream sockets.
RetroOS now provides local bind/listen/connect/accept streams, bounded byte
queues, polling, half-close/EOF, peer credentials, and abstract names. Pathname
nodes use the VFS mount namespace and write grants, retain their inode until
unlink, and support the daemon's chmod and inode-based cleanup checks. These
streams never use an IP socket or network port. This does not implement Unix
datagrams, sequenced packets, or descriptor passing. Run
`bazelisk test //tests:linux_unix_socket` for forked endpoints, credentials,
large writes, unlink/rebind behavior, and a six-CPU bootstrap.

The legacy PID record also invokes `ps -p PID -o stat= -o lstart=`.
Providing `/proc/PID/stat` alone was insufficient: GNU procps exited with
`Unable to get system boot time` because `/proc/stat` lacked `btime`.
The kernel now exposes a stable boot epoch derived from the RTC and its own
monotonic clock. CPU headers required by libproc2 contain zero counters;
CPU usage accounting remains unavailable. Host counters are never imported. Run
`bazelisk test //tests:linux_ps` for the installed procps command, stable start
times across repeated queries, and missing guest PID rejection.

An earlier lower-I/O experiment was withdrawn after a metal SHELL.ELF freeze.
The current implementation groups complete filesystem blocks above the same
JBD2 writer, preserving its five ordered barriers per committed batch. The
kernel enables a batch bounded by journal capacity and at most 64 blocks
(256 KiB on a 4 KiB filesystem). Reads, path lookup and allocation accounting
see pending changes immediately. Explicit file/directory fsync and shutdown
commit the batch; ordinary operations can share it until a 100 ms background
writeback or the size limit. Unsynced changes are therefore buffered rather
than durably committed on every close. Explicit kernel-log flushes still sync
the backing filesystem. Unsupported journal write profiles keep direct commits.

Three modern-image regressions cover grouped visibility, failed-operation
rollback, automatic capacity rollover and power loss at every commit step.
`//tests:linux_fsync_crash` kills the native guest immediately after file and
directory fsync, then verifies contents, rename persistence and a clean e2fsck.
`//tests:linux_ext4_batching` reports physical write amplification and checks
readback and fsync. `//tests:linux_sqlite_ext4` checks native ext4 WAL snapshots,
checkpoint, reopen and host integrity.

Linux `fchdir` restores a working directory through an open directory
handle; it previously returned ENOSYS during Python activity on metal.
The process-fd probe covers both Linux ABIs on SMB and ext4.

Linux processes sharing one terminal now rotate at 10 ms quanta. A CPU-busy
helper previously kept its parent UI from running until the helper blocked
or exited. Ready peers and blocked peers with pending work are visited in
round-robin order, after activating the appropriate address space; parents
whose vfork child still borrows their space remain suspended. Terminal
presentation stays shared and DOS launchers are excluded from this rotation.
`bazelisk test //tests:linux_responsiveness` runs two CPU-busy children and
checks parent progress and timer wakeups. The regression's first/second
parent delays fell from 2000/4000 ms to 7/36 ms in QEMU. The companion
`//tests:linux_console_responsiveness` keeps a helper CPU-busy behind a
blocked shell ancestor and verifies typed input reaches the waiting UI in
under a second without clearing its frame (0.2 seconds in the measured run).
The rotation cursor survives a blocked peer lending execution back to the
helper, so later blocked peers cannot be skipped indefinitely. These are
scheduler measurements, not an end-to-end Codex speed claim.

The DOS-to-Linux display handoff retires the outgoing DOS beam before
publishing the terminal scene. A batch helper can exec SHELL.ELF before its
first display tick, leaving the previous scanout bound to an obsolete VRAM
epoch. That scanout can suppress both the terminal and F12 while the shell
continues accepting commands. A renderer regression recreates the stale
epoch and checks physical pixel output after retirement. `//tests:linux_dn_shell`
also captures the QEMU framebuffer through DN, COMMAND.COM and SHELL.ELF,
checks terminal pixels and the F12 overlay, and restores the terminal with
HDA audio and two CPUs. The reported live VM still needs a reboot with this
kernel to confirm that this accounts for its freeze.

An existing Linux daemon socket alias exposed a separate identity bug on
metal: Linux had left a link into `/tmp/codex-daemon-1001`, while RetroOS
reported UID 0 and selected `/tmp/codex-daemon-0`. Codex intentionally removes
only its deterministic alias, so publication failed with `File exists`.
Linux session UID/GID now come from the configured home (or legacy C: home)
ownership, matching the existing VFS grant. Both get-ID ABIs, ELF auxiliary
IDs, and Unix peer credentials agree. Stat layouts expose backing ownership;
ownershipless session files use the session identity. Fork/exec cannot change
identity by supplying a different HOME. Identity switching remains unsupported
and attempts to select other IDs are rejected. Legacy ownershipless homes
retain UID/GID 0. Run `bazelisk test //tests:linux_identity` for distinct
UID/GID, foreign-owned files, all stat layouts, and fork/exec checks.
The interactive probe's `--stale-daemon-link` seeds a dangling alias from
the native home's owner; SQLite-only snapshots did not cover this case.
The full daemon/command probe passed with this pre-existing link, native
ext4 home, 32 GiB RAM, NVMe, and a WAL-preserving state copy. It verified
a fresh daemon PID record and saved command output after stopping the VM.

The corrected full probe passed with CLI 0.163.0 and managed server 0.167.0:
it created a fresh daemon PID record, connected the TUI, executed a shell
command through Codex, and verified the saved output after stopping the VM.
This run used 32 GiB RAM, NVMe, native ext4 home, and a private WAL-preserving
copy of the existing SQLite state. Its initial editor draft needed another
Enter; the probe's retry now tolerates stale cells in the terminal snapshot.
This is QEMU validation, not a completed physical-machine run. Reproduce with:

```sh
python3 test/linux_codex_interactive.py --daemon --tools --ext4-home \
  --state-from "$HOME/.codex" --raw-state \
  --managed-daemon "$HOME/.codex/packages/app-server-daemon/current" \
  --memory 32768 --storage nvme --stale-daemon-link \
  --timeout 480 --control-timeout 120
```

The child-setup errors were `prctl(PR_SET_PDEATHSIG, SIGTERM)` returning
`EINVAL`, followed by x86-64 `getppid` reporting the child's own PID. `getppid`
now reports the parent process. `PR_SET_PDEATHSIG` and `PR_GET_PDEATHSIG` store
per-thread settings; fork clears them, exec retains the calling thread's
setting, and exit of the creating thread queues the configured signal to the
child process. Blocked children wake for signal delivery; masks, handlers,
ignored signals, and the sender PID are preserved. Orphaned Linux processes
are adopted by the live init task. Linux waits report signal deaths separately
from ordinary eight-bit exit codes.

Run `bazelisk test //tests:linux_parent_death` for the native regression covering
parent identity, fork/exec, default SIGTERM/SIGKILL termination, handlers,
masking, clearing, ignoring, and a creating pthread exiting while its process
continues running.

The heap allocator also now preserves page alignment when a
free block leaves a prefix smaller than its free-list header; previously that
case could abort SQLite shared-page mapping during Codex startup.

The interactive test accepts `--timeout` and `--control-timeout` to distinguish
slow startup from a short diagnostic socket deadline. It retries Enter once
when the prompt remains in the editor after thread initialization and fails
early on explicit command-tool startup errors.

Run `python3 test/linux_console_focus.py` to check Linux terminal ownership
above a ready DOS launcher. It exercises yield, fork and blocking wait, samples
the framebuffer for clearing/flicker, and delivers keyboard input while stdin
is redirected to an IPC pipe. Processes sharing a terminal retain its display
across CPU switches, with shared keyboard modifier state and console input.

SQLite uses shared VFS process-owned advisory byte-range locks. Linux exposes
`F_GETLK`, `F_SETLK`, and `F_SETLKW`, including both i386 flock layouts. Closing
any descriptor for a file releases that process's record locks; fork does not
inherit them. Lock intervals support shared readers, exclusive writers, partial
unlocks, conversions and ranges beyond 4 GiB. These locks coordinate RetroOS
processes, not other SMB clients or Linux host processes. Positioned writes
preserve the open-file offset and update size for other open descriptions.
Run `python3 test/linux_record_lock.py` for native ABI and blocking-wait checks.

Linux monotonic clocks use the architecture's millisecond tick units; absolute
futex waits use the same time base. Socket I/O also records loss of readiness
for edge-triggered epoll, so EAGAIN followed by new data before the next wait
still produces an event. `python3 test/linux_epoll_network.py` checks this with
real UDP packets over VirtIO; `python3 test/linux_runtime.py` covers absolute
futex deadlines, Rust threads, TLS and synchronization.

Linux `dup` shares file offsets, socket/pipe ownership and virtual event
counters, and clears close-on-exec. `renameat` resolves both directory
arguments independently. `/proc/self/exe` reports the executable after following
symlinks, so package resources are found beside the installed native binary.

Codex creates helper aliases using Linux `symlink`/`symlinkat`. These calls
use the shared VFS and create persistent ext4 symlinks with parent-directory
write checks. Both inline and block-backed targets are journaled atomically.
Run `python3 test/linux_symlink.py` for both Linux ABIs, Linux fsck validation,
and an installed Codex version check without the helper-alias warning.
The SMB2 adapter creates persistent Minshall–French (`mfsymlinks`) files,
compatible with Linux CIFS's mount option of that name. It validates the fixed
1067-byte format and target checksum before treating a file as a symlink.
VFS handles absolute/relative targets, directory links, mount crossings and
loop limits for all personalities. On the server's local filesystem these
appear as encoded ordinary files, rather than native Unix links. Existing
native server links continue to be followed by Samba. Run
`python3 test/linux_smb_symlink.py` for both Linux ABIs, independent wire-format
checks and resolution after a guest reboot. FAT still returns `EOPNOTSUPP`.

The installed native Linux Codex binary can be exercised in QEMU:

```sh
python3 test/linux_codex.py
python3 test/linux_codex.py --request
```

The first command checks `--version` without a model request. The second
copies saved CLI authentication into a private temporary C:, requests one
short response without tool calls, and removes the copy on exit. Both start
`SHELL.ELF` and resolve `codex` through its normal PATH, without exporting
HOME/PATH/TMPDIR in the test script. They use 2 GiB guest RAM and the live host
root; `--binary /absolute/path/to/codex` selects another native executable.
Results are saved under `build/ci/codex-*`.
The request test does not validate interactive terminal
operation or execution of model-generated tools.

Codex CLI 0.163.0 has returned `Hello from Codex on RetroOS.` from a real
model request and exited with code 0 in this configuration. Model-catalog
refresh timeouts still appeared during that successful run.

Linux socket `writev` and `recvmsg` use the common network stack. Run
`python3 test/linux_message.py` to check both word sizes, UDP scatter/gather,
peeking, truncation, executable-path reporting and filesystem initialization
calls. BSD file locks belong to VFS open file descriptions and survive
`dup`/`fork` until the last close. They coordinate RetroOS processes; they
do not acquire locks in other SMB clients or host applications.

## DOS multiplayer and null modem

Press **F12**, open **Network**, and choose **Create LAN**. This starts a
DOSBox-compatible IPXNET relay on UDP port 213. On other RetroOS machines on
the same IPv4 LAN, select **Join LAN**. The creator must remain in the LAN
while playing. No `RETROOS.INI` networking entries are needed. Select the LAN
and wait for **Connected** (or **Hosting**) before launching a DOS game.

To play with DOSBox, enable `ipx=true` in its configuration, then run:

```text
IPXNET CONNECT <RetroOS-IP> 213
IPXSETUP -nodes 2 -deathmatch -warp 1 1
```

Alternatively, run `IPXNET STARTSERVER 1213` in DOSBox and choose **Join DOSBox
server...** in RetroOS's OSD. Type the server's IPv4 address and optional port,
for example `192.168.1.20:1213`, then Enter. Omitting the port uses 213.
Backspace edits the address; Escape cancels. Run the same Doom version and WAD
on both machines, with `IPXSETUP -nodes 2 -deathmatch -warp 1 1` on RetroOS too.

RetroOS supplies the Novell IPX software interface: discovery through
`INT 2Fh AX=7A00h`, its far-call entry and `INT 7Ah`, sockets, scatter/gather
ECBs, real-mode ESR callbacks, cancellation and timed events. IPX uses DOSBox's
raw IPX-over-UDP framing and socket-2 registration; the relay assigns node
addresses and forwards broadcasts and directed packets. There is no custom
RetroOS wrapper around game packets. SPX and the Ethernet packet-driver API
are not implemented. The relay accepts up to 16 remote registrations; leaving
and recreating the LAN clears its registration table.

For a two-player serial connection between RetroOS machines, select each
other's **COM1 cable** row with Enter or Left/Right. Both ends must select
their partner; the status then becomes **connected**. Run serial software
using COM1/IRQ4, such as Doom's `SERSETUP -com1`. The virtual UART provides
divisor registers, loopback, FIFOs, cable connection status and interrupts.
An ordered TCP stream carries the cable's bytes; baud settings do not throttle
the virtual cable. Each machine exposes one cable, owned by the first DOS UART
user until it exits. Changing rooms or partners clears queued cable data.
This serial transport is separate from DOSBox IPXNET compatibility.

RetroOS discovery uses UDP port 1213 and requires a shared broadcast network;
the serial cable uses TCP port 1214. IPXNET game traffic uses UDP port 213 on a
RetroOS host, or the selected external server port. Explicit server addresses
work without discovery. For QEMU user networking, a DOSBox server on the host
is reachable at `10.0.2.2:<port>`. To host in RetroOS and connect from DOSBox on
the host, add a UDP forward:

```sh
./run.sh qemu --net none -- \
  -netdev user,id=net0,hostfwd=udp:127.0.0.1:1213-:213 \
  -device virtio-net-pci,netdev=net0
```

Then DOSBox uses `IPXNET CONNECT 127.0.0.1 1213`. Discovery and rooms provide
no authentication or encryption.

`python3 test/ipx.py` exercises the DOS ABI between two VMs joined through
the actual OSD. `python3 test/ipx_doom.py` tests original Doom/IPXSETUP,
and `python3 test/ipx_doom.py --serial` tests Doom/SERSETUP through COM1.
`python3 test/ipx_dosbox.py` runs original Doom between RetroOS/QEMU and DOSBox
with RetroOS hosting; add `--dosbox-server` to reverse the roles. Install
DOSBox or set `DOSBOX_BIN` to its executable. The interoperability tests check
advancing game ticks in both directions and retain packet captures, logs and
a RetroOS screenshot. All tests use private game copies and disk snapshots.

## QEMU networking

The QEMU launchers enable **VirtIO user networking** by default. No TAP
device or host bridge is needed. Use `--net none` to disable it:

```sh
./run.sh qemu --net virtio
./run.sh qemu --net e1000
./run.sh qemu --net e1000e
./run.sh qemu --net none
```

RetroOS discovers a VirtIO 1.0+ PCI Ethernet interface or a supported Intel
controller and obtains its IPv4 address, default gateway and DNS servers by
DHCP. QEMU normally assigns `10.0.2.15`, with the host reachable at `10.0.2.2`. DHCP supplies a volatile
`/etc/resolv.conf` when no direct resolver is configured. Inherited loopback
DNS stubs such as Linux systemd-resolved at `127.0.0.53` are replaced in the
RetroOS namespace; the host file is untouched. Explicit direct DNS servers
retain precedence. The initial lease gets
up to three seconds during startup; discovery and renewal continue afterward.

The socket table, TCP/UDP/IP stack, DHCP and Ethernet drivers are common
RetroOS infrastructure. The typed socket API uses personality-independent
endpoints, options, errors and readiness; each personality translates its own
ABI and waiting rules. Linux is the first adapter; OS/2 sockets and Windows
Winsock adapters are not implemented yet.

Networking is available through the Linux personality's IPv4 TCP and UDP
socket calls, including blocking/nonblocking I/O, poll, bind/listen/accept,
and shared descriptors. For example, serve a file on the host with
`python3 -m http.server 8000`, then download it with the bundled BusyBox:

```sh
./run.sh qemu --cmd '/bin/busybox wget -O /home/retroos/download.txt http://10.0.2.2:8000/example.txt'
```

For incoming connections, supply a QEMU port forward. Disable the default
network first so the custom transport is the only one:

```sh
./run.sh qemu --net none -- \
  -netdev user,id=net0,hostfwd=tcp:127.0.0.1:8080-:8080 \
  -device virtio-net-pci,netdev=net0
```

Both default transitional and modern-only VirtIO devices are supported through
their modern PCI interface. The native Intel driver supports the 82540EM
(`8086:100e`, QEMU `e1000`) and 82574L (`8086:10d3`, QEMU `e1000e`). Both use
one shared legacy-descriptor RX/TX implementation. Following Linux’s driver
structure, PCI IDs select controller descriptions with MAC, PHY and NVM
operation tables. Model-specific Rust functions handle reset and configuration;
common helpers handle shared register protocols and link setup. Packet buffers
and descriptor rings use the common DMA allocator; the event loop polls completions with
interrupts and checksum offloads disabled. VirtIO takes priority when both
supported NIC types are present.

The Intel models are tested in QEMU under BIOS and UEFI; physical Intel boards
have not been validated. Integrated I217/I218/I219 controllers need additional
PCH/PHY initialization and are deliberately not claimed by this driver. Intel
I225/I226 and other Ethernet controllers are also unsupported. Legacy-only
VirtIO, IPv6, static addressing, raw sockets and DOS Ethernet packet drivers
are not implemented. DOS IPX and COM1 networking use the OSD LAN described above;
OS/2 sockets and Windows Winsock remain unimplemented.

Run `python3 test/e1000.py` to exercise both Intel models with BIOS/32-bit and
UEFI/64-bit Linux socket clients: DHCP/DNS, TCP transfers larger than the DMA
rings, UDP, incoming connections and a BusyBox HTTP download. The same socket
probe is used by `python3 test/virtio_net.py`.

The first interface is used, with up to 64 live/closing sockets. Each listener
holds one pending connection; UDP payloads are limited to 1472 bytes because
IP fragmentation is disabled. Hardware queues are polled from the event loop.

Run `python3 test/virtio_net.py` to check BIOS/UEFI DHCP, TCP transfers, UDP,
incoming connections, poll timeouts, descriptor sharing and a BusyBox HTTP
download against local servers. Tests retain packet captures and boot logs
in their printed temporary directory and do not depend on internet access.

With GNU `wget` from a Linux root, HTTPS is handled by its userspace OpenSSL
libraries. Keep the Linux root's CA certificates installed for verification:

```sh
wget -O /home/retroos/HTTPS.TXT https://example.com/
```

Native QEMU verifies an HTTPS download from `example.com`. Run
`python3 test/linux_https.py` for local TLS 1.2/1.3 downloads and rejection of
untrusted issuers and mismatched hostnames. That test uses host GNU `wget`
and its libraries in an isolated ext4 image, generated test certificates,
KVM and VirtIO; certificate verification stays enabled.

## DOS display scaling

Press **F12**, then **Tab** to **Display**. Select an option with Up/Down
and Enter, or cycle the setting with Left/Right:

- **Fit (4:3)** is the default: fit the largest centered 4:3
  image, with black borders and nearest-neighbor scaling.
- **Fill screen** fills the framebuffer, allowing aspect distortion.
- **Integer (near 4:3)** repeats every source pixel a whole number of
  times horizontally and vertically. It prefers the closest 4:3 aspect,
  then the largest picture with that aspect. For 320x200, exact 4:3 first
  fits at 1600x1200. If no integer pair fits within 10% of 4:3, it falls
  back to Fit (4:3) rather than severely distorting the image.
- **Integer (square pixels)** uses the largest equal whole-number scale on
  both axes, without correcting to 4:3. For example, 320x200 becomes
  1600x1000 on a 1920x1080 framebuffer. If the source is too large to fit
  at 1x, it shrinks while preserving the source's width-to-height ratio.

The selection applies when DOS resumes fullscreen framebuffer output after
closing the OSD. It lasts for the current boot. Native hardware VGA and the
desktop are unaffected; this setting does not change the framebuffer resolution.

## USB and optical boot

The boot partition contains `/boot/grub/grub.cfg`, editable
`/boot/retroos/BOOT.INI` and `/boot/retroos/RETROOS.INI`, and versioned boot files
under `/boot/retroos/releases/<version>/`. GRUB loads the core image as a module
because RetroOS cannot read USB storage yet. `[bundle] source=module` selects
that image. Default boot loads the 16 MiB core (runtime libraries, DN and
BusyBox) plus one 256 MiB showcase module with VC, MC, RC, NDN
(DOS/Windows/OS/2), DN/2 (DOS/Windows/OS/2) and games. The “Core only
(less RAM)” choice omits the showcase module. With RAM C:, the user INI is session content; edit the ordinary USB file
from another OS for persistent changes. An existing INI on a selected disk C:
keeps its disk backing.

## Module installation for filesystems RetroOS cannot read

Use Linux with GRUB 2 installed. The USB image supplies both the kernel and RAM base
module. Build and prepare as your normal user, review the generated entry, then
install it as root:

```sh
tools/install_kernel.sh --module --prepare
# Review build/grub-module-install/<image hash>/grub.cfg
sudo tools/install_kernel.sh --module
```

Linux enumerates FAT and ext4 partitions on non-USB disks. If several could be
C:, preparation prints their paths and UUIDs; rerun with
`--c-uuid=ABCD-1234` (FAT) or an ext4 UUID. A selected ext4 volume may be
unmounted in Linux: installation temporarily mounts it to check or create
the selected DOS directory, then unmounts it. Installation also creates the `retroos`
group when needed. With no supported
data volume, the RAM module supplies C:. Use `--c-ram` to choose this explicitly.
For ext4, add `--c-dir=/path/on/volume` during preparation to use a different
C: directory; the installer creates that directory and passes the same path
through the INI mount configuration. The default is the installing user's
`DOS` directory when their home is on that volume, otherwise `/DOS`.
With one eligible FAT/ext4 volume, it is selected automatically, including
on Btrfs hosts. Multiple candidates require `--c-uuid` or `--c-root`. With
no supported volume, C: uses RAM. Existing RetroOS files are not required. The RAM module supplies the runtime in `C:\RETROOS`; user and boot INIs on
physical C: keep their disk backing. Upgrading an older installation copies
the boot-directory settings into C: once, preserving existing C: settings.
Add `--copy-showcase` to copy missing games and commanders into physical C:.

For example, with Linux `/boot` on Btrfs and a separate FAT32 data partition,
find that partition's UUID and prepare the entry with it:

```sh
lsblk -o NAME,FSTYPE,UUID,PARTTYPE,MOUNTPOINTS
tools/install_kernel.sh --module --prepare --c-uuid=ABCD-1234
# Review build/grub-module-install/<image hash>/grub.cfg
sudo tools/install_kernel.sh --module
```

Replace `ABCD-1234` with the FAT32 data partition's UUID, not the EFI System
Partition's UUID. The installer stores `kernel.elf` and
`retroos-base.img.gz` under Linux `/boot/retroos/releases/...`. With physical
C:, both INIs live in its `RETROOS/` directory; GRUB loads them directly from
that data volume. With RAM C:, the INIs stay under `/boot/retroos/`. RetroOS then reads the selected
FAT32 partition as C:. It cannot read Btrfs itself, so `C:\RETROOS` comes
from the RAM base module and the Btrfs boot filesystem is not C:.

The installer detects whether `/boot` is separate, including a Btrfs boot
filesystem, copies versioned files there, and installs two GRUB entries:
protected disk and persistent disk. It does not partition or format a disk. A prebuilt USB image can be supplied
with `--image=/path/to/retroos_grub_module_usb.img`; preparation then needs no Bazel
build. The Linux `/` filesystem is used only for discovery. RetroOS cannot
mount Btrfs yet; with no supported physical root it uses the RAM module for
its own `/` and C:.

## Manual GRUB deployment

Use this when GRUB is already installed and you want to choose the kernel and
base files yourself. The kernel and base image must come from the same build.
The base image holds `C:\RETROOS`, startup defaults, and a RAM fallback C:.
It is a GRUB Multiboot module, not a partition to extract onto the disk.

Build `//:grub_module_usb` and copy the selected version from `/boot/retroos/releases/<version>/` and both
INI files from `/boot/retroos/`
to a directory on a filesystem GRUB can read:

```text
kernel.elf
retroos-base.img.gz
BOOT.INI                  # bundle backing and mounts
RETROOS.INI               # editable user settings
retroos-showcase.img.gz       # optional showcase content
```

The image is also distributed as `retroos_grub_module_usb.img`. On Linux,
replace `VERSION` with the selected release directory and copy from the first
FAT32 partition with mtools:

```sh
mkdir -p /tmp/retroos-manual
mcopy -i retroos_grub_module_usb.img@@1048576 ::/boot/retroos/releases/VERSION/kernel.elf /tmp/retroos-manual/
mcopy -i retroos_grub_module_usb.img@@1048576 ::/boot/retroos/releases/VERSION/retroos-base.img.gz /tmp/retroos-manual/
mcopy -i retroos_grub_module_usb.img@@1048576 ::/boot/retroos/BOOT.INI /tmp/retroos-manual/
mcopy -i retroos_grub_module_usb.img@@1048576 ::/boot/retroos/RETROOS.INI /tmp/retroos-manual/
sudo mkdir -p /boot/retroos/manual
sudo cp /tmp/retroos-manual/* /boot/retroos/manual/
findmnt -no UUID --target /boot/retroos/manual
```

Keep the kernel and module images together when upgrading. If `/boot`
is a separate filesystem, GRUB paths start at that filesystem's root; the
example's `/boot/retroos/manual/` becomes `/retroos/manual/`.

Choose physical filesystems with `lsblk -o NAME,FSTYPE,UUID,MOUNTPOINTS`.
Copy [etc/BOOT.INI](etc/BOOT.INI) and [etc/RETROOS.INI](etc/RETROOS.INI)
alongside the kernel, replace the BOOT.INI session mount with your UUID mounts, and set their paths and access modes.
A FAT C: normally uses `path=/dos`, `drive=C`, and `subdir=/`.
An ext4 C: can use `path=/home/alice/DOS`, `subdir=/home/alice/DOS`,
and a matching `grant` directory, alongside a Linux root mounted at `/`.
The base module supplies `C:\RETROOS`, `C:\DN`, and `/bin` independently.
For persistent DN settings, explicitly mount a writable directory at the
C: namespace's `DN` path; the default bundled DN stores changes in RAM.
`C:\TEMP` is always RAM-backed.

`BOOT_FS_UUID` below is the UUID of the filesystem containing the kernel,
base image and INI. Physical data UUIDs belong in the INI.
Add this entry to GRUB's custom configuration, adjusting the paths if needed.
On Debian or Ubuntu, use `/etc/grub.d/40_custom` and run
`sudo update-grub`; on other distributions, regenerate `grub.cfg` with the
distribution's GRUB command. `grub-script-check` can check the entry first.

```grub
menuentry "RetroOS (manual, protected disk)" {
    insmod multiboot2
    insmod gzio
    search --no-floppy --fs-uuid --set=root BOOT_FS_UUID
    multiboot2 /boot/retroos/manual/kernel.elf ram-overlay
    if [ "$grub_platform" = "pc" ]; then
        set gfxpayload=text
    else
        insmod all_video
        set gfxmode=auto
        set gfxpayload=auto
    fi
    module2 /boot/retroos/manual/retroos-base.img.gz retroos.mount=/
    module2 /boot/retroos/manual/BOOT.INI retroos.config=boot
    module2 /boot/retroos/manual/RETROOS.INI retroos.config=ini
    # Optional showcase content, separate from physical game directories:
    # module2 /boot/retroos/manual/retroos-showcase.img.gz retroos.mount=/showcase
    boot
}
```

The example starts with physical writes protected. Remove `ram-overlay` to
persist writes on mounts configured `access=rw`. For a boot log that stays
on screen, add `boot-log-only`. Missing or ambiguous data UUIDs produce a
diagnostic and stop boot; no other partition is selected.
Unlisted physical filesystems remain unmounted. RetroOS does not read USB
mass storage after GRUB hands off.

## Mount setup and file images

F12 → Disk → Mnt lists detected FAT/ext4 partitions and their UUIDs. Use
Left/Right on the drive and access rows to stage choices. Select an export
destination, then **Export RETROOS.INI**. The export follows the destination's
active write permissions and the Protected Disk setting. Copy the exported
file onto the GRUB boot medium from another OS, next to the base image, and
load it with `retroos.config=ini`. Staging does not change active mounts.

An image on a mounted filesystem can itself supply a drive without copying:

```ini
[mount "linux"]
source=UUID=<ext4-filesystem-UUID>
path=/
access=rw
grant=/home/priv-gerben

[mount "data"]
source=file:/home/priv-gerben/project/RetroOS/build/data.bin
partition=1
path=/home/retroos
drive=C
access=rw

[mount "cd"]
source=file:/home/priv-gerben/game.iso
format=iso9660
path=/cdrom
drive=D
access=ro
```

Image dependencies determine mount order. `partition` is numbered from 1;
raw filesystem images need no partition selector. With multiple supported
partitions, select one explicitly. File images currently must be smaller
than 4 GiB, matching the VFS file-offset limit. ISO9660 is read-only.
`access=ram` overlays a disk or image with session writes. `access=ro`
rejects write opens and mutations. Bundle content always has a RAM overlay,
so applications can open bundled DLLs or settings for writing safely.

## Legacy installer for a Linux ext4 root

The installer uses the existing GRUB and ext4 root. It does not repartition the
machine or use emulator image files. `/home/retroos` is the persistent DOS C:.

Run the build/preparation as your normal user, then install the prepared release:

```sh
tools/install_kernel.sh --prepare
# Review build/machine-install/<release>/grub.cfg
sudo tools/install_kernel.sh
```

Preparation builds one `//:machine_boot_tar` containing the matching kernel,
symbols, COMMAND.COM, SHELL.ELF, and DN program/resources. Installation puts that
release under `/boot/retroos/releases/<release>/`, installs managed entries in
`/etc/grub.d/41_retroos`, and regenerates GRUB using `update-grub` or, when it
is absent, `grub-mkconfig`/`grub2-mkconfig`. No reboot is performed. Previous
releases and unrelated GRUB entries remain. The obsolete RetroOS entries are
backed up and replaced by managed entries named
**RetroOS (current, persistent)** and **RetroOS (current, protected disk)**.

Both disk-protection entries use the same video policy. When GRUB boots through
legacy BIOS (`grub_platform=pc`), it hands over text mode (`gfxpayload=text`),
so RetroOS uses native BIOS video and hardware VGA, including planar/Mode X.
When GRUB boots through UEFI, it keeps the GOP framebuffer and RetroOS uses
its substitute BIOS and software VGA rendering. RetroOS selects this path from
the display handoff, not by searching memory for a BIOS ROM. Custom GRUB entries
should use the same policy: forcing a linear framebuffer on BIOS selects the
software rendering path too.

Select the firmware boot mode before entering GRUB, using the machine's
firmware setup or boot-device menu (the key and entry names vary by manufacturer).
A UEFI entry loads GRUB's EFI executable and reports `grub_platform=efi`.
A legacy entry starts the disk's BIOS bootloader and reports `grub_platform=pc`.

To use native BIOS video, enable Legacy/CSM if supported and select the legacy
boot entry. The disk must also have BIOS GRUB installed: enabling CSM alone
does not install a BIOS bootloader, and selecting a UEFI entry still uses GOP.
On UEFI-only machines, RetroOS uses its substitute BIOS and software rendering
to support DOS applications. The RetroOS installer adds menu entries to the
existing GRUB; it does not install another firmware variant or enable CSM.
Choosing persistent versus protected inside GRUB only changes disk writes.

After updating RetroOS's installer, rerun preparation and installation to apply
the generated video policy to an existing machine's GRUB entries.

The directory installer locates its matched release using Multiboot arguments.
The release's `RETROOS/RETROOS.INI` selects Linux `/` and DOS `C:` by UUID,
with writes granted to the chosen C: directory. The module installer supplies
that same policy as a GRUB configuration module.

There is one configuration format: `RETROOS.INI`. Startup arguments go in
`[system] start=`, regional settings in `[locale]`, and guest environment
variables in `[environment]`. `--cmd` and `[environment] TEST=` override
normal startup for command execution and tests.

The boot bundle supplies `C:\RETROOS`, `C:\DN`, and `/bin` as writable RAM
content. When a Linux filesystem supplies `/`, its `/bin` and `/usr/bin` are used.
Bundled BusyBox serves the RAM root, or an explicit bundle mount at `/bin`.

Application settings stay with the application unless its own
configuration selects another directory. To persist application settings,
configure an explicit writable directory mount. `C:\TEMP` is RAM-backed.

For a direct hosted C: directory, `tools/install_boot_dir.sh /path/to/c-root`
installs the same flat bundle layout and `RETROOS/RETROOS.INI`.

## Disk writes and `ram-overlay`

Mounts configured `access=rw` persist writes. The VM launcher generates rw
mounts for its explicitly attached data disk. The default standalone bundle
uses RAM and leaves physical partitions unmounted.

Add the Multiboot argument `ram-overlay` and every write to a physical disk
goes into volatile RAM instead. Writes appear to work for the whole session
and vanish on reboot:

```
multiboot /retroos/kernel.elf ram-overlay
```

The boot screen says which you got, and it is the ground truth — not the menu
entry's name:

```
Disk writes: volatile RAM overlay (ram-overlay) — changes will NOT persist
Disk writes: PERSISTENT — physical devices are writable        (in red)
```

### Which disk is at stake

The installed-machine entries select the ext4 filesystem by UUID. `C:` is
the DOS directory selected in BOOT.INI on that filesystem (by default
`$HOME/DOS`). INI layouts mount only their listed sources. Without `ram-overlay`,
permitted writes persist on the selected filesystem.

What it can and cannot reach:

- **Cannot**, structurally: the partition table, any unselected partition,
  firmware. A separate EFI System Partition stays read-only unless selected
  as the root itself. Every write
  goes through `Volume::write`, which is volume-relative and bounds-checked, so
  a filesystem cannot address past its own extent.
- **Can**: the contents of that one filesystem — which includes `/boot`. A bug
  in the ext4 write path could therefore leave Linux unbootable until you fsck
  it from a live USB. Recoverable, not catastrophic, but plan for it.

A second gate limits ordinary ext4 file writes: a file is writable only if its owner UID
matches the `C:`-root's owner **and** it is owner-writable (`chown <C:-owner>` +
`chmod u+w`). FAT has no such ownership gate. That bounds deliberate ext4
writes; it does not bound a metadata bug.

No host `retroos` account is required. New C: directories belong to the installing
user; their numeric owner UID supplies the grant. Ordinary owner-writable copies
work without changing their group. Files from older images that have only the
group-write bit need `chmod u+w` before they can be written with this policy.

### Status

Writing to a real laptop root has been exercised once, successfully: a file
created from DOS survived the reboot with correct contents and ownership, ext4
recorded no errors, and the next Linux mount needed no journal recovery. That
is one data point, not a guarantee — every other write test has run against a
~1 GiB image, in a layer that has had big-disk-only bugs before. There is also
no way yet to point RetroOS at a scratch partition instead of the real root,
so there is nowhere safe to stress it.

Until that exists, `ram-overlay` is the sensible default for a machine you care
about, and the writable entry is for when you specifically want persistence and
have a live USB within reach.

Why an argument rather than a probe: nothing can infer whether a disk is
precious. An earlier version tried — protect on "real hardware", detect
emulators by their southbridge — and got this project's own audience backwards,
since a real Pentium with a PIIX4 is a first-class RetroOS target and the
likeliest machine to be holding someone's data. Only the owner knows, so only
the owner says.

## Booting GRUB Multiboot module images

For a USB boot, build `//:grub_module_usb` and write
`bazel-bin/retroos_grub_module_usb.img` to the whole stick. It has an ordinary
MBR with one FAT32 EFI partition; the editable menu is
`/boot/grub/grub.cfg` on partition 1. The GRUB menu contains protected
and persistent disk choices for the base-plus-games image, plus a base-only
submenu with the same choices for framebuffer video (GOP on UEFI,
VBE on BIOS). BIOS boots also offer native BIOS VGA entries, selected by
default; the framebuffer entries explicitly select software VGA rendering.
UEFI boots default to GOP. Disk protection (`ram-overlay`) is the default in
both firmware modes. To persist changes, configure rw data mounts in the INI
and select persistent disk. The module artifacts are raw ext4
images, not partitioned disks; GRUB expands the reproducible gzip files before
the Multiboot handoff:

```text
multiboot /boot/kernel.elf
module /boot/retroos-base.img.gz retroos.mount=/
module /boot/retroos-showcase.img.gz retroos.mount=/showcase
boot
```

Filesystem modules use `retroos.mount=<absolute-vfs-path>` and replacement
mounts. Raw FAT12/16/32 images are also accepted. Plain-text configuration uses
`retroos.config=ini`. The base module supplies system files, DN, BusyBox and the
bundled RETROOS.INI. Module filesystems have writable RAM overlays; physical
filesystems are selected explicitly by the INI and follow its access modes.
Optional game modules remain separate even with a physical C:.
Unlisted physical filesystems remain unmounted.

Module images remain resident in the physical RAM where GRUB loaded them, but
they are not permanently mapped into a size-matched kernel virtual window.
Reads and writes use a reusable 64 KiB physical aperture immediately below the
framebuffer. Legacy 32-bit paging and PAE both support module access; available
physical RAM and the Multiboot address format remain the practical limits.
Boot the USB image through QEMU's USB controller, for example:

```sh
bazelisk build //:grub_module_usb
qemu-system-i386 -m 512 -device qemu-xhci,id=usb \
  -drive if=none,id=stick,file=bazel-bin/retroos_grub_module_usb.img,format=raw,snapshot=on \
  -device usb-storage,bus=usb.0,drive=stick,bootindex=1
```

## FAT roots

GRUB loads `kernel.elf` as usual. The kernel probes filesystem contents and
accepts FAT12/16/32 partitions, unpartitioned FAT media, and raw FAT Multiboot
modules. On a selected FAT root, `C:` maps to the volume root: put the DOS
system files in `/RETROOS` (`C:\RETROOS`), alongside the partition's existing
Windows/DOS files and games. No `/home/retroos` directory is needed on FAT.
Legacy Unix/ext4 boots without explicit mount configuration retain
`/home/retroos` as C:, even if missing; they never silently fall back to `/`.
New installations select C: through BOOT.INI as described above. Explicit
C-drive overrides take precedence. FAT root modules use the same mapping as physical FAT.

Preserve the exact spelling of the VFS startup paths, including `RETROOS`.
When multiple filesystems are present, `/etc` plus `/usr` take precedence,
followed by a filesystem containing its DOS home (top-level `RETROOS` for FAT).
This keeps a separate EFI system partition from displacing an installed DOS
root. GRUB's kernel location does not override this root-selection policy.

A selected physical FAT root is writable; FAT has no Unix ownership/group
grant. Use `ram-overlay` to keep physical writes volatile. FAT modules write
directly to their volatile RAM, and secondary disk mounts remain read-only.

FAT directory entries expose both the long name and the stored 8.3 alias.
VFS uses exact names on every storage format; DOS case folding belongs to
DosFS. DosFS preserves FAT's alias; ext4 entries receive generated aliases.
DOS applications can use the INT 21h/AH=71h LFN services on either format;
see [DOS LFN support](test/dos/lfnprobe/README.md) for the implemented calls
and remaining limits.

Regression test: `python3 test/grub_fat.py` (GRUB, QEMU, gcc, dosfstools,
and mtools required).

## Booting from a GRUB hard disk (`//:image_grub`)

This is for a *self-contained* disk — one you write to a spare drive or a USB
stick and boot without touching that machine's GRUB, and what QEMU/Bochs/86Box
boot. Installing on a machine that already has GRUB does not need it; use the
one-file install above. `bazelisk build //:image_grub` produces a disk with
**no RetroOS bootloader**:
GRUB's `boot.img` in sector 0, `core.img` in the MBR gap, and a single ext4
partition holding `/boot/kernel.elf`, `/boot/grub/grub.cfg` and the usual
content. To test that standalone legacy image directly, use
`qemu-system-i386 -drive file=bazel-bin/image_grub.bin,format=raw,snapshot=on`.
Normal `./run.sh qemu` launches use the shared boot/data layout.

The legacy `//:image` (our own MBR + a 0xDA boot-bundle partition holding
`kernel.elf` as a TAR member) still builds. `//:image_grub` is the candidate
replacement: same job, a stock loader, and one fewer on-disk format to
maintain.

The image is assembled by `tools/build_grub_hdd.py`, which does GRUB's two
embed steps itself (`boot.img`'s core LBA, `core.img`'s block list) because
`grub-install` wants a real block device and `grub-bios-setup` is not always
packaged. It needs `grub-mkimage` plus the i386-pc modules (`grub-pc-bin`).

## What happens

GOP text console (the kernel renders into the framebuffer GRUB hands over —
`kernel/src/arch/fbcon.rs`), then storage discovery. RetroOS walks MBR or GPT
partitions and applies BOOT.INI to FAT/ext4 volumes and file images. The
bundle supplies writable RAM views of `C:\DN`, `C:\RETROOS` and `/bin`. Writes
on rw data mounts persist unless `ram-overlay` was passed. Disk boots require both INI modules; unlisted physical partitions stay unmounted.

Keyboard: the i8042 path (most laptops expose one via EC emulation) feeds
the personality BIOS's INT 09. Machines with USB-only input are handled by the
xHCI USB-HID boot-keyboard driver, which works on real full-speed hardware
(verified on a Razer Blade — SkyRoads played from USB keyboard input).

USB input supports xHCI controllers and HID boot keyboards and mice attached
directly or through USB 1.x/2.0 hubs, including composite devices exposing both
interfaces. Hub enumeration powers and resets downstream ports, constructs
nested route strings, and supplies transaction-translator ancestry for
low/full-speed devices below a high-speed hub. High-speed hubs use their
default single-TT alternate setting. Input devices must be connected at boot.

Each of up to four controllers retains at most twelve devices, including hubs,
with a keyboard and a mouse endpoint for every retained HID device. Each mouse
has an independent report pipe; button state is combined across mice so an
idle interface cannot release a button held on another mouse. Routes support
five downstream tiers and hub ports 1–15. Boot interfaces are switched to boot
protocol; a legacy report-ID layout supports certain gaming keyboards.
SuperSpeed hubs, hotplug, EHCI/OHCI/UHCI, USB game controllers, and general HID
report-descriptor parsing remain unsupported. In KLOG, `keyboard ready` /
`mouse ready` means endpoint setup succeeded, not that input reports arrived.

Run `python3 test/xhci_smoke.py` for direct devices, powered hubs, nested hubs
(including a five-hub chain), split controllers and BIOS/UEFI. PS/2 is disabled;
the DOS probe must receive a keyboard press, mouse motion and a click. Two-mouse
cases activate each QEMU mouse separately and require movement and clicks from
both devices. QEMU's
hub model is full-speed, so physical high-speed hub/TT operation and the KVM
switch reported in issue #71 still require testing on the affected hardware.
`bazelisk test //arch-metal:xhci_dma_test` also checks route limits, inherited
TT ancestry, both context sizes and nonoverlapping DMA storage.

Caveats on real hardware (vs the `run_uefi.sh` mock):
- fbcon accepts packed 16/24/32bpp direct-RGB framebuffers and converts its pixels using the
  channel positions and widths reported by GRUB.
- If boot stops with white bars at the top of an otherwise black screen, count
  the bars: one means unsupported framebuffer type, two means unsupported RGB
  layout, three means pitch smaller than the pixel row, and four means the mode
  is below the 640x400 boot console minimum. Each bar is four scanlines tall,
  followed by four black scanlines.
- ACPI shutdown is wired for QEMU/Bochs/VirtualBox and PIIX4 boards; on a
  modern laptop it falls through to a halt, so power off by holding the button.
- An MBR- or GPT-partitioned disk containing ext4 or FAT can become the RetroOS root,
  and its files appear in DN. Whether changes reach the medium is the
  `ram-overlay` question above.
- Returning to Linux after a RetroOS session has been seen to add ~34 s to the
  next boot, stalling just before the root mount. The filesystem is clean when
  it gets there (no journal recovery), so this looks like a device-handoff
  problem — RetroOS parks the HDA codec on the way out but not storage or USB.
  Under investigation.

Disk installer preparation asks whether to copy the showcase only when the C:
directory does not yet exist. Existing C: directories skip copying by default.
Use `--copy-showcase` or `--no-copy-showcase` for scripted preparation.
Copying adds missing ordinary files and preserves existing files and symlink
directories. These are disk files, with no showcase mount or RAM image.

The machine release includes `showcase.tar` alongside `machine_boot.tar`.
It supplies `ULTRASND` instrument patches, OS/2 and Windows samples under
`OS2/APPS` and `WINDOWS/APPS`, and the `SRC` and `TESTS` folders. Compatibility
DLLs live under `RETROOS/` and ship with the matching kernel. To add missing
showcase files to an existing persistent C:, prepare with `--copy-showcase`
and then install; existing files are preserved. No image extraction is needed.

## Native Wi-Fi connection settings

Add a profile to your existing `RETROOS/RETROOS.INI`:

```ini
[wifi]
ssid=MyNetwork
password=your-password
autoconnect=true
```

The kernel scans at boot, selects the strongest compatible BSSID with that
SSID, and retries failed connections. `autoconnect=false` leaves the radio
available for discovery without joining. The initial connection mode is
WPA2-Personal with CCMP-128 on 2.4/5 GHz, using legacy 20-MHz rates. WPA3,
enterprise authentication and networks requiring protected management frames
are not supported yet. Native WCN7850 boot autoconnect is confirmed on hardware:
KLOG0010 (build `b0e150579408`) completes association and WPA2, authorizes the
encrypted link, and receives DHCP address `192.168.1.160/24` with DNS server
`192.168.1.254`. KLOG0011 exposed missing Linux resolver/socket calls in GNU wget. The follow-up
adds UDP error-reporting registration, `sendmsg`/`sendmmsg` and `pselect6`, plus
clock resolution and ABI-correct time structures. GNU wget now resolves
`example.com` and downloads its HTTP page with exit code 0 in an isolated
QEMU ext4 fixture. KLOG0012 confirms DNS resolution, HTTP 200 and a 577-byte
`example.com` download over native Wi-Fi.
The stack currently registers UDP error-reporting interest without generating
ICMP auxiliary error records. GNU wget's optional alarm timer and setting a
remote file timestamp can still report unsupported calls; the tested HTTP
transfer itself completes successfully.
KLOG0007 confirms profile loading, selecting `gmc`,
channel-start requests, stop/delete cleanup and automatic rescans on hardware;
it stops before 802.11 authentication. The follow-up uses Linux's zero
requestor field and accepts the single pending vdev-start reply, logging its
requestor and firmware status instead of silently ignoring a differing ID. KLOG0008
confirms successful channel start, 802.11 authentication/association, validated
WPA2 message 3 and firmware acknowledgement of pairwise/group keys. Final-link
confirmation was blocked by classifying firmware HTT completions as failures;
the follow-up accepts HTT OK alongside TQM ACKED and logs their source/status.
KLOG0010 confirms that both EAPOL completions use firmware source 3/status 0,
followed by successful link authorization and DHCP.

Authentication, key derivation, replay handling, association policy and retries
live in the common Wi-Fi service. Radio drivers supply channel, frame and
key-install operations. All guest personalities use the existing common
Ethernet/IP/DHCP stack once the encrypted link is authorized. `/proc/wifi`
(`C:\proc\wifi`) and the automatic kernel log show connection progress;
DHCP address assignments appear in the kernel log. Credentials are kernel settings,
excluded from guest environment blocks and diagnostic debug output. The INI
itself contains the password, so keep its host file private. Installer staging
copies are created with mode 0600.

## SMB network mounts

RetroOS can mount an authenticated SMB 2.0.2/2.1 share through its common VFS.
All personalities use the same mount through their ordinary file APIs.
Add a section to `RETROOS/RETROOS.INI` (repeat `[smb]` for additional shares):

```ini
[smb]
server=10.0.2.2
port=445
share=data
username=retroos
password=your-password
domain=WORKGROUP
path=/home/retroos/NET
```

`server` is an IPv4 address; `port` defaults to 445 and `domain` may be omitted.
`path` must be an absolute VFS path. `/` is accepted only with `access=ro`.
Other mounts default to `access=rw`; `subdir=/some/directory` selects a
canonical subdirectory of the share instead of its root. With the normal C: mapping, this
example appears as `C:\NET` to DOS/OS2/Windows and `/home/retroos/NET` to Linux.
To give a share its own DOS/OS2/Windows drive, add `drive=H` and use
`path=/host`; Linux then accesses the same share at `/host`. Explicit network
drive letters E through L are supported; letters already used by storage
mounts are rejected. Omitting `drive` keeps the path-only mount behavior.
The password is a kernel mount setting, not an exported guest environment
variable; configuration debug output omits credentials.

The server must permit SMB2 and NTLMv2. Signing is mandatory; invalid
signatures, guest/anonymous fallback, and encryption-required shares are
rejected. File permissions remain the server's responsibility. Create,
read/write, close/flush, directory enumeration, rename, delete, mkdir/rmdir,
and truncate are supported. Directory enumeration keeps server cursors
between batches. File sizes and offsets currently follow the VFS's 32-bit
limit. SMB3/encryption, Kerberos, DFS, leases and automatic reconnect are not
implemented.

NTLM challenges and signing keys use the shared kernel random service:
a software HMAC-DRBG/SHA-256 generator seeded by an optional entropy source
or irregular input/disk interrupt timing. RDRAND is the current optional
hardware source; it is no longer required once timing has seeded the pool.
Hardware events retain the nanosecond timestamp sampled at interrupt entry
through queued delivery, using TSC, HPET, or the PIT on older CPUs. Hosted
input is timestamped on arrival using a real clock, independently of the
interpreter's deterministic guest clock. Polled USB HID reports carry their
observation timestamp, since original USB arrival time is unavailable.

Typematic repeats, key releases, and periodic timer interrupts do not earn
entropy credit. The collector credits irregular keyboard, mouse, and legacy
IDE IRQ14/15 timing separately. Unknown/shared device IRQs and MSI sources are
mixed without entropy credit. It waits for 256 estimated bits (at most one per
irregular eligible event) before seeding; it logs
`random: seeded from interrupt timing` when ready. This estimate is heuristic:
scripted or observable input must not be treated as a secret entropy source.

An unattended early-boot mount still needs an available entropy source: input
normally arrives after boot-time mounts are attempted. The default QEMU UEFI
launcher uses `-cpu max`; for BIOS, pass `-- -cpu max` for immediate hardware
seeding. An unseeded pool fails the mount rather than using the guest PRNG.
There is no automatic retry of a failed boot-time SMB mount.

Linux `getrandom` uses that same entropy service for both 32-bit and 64-bit
applications, including userspace TLS libraries. Blocking requests wait for a
seeded generator; `GRND_NONBLOCK` returns `EAGAIN` while entropy is unavailable.
`GRND_RANDOM` also uses the shared generator. Unknown flags and the insecure
fallback flag are rejected, and large requests return at most 64 KiB per call.
No scheduler-PRNG fallback is exposed through this interface.
`python3 test/random_interrupts.py` checks these semantics without RDRAND on
486/PIT and UEFI/x86-64, including waking a blocked call after input seeding.
Injected input validates the waiting/wakeup path, not entropy quality.

This first implementation uses synchronous VFS operations and pumps the
network while waiting, with a three-second request timeout. VFS operations
remain serialized, so a slow server can pause other guest work until the
operation completes or times out. Failed connections are closed; reboot to
reconnect. SMB is not currently a boot-root filesystem.

The deprecated `run.sh --host DIR` shortcut and all native/serial file-sharing backends
have been removed. Configure `[smb]` mounts explicitly; the launcher does not
start an SMB server or automatically assign H:. Hosted binaries also require
disk images. Tests and compiler build actions stage inputs on private ext4
volumes; they do not install an alternative filesystem backend.

For QEMU's host-directory SMB export, the server is normally `10.0.2.4` and
the share is `qemu`. Samba must be installed on the host. For example, select
the custom network instead of the default one:

```sh
./run.sh qemu --net none -- \
  -netdev user,id=net0,smb=/path/to/shared-directory \
  -device virtio-net-pci,netdev=net0
```

The share must allow the configured authenticated account; RetroOS does not
accept a guest-only export. An explicitly configured Samba share on the host
at `10.0.2.2` is suitable for normal authenticated mounts.

## Native Qualcomm Wi-Fi bring-up

The initial native driver targets WCN7850 hw2.0, PCI `17cb:1107` (including
the Foxconn `105b:e109` subsystem). It detects the controller, recovers its
PCIe/MHI state, transfers the signed AMSS firmware through BHI/BHIE, starts
MHI IPCR channels, and discovers the WLANFW control service through QRTR.
Progress and failures are logged with a `WiFi:` prefix; `/proc/wifi` exposes
the current status. Device timeouts and malformed DMA completions stop the
transport and disable bus mastering; DMA allocations remain reserved until
reboot. The initial path uses one shared MSI vector and polls control rings;
runtime power saving is disabled. Context arrays and each DMA ring occupy
separate pages, matching x86 Linux coherent allocation placement even when a
ring is smaller than a page. The WCN7850 profile adds a 1 ms firmware settling
delay before START, following the
[OpenBSD qwx startup workaround](https://github.com/openbsd/src/blob/master/sys/dev/pci/if_qwx_pci.c).
Physical laptop log `KLOG0025.TXT` confirms AMSS/M0, successful IPCR channel
startup, and WLANFW service discovery at QRTR node 7, port 1. The preceding
build without the settling delay timed out starting channel 20.

The Wi-Fi service uses a shared radio interface. MHI boot, DMA staging, and
packet channels live in `kernel/src/kernel/drivers/mhi`; QRTR framing and service
discovery live in `kernel/src/kernel/qrtr.rs`; reusable QMI framing and bounded
transactions live in `kernel/src/kernel/qmi.rs`. Channels and service identities
are supplied by drivers. The WCN785x hardware profile owns its PCI ID, firmware
path, DMA limit, and chip-specific reset register; only WCN7850 hw2.0 is enabled.

After service discovery, the driver runs WLANFW QMI initialization: indication
registration, host capabilities, requested host memory (up to 48 MiB total),
firmware-memory-ready, target capabilities, board/regulatory data download, M3
DMA staging, and firmware-init-ready. Startup RPCs use a local QRTR port and
accept replies only from the discovered endpoint with the matching transaction
and message ID. Each wait has a 10-second deadline and a spin budget; failures
report the stage and QMI result/error in the saved kernel log. Unsupported
firmware memory types receive a null address, following ath12k. Allocated DMA
remains reserved until reboot, including on failure.

Board data is selected from `board-2.bin` using the exact PCI/subsystem IDs and
firmware chip/board IDs. Regulatory data uses the matching entry or the
bundle's `bus=pci` entry, with an external `regdb.bin` fallback if installed.
No other board's calibration data is substituted. SMBIOS board variants are not yet
parsed. The existing firmware installation already supplies `board-2.bin` and
`m3.bin`; no firmware reinstall is needed for the local WCN7850 bundle.
Physical logs `KLOG0027.TXT` and `KLOG0028.TXT` confirm the complete QMI startup:
notification registration, host capabilities, memory response/memory-ready,
target capabilities, regulatory and exact board data downloads, M3 information,
and firmware-init-ready (indication `0x0038`). Firmware reports chip 2, family 4,
board 255, SoC `0x40170200`, and version `0x1108811c`.
`KLOG0026.TXT` confirms successful indication registration and host capability
RPCs, followed by requests for 7,012,352 bytes of host DDR and 8,454,144 bytes
of calibration memory. Firmware entered SYS_ERR/RDDM after the memory response.
The current build physically aligns these buffers (and M3) to the smallest
power-of-two page order large enough for each buffer, preserving the device
address alignment guaranteed by Linux coherent DMA allocation. Their addresses
are logged before sending the memory response. Both successful physical boots
used host DDR at `0x05800000` and calibration memory at `0x06000000`, respecting
8 MiB and 16 MiB alignment respectively. The earlier page-separated MHI layout
is retained.

**This is firmware/control bring-up, not a working wireless connection.**
Radio configuration, channel/regulatory setup, scanning, association,
WPA authentication, and Ethernet data delivery are not yet implemented.
Firmware boot, QRTR discovery, and QMI firmware initialization have been
confirmed on the physical laptop. The next build adds polled CE rings, WLANFW
pipe configuration and mission mode, HTC ready/service negotiation, and WMI
service/resource initialization through unified-ready. CE, HTC, and WMI use
shared modules; WCN7850 pipe mappings and resource settings live in its hardware
profile. This stage still needs physical validation. The success marker is
`WiFi: WMI ready MAC=...`; failures log the startup stage and CE ring pointers.
`KLOG0029.TXT` confirms WLANFW pipe configuration/mission mode, CE transport,
HTC target-ready (credit size 2176), and HTT/WMI endpoint connections (1/2).
It stops on WMI service-ready parsing after service-available. The follow-up
parser accepts repeated array type tags, using the first UINT32 array as the
service bitmap, and logs startup TLV tags/lengths and RF chain count. Fixed
event fields still reject duplicates; WMI unified-ready remains unverified.
`KLOG0030.TXT` verifies that correction: service-ready reports two RF chains,
followed by extended-ready and extended-ready-2. After WMI INIT is consumed,
firmware sends memory-dump notification `0x016005` and enters RDDM (EE 3).
The next diagnostic build arms shared MHI BHIE receive vectors before HTC
startup, with the WCN7850 profile's 0x780000-byte dump capacity. On an
initialization crash, it waits for completed DMA and saves the raw bytes to
the first unused `C:\WIFI0001.DMP`, `C:\WIFI0002.DMP`, etc., flushing the file
before continuing boot. It logs capture/write failures and never treats an
incomplete transfer as a valid dump. This capture path needs physical validation;
the underlying firmware crash is still unresolved.
`KLOG0031.TXT` and `WIFI0001.DMP` confirm successful crash DMA and persistent
dump saving. The Q6-SFR section reports
`cmnos_thread_patch.c:1174:0x8Asserted in:0x1f26a9c:0x1f269ac, line#386`.
The referenced text is absent from the captured SRAM sections; its location
has not yet been resolved. Follow-up captures append QMI type-1 host DDR
(firmware paging memory), preserving the raw RDDM bytes and their offsets.
A versioned `RTWFPAGE` descriptor table and `RTWFEND1` footer record each
region's type, requested size, and physical address. Calibration buffers and
allocation padding are excluded. Inspect either dump version with
`python3 tools/inspect_wifi_dump.py /home/retroos/WIFI0001.DMP`; use
`--find TEXT` to search printable strings in each section. The firmware crash
is still unresolved; these additional bytes need another physical capture.
`KLOG0032.TXT` and `WIFI0002.DMP` verify the host DDR extension (7,012,352
bytes at physical `0x05800000`). The same line-386 assertion recurs; its
referenced text is still unresolved. Firmware's copy of the WMI INIT/resource
TLVs is present and agrees with the transmitted message.
The follow-up build adds missing packet-engine bootstrap storage: a contiguous
bank of 32,768 aligned 128-byte link descriptors with 32,767 supplied to the
WBM idle ring before HTC startup, and eight empty 2,048-entry REO destinations
after WMI service-ready and before INIT. CE and these rings now share SRNG
register setup. Hardware addresses/counts live in the WCN7850 profile. This is
partial packet-engine infrastructure; common TX/release rings, cookie
conversion, HTT ring configuration, and Ethernet delivery remain unimplemented.
Whether this bootstrap changes the firmware assertion needs a physical boot.
`KLOG0033.TXT` and `WIFI0003.DMP` show both bootstrap stages completed, with
the same firmware assertion afterward. Descriptor-pool setup did not resolve it.
The captured service-available bitmap advertises service 281 (extended
regulatory events), while our INIT host-service flag was zero. The follow-up
build implements receiving and retaining these reports, including rule groups,
DFS/bandwidth metadata, restriction flags and PSD values, and acknowledges
support with host-service bit 4 when firmware advertises service 281. It logs
the negotiated flag and country/PHY/rule count. This matches ath12k's capability
negotiation; whether it changes this crash is still unverified. Scanning and
transmission remain unimplemented; retaining regulatory data does not enable
the radio or implement channel selection policy.
`KLOG0034.TXT` and `WIFI0004.DMP` show the same line-386 assertion with
extended regulatory support negotiated. That change did not resolve the crash.
The next diagnostic build arms crash capture before a read-only WLANFW
ATHDIAG request (`0x0030`). Only firmware `0x1108811c` receives the temporary
profile read: 512 bytes at `0x01f26900`, memory type 0, covering the two reported
assertion pointers. Success logs raw words and printable strings; rejection or
a one-second timeout logs an unavailable diagnostic and continues startup.
This does not change INIT settings. Support for the request and interpretation
of that device memory address still need physical validation.
`KLOG0035.TXT` records an immediate QMI rejection (result 1, error 48),
and `WIFI0005.DMP` contains the same assertion. The temporary profile read
is now disabled; it did not reveal the assertion source.
The next build adds the common rings missing from the Linux startup sequence:
three TCL transmit queues and their WBM completions (0/2/4), software release,
RX release/error, REO exception/reinjection, and REO command/status rings.
All queues start empty; REO command slots receive sequence numbers without
publishing commands. Hardware-profile ring maps use the shared SRNG engine,
with separate DMA descriptor spans and pointer writebacks. REO aging,
fragment/BAR exception routing, and hash routing to SW1..SW4 are configured.
Ring register state is logged before INIT while the hardware is available.
This closes a startup gap, but has not been validated on the physical card
and is not an identified fix for the assertion. Cookie conversion, HTT ring
configuration, scanning, association and packet processing remain outstanding.
`KLOG0036.TXT` verifies the 12 common rings and eight REO destinations before
INIT: base addresses and sizes read back correctly, and all common queues
remain empty. `WIFI0006.DMP` still reports the same line-386 assertion, so
adding the common rings did not resolve it. Firmware and board-bundle files
installed on C: were compared byte for byte with the decompressed Linux
firmware files and match. The Linux host currently uses kernel
`7.0.0-38-generic` with `ath12k_wifi7_pci`. The saved Linux kernel journal
confirms the same chip, board and firmware version (`0x1108811c`) boot there;
it does not contain INIT packet bytes.
Offline inspection of the SRAM copy of INIT finds tags `74:28, 75:288, 0:0`
inside the HTC payload, whereas the host builder produces
`74:28, 75:288, 18:0`. An empty-array tag is present 44 bytes later in SRAM.
Firmware may have translated or consumed this copy, so this is not evidence
that the transmitted packet was malformed. The next diagnostic build appends
a snapshot of the host CE DMA allocation after RDDM completes, using private
trailer kind `0x100`. This preserves source buffers and descriptors for
comparison with the firmware-side copy without changing the startup commands.
`python3 tools/inspect_wifi_dump.py WIFIxxxx.DMP --wmi-init` locates bounded
INIT candidates in both regions and reports their TLV sequences. CE snapshots
are labeled `CE-DMA`; firmware SRAM candidates must not be treated as pristine
wire captures. This remains diagnostic, not a confirmed assertion fix.
`WIFI0007.DMP` and `WIFI0008.DMP` contain the expected complete INIT sequence
in the host CE source buffer. The differing firmware-side copy does not
establish a host serialization error. The same assertion remains.
The next implementation adds the remaining pre-INIT cookie-conversion stage:
QMI capability TLV `0x1c` supplies four fixed address/size pairs, with CMEM at
index zero. The driver validates the region before any CMEM access, allocates
256 TX and 24 RX secondary pages and driver-owned descriptor slots, and
populates and verifies the primary table while conversion is disabled.
Unused primary entries are zero. Conversion is enabled after service-ready,
before REO destinations and INIT, using WCN7850's WBM ring mask (0/2/3/4).
CMEM MMIO uses the 25-bit PCI window alias while the hardware conversion
registers retain the complete base address, including its target-bus prefix.
Converted values are bounded physical slot tokens, not unchecked CPU pointers;
future packet handling must validate both cookie and token before slot access.
Table initialization failure prevents enable and follows the existing crash
capture path. CMEM address, table verification and enable are logged.
This is required packet-engine infrastructure but has not been validated on
the laptop or established as the cause of the assertion. HTT configuration,
scanning, association and packet processing remain outstanding.
`KLOG0039.TXT` reports CMEM at `0x00113000` (20,480 bytes), verifies all
primary table entries and enables cookie conversion. `WIFI0009.DMP` still
contains the same line-386 assertion and a valid host INIT packet, so this
addition did not resolve the crash.
The installed board bundle contains two different calibration entries for
subsystem `105b:e109`: the default (88,872 bytes) and `variant=QC_5mm`
(88,824 bytes). Linux checks SMBIOS type `0xf8`, formatted length 9, for an
enabled `BDF_` variant before board lookup; RetroOS currently uses the default.
The read-only Linux helper `tools/inspect_wifi_platform.py` prints only this
Wi-Fi metadata, skipping unrelated SMBIOS records. Its result is needed to
establish whether this laptop selects a variant; neither profile is substituted
based on subsystem ID alone. The table is root-readable on Linux:

```sh
sudo python3 tools/inspect_wifi_platform.py > build/linux-wifi-platform.txt
```

The saved platform report contains one type-248 record with formatted length
17. Linux v7.0's ath12k parser requires exactly 9 and ignores that record, as
does the helper. Its result is no selected variant, so the documented Linux
selection path and RetroOS both use the default entry. There is no evidence
for switching to `QC_5mm` on this laptop.
Offline analysis of `WIFI0009.DMP` finds assertion arguments near target
address `0x0157edd8` and the original INIT size (`0x14c`) nearby. These are
raw stack candidates, not an unwound call chain or an identified bad TLV.
The assertion source pointers are not covered by the installed AMSS ELF's
loadable virtual ranges. The ELF declares ARM despite containing Hexagon
instructions; disassembly was attempted only on a temporary copy with the
machine field set to Hexagon. Installed firmware was not changed. The BIOS
check and this offline examination do not establish a fix, and no additional
hardware test build has been prepared from them.

To compare against successful Linux initialization, prepare a separate Linux
initramfs with startup tracing (from the repository directory):

```sh
sudo python3 tools/record_linux_wifi.py prepare
```

This validates disabled kprobes, reads `sk_buff` offsets from the running
kernel's BTF, and builds `/boot/initrd.img-<running-kernel>-retroos-wifi-v2`.
It does not reload the current NIC or change GRUB defaults. It installs
`/etc/grub.d/43_retroos_wifi_capture` and runs `update-grub`, adding
**Linux Wi-Fi startup capture (<running-kernel>)**. Select that entry at
the next boot. Its disk search, kernel options and any microcode initrd
come from the existing normal Linux entry. If the diagnostic image was
already prepared, rerunning `prepare` adds or refreshes just the GRUB entry.

Tracing starts before initramfs udev, using deferred module kprobes in its
own tracing instance. It records WMI command IDs and lengths, the 328-byte
WMI INIT payload when its length matches, PCI writes, QMI message IDs and
buffer capacities, and the firmware-ready wait result. QMI capacities are
not encoded message lengths. Version 2 additionally records encoded WLANFW
QMI startup requests (up to 1,024 bytes, excluding board-data downloads) at
`kernel_sendmsg`, and HTC endpoint-zero negotiation in both directions (up
to 64 bytes). Socket family and `kvec` offsets also come from kernel BTF;
connected QRTR sockets have no `msg_name`, so filtering uses the socket's
family rather than the destination argument. It stops on a successful firmware-ready wait;
the ring buffer is bounded to 4 MiB per CPU if startup fails. After Linux
starts, save the trace and kernel log:

```sh
sudo python3 tools/record_linux_wifi.py collect
```

Results go into the next unused `build/linux-wifi-trace/` or
`build/linux-wifi-trace-N/`, preserving earlier captures. Fixed-fetch padding
is discarded before writing `trace.txt`. The `packets/` subdirectory contains
binary packets and `decoded.txt` with QMI TLVs, CE/service maps, HTC credits,
connection flags and assigned endpoints. Incomplete packet sets or malformed
lengths are reported explicitly. Verify that `trace.txt` contains
`wmi_init` and a successful `ready` result, and inspect `buffer-stats.txt`
for overruns before treating the trace as complete. The setup checks shell
syntax and generated initramfs ordering; actual probe registration and a
successful boot capture require the privileged commands above. A subsequent
normal boot removes the probes. To remove the diagnostic boot option, delete
`/etc/grub.d/43_retroos_wifi_capture` and run `sudo update-grub`; the separate
diagnostic initramfs can then be deleted. The original Linux initramfs is
retained throughout.

Re-run `prepare` to install version 2 if the original diagnostic image was
already installed, then boot the same capture entry and run `collect`.
The original version-1 image and saved traces remain available. The decoder
can also run without root on an already saved trace, writing a fresh directory:

```sh
python3 tools/inspect_linux_wifi_trace.py build/linux-wifi-trace-2/trace.txt --output build/linux-wifi-decoded
```

The first successful Linux capture is in `build/linux-wifi-trace/` (Linux
7.0.0-38, same WCN7850 and firmware). It records one 328-byte INIT and
`ready result=0`, stops automatically, and reports zero overruns and dropped
events on every CPU. Comparing its payload with the original host CE-DMA
packet at physical `0x06b2f000` in `WIFI0009.DMP` finds exactly two differing
DWORDs: payload words 52 and 76, resource words 44 (`flag1`) and 68 (`flags2`).
Linux sends `0x40020` and `0x210`; RetroOS sent zero for both. Linux v7.0
`ath12k/wmi.h` and `ath12k_wmi_copy_resource_config()` identify these as
64-bit BSS channel information, ACK RSSI, RX peer metadata version 1, and
next-DTIM-count calculation. The WCN7850 profile now supplies those flags,
and a regression test checks all 73 resource words against the successful
capture (with the separately negotiated regulatory service flag excluded).
This aligns the INIT payload with observed Linux behavior; a physical
RetroOS boot is still needed to determine whether it resolves the assertion.

Physical build `c77b2778497a` was tested in `KLOG0040.TXT` / `WIFI0010.DMP`.
It still reaches the same `cmnos_thread_patch.c:1174`, line-386 assertion.
The original CE-DMA INIT packet at `0x06b2f000` now matches the captured Linux
328-byte payload byte for byte, including both corrected flags. Those flags
were missing but were not sufficient to fix startup. The comparison is saved
in `build/linux-wifi-trace/comparison-boot40.txt`. All 21 packet-engine ring
entry-size/ID configurations agree with Linux; the only capacity difference
is REO command ring 20 (Linux 256 entries, RetroOS 128). The extra `0x80` in
RetroOS's healthy ring-misc readback is hardware idle status. Neither this
capacity difference nor the already matching INIT identifies the assertion
cause. The current Linux capture has QMI IDs/capacities but does not contain
the encoded QMI or HTC negotiation payloads needed for those comparisons.

The version-2 Linux capture in `build/linux-wifi-trace-2/` contains all 15
selected QMI/HTC packets, a successful firmware-ready result, and zero dropped
events or overruns. All three outgoing HTC negotiation payloads are identical
to the original host CE buffers in `WIFI0010.DMP`. QMI registration, target CE
pipe records and service routing also agree. Linux additionally supplies 36
ordered shadow-v3 target doorbells in WLAN_CONFIG TLV `0x17` (not `0x16`).
Its resulting WLAN_CONFIG request is 517 bytes; RetroOS previously omitted
that TLV. The hardware profile now includes that map and the shared SRNG
module validates and translates its BAR aliases starting at `0x8fc`. Firmware
receives the map before mission mode; after successful mode setup and initial
CE posting, the driver redirects subsequent mapped doorbell writes through
the aliases. Target reads remain direct. The complete resulting configuration
TLVs, derived from the profile, match the Linux capture.

Other observed QMI differences remain explicit: Linux queries PHY capabilities,
enables firmware logging, and advertises MLO with a two-link topology (chip 0,
group 255, peer limit 32). RetroOS still advertises no MLO and has not implemented
that topology. The shadow-map change is a focused physical test, not proof that
the firmware assertion is resolved or that the remaining differences are safe
to ignore.

Physical build `816e05938c3a` was tested in `KLOG0041.TXT` / `WIFI0011.DMP`.
WLAN_CONFIG accepted its 510-byte body, shadow-v3 aliases were enabled, and
CE/HTC plus all WMI service-ready extensions completed. INIT still matches
Linux byte for byte, followed by the same line-386 firmware assertion. The
shadow path works far enough for control traffic but did not resolve startup.
The next diagnostic build adds Linux's previously omitted PHY_CAP query
(`0x57`, before registration) and WLAN_INI firmware-logging request (`0x2f`,
after firmware initialization and before WLAN_CONFIG). PHY count, board ID
and single-chip MLO support are logged with optional-field length validation;
no MLO capability is advertised as a result. Explicit negative QMI replies
to these optional requests are logged and startup continues; transport and
malformed-packet errors remain errors. Logging acceptance is recorded without
claiming that a firmware log stream or assertion source has been decoded.

Physical build `dae0591779b5` was tested in `KLOG0042.TXT` / `WIFI0012.DMP`.
PHY_CAP succeeds and reports two PHYs plus single-chip MLO support; board ID
is absent in that reply. WLAN_INI accepts firmware logging, but no new decoded
assertion condition appears: the same line-386 assertion follows INIT. The
next change supplies the single-chip firmware topology, gated on both the
verified WCN7850 profile and that positive PHY_CAP response. It encodes logical
chip 0, group 255, peer limit 32, link IDs 0 and 1, and the fixed-size unused
partner-chip records. The resulting complete HOST_CAP TLV body matches the
successful Linux capture, checked by a golden-packet test. Missing/negative
PHY support retains the non-MLO advertisement; out-of-range reported link
counts or invalid profile IDs are rejected. Single-chip type-8 firmware memory,
if requested, receives bounded driver-owned DMA backing and is included in
the crash trailer. This implements firmware topology bootstrap and retains
that topology with the device; multi-link association and packet processing
are still unimplemented. A physical test is required to establish whether
this remaining HOST_CAP difference caused the assertion.

Physical build `c3d3fab418ba` was tested in the new `KLOG.TXT` (preserved as
`build/linux-wifi-trace-2/retroos-topology-boot.log`). Firmware accepts the
85-byte HOST_CAP body and sends additional WMI events after INIT, including
regulatory event `0x3a003`. There is no new RDDM dump; MHI remains in mission
execution environment 2 with healthy CE/DP registers. This is evidence that
the firmware-topology change got beyond the earlier assertion, although the
host still stops before observing unified-ready.

The new failure is `WMI Packet` while parsing a regulatory event with a
312-byte fixed field and three ARRAY_STRUCT bodies of 120, 8 and 16 bytes.
The parser incorrectly required tag 18 to be unique. It now treats the first
array as the regulatory rules and preserves later arrays as bounded opaque
extensions, following Linux's positional rule-array layout. Rule counts,
frequency ranges and all raw NO_IR/DFS/indoor/PSD restrictions remain checked
and retained. Malformed extensions or invalid rules cannot replace a valid
stored report. A synthetic 476-byte packet reproduces the observed layout;
the raw event bytes were not saved in the physical log. Additional error
context records fixed fields if another regulatory validation fails.

Physical build `3d1a7cf8dcfc` was tested in `KLOG0001.TXT`. It still rejects
the regulatory report: status 0, PHY 0 of 2, country `00`, and 2/4 rules for
2G/5G. Firmware remains healthy; this is another host parser validation
failure, not a recurrence of the firmware assertion. The header summary is
insufficient to tell whether rule counts, rule contents or nested extension
encoding caused it. The next diagnostic build logs the rejected packet as
numbered little-endian DWORDs, bounded to 2,048 bytes with explicit original
and captured lengths. No regulatory checks are relaxed without the bytes.
The normal persistent boot log saves this capture automatically. Recover and
inspect it offline with a fresh output directory:

```sh
python3 tools/inspect_wifi_event.py /home/retroos/KLOG0002.TXT --output build/wifi-regulatory-event
```

The tool exports the exact WMI packet plus fixed fields, rule counts and all
array/child TLVs; incomplete, oversized or reordered captures are rejected.

Physical build `2a6a558ea50f` produced the full rejected 476-byte event in
`KLOG0002.TXT`, recovered into `build/wifi-regulatory-event/`. Its six rule
records use legacy WMI tag 608 (`REGULATORY_RULE_STRUCT`) with 16-byte extended
bodies, rather than extended tag 937. Linux's regulatory parser reads this
array by record layout and does not impose our former tag-937-only check.
All fixed fields, counts and nested extension TLVs in this packet are valid.
The shared WMI parser now accepts both documented structure IDs with the full
four-word layout and retains each rule's original tag and complete body,
including trailing fields, for future hardware/protocol extensions. There is
no PCI-ID or firmware-version quirk in this decoder. Short records still
fail rather than inventing missing restriction/PSD fields. A regression
fixture matches every byte of the captured event, and tests verify mixed
formats, additive fields and preservation of restrictions. A physical boot
must still confirm that initialization subsequently reaches unified-ready.

Physical build `218a1aede039` succeeds in `KLOG0003.TXT`, preserved at
`build/linux-wifi-trace-2/retroos-firmware-ready.log`. Both PHY regulatory
reports parse (country `00`, six rules and two extension arrays each), then
WMI READY event `0x000002` supplies a valid unicast MAC. The driver reaches
`WCN785x CE/HTC/WMI ready` and receives later WMI events through normal OS
polling before user shutdown. No startup error or firmware crash is reported.
The earlier assertion is no longer observed with the complete startup fixes;
the topology change was the first boot beyond it, and the shared regulatory
decoder fixes now allow unified-ready. Event `0x16005` also appears during
this successful boot, so that notification alone is not a crash indication.
This is the working firmware-startup baseline. Scanning, association,
authentication and packet transfer are the next development phase.

The next development build adds an automatic passive scan after startup.
Shared code in `kernel/src/kernel/wifi/scan.rs` parses beacons and probe
responses and retains up to 128 networks with BSSID, binary SSID, frequency,
estimated signal, security advertisements and complete information elements.
WMI command/event handling lives in `kernel/src/kernel/wmi/scan.rs`; the
hardware profile supplies the logical pdev and regulatory PHY. WCN7850 uses
logical pdev 0 and regulatory PHY 0, matching Linux's single-pdev model.
The scan creates a station interface, configures its NSS and wake policy,
uploads a passive channel list and requests a passive scan. Channels must
have full 20-MHz coverage in the firmware report; disabled/no-20-MHz channels
are excluded, and radar restrictions remain present. The captured world
report produces 41 channels across 2.4 and 5 GHz. This first scan path excludes
6 GHz and sends no probes or authentication frames.

After boot, wait about 25 seconds, then use `type proc/wifi` from DOS to see
scan state and networks. A completed scan also writes its results into the
automatically saved kernel log. From the Linux shell (`SH` from DOS),
`echo scan > /proc/wifi` requests another scan; an active or queued scan
rejects a duplicate request. The DOS command shell does not yet implement
file redirection. Network names are
escaped so control characters cannot affect the terminal. Requests and
completion events are matched by scan ID, requester and interface; timeouts
cancel the firmware scan. A scan failure leaves the control session intact
unless the transport itself fails. Scanning still needs a physical test;
association, authentication and packet transfer remain unimplemented.

Physical scan build `cf789bd4fe89` completes in `KLOG0004.TXT`: station
interface creation succeeds, STARTED arrives, firmware visits all 41 requested
frequencies (with interleaved 2.4/5-GHz progress), and COMPLETED has reason 0.
The reported network count is zero. This build silently discarded management
decode failures, so the log cannot distinguish missing management events
from rejected frames. Source review found an error in our receive decoder:
Linux's `ath12k_wmi_mgmt_rx_params` contains four antenna RSSI words, making
its fixed body 68 bytes, with `chan_freq` at offset 64. We had required 76
bytes and used offset 72. The correction accepts the 68-byte base layout and
additive fields, with a regression fixture in Linux's field order. Scan-end
logs now include management events received, networks decoded, ignored
frames, malformed events and queue drops; the first malformed event is
captured with bounded raw bytes. The next hardware test must establish
whether this correction exposes nearby networks.

Physical build `988116cfc5d5` in `KLOG0005.TXT` again completes all 41
frequencies successfully, but reports `management RX=0 decoded=0 ignored=0
malformed=0 queue-dropped=0`. This rules out the management decoder as the
cause of that boot's empty result: no management event reached it. The header
correction remains necessary, but was not the missing receive setup.

The next build adds the missing HTT/RXDMA bootstrap after unified-ready.
HTT version negotiation requests TCL metadata v2 and requires protocol major
3. `kernel/src/kernel/htt.rs` encodes firmware ring registration and receive
filters; `drivers/qca_dp/rx.rs` owns remote DMA head/tail pointers, rings and
a bounded pool of 8192 2048-byte receive buffers. The hardware profile supplies
ring IDs, directions, pdev IDs, sizes, return-buffer manager and descriptor
offsets. WCN7850 registers the host-to-firmware refill ring, two per-MAC
buffer rings, one exception ring and two monitor-status rings. Monitor capture
is disabled and those monitor rings remain empty. Main RX filters match
Linux's WCN7850 MPDU_START/RX_PACKET/MSDU_END selection. Compiling Linux's
`hal_rx_desc_wcn7850` declaration confirms size 400, MPDU tag offset 144,
MSDU tag offset 0 and packet-header TLV offset 272.

The shared WMI radio setup configures basic pdev parameters and profile-supplied
TX/RX chain masks. When firmware advertises RF-kill capability, the profile's
GPIO configuration is sent and radio-on is requested; physical radio-state
events are recorded, and a reported hardware-off state prevents new scans.
Scan completion logs both management counters and all remote ring pointers.
Firmware consuming a refill descriptor does not establish that packet DMA has
finished: consumed buffers remain reserved and are never reused. The initial
receive pool is finite; completion validation and recycling must be implemented
before continuous packet traffic. Association, authentication and IP packet
transfer remain unsupported. The next physical boot must validate HTT version
negotiation, buffer consumption and delivery of management frames.

Physical build `42ee1e1b9ace` succeeds in `KLOG0006.TXT`, preserved as
`build/linux-wifi-trace-2/retroos-scan-success.log`. HTT negotiates version
3.129 and an RF-kill event reports radio on. The management fixed TLV is
68 bytes, confirming the corrected receive-header layout. The passive scan
completes with reason 0: 55 management frames received and decoded, zero
ignored/malformed frames or queue drops, and 45 BSSID/frequency results across
2.4 and 5 GHz. The user's saved `WIFI.TXT` contains the same scan results.
This is the working passive-scan baseline. The combined receive bootstrap
and radio configuration enabled discovery; this test does not isolate which
individual command was decisive. Posted-buffer counts and remote-pointer
snapshots do not establish continuous packet reception or recycling.
Association, WPA authentication, validated completions/recycling and packet
transfer remain the next phase.

QEMU has no WCN7850 model; simulated protocol tests cannot
validate the real controller or its board-specific behavior.

Install locally available firmware into a persistent VM data disk:

```sh
python3 tools/wifi_firmware.py --data-image build/data.bin
```

The helper reads `ath12k/WCN7850/hw2.0` below `/lib/firmware`, unpacks `.zst`
or `.xz` files, and installs AMSS, M3, board data, and their license under
`C:\RETROOS\FIRMWARE`. It takes the launcher's disk lock. Alternatively,
`--directory /mounted/retroos-root` installs below that root's `lib/firmware`.
The kernel searches `/lib/firmware` and `C:\RETROOS\FIRMWARE`, accepting
only bounded, complete, uncompressed files.

For a normal directory-backed installation with C: at `/home/retroos`, install
the firmware on persistent C: and use the normal kernel installer:

```sh
python3 tools/wifi_firmware.py --c-root /home/retroos
tools/install_kernel.sh --prepare
sudo tools/install_kernel.sh
```

Select the **persistent** GRUB entry to keep diagnostic logs across reboot.
The protected entry keeps log writes in RAM. Logs are numbered (`KLOG.TXT`,
`KLOG0001.TXT`, etc.); use the newest file in `/home/retroos`. The live status
is also available at `C:\PROC\WIFI`, including installations with a separate
Unix root.

A self-contained native test image can be built without mounting any of the
laptop's internal filesystems:

```sh
python3 tools/build_wifi_image.py
```

The output is `build/native-wifi/retroos-wifi.img`. It includes locally
installed firmware in the GRUB-loaded RAM filesystem, so the driver does not
need USB mass-storage support after boot. This helper creates an image file;
it never flashes a USB device. Boot its default RAM session and inspect
`C:\KLOG.TXT` for the last `WiFi:` stage and register diagnostics, or
`C:\PROC\WIFI` for status. Internal disks are not mounted by its boot profile.
Firmware contents and the generated image remain local build artifacts.


QEMU live-root Codex state is separate from the Linux session: with the normal
live profile it lives in $HOME/DOS/.codex and appears as /home/retroos/.codex.
setup_codex.py preserves an existing guest login by default. If that copy has
expired while the Linux login still works, refresh only the guest cache from
Linux with:

    python3 tools/setup_codex.py --home "$HOME/DOS" --refresh-auth

The replacement is atomic, mode 0600, and refuses shared authentication
symlinks or using the source as its own destination. The source login is never
written. Project trust must name the actual mounted project path; the DOS
home does not itself contain project/RetroOS.

KLOG0218 contained an expired guest login, a project trust warning and a
managed app-server timeout. Refreshing auth and adding trust cleared the first
two errors. Direct --no-daemon startup was verified in the same 2 GiB/2 CPU
live-SMB setup; managed startup remained timing-sensitive (two failures and a
profiled success after about 62 seconds). Testing managed 0.167 did not resolve
the failure, so the original 0.163 package selection was restored.

Older guest arg0 caches contain native host symlinks into deleted package
staging directories. This Samba configuration hides the dangling entries from
metadata access; unlink returns ENOENT and rmdir returns ENOTEMPTY. The manual
known-failure //tests:linux_smb_native_cleanup preserves a small reproduction
for both Linux ABIs and also checks that live-link targets survive deletion.
No client-side kernel fix has been validated for this case. Unsuccessful VFS/
reparse-point experiments were reverted. The existing guest's obsolete cache
was moved intact under .codex/diagnostics, rather than deleted.

Evidence and startup profiles: build/ci/qemu-error-check/.

The final repaired-cache startup check reached the UI at 58.79 seconds with
profiling enabled. Generic arg0 cleanup warnings can recur even for guest MF
links; moving the old native-link cache is a migration, not a general fix.
The manual native-cleanup repro remains expected to fail. Kernel experiments
were reverted and all 538 kernel unit tests pass again.


The November 10 QEMU KVM fixes address the separate open-lock cleanup error:
ext4 now retains unlinked open inodes through its orphan chain, and SMB
removes the name immediately while retaining descriptor access. VFS prevents
an old descriptor from changing a replacement file's metadata. Replayed ext4
journals are checkpointed before the next mutation, including orphan recovery.
The native dangling-host-symlink limitation described above remains.

The same build fixes FAT writes beyond EOF (the assembler temporary-object
corruption) and implements process `kill` for both Linux ABIs. Focused KVM
regressions are `//tests:linux_temp_build`, `//tests:linux_kill`, and
`//tests:linux_open_file_cleanup`. The latter tests both ext4 and SMB and runs
`e2fsck` on the ext4 images. The ext4 modern-image unit tests cover interrupted
unlink/close and interrupted journal/orphan recovery.

Managed Codex 0.163 now starts without the ext4 arg0 cleanup warning in the
private fixture and accepts typing. This does not establish that the remaining
live-SMB startup timeout or physical-machine latency is resolved. Current
findings and artifact locations are recorded in `METAL_FINDINGS.txt`.


The KLOG0219 follow-up adds bounded, version-checked executable caching and
TCP/Unix-stream readable-notification tracking for edge-triggered epoll.
Repeated large execs no longer always reread the complete binary. A private
2 GiB/two-CPU live-tools SMB comparison reduced startup from 66.2 to 40.0
seconds after the start gate. Managed Codex also passed an actual command-tool
round trip, including verification of its output file. The model-refresh
warning and substantial remaining latency are still unresolved; neither the
cache nor the epoll fix is a claim of complete Codex compatibility.

Reproduce the matching startup fixture with:

```sh
RETROOS_PREBUILT=1 python3 test/linux_codex_native_resume.py \
  --storage smb --live-tools --memory 2048 --cpus 2 \
  --state-from "$HOME/DOS/.codex" --daemon --full-features --existing-skills \
  --screen-transport qmp --no-profile --sample-interval 0 --timeout 120
```

Build `//:boot_disk` first when using `RETROOS_PREBUILT=1`. New regression
`//tests:linux_exec_cache` checks both Linux ABIs after executable writes,
shared mappings and name replacement. `//tests:linux_epoll_network` now checks
notifications for new TCP data with old bytes still unread; the corresponding
Unix-stream case is covered by `//tests:linux_unix_socket`.


The KLOG0220 follow-up reproduces the fatal readiness error with the installed
home and normal configuration. Metadata and socket namespace edits now retain
unrelated directory caches, and new `/proc` enumerations refresh the process
list so GNU `ps` can find a newly created daemon. The full DN → COMMAND.COM →
SHELL.ELF launch now reaches readiness with that state. A separate DN launch
also executes a command through the managed server and verifies its result.
Startup still takes roughly 25–28 seconds; diagnostic-log database warnings
and further interactive latency remain under investigation.

To test the actual installed state, build `//:boot_disk`, then run:

```sh
python3 test/linux_codex_dn.py --home "$HOME/DOS" --profile
# Also submit a bounded command and verify the output file:
python3 test/linux_codex_dn.py --home "$HOME/DOS" --tools --label tools
```

This driver uses the supplied home as writable guest state, including its
existing configuration, packages and caches. It creates normal Codex sessions
and retains test output under `.codex/diagnostics`; `--tools` confirms only the
known diagnostic command if Codex asks for approval. It does not replace the
home with the private startup fixture. Artifacts are in `build/ci/codex-dn-*`.
