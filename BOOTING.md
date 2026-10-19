# Booting RetroOS with GRUB

GRUB supplies the kernel and two ordinary configuration files: `BOOT.INI`
for bundle backing and mounts, and `RETROOS.INI` for user settings.

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

On the default ext4 Linux-root installation, C: is `/home/retroos` and the
Linux filesystem supplies `/`, `/bin` and `/usr/bin`. A separate FAT or
ext4 data volume uses the bundled BusyBox root unless a Linux root is
explicitly selected with `--root-uuid`. The RetroOS C: tree is identical.
Unix command aliases use the same link manifest on both filesystems.

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

`C:\RETROOS\SHELL.ELF` starts a Linux shell session. It supplies `PATH` with
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

Names are case-sensitive. Shell defaults fill missing values; explicit values
are preserved. The kernel supplies Linux entry settings to ELF launches and
does not export the DOS `[environment]` into Linux processes.

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
a process runs or its blocked I/O is polled; the foreground process scheduler
does not yet preempt a child to run a background parent’s timeout handler. `python3 test/linux_xmm_context.py` checks SIMD preservation and
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

Directory identities grow as needed rather than limiting all processes to 32
open directories. The proc-fd test holds 48 directory descriptors open and
checks complete 300-entry listings on ext4 and SMB. Serial `trace fs` records
Linux filesystem metadata calls while excluding clock and futex noise.
The same regression creates and removes trees beyond 256 bytes and exercises
rename, chmod, symlink and unlinkat there. Path mutations use the VFS path
limit and reject overflow rather than silently changing a truncated path.

The helper defaults to `MALLOC_ARENA_MAX=2`, one loading thread, one globbing
thread (`--legacy_globbing_threads=1`) and one build job. Java uses its normal
process-spawn mechanism. This fits the current 3 GiB address space and 64-descriptor process
limit; Bazel's separate default globbing pool uses 100 threads.
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
The existing runtime can remain read-only: Bazel ignores `EROFS` when
updating its directory's last-use timestamp. Returning `ENOSYS` for this
operation previously made that optional update fatal. The guest cache and
outputs remain writable. `python3 test/linux_timestamps.py` checks 32/64-bit
Linux stat layouts, file/directory descriptors, ext4 links, and persistent
SMB timestamp updates. Linux `utimensat` uses shared VFS mount policy and
backend updates, including `UTIME_NOW`, `UTIME_OMIT` and no-follow semantics.
Existing timestamps retain one-second precision; Linux `statx` reports
unsupported access/change timestamp reads as unavailable.

File mappings currently use eager copies. Writable shared file mappings return
`ENODEV`; accepting them silently discarded linker output. Mapping failures leave an
existing `MAP_FIXED` destination intact. `python3 test/linux_rustc.py` compiles,
links and executes a native Rust program, checking its ELF header and output.
The proc-fd test covers private-copy isolation and rejected writable shared mappings
through both Linux ABIs on ext4 and SMB.

To expose the locally installed native Codex executable and seed its separate
RetroOS login, run as your Linux user:

```sh
python3 tools/setup_codex.py
```

This installs links under `/home/retroos/bin` for Codex and its code-mode
helper, bypassing the npm Node launcher. It copies saved CLI authentication
into a private `/home/retroos/.codex` only when no RetroOS login exists.
Existing login state is preserved. After installing the updated kernel and
runtime, start `SHELL.ELF` and run `codex --version` or `codex exec`.
The same setup is used with live QEMU files and the physical-machine root.

Interactive Codex 0.163.0 has returned `Hello from interactive Codex on
RetroOS.` in the actual QEMU/KVM terminal, with a prompt entered through the
guest keyboard and the assistant reply verified from the terminal grid.
From `SHELL.ELF`, the tested response-only configuration is:

```sh
codex --no-daemon --disable apps --disable shell_snapshot
```

The default background server still requests the unsupported
`clone(CLONE_VM | CLONE_VFORK | SIGCHLD)` process-spawning mode. The test uses
the in-process server and disables Apps and shell snapshots; model-generated
tool execution and the normal daemon mode are not covered by this result.

Run `python3 test/linux_codex_interactive.py` to reproduce the interactive
request with a private copy of saved authentication, a separate temporary home,
and live SMB files. It retains terminal text and a QEMU screenshot under
`build/ci/codex-interactive`, then removes the private login. Since SMB follows
host symlinks without exposing their target bytes, this test invokes the native
package entrypoint explicitly; metal uses the ordinary `~/bin/codex` link.

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

## QEMU networking

The QEMU launchers enable **VirtIO user networking** by default. No TAP
device or host bridge is needed. Use `--net none` to disable it:

```sh
./run.sh qemu --net virtio
./run.sh qemu --net none
```

RetroOS discovers a VirtIO 1.0+ PCI Ethernet interface and obtains its IPv4
address, default gateway and DNS servers by DHCP. QEMU normally assigns
`10.0.2.15`, with the host reachable at `10.0.2.2`. DHCP supplies a volatile
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
their modern PCI interface. Legacy-only VirtIO, other NIC drivers, IPv6,
static addressing, raw sockets, and DOS/OS2/Windows network APIs are not implemented.
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
`home/retroos`, then unmounts it. Installation also creates the `retroos`
group when needed. With no supported
data volume, the RAM module supplies C:. Use `--c-ram` to choose this explicitly.
For ext4, add `--c-dir=/path/on/volume` during preparation to use a different
C: directory; the installer creates that directory and passes the same path
through the INI mount configuration. The default is `/home/retroos` on the selected ext4 volume.
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
A FAT C: normally uses `path=/home/retroos`, `drive=C`, and `subdir=/`.
An ext4 C: can use `subdir=/home/retroos` with a matching `grant` directory.
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
`/home/retroos` on that filesystem. INI layouts mount only their listed sources. Without `ram-overlay`,
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
On a Unix/ext4 root, `C:` remains `/home/retroos` even if that directory is
missing; it never silently falls back to `/`. Explicit C-drive overrides
still take precedence. FAT root modules use the same mapping as physical FAT.

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

USB input currently supports xHCI controllers and directly attached HID boot
keyboards and mice, including composite devices that expose both interfaces
(such as some KVMs). Boot interfaces are switched to boot protocol; a legacy
report-ID keyboard layout is also supported for certain gaming keyboards.
Each of up to four controllers can retain two devices with at most two keyboard
endpoints and one mouse endpoint. Input devices must be connected at boot.
External USB hubs and their downstream devices, hotplug, EHCI/OHCI/UHCI,
USB game controllers, and general HID report-descriptor parsing are not yet
supported. A KVM that exposes a hub may therefore need a dedicated keyboard
or mouse emulation port. In KLOG, `keyboard ready` / `mouse ready` means
endpoint setup succeeded; it does not confirm that input reports arrived.

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

The deprecated `run.sh --host DIR` shortcut and its QEMU serial HostFS bridge
have been removed. Configure `[smb]` mounts explicitly; the launcher does not
start an SMB server or automatically assign H:. Low-level hosted binaries
retain their native-directory option for test fixtures and build tooling;
it is separate from network filesystem support.

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
