# Windows runtime tests

The handwritten Windows DLLs were checkpointed in commit `e00da4b7` and removed.
The runtime now bundles pinned Wine 11.0 PE DLLs, including a source-built Wine NTDLL, and the
RetroOS host-service DLL, built under `lib/wine`.

Build the runtime with `bazelisk build //lib/wine:runtime`. Every Windows test
runner installs that same archive rather than selecting its own DLL subset.

`ENGINE=kvm python3 test/wine_boundary.py` exercises upstream Wine RTL,
forwarded DLL imports and the RETROOS.DLL kernel boundary. It also exercises
reservation, commit/recommit, decommit/recommit zeroing, release/reuse, and
Wine heap allocation and growth to 1 MiB. `ENGINE=tcg` runs
the same test through the interpreter backend. It also checks that NTDLL's
imports target RETROOS.DLL and that its code contains no host syscall entries.

`test/windows_ntdll.py` remains the full NT loader acceptance test, covering
initializers, delay loading, failure hooks and rollback. It is not replaced
by the boundary test; full Wine process initialization is still being ported.

The existing Win32 and Win16 application tests remain acceptance targets for
the port. They do not currently pass: the NT runtime, WIN32U backend and Wine
WOW integration are incomplete. Missing imports fail explicitly; they never
fall back to the retired kernel export table.

Wine Win16 adapters are PE modules with 16-bit export metadata, not standalone
NE replacement DLLs. Their original filenames are preserved in the bundle.

The initial memory backend reserves in 0x01000000–0x10000000, excluding mapped
images and existing reservations, to avoid DLL slots and the legacy Win16 heap.
It supports current-process reserve/commit/decommit/release, with read/write/execute
page permissions. Remote-process allocation, ZeroBits constraints, guard pages,
committed PAGE_NOACCESS and whole-region size-zero decommit are not implemented;
they return explicit errors. Full-address-space allocation, protection/query
services and process bootstrap remain porting work.

`bazelisk test //kernel:wine_ne_test --platforms=@platforms//host` checks the
embedded NE descriptors in the six bundled Wine Win16 modules, including
WIN87EM. NE dependency loading recognizes Wine's EXE16/DLL16 filenames,
loads and relocates the owning PE, and copies the relocated embedded segments
with their 16/32-bit selector attributes. Dynamic-load failures roll back newly
mapped PE owners too. Wine modules are not sent through the retired private
Retro16 ordinal ABI: application execution remains blocked until Wine's PE
initializers, per-thread WOW state and far-call relay targets are set up.
