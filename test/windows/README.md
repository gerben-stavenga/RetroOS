# Windows runtime tests

The handwritten Windows DLLs were checkpointed in commit `e00da4b7` and removed.
The runtime now bundles pinned Wine 11.0 PE DLLs, including a source-built Wine NTDLL, and the
RetroOS host-service DLL, built under `lib/wine`.

Build the runtime with `bazelisk build //lib/wine:runtime`. Every Windows test
runner installs that same archive rather than selecting its own DLL subset.

`ENGINE=kvm python3 test/wine_boundary.py` exercises upstream Wine RTL,
forwarded DLL imports and the RETROOS.DLL kernel boundary. It also exercises
reservation, commit/recommit, decommit/recommit zeroing, release/reuse, and
Wine heap allocation and growth to 1 MiB. The probe also checks registry value
creation/query/deletion, atom reference counts, event waits/timeouts, native file
reads/position/close, directory masks/restarts, file metadata, read-only and PE
image sections, memory queries, window-station/desktop/class lifetimes, TLS clearing,
LDT selectors beyond index 2047, and read-only shared-session view lifetimes. `ENGINE=tcg` runs
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
they return explicit errors. Full-address-space allocation and complete process bootstrap remain porting work.
Basic memory queries cover tracked reservations, images and stacks. File sections
currently snapshot file contents; shared writable file mappings are not supported. Protection changes and TLS-slot clearing are implemented.
Win16 allocations start at 64 MiB to leave its NE segment arenas intact.

`bazelisk test //kernel:wine_ne_test --platforms=@platforms//host` checks the
embedded NE descriptors in the bundled Wine Win16 modules, including
WIN87EM. NE dependency loading recognizes Wine's EXE16/DLL16 filenames,
loads and relocates the owning PE, and copies the relocated embedded segments
with their 16/32-bit selector attributes. Dynamic-load failures roll back newly
mapped PE owners too. Wine modules are not sent through the retired private
Retro16 ordinal ABI. The source-built KRNL386 exposes Wine's own relay assembly;
the loader patches CALLFROM16 targets, provides TEB/PEB and separate stacks,
and creates Wine's LDT-copy layout. Startup creates the Wine heap and runs PE
initializers before entering Wine's NE loader. The initial task follows winevdm's
GDI/USER/MMSYSTEM setup and creates a Wine TDB/TIB with its startup event. Runtime
DLL loads use image-section mapping, with relocation and import binding in Wine.
The process receives its inherited environment and a valid TEB conversion buffer.
Source-built WIN32U contains Wine's drawing and windowing implementation as PE
code. Desktop roots have shared USER handles, class lifetimes and window properties.
Client objects such as menus and icons use typed, generation-checked handles.
The callback boundary stays in RETROOS.DLL: it calls Wine's own dispatcher and
handles NtCallbackReturn with a per-thread, nested userspace continuation.
Return data is copied before leaving the callback stack. The boundary probe checks
nested and ordinary returns, no-active-callback errors, window properties and
USER handle ownership/double frees on KVM and the interpreter.
Civ now passes the desktop, property, callback and client-handle boundaries,
window enumeration, cursor updates, region queries and hit-testing. Application
windows retain their classes, extra bytes, titles, tree relationships and regions;
destroying a window also removes its descendants, timers and compositor snapshot.
WIN32U installs the RetroOS display adapter during DLL attachment. It reports a
640x480 virtual display and copies dirty rectangles from Wine's 32-bit software
surfaces into compositor-owned RGB buffers. Position, visibility and destruction
use the existing desktop compositor. Layered and nonrectangular surfaces remain
unsupported. Window/message services remain incomplete; this
is not yet a successful gameplay test. Update-region queries, redraw invalidation,
paint queue wakeups and BeginPaint-style validation now share desktop window state.
The boundary probe checks WM_PAINT, short-buffer retry without losing damage,
validation, and caret position/visibility/state. Ordinary windows correctly report
that they have no layered attributes; layered rendering remains unsupported.
Foreground activation now publishes the desktop's input locator and updates the
shared foreground/active/focus/capture fields. Destruction clears those handles;
owned windows track their last active popup. Wine remains responsible for its
activation callbacks. Cross-process activation and attached input queues remain
unsupported. Native threads now support current-process creation (including
suspended creation), resume, termination, basic/last-thread queries and waits.
Each owns a stable TEB and guarded stack; closed, exited contexts release their
private mappings. Wine handles TLS/FLS and DLL thread attach/detach in userspace.
The boundary test checks a suspended worker, scheduling, TEB/last-error isolation,
return/exit status and handle closure on KVM and the interpreter. Remote thread
creation, APC delivery and general suspend/context operations remain unsupported.
Wine address waits use per-thread sticky alerts: alerts preceding a wait are
retained, repeated alerts coalesce, and waiting consumes one alert. The boundary
probe covers zero-timeout polling, invalid thread IDs and a worker waking its
parked parent.
Paint/timer messages use Wine's MSG_POSTED type (checked against its headers),
rather than being misclassified as cross-process sends. General-protection faults
now enter Wine SEH on the thread's flat stack. NtContinue restores user integer,
segment and control state; interrupted FPU state is preserved across handlers.
The probe exercises an actual selector fault and handler-directed continuation.
This is not full exception support: page-fault delivery, floating-point context
editing, alertable continuations and unhandled-exception policy remain incomplete.
The KVM Civ run now survives Wine's Win16 relay selector-recovery path and stays
running, including Win16 lock contention through the alert-wait primitive, but
the intro now draws its MicroProse presentation text using CIVFONTS.FON.
Gameplay is not verified. WIN32U now links FreeType as PE code and maps fonts
through NT file/section services. The runtime includes Wine's redistributable
TrueType fonts. `python3 test/wine_fonts.py` checks GDI font selection, nonzero
text metrics and nonempty glyph rasterization (`ENGINE=tcg` selects the interpreter).
PE and NE use the same Wine PEB/module/locale bootstrap before DLL attach; the
initial thread also receives an initialized activation-context stack.
Win16 and Win32 startup share normalized process strings, including the trailing
backslash Wine requires in the current directory. Civ can now open its resource
files relative to its game directory; the probe checks this from a non-root path.
Native event waits park the guest continuation; the kernel's existing input/timer
service checks wakeups without an INT polling loop. Interpreter idle time advances
separately from retired instructions, so parked-thread timeouts also expire.
Alertable object waits/APCs remain unsupported. The boundary probe also verifies process queries and
mapped Wine locale/code-page data on both execution backends. The TEB allocation
includes Wine's trailing debug-string storage and preserves it when switching
threads; the probe checks that these strings cannot overwrite the PEB lock.
Thread contexts keep guest TEB addresses rather than inline TEB buffers, and the Windows event handler
is kept out of the shared dispatcher by an inlining boundary. This prevents
Windows-only scratch space from exhausting the DOS/SMB kernel stack.

The native boundary probe also exercises synchronous file creation, write/seek/read,
EOF changes and flushing; unnamed semaphore counts and recursive mutant ownership;
registry key metadata, symbolic links, modification timestamps, value
enumeration/alignment and deletion; and thread/window
timer queue wakeups with peek/remove/cancel behavior. It also checks application
window creation/destruction, extra bytes, positioning, shaped regions, hit-testing,
Unicode title truncation, reparenting cycle rejection, monitor generations,
thread-input locators and cursor clipping. Graphics transport unit tests cover
pixel conversion, partial updates, resize and lifecycle. Mixed wait-all acquisition is tested
in the kernel unit tests. Registered-message atoms use the USER namespace; their
protocol tests cover string names and truncated name replies. Named synchronization
objects and cross-process sent-message delivery remain incomplete. Window occlusion,
topmost ordering and repaint invalidation are not yet complete.

Run `python3 test/wine_backend_audit.py --output tmp/wine-backend-audit.json`
after building the runtime to inventory the pinned host imports and server requests.
An adapter's presence is not a claim that every information class or option works.

Keyboard input now enters Wine hardware queues instead of the former personality
message list. Focused queues receive virtual keys, scan/extended/repeat/transition
bits and timestamps; `accept_hardware_message` consumes the event and advances
thread keyboard state. Async state is published separately. Queue wake masks,
no-remove peeks and posted messages support Wine's own `TranslateMessage` path.
The kernel does not synthesize WM_CHAR. Mouse input and attached input queues
still need integration.

`python3 test/wine_keyboard.py` exercises a Win32 window with make/repeat/break,
Shift+A, extended arrows, async press-bit consumption, no-remove peeks, and
character messages. `WIN16=1 python3 test/wine_keyboard.py` checks real NE window
input and character translation through Wine's Win16 adapters. Set `ENGINE=tcg`
to run either probe with the interpreter instead of KVM.
