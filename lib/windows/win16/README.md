# Win16 adapters over guest USER32/GDI32

The NE USER and GDI facades contain ordinary 16-bit protected-mode code for
migrated exports. They enter the same guest Rust USER32 and GDI32 libraries used
by PE programs. The facades are linked as NE DLLs by Open Watcom and contain no
Microsoft code. Core NE facades load exclusively from
`C:\RETROOS\WINDOWS\SYSTEM`; application-local copies cannot override them, and
a missing runtime is an error. Other dependencies retain application-local
lookup (for example, a game-supplied COMMDLG.DLL). The kernel maps the DLLs,
establishes descriptors and binds two far pointers per facade; it does not suspend a kernel continuation for callbacks.

```
NE caller -> USER.DLL / GDI.DLL -> USER32 Rust adapter -> shared USER32 / GDI32
                                          |
                                          +-> far call to NE application
```

`bridge.inc` saves the NE caller's registers and segment registers on its original
16-bit stack. `Retro16Enter` in `user32.asm` switches to flat segments and a separate
256 KiB guest stack before calling Rust. `Retro16Return` is the reverse callback
entry. Every nested call has its own saved frame. The stack cursor is saved and
restored around callbacks; no suspended Rust frame is overwritten by reentry.
This is currently one NE task per process, not support for concurrent Win16 tasks
sharing the same adapter state.

The saved NE frame has the following byte offsets:

| Offset | Value |
| --- | --- |
| 0, 2, 4, 6 | GS, FS, ES, DS |
| 8..39 | PUSHAD registers (EAX at 36, EDX at 28) |
| 40 | EFLAGS |
| 44 | Near return into the export stub |
| 46 | Adapter operation |
| 48 | Application's far return IP:CS |
| 52 | Pascal arguments, last argument first |

Rust adapters validate segmented data pointers against a read-only descriptor
base/limit table and widen arguments and structures. Callback scratch structures
live below the suspended NE frame, above the callback's stack. Creation, text,
window-position and command messages translate their layouts at the boundary.
Window procedures return DX:AX; dialog procedures return BOOL in AX only.

Native handles below 0x8000 retain their values. Larger shared handles (notably
menus and stock objects) have process-local 16-bit aliases. Registered NE
procedures use a separate token table; those tokens are recognized at the shared
USER callback boundary and are never invoked as flat function addresses.
Conversely, shared control procedures returned to Win16 use opaque tokens;
CallWindowProc translates messages back to the shared procedure, and SetWindowLong
can restore it. Native procedures are never interpreted as segmented addresses.

`Retro16Config` is the private loader/assembly/Rust binding, in DWORDs:
flat data selector, TEB selector, stack cursor, active frame, descriptor table,
NE callback return IP:CS, descriptor count, stack base, read-only NE image address,
image size, and instance selector. The binding belongs to the matched boot runtime.

The adapter covers window/class creation, dispatch and nested sends, queues,
timers, focus/capture, client DCs and painting, rectangles, menus, dialogs, and
core GDI drawing. NE menu/dialog resources are converted into the shared resource
formats in the DLL. NE LoadBitmap uses the same bounded DIB decoder as PE, including
RLE4/RLE8 resources; bitmap decompression stays outside the kernel. Segmented allocation, file/resource loading and remaining
unmigrated GDI/services still use native INT 83h gates. This is not complete
Win16 API or message-marshalling coverage; resources from additional NE modules,
multiple NE tasks, and unsupported controls/messages need further work.

Run the source-built NE regression programs on both CPU backends:

```
ENGINE=kvm python3 test/windows_win16.py
ENGINE=tcg python3 test/windows_win16.py
```

They check recursive far callbacks, register/stack preservation, CREATESTRUCT
conversion, nested SendMessage, queued dispatch, initial size notifications,
maximize/restore geometry, WINDOWPOS forwarding, shared control subclassing,
window words, scrollbar range/position and drag notifications, client dimensions, painting and
pixel readback, dialog-template conversion and numeric controls, the 16-bit
DLGPROC return convention, and process termination. No proprietary game is needed.
Windows 3.1 Minesweeper is also a local acceptance test for its resource menus,
Custom Field dialog, board resizing, flagging, revealing cells and closing.

The legacy dialog-template layout was checked against
[Wine's Win16 dialog parser](https://github.com/wine-mirror/wine/blob/master/dlls/user.exe16/dialog.c);
the resource adapters here convert formats and reuse RetroOS's existing policy.

The shared bitmap decoder has host tests for encoded runs, absolute packets and
padding, delta moves, row orientation, scaling, and malformed input:

```
bazelisk test //lib/windows/user32:bitmap_test --platforms=@platforms//host
```

Castle of the Winds is a local acceptance test for maximizing its initially
zero-width Startup window and displaying its RLE4 title banners. This does not
assert complete gameplay compatibility.

Shared USER draws checkbox/radio indicators, group-box frames and scrollbar
controls. Shared GDI implements Rectangle using the kernel's existing pixel-fill
and polygon primitives; stock brushes/pens preserve their types and null behavior.
Win16 WM_CTLCOLOR is translated to the corresponding Win32 control-color message.
The Win32 callback suite checks radio grouping, transparent group-box interiors,
and rectangle brush/pen behavior.

`WIN87EM.DLL` supplies ordinal 1 (`__FPMATH`) as guest x87 code for
initialization, control/status, rounding, integer conversion, and coprocessor
presence. The register-call operation numbers were checked against
[Wine's WIN87EM interface](https://github.com/wine-mirror/wine/blob/master/dlls/win87em.dll16/win87em.c).
This is not a software 8087 emulator; exception callback delivery and the
save/restore/info exports are not implemented. The `fpmath` NE regression
checks arithmetic, control-word restoration, conversion, and stack balance.

Civilization for Windows now binds its imports and creates its custom dialogs.
The adapters include huge-buffer memory/file operations, palette entries,
indexed bitmap uploads/blits, and the protected-mode BIOS clock. Shared GDI
retains uploaded indices for palette conversion; composed bitmap contents are
preserved when subsequently used as a blit source. Palette changes do not yet
recolour pixels already drawn to a window.

MMSYSTEM reports sound/MCI services unavailable, and COMMDLG returns a dialog
initialization error. External font-resource loading and enumeration are also
unimplemented. These are failure-reporting compatibility exports, not working
multimedia or common-dialog implementations.

Local KVM acceptance reaches Civ's main menu, completes new-game setup, and
reaches the opening capital-founding prompt. Palette rendering still has
inaccuracies, and paths such as GetBitmapBits and FrameRect remain incomplete.
The native presentation path still shows only the foremost top-level window,
so Civ's separate Status window hides its map instead of composing both.
This is not a complete gameplay acceptance test.
Civilization II additionally imports video and AVI libraries.

The `civ_apis` NE regression covers huge copies across a selector boundary,
locked global-memory release, NE segment allocation padding, bitmap updates and
two-stage palette blits, custom dialog class forwarding through DefDlgProc, non-keyboard dispatch through
IsDialogMessage, separate DIB headers/palettes, BIOS clock advancement,
optional-service failure results, and guest stack balance. Run it with the
other Win16 tests using `ENGINE=kvm python3 test/windows_win16.py` or
`ENGINE=tcg python3 test/windows_win16.py`.
