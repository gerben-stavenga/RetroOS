# Win16 adapters over guest USER32/GDI32

The NE USER and GDI facades contain ordinary 16-bit protected-mode code for
migrated exports. They enter the same guest Rust USER32 and GDI32 libraries used
by PE programs. The facades are linked as NE DLLs by Open Watcom and contain no
Microsoft code. The kernel maps the DLLs, establishes descriptors and binds two
far pointers per facade; it does not suspend a kernel continuation for callbacks.

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

`Retro16Config` is the private loader/assembly/Rust binding, in DWORDs:
flat data selector, TEB selector, stack cursor, active frame, descriptor table,
NE callback return IP:CS, descriptor count, stack base, read-only NE image address,
image size, and instance selector. The binding belongs to the matched boot runtime.

The adapter covers window/class creation, dispatch and nested sends, queues,
timers, focus/capture, client DCs and painting, rectangles, menus, dialogs, and
core GDI drawing. NE menu/dialog resources are converted into the shared resource
formats in the DLL. Segmented allocation, file/resource loading and remaining
unmigrated GDI/services still use native INT 83h gates. This is not complete
Win16 API or message-marshalling coverage; resources from additional NE modules,
multiple NE tasks, and unsupported controls/messages need further work.

Run the source-built NE regression programs on both CPU backends:

```
ENGINE=kvm python3 test/windows_win16.py
ENGINE=tcg python3 test/windows_win16.py
```

They check recursive far callbacks, register/stack preservation, CREATESTRUCT
conversion, nested SendMessage, queued dispatch, client dimensions, painting and
pixel readback, dialog-template conversion and numeric controls, the 16-bit
DLGPROC return convention, and process termination. No proprietary game is needed.
Windows 3.1 Minesweeper is also a local acceptance test for its resource menus,
Custom Field dialog, board resizing, flagging, revealing cells and closing.

The legacy dialog-template layout was checked against
[Wine's Win16 dialog parser](https://github.com/wine-mirror/wine/blob/master/dlls/user.exe16/dialog.c);
the resource adapters here convert formats and reuse RetroOS's existing policy.
