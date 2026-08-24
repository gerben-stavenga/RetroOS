# RetroOS graphical substrate

RetroOS has one graphical mechanism and multiple graphical personalities.  The
mechanism does not define a desktop appearance, widget set, message loop, or
native window API.

The primitive is an owned presentation node:

```text
presentation node
├── parent and stacking order
├── geometry and clipping
├── input region and endpoint
├── opaque content identity
└── visibility and opacity
```

Windows USER/GDI and OS/2 PM/GPI project their native object, messaging, paint,
and drawing semantics onto these nodes.  A Linux terminal is a native RetroOS
window connected to a Linux PTY; later, Wayland can provide Linux graphical
surfaces without introducing a Linux desktop.  DOS does not call a window API:
its virtual VGA produces content that can occupy a node or be promoted to an
entire output.

The first implementation is `kernel::gui::Scene`.  It establishes:

- generation-tagged node identities so stale personality handles cannot alias;
- hierarchy, local geometry, stacking, clipping, and hit testing;
- separate visual content and input regions;
- endpoint ownership; and
- atomic state transactions.

`SurfaceId` is the stable content identity. A producer transfers a completed
owned `SurfaceBuffer` to `Desktop::commit_surface`; width, height, stride,
format, and pixel storage become visible atomically, and the previous buffer is
returned for reuse. The lower-level `PixelBuffer` remains the borrowed view used
inside one composition. `Scene` performs stacking, clipping, nearest-neighbour
scaling, format conversion, and global opacity into the display shadow. The
Linux terminal is the first producer using this route: its native 720x400
surface is independent of the physical output format and is attached to a
presentation node before publication. The existing display boundary still
paints the system OSD over the completed scene.

The event loop owns one `WindowManager`, which in turn owns the retained
`Desktop`. `Presentation::{Desktop, Fullscreen(WindowId)}` makes output policy
explicit instead of deriving it from which personality happens to hold a
display token. Each thread is currently one graphical endpoint with one primary
`WindowId`; Windows and OS/2 can later register multiple native top-level
windows without changing the focus or presentation operations. A
`PresentationKey` gives every retained role (terminal, DOS VGA scanout, later a
native child/top-level surface) a stable node within that endpoint.

Every visible endpoint participates in composition and pointer hit testing.
Keyboard focus is stored separately and does not destroy, hide, translate, or
suppress the other personalities' retained window state. Until personalities
supply native window positions, top-level presentations form an overlapping
stack at the origin, and focusing an endpoint raises its windows to the front.

The OSD is a temporary system overlay, not the owner of window state. Sound,
Disk, and Debug operate over either presentation. Every primary window retains
its own windowed/fullscreen preference. The Windows selector restores the
selected window in that saved mode; a separate Fullscreen/Window action changes
the focused window's preference, and Kill task follows normal process teardown.
An ordinary OSD close returns a borrowed fullscreen scanout lease, while a
selection or mode change transfers that lease according to the destination.
Opening and closing the OSD from the desktop never creates such a lease.

State-only DOS VGA is the second producer. Its completed packed scanout is
attached at the VGA mode's native width and height as opaque content to the DOS
endpoint before the OSD/display boundary. It uses the same fused row rasterizer
as direct scanout with a horizontal stretch ratio of one. Fullscreen native VGA
deliberately remains outside the compositor while its window has a direct
scanout lease;
emulated fullscreen GOP scanout keeps its fitted-width stretch and pixel-format
translation fused in that rasterizer. The modes therefore differ in presentation
policy, not in the VGA device model.

Pixel allocation, rendering commands, buffer synchronization, decorations,
widgets, focus policy, and personality message semantics remain deliberately
outside the scene. They should be added only when Windows and OS/2 experiments
show which shared mechanism is actually required.
