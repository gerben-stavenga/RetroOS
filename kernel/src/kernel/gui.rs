//! Personality-neutral windowing mechanisms.
//!
//! This is deliberately not a widget toolkit or a desktop policy.  A Windows
//! personality may interpret a node as an HWND, OS/2 as a PM window, Linux as
//! a Wayland surface, and DOS as a virtual display head.  The kernel only sees
//! an owned hierarchy of rectangular presentation nodes with opaque content
//! and an input endpoint.
//!
//! Nodes are born invisible.  A personality can construct one, then atomically
//! attach content, establish geometry, and reveal it with [`Scene::commit`].
//! This is the same boundary a compositor needs: incomplete state is never
//! observable by rendering or hit testing.

use alloc::vec::Vec;

/// The personality server or session that receives input for a node.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct EndpointId(pub u32);

/// Stable identity of a producer's submitted image buffers.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct SurfaceId(pub u64);

/// Stable surface role within one personality endpoint.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct SurfaceKey(pub u64);

/// Stable presentation role within one personality endpoint.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct PresentationKey(pub u64);

/// Stable identity of a top-level window as understood by the window manager.
/// The first personality adapters expose one primary window per endpoint;
/// native Windows/OS/2 personalities can later allocate additional ids.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct WindowId(pub u64);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Presentation {
    Desktop,
    Fullscreen(WindowId),
}

/// Presentation preference retained independently for each top-level window.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WindowMode {
    Windowed,
    Fullscreen,
}

/// Borrowed view of one completed image buffer.
#[derive(Clone, Copy, Debug)]
pub struct PixelBuffer<'a> {
    pub width: usize,
    pub height: usize,
    pub stride: usize,
    pub format: vga::PixelFormat,
    pixels: &'a [u8],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BufferError {
    InvalidFormat,
    InvalidStride,
    TooShort,
    Overflow,
}

impl<'a> PixelBuffer<'a> {
    pub fn new(
        width: usize,
        height: usize,
        stride: usize,
        format: vga::PixelFormat,
        pixels: &'a [u8],
    ) -> Result<Self, BufferError> {
        if !valid_format(format) {
            return Err(BufferError::InvalidFormat);
        }
        let row_bytes = width
            .checked_mul(format.bytes_per_pixel as usize)
            .ok_or(BufferError::Overflow)?;
        if stride < row_bytes {
            return Err(BufferError::InvalidStride);
        }
        let required = stride.checked_mul(height).ok_or(BufferError::Overflow)?;
        if pixels.len() < required {
            return Err(BufferError::TooShort);
        }
        Ok(Self {
            width,
            height,
            stride,
            format,
            pixels,
        })
    }
}

#[derive(Clone, Copy, Debug)]
pub struct Content<'a> {
    pub id: SurfaceId,
    pub buffer: PixelBuffer<'a>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ComposeError {
    InvalidOutputFormat,
    Overflow,
}

/// Generation-tagged handle.  Destroying and reusing a slot cannot make a
/// stale personality handle refer to a different window.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct NodeId {
    slot: u32,
    generation: u32,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Point {
    pub x: i32,
    pub y: i32,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Size {
    pub width: u32,
    pub height: u32,
}

/// Half-open rectangle: the right and bottom edges are outside.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Rect {
    pub x: i32,
    pub y: i32,
    pub width: u32,
    pub height: u32,
}

impl Rect {
    pub const fn new(x: i32, y: i32, width: u32, height: u32) -> Self {
        Self {
            x,
            y,
            width,
            height,
        }
    }

    pub fn contains(self, point: Point) -> bool {
        let px = i64::from(point.x);
        let py = i64::from(point.y);
        let left = i64::from(self.x);
        let top = i64::from(self.y);
        px >= left
            && py >= top
            && px < left + i64::from(self.width)
            && py < top + i64::from(self.height)
    }
}

/// Local coordinates in which a node accepts input.  Visual content and input
/// are independent: an invisible-sized input proxy or a click-through visual
/// node requires no special case in the compositor.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum InputRegion {
    Bounds,
    Empty,
    Rects(Vec<Rect>),
}

impl InputRegion {
    fn contains(&self, point: Point, size: Size) -> bool {
        match self {
            Self::Bounds => Rect::new(0, 0, size.width, size.height).contains(point),
            Self::Empty => false,
            Self::Rects(rects) => rects.iter().any(|rect| rect.contains(point)),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Node {
    pub owner: EndpointId,
    pub parent: Option<NodeId>,
    /// Position in parent coordinates and the node's local extent.
    pub geometry: Rect,
    /// Optional local clip applied to this node and its descendants.
    pub clip: Option<Rect>,
    pub input: InputRegion,
    pub content: Option<SurfaceId>,
    pub visible: bool,
    /// Reserved for composition; it deliberately does not change hit testing.
    pub opacity: u8,
    children: Vec<NodeId>,
}

impl Node {
    pub fn children(&self) -> &[NodeId] {
        &self.children
    }
}

#[derive(Clone, Debug)]
struct Slot {
    generation: u32,
    node: Option<Node>,
}

#[derive(Clone, Debug, Default)]
pub struct Scene {
    slots: Vec<Slot>,
    /// Back-to-front order.  Child arrays use the same convention.
    roots: Vec<NodeId>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Hit {
    pub node: NodeId,
    pub endpoint: EndpointId,
    pub local: Point,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SceneError {
    StaleNode(NodeId),
    NotOwner(NodeId),
    InvalidParent(NodeId),
    Cycle,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Binding {
    endpoint: EndpointId,
    key: PresentationKey,
    node: NodeId,
}

#[derive(Debug)]
struct Surface {
    owner: EndpointId,
    key: SurfaceKey,
    id: SurfaceId,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SurfaceError {
    Unknown(SurfaceId),
    NotOwner(SurfaceId),
    Exhausted,
}

/// Event-loop-owned graphical state.
///
/// Every personality retains its complete node tree and every visible endpoint
/// participates in composition and pointer hit testing. Keyboard focus is an
/// independent endpoint selection, not visibility or repaint policy.
#[derive(Debug, Default)]
pub struct Desktop {
    scene: Scene,
    keyboard_focus: Option<EndpointId>,
    pointer: Option<Point>,
    bindings: Vec<Binding>,
    surfaces: Vec<Surface>,
    next_surface: u64,
    revision: u64,
}

impl Desktop {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn focus(&mut self, endpoint: EndpointId) -> bool {
        let changed = self.keyboard_focus != Some(endpoint);
        self.keyboard_focus = Some(endpoint);
        if changed {
            self.scene.raise_endpoint(endpoint);
            self.revision = self.revision.wrapping_add(1);
        }
        changed
    }

    pub fn focused(&self) -> Option<EndpointId> {
        self.keyboard_focus
    }

    /// Set the compositor-owned pointer position in desktop coordinates.
    pub fn set_pointer(&mut self, point: Point) -> bool {
        let changed = self.pointer != Some(point);
        self.pointer = Some(point);
        if changed {
            self.revision = self.revision.wrapping_add(1);
        }
        changed
    }

    /// Move the single compositor-owned pointer, clamped to the desktop rather
    /// than to any personality's client area.
    pub fn move_pointer(&mut self, dx: i16, dy: i16) -> Point {
        let extent = self.extent();
        let old = self.pointer.unwrap_or_default();
        let point = Point {
            x: old.x.saturating_add(i32::from(dx))
                .clamp(0, extent.width.saturating_sub(1) as i32),
            y: old.y.saturating_add(i32::from(dy))
                .clamp(0, extent.height.saturating_sub(1) as i32),
        };
        self.set_pointer(point);
        point
    }

    /// Translate the desktop pointer into a top-level endpoint's coordinates.
    /// Coordinates deliberately remain outside the client rectangle when the
    /// pointer leaves it; capture and hit-test policy belong above this layer.
    pub fn pointer_for(&self, endpoint: EndpointId) -> Option<Point> {
        let point = self.pointer?;
        let node = self.scene.roots.iter().rev().find_map(|&id| {
            self.scene.node(id).filter(|node| node.visible && node.owner == endpoint)
        })?;
        Some(Point { x: point.x - node.geometry.x, y: point.y - node.geometry.y })
    }

    /// Return the retained node for `(endpoint, key)`, creating it invisible
    /// on first use. Node identity survives focus changes.
    pub fn ensure_node(
        &mut self,
        endpoint: EndpointId,
        key: PresentationKey,
        geometry: Rect,
    ) -> Result<NodeId, SceneError> {
        if let Some(binding) = self
            .bindings
            .iter()
            .find(|binding| binding.endpoint == endpoint && binding.key == key)
        {
            return Ok(binding.node);
        }
        let node = self.scene.create(endpoint, None, geometry)?;
        self.revision = self.revision.wrapping_add(1);
        self.bindings.push(Binding {
            endpoint,
            key,
            node,
        });
        Ok(node)
    }

    pub fn geometry(&self, node: NodeId) -> Option<Rect> {
        self.scene.node(node).map(|node| node.geometry)
    }

    /// Bounding size of all visible top-level presentations in output space.
    pub fn extent(&self) -> Size {
        let mut size = Size::default();
        for &root in &self.scene.roots {
            let Some(node) = self.scene.node(root) else { continue };
            if !node.visible {
                continue;
            }
            let right = i64::from(node.geometry.x) + i64::from(node.geometry.width);
            let bottom = i64::from(node.geometry.y) + i64::from(node.geometry.height);
            size.width = size.width.max(right.clamp(0, i64::from(u32::MAX)) as u32);
            size.height = size.height.max(bottom.clamp(0, i64::from(u32::MAX)) as u32);
        }
        size
    }

    /// Return the stable surface for `(endpoint, key)`, creating an empty one
    /// on first use. Its identity survives buffer-size and focus changes.
    pub fn ensure_surface(
        &mut self,
        endpoint: EndpointId,
        key: SurfaceKey,
    ) -> Result<SurfaceId, SurfaceError> {
        if let Some(surface) = self
            .surfaces
            .iter()
            .find(|surface| surface.owner == endpoint && surface.key == key)
        {
            return Ok(surface.id);
        }
        let raw = self.next_surface.checked_add(1).ok_or(SurfaceError::Exhausted)?;
        self.next_surface = raw;
        let id = SurfaceId(raw);
        self.surfaces.push(Surface { owner: endpoint, key, id });
        self.revision = self.revision.wrapping_add(1);
        Ok(id)
    }

    pub fn surface_id(&self, endpoint: EndpointId, key: SurfaceKey) -> Option<SurfaceId> {
        self.surfaces
            .iter()
            .find(|surface| surface.owner == endpoint && surface.key == key)
            .map(|surface| surface.id)
    }

    pub fn surface_endpoints(&self) -> impl Iterator<Item = EndpointId> + '_ {
        self.surfaces.iter().map(|surface| surface.owner)
    }

    pub fn commit(&mut self, transaction: Transaction) -> Result<(), SceneError> {
        self.scene.commit(transaction)?;
        self.revision = self.revision.wrapping_add(1);
        self.bindings
            .retain(|binding| self.scene.node(binding.node).is_some());
        Ok(())
    }

    pub fn compose(
        &self,
        contents: &[Content<'_>],
        width: usize,
        height: usize,
        format: vga::PixelFormat,
        output: &mut Vec<u8>,
    ) -> Result<usize, ComposeError> {
        self.scene.compose(contents, width, height, format, output)
    }

    /// Composite immutable views of process-owned surfaces.
    pub fn compose_surfaces(
        &self,
        contents: &[Content<'_>],
        width: usize,
        height: usize,
        format: vga::PixelFormat,
        output: &mut Vec<u8>,
    ) -> Result<usize, ComposeError> {
        self.compose_surfaces_with(contents, None, width, height, format, output)
    }

    fn compose_surfaces_with(
        &self,
        contents: &[Content<'_>],
        system: Option<Content<'_>>,
        width: usize,
        height: usize,
        format: vga::PixelFormat,
        output: &mut Vec<u8>,
    ) -> Result<usize, ComposeError> {
        let resolve = |id| {
            if let Some(content) = system.filter(|content| content.id == id) {
                return Some(content.buffer);
            }
            if let Some(content) = contents.iter().find(|content| content.id == id) {
                return Some(content.buffer);
            }
            None
        };
        self.compose_resolved(&resolve, width, height, format, output)
    }

    fn compose_resolved<'a, F>(
        &self,
        resolve: &F,
        width: usize,
        height: usize,
        format: vga::PixelFormat,
        output: &mut Vec<u8>,
    ) -> Result<usize, ComposeError>
    where
        F: Fn(SurfaceId) -> Option<PixelBuffer<'a>>,
    {
        let pixels = self.scene.compose_endpoint_with(
            None,
            resolve,
            width,
            height,
            format,
            output,
        )?;
        if let Some(point) = self.pointer {
            draw_pointer(
                output,
                width,
                height,
                width * format.bytes_per_pixel as usize,
                format,
                point,
            );
        }
        Ok(pixels)
    }

    pub fn hit_test(&self, point: Point) -> Option<Hit> {
        self.scene.hit_test(point)
    }
}

/// Classic arrow drawn after scene composition, leaving application surfaces
/// untouched as the pointer moves.
fn draw_pointer(
    output: &mut [u8], width: usize, height: usize, stride: usize,
    format: vga::PixelFormat, point: Point,
) {
    let step = format.bytes_per_pixel as usize;
    let black = format.encode(0x0000_0000).to_le_bytes();
    let white = format.encode(0x00ff_ffff).to_le_bytes();
    let mut pixel = |x: i32, y: i32, color: &[u8; 4]| {
        if x < 0 || y < 0 || x >= width as i32 || y >= height as i32 { return; }
        let at = y as usize * stride + x as usize * step;
        if at + step <= output.len() { output[at..at + step].copy_from_slice(&color[..step]); }
    };
    for y in 0..14i32 {
        let edge = y / 2;
        for x in 0..=edge {
            let outline = x == 0 || x == edge || y == 13;
            pixel(point.x + x, point.y + y, if outline { &black } else { &white });
        }
    }
    for y in 10..18i32 {
        for x in 3..=5i32 {
            let outline = x == 3 || x == 5 || y == 17;
            pixel(point.x + x, point.y + y, if outline { &black } else { &white });
        }
    }
}

/// Event-loop-owned window policy and retained graphical state.
///
/// `Desktop` remains the personality-neutral scene and surface registry. This
/// layer names the persistent windows, owns keyboard focus, and decides
/// whether the output is presenting the desktop or granting one window the
/// fullscreen direct-scanout fast path.
#[derive(Debug)]
pub struct WindowManager {
    desktop: Desktop,
    composed: Vec<u8>,
    osd_pixels: Vec<u8>,
    osd_rect: Option<Rect>,
    osd_geometry: Option<(usize, usize, vga::PixelFormat)>,
    presented_revision: u64,
    focused: Option<WindowId>,
    presentation: Presentation,
    modes: Vec<(WindowId, WindowMode)>,
}

impl WindowManager {
    pub fn new(initial: Presentation) -> Self {
        let focused = match initial {
            Presentation::Desktop => None,
            Presentation::Fullscreen(window) => Some(window),
        };
        let mut modes = Vec::new();
        if let Presentation::Fullscreen(window) = initial {
            modes.push((window, WindowMode::Fullscreen));
        }
        Self {
            desktop: Desktop::new(),
            composed: Vec::new(),
            osd_pixels: Vec::new(),
            osd_rect: None,
            osd_geometry: None,
            presented_revision: 0,
            focused,
            presentation: initial,
            modes,
        }
    }

    /// The primary-window mapping used until personalities expose more than
    /// one native top-level window.
    pub const fn primary_window(endpoint: EndpointId) -> WindowId {
        WindowId(endpoint.0 as u64)
    }

    pub const fn window_endpoint(window: WindowId) -> EndpointId {
        EndpointId(window.0 as u32)
    }

    pub fn desktop(&self) -> &Desktop {
        &self.desktop
    }

    pub fn desktop_mut(&mut self) -> &mut Desktop {
        &mut self.desktop
    }

    pub fn compose<'a>(
        &'a mut self,
        contents: &[Content<'_>],
        width: usize,
        height: usize,
        format: vga::PixelFormat,
    ) -> Result<&'a mut Vec<u8>, ComposeError> {
        const OSD_ENDPOINT: EndpointId = EndpointId(u32::MAX);
        const OSD_SURFACE: SurfaceKey = SurfaceKey(u64::MAX);
        let Self { desktop, composed, osd_pixels, osd_rect, presented_revision, .. } = self;
        let system = if crate::kernel::osd::is_open()
            && let Some(id) = desktop.surface_id(OSD_ENDPOINT, OSD_SURFACE)
            && let Some(rect) = osd_rect
            && let Ok(buffer) = PixelBuffer::new(
                rect.width as usize,
                rect.height as usize,
                rect.width as usize * format.bytes_per_pixel as usize,
                format,
                osd_pixels,
            )
        {
            Some(Content { id, buffer })
        } else {
            None
        };
        desktop.compose_surfaces_with(contents, system, width, height, format, composed)?;
        *presented_revision = desktop.revision;
        Ok(composed)
    }

    pub fn compose_processes<'a, F>(
        &'a mut self,
        resolve_process: F,
        width: usize,
        height: usize,
        format: vga::PixelFormat,
    ) -> Result<&'a mut Vec<u8>, ComposeError>
    where
        F: Fn(EndpointId, SurfaceKey) -> Option<PixelBuffer<'a>>,
    {
        const OSD_ENDPOINT: EndpointId = EndpointId(u32::MAX);
        const OSD_SURFACE: SurfaceKey = SurfaceKey(u64::MAX);
        let Self { desktop, composed, osd_pixels, osd_rect, presented_revision, .. } = self;
        let osd = if crate::kernel::osd::is_open()
            && let Some(id) = desktop.surface_id(OSD_ENDPOINT, OSD_SURFACE)
            && let Some(rect) = osd_rect
            && let Ok(buffer) = PixelBuffer::new(
                rect.width as usize,
                rect.height as usize,
                rect.width as usize * format.bytes_per_pixel as usize,
                format,
                osd_pixels,
            )
        {
            Some(Content { id, buffer })
        } else {
            None
        };
        let resolve = |id| {
            if let Some(content) = osd.filter(|content| content.id == id) {
                return Some(content.buffer);
            }
            let surface = desktop.surfaces.iter().find(|surface| surface.id == id)?;
            resolve_process(surface.owner, surface.key)
        };
        desktop.compose_resolved(&resolve, width, height, format, composed)?;
        *presented_revision = desktop.revision;
        Ok(composed)
    }

    pub fn needs_present(&self) -> bool {
        self.presented_revision != self.desktop.revision
    }

    pub fn sync_osd(
        &mut self,
        width: usize,
        height: usize,
        scale_y: usize,
        format: vga::PixelFormat,
    ) {
        const OSD_ENDPOINT: EndpointId = EndpointId(u32::MAX);
        const OSD_SURFACE: SurfaceKey = SurfaceKey(u64::MAX);
        const OSD_PRESENTATION: PresentationKey = PresentationKey(u64::MAX);
        if width == 0 || height == 0 {
            return;
        }
        let geometry = (width, height, format);
        let repaint = crate::kernel::osd::take_repaint_request();
        let open = crate::kernel::osd::is_open();
        let frontmost = self.desktop.bindings
            .iter()
            .find(|binding| {
                binding.endpoint == OSD_ENDPOINT && binding.key == OSD_PRESENTATION
            })
            .is_some_and(|binding| self.desktop.scene.roots.last() == Some(&binding.node));
        let redraw = repaint || self.osd_geometry != Some(geometry);
        if !redraw && (!open || frontmost) {
            return;
        }
        self.osd_geometry = Some(geometry);
        let step = format.bytes_per_pixel as usize;
        if redraw && open {
            self.osd_pixels.clear();
            self.osd_rect = crate::kernel::osd::window_size(width, height, scale_y)
                .map(|(panel_width, panel_height)| {
                    self.osd_pixels.resize(panel_width * panel_height * step, 0);
                    crate::kernel::osd::paint(
                        &mut self.osd_pixels,
                        panel_width * step,
                        panel_width,
                        panel_height,
                        width,
                        height,
                        scale_y,
                        format,
                    );
                    Rect::new(
                        ((width - panel_width) / 2) as i32,
                        ((height - panel_height) / 2) as i32,
                        panel_width as u32,
                        panel_height as u32,
                    )
                });
        }
        let rect = self.osd_rect.unwrap_or(Rect::new(0, 0, 1, 1));
        let surface = self.desktop.ensure_surface(OSD_ENDPOINT, OSD_SURFACE)
            .expect("create OSD surface");
        let node = self.desktop.ensure_node(
            OSD_ENDPOINT,
            OSD_PRESENTATION,
            rect,
        ).expect("create OSD presentation node");
        let mut transaction = Transaction::new(OSD_ENDPOINT);
        transaction
            .set_geometry(node, rect)
            .attach(node, Some(surface))
            .set_visible(node, open && self.osd_rect.is_some())
            .raise(node);
        self.desktop.commit(transaction).expect("commit OSD window");
    }

    pub fn presentation(&self) -> Presentation {
        self.presentation
    }

    pub fn uses_desktop(&self) -> bool {
        matches!(self.presentation, Presentation::Desktop)
    }

    pub fn focused(&self) -> Option<WindowId> {
        self.focused
    }

    pub fn mode(&self, window: WindowId) -> WindowMode {
        self.modes
            .iter()
            .find_map(|&(candidate, mode)| (candidate == window).then_some(mode))
            .unwrap_or(WindowMode::Windowed)
    }

    fn remember_mode(&mut self, window: WindowId, mode: WindowMode) {
        if let Some((_, saved)) = self.modes.iter_mut().find(|(candidate, _)| *candidate == window) {
            *saved = mode;
        } else {
            self.modes.push((window, mode));
        }
    }

    pub fn focus(&mut self, window: WindowId) -> bool {
        let changed = self.focused != Some(window);
        if !self.modes.iter().any(|(candidate, _)| *candidate == window) {
            self.modes.push((window, WindowMode::Windowed));
        }
        self.focused = Some(window);
        self.desktop.focus(Self::window_endpoint(window));
        changed
    }

    /// A freshly-created child has no saved policy yet, so give it the mode
    /// of the process whose execution identity it continues.
    pub fn inherit_mode(&mut self, parent: WindowId, child: WindowId) {
        let mode = self.mode(parent);
        self.remember_mode(child, mode);
    }

    /// Selecting a window restores the presentation mode it had when focus
    /// last left it. Selection does not itself change that retained policy.
    pub fn select_window(&mut self, window: WindowId) -> bool {
        let presentation = match self.mode(window) {
            WindowMode::Windowed => Presentation::Desktop,
            WindowMode::Fullscreen => Presentation::Fullscreen(window),
        };
        let changed = self.presentation != presentation || self.focused != Some(window);
        self.presentation = presentation;
        self.focus(window);
        changed
    }

    pub fn enter_fullscreen(&mut self, window: WindowId) {
        self.remember_mode(window, WindowMode::Fullscreen);
        self.focus(window);
        self.presentation = Presentation::Fullscreen(window);
    }

    pub fn enter_windowed(&mut self, window: WindowId) {
        self.remember_mode(window, WindowMode::Windowed);
        self.focus(window);
        self.presentation = Presentation::Desktop;
    }

    pub fn toggle_presentation(&mut self, window: WindowId) -> WindowMode {
        match self.mode(window) {
            WindowMode::Windowed => {
                self.enter_fullscreen(window);
                WindowMode::Fullscreen
            }
            WindowMode::Fullscreen => {
                self.enter_windowed(window);
                WindowMode::Windowed
            }
        }
    }
}

#[derive(Clone, Debug)]
enum Operation {
    SetGeometry(NodeId, Rect),
    SetClip(NodeId, Option<Rect>),
    SetInput(NodeId, InputRegion),
    Attach(NodeId, Option<SurfaceId>),
    SetVisible(NodeId, bool),
    SetOpacity(NodeId, u8),
    Reparent(NodeId, Option<NodeId>),
    Raise(NodeId),
    Destroy(NodeId),
}

/// State changes issued by one personality endpoint.
#[derive(Clone, Debug)]
pub struct Transaction {
    owner: EndpointId,
    operations: Vec<Operation>,
}

impl Transaction {
    pub fn new(owner: EndpointId) -> Self {
        Self {
            owner,
            operations: Vec::new(),
        }
    }

    pub fn set_geometry(&mut self, node: NodeId, geometry: Rect) -> &mut Self {
        self.operations.push(Operation::SetGeometry(node, geometry));
        self
    }

    pub fn set_clip(&mut self, node: NodeId, clip: Option<Rect>) -> &mut Self {
        self.operations.push(Operation::SetClip(node, clip));
        self
    }

    pub fn set_input(&mut self, node: NodeId, input: InputRegion) -> &mut Self {
        self.operations.push(Operation::SetInput(node, input));
        self
    }

    pub fn attach(&mut self, node: NodeId, content: Option<SurfaceId>) -> &mut Self {
        self.operations.push(Operation::Attach(node, content));
        self
    }

    pub fn set_visible(&mut self, node: NodeId, visible: bool) -> &mut Self {
        self.operations.push(Operation::SetVisible(node, visible));
        self
    }

    pub fn set_opacity(&mut self, node: NodeId, opacity: u8) -> &mut Self {
        self.operations.push(Operation::SetOpacity(node, opacity));
        self
    }

    pub fn reparent(&mut self, node: NodeId, parent: Option<NodeId>) -> &mut Self {
        self.operations.push(Operation::Reparent(node, parent));
        self
    }

    pub fn raise(&mut self, node: NodeId) -> &mut Self {
        self.operations.push(Operation::Raise(node));
        self
    }

    pub fn destroy(&mut self, node: NodeId) -> &mut Self {
        self.operations.push(Operation::Destroy(node));
        self
    }
}

impl Scene {
    pub fn new() -> Self {
        Self::default()
    }

    /// Create an invisible node.  Cross-endpoint parenting is excluded from
    /// this first capability boundary; an embedding protocol can later grant
    /// it explicitly instead of making it ambient authority.
    pub fn create(
        &mut self,
        owner: EndpointId,
        parent: Option<NodeId>,
        geometry: Rect,
    ) -> Result<NodeId, SceneError> {
        if let Some(parent_id) = parent {
            let parent_node = self
                .node(parent_id)
                .ok_or(SceneError::InvalidParent(parent_id))?;
            if parent_node.owner != owner {
                return Err(SceneError::NotOwner(parent_id));
            }
        }

        let slot_index = self.slots.iter().position(|slot| slot.node.is_none());
        let id = if let Some(index) = slot_index {
            NodeId {
                slot: index as u32,
                generation: self.slots[index].generation,
            }
        } else {
            let id = NodeId {
                slot: self.slots.len() as u32,
                generation: 1,
            };
            self.slots.push(Slot {
                generation: 1,
                node: None,
            });
            id
        };
        self.slots[id.slot as usize].node = Some(Node {
            owner,
            parent,
            geometry,
            clip: None,
            input: InputRegion::Bounds,
            content: None,
            visible: false,
            opacity: u8::MAX,
            children: Vec::new(),
        });
        self.insert_into_parent(id, parent);
        Ok(id)
    }

    pub fn node(&self, id: NodeId) -> Option<&Node> {
        let slot = self.slots.get(id.slot as usize)?;
        (slot.generation == id.generation)
            .then_some(slot.node.as_ref())
            .flatten()
    }

    /// Apply all state changes or none.  The clone is intentionally simple;
    /// validation can later be made journal-based without changing semantics.
    pub fn commit(&mut self, transaction: Transaction) -> Result<(), SceneError> {
        let mut candidate = self.clone();
        for operation in transaction.operations {
            candidate.apply(transaction.owner, operation)?;
        }
        *self = candidate;
        Ok(())
    }

    /// Find the frontmost input node at output coordinates.
    pub fn hit_test(&self, point: Point) -> Option<Hit> {
        self.hit_test_endpoint(None, point)
    }

    /// Move every top-level window owned by one endpoint to the front while
    /// preserving the endpoint's internal root order.
    fn raise_endpoint(&mut self, endpoint: EndpointId) {
        let mut index = 0usize;
        let mut remaining = self.roots.len();
        while index < remaining {
            let id = self.roots[index];
            if self.node(id).is_some_and(|node| node.owner == endpoint) {
                self.roots.remove(index);
                self.roots.push(id);
                remaining -= 1;
            } else {
                index += 1;
            }
        }
    }

    fn hit_test_endpoint(&self, endpoint: Option<EndpointId>, point: Point) -> Option<Hit> {
        for &root in self.roots.iter().rev() {
            if endpoint
                .is_some_and(|active| self.node(root).is_none_or(|node| node.owner != active))
            {
                continue;
            }
            if let Some(hit) = self.hit_node(root, point) {
                return Some(hit);
            }
        }
        None
    }

    /// Composite visible content back-to-front into one packed output shadow.
    ///
    /// Content buffers remain producer-owned and may use any validated packed
    /// RGB layout.  Geometry, clipping, stacking, scaling, and global opacity
    /// are scene mechanisms; decorations and native paint semantics remain in
    /// the personality that produced the buffers.
    pub fn compose(
        &self,
        contents: &[Content<'_>],
        width: usize,
        height: usize,
        format: vga::PixelFormat,
        output: &mut Vec<u8>,
    ) -> Result<usize, ComposeError> {
        self.compose_endpoint(None, contents, width, height, format, output)
    }

    fn compose_endpoint(
        &self,
        endpoint: Option<EndpointId>,
        contents: &[Content<'_>],
        width: usize,
        height: usize,
        format: vga::PixelFormat,
        output: &mut Vec<u8>,
    ) -> Result<usize, ComposeError> {
        let resolve = |id| {
            contents
                .iter()
                .find(|entry| entry.id == id)
                .map(|entry| entry.buffer)
        };
        self.compose_endpoint_with(endpoint, &resolve, width, height, format, output)
    }

    fn compose_endpoint_with<'a, F>(
        &self,
        endpoint: Option<EndpointId>,
        resolve: &F,
        width: usize,
        height: usize,
        format: vga::PixelFormat,
        output: &mut Vec<u8>,
    ) -> Result<usize, ComposeError>
    where
        F: Fn(SurfaceId) -> Option<PixelBuffer<'a>>,
    {
        if !valid_format(format) {
            return Err(ComposeError::InvalidOutputFormat);
        }
        let step = format.bytes_per_pixel as usize;
        let len = width
            .checked_mul(height)
            .and_then(|pixels| pixels.checked_mul(step))
            .ok_or(ComposeError::Overflow)?;
        output.clear();
        output.resize(len, 0);
        let output_clip = Rect::new(
            0,
            0,
            u32::try_from(width).unwrap_or(u32::MAX),
            u32::try_from(height).unwrap_or(u32::MAX),
        );
        let target = Target {
            width,
            height,
            stride: width * step,
            format,
            pixels: output,
        };
        let mut target = target;
        for &root in &self.roots {
            if endpoint
                .is_some_and(|active| self.node(root).is_none_or(|node| node.owner != active))
            {
                continue;
            }
            self.compose_node(root, Point::default(), output_clip, resolve, &mut target);
        }
        Ok(width.saturating_mul(height))
    }

    fn apply(&mut self, owner: EndpointId, operation: Operation) -> Result<(), SceneError> {
        match operation {
            Operation::SetGeometry(id, geometry) => self.owned_mut(owner, id)?.geometry = geometry,
            Operation::SetClip(id, clip) => self.owned_mut(owner, id)?.clip = clip,
            Operation::SetInput(id, input) => self.owned_mut(owner, id)?.input = input,
            Operation::Attach(id, content) => self.owned_mut(owner, id)?.content = content,
            Operation::SetVisible(id, visible) => self.owned_mut(owner, id)?.visible = visible,
            Operation::SetOpacity(id, opacity) => self.owned_mut(owner, id)?.opacity = opacity,
            Operation::Reparent(id, parent) => self.reparent(owner, id, parent)?,
            Operation::Raise(id) => self.raise_owned(owner, id)?,
            Operation::Destroy(id) => {
                self.owned(owner, id)?;
                self.destroy_subtree(id);
            }
        }
        Ok(())
    }

    fn owned(&self, owner: EndpointId, id: NodeId) -> Result<&Node, SceneError> {
        let node = self.node(id).ok_or(SceneError::StaleNode(id))?;
        if node.owner != owner {
            return Err(SceneError::NotOwner(id));
        }
        Ok(node)
    }

    fn owned_mut(&mut self, owner: EndpointId, id: NodeId) -> Result<&mut Node, SceneError> {
        self.owned(owner, id)?;
        Ok(self.slots[id.slot as usize]
            .node
            .as_mut()
            .expect("validated node"))
    }

    fn insert_into_parent(&mut self, id: NodeId, parent: Option<NodeId>) {
        if let Some(parent) = parent {
            self.slots[parent.slot as usize]
                .node
                .as_mut()
                .expect("validated parent")
                .children
                .push(id);
        } else {
            self.roots.push(id);
        }
    }

    fn remove_from_parent(&mut self, id: NodeId, parent: Option<NodeId>) {
        let siblings = if let Some(parent) = parent {
            &mut self.slots[parent.slot as usize]
                .node
                .as_mut()
                .expect("live parent")
                .children
        } else {
            &mut self.roots
        };
        if let Some(index) = siblings.iter().position(|&sibling| sibling == id) {
            siblings.remove(index);
        }
    }

    fn reparent(
        &mut self,
        owner: EndpointId,
        id: NodeId,
        parent: Option<NodeId>,
    ) -> Result<(), SceneError> {
        let old_parent = self.owned(owner, id)?.parent;
        if old_parent == parent {
            return Ok(());
        }
        let mut cursor = parent;
        while let Some(candidate) = cursor {
            if candidate == id {
                return Err(SceneError::Cycle);
            }
            let candidate_node = self
                .node(candidate)
                .ok_or(SceneError::InvalidParent(candidate))?;
            if candidate_node.owner != owner {
                return Err(SceneError::NotOwner(candidate));
            }
            cursor = candidate_node.parent;
        }
        self.remove_from_parent(id, old_parent);
        self.slots[id.slot as usize]
            .node
            .as_mut()
            .expect("live node")
            .parent = parent;
        self.insert_into_parent(id, parent);
        Ok(())
    }

    fn raise_owned(&mut self, owner: EndpointId, id: NodeId) -> Result<(), SceneError> {
        let parent = self.owned(owner, id)?.parent;
        self.remove_from_parent(id, parent);
        self.insert_into_parent(id, parent);
        Ok(())
    }

    fn destroy_subtree(&mut self, id: NodeId) {
        let (parent, children) = {
            let node = self.node(id).expect("live subtree node");
            (node.parent, node.children.clone())
        };
        self.remove_from_parent(id, parent);
        for child in children {
            self.destroy_subtree_detached(child);
        }
        self.retire(id);
    }

    fn destroy_subtree_detached(&mut self, id: NodeId) {
        let children = self.node(id).expect("live subtree node").children.clone();
        for child in children {
            self.destroy_subtree_detached(child);
        }
        self.retire(id);
    }

    fn retire(&mut self, id: NodeId) {
        let slot = &mut self.slots[id.slot as usize];
        slot.node = None;
        slot.generation = slot.generation.wrapping_add(1).max(1);
    }

    fn hit_node(&self, id: NodeId, parent_point: Point) -> Option<Hit> {
        let node = self.node(id)?;
        if !node.visible {
            return None;
        }
        let local = Point {
            x: parent_point.x.saturating_sub(node.geometry.x),
            y: parent_point.y.saturating_sub(node.geometry.y),
        };
        if node.clip.is_some_and(|clip| !clip.contains(local)) {
            return None;
        }
        for &child in node.children.iter().rev() {
            if let Some(hit) = self.hit_node(child, local) {
                return Some(hit);
            }
        }
        let size = Size {
            width: node.geometry.width,
            height: node.geometry.height,
        };
        node.input.contains(local, size).then_some(Hit {
            node: id,
            endpoint: node.owner,
            local,
        })
    }

    fn compose_node<'a, F>(
        &self,
        id: NodeId,
        parent_origin: Point,
        inherited_clip: Rect,
        resolve: &F,
        target: &mut Target<'_>,
    )
    where
        F: Fn(SurfaceId) -> Option<PixelBuffer<'a>>,
    {
        let Some(node) = self.node(id) else { return };
        if !node.visible {
            return;
        }
        let origin = Point {
            x: parent_origin.x.saturating_add(node.geometry.x),
            y: parent_origin.y.saturating_add(node.geometry.y),
        };
        let node_rect = Rect::new(
            origin.x,
            origin.y,
            node.geometry.width,
            node.geometry.height,
        );
        let mut subtree_clip = inherited_clip;
        if let Some(local_clip) = node.clip {
            let world_clip = Rect::new(
                origin.x.saturating_add(local_clip.x),
                origin.y.saturating_add(local_clip.y),
                local_clip.width,
                local_clip.height,
            );
            let Some(clip) = intersect(subtree_clip, world_clip) else {
                return;
            };
            subtree_clip = clip;
        }
        if node.opacity != 0
            && let Some(content) = node.content
            && let Some(source) = resolve(content)
        {
            blit_scaled(source, node_rect, subtree_clip, node.opacity, target);
        }
        for &child in &node.children {
            self.compose_node(child, origin, subtree_clip, resolve, target);
        }
    }
}

struct Target<'a> {
    width: usize,
    height: usize,
    stride: usize,
    format: vga::PixelFormat,
    pixels: &'a mut [u8],
}

fn valid_format(format: vga::PixelFormat) -> bool {
    vga::PixelFormat::from_rgb(
        format.bytes_per_pixel,
        [
            format.red_pos,
            format.red_size,
            format.green_pos,
            format.green_size,
            format.blue_pos,
            format.blue_size,
        ],
    ) == Some(format)
}

fn intersect(a: Rect, b: Rect) -> Option<Rect> {
    let left = i64::from(a.x).max(i64::from(b.x));
    let top = i64::from(a.y).max(i64::from(b.y));
    let right = (i64::from(a.x) + i64::from(a.width)).min(i64::from(b.x) + i64::from(b.width));
    let bottom = (i64::from(a.y) + i64::from(a.height)).min(i64::from(b.y) + i64::from(b.height));
    if right <= left || bottom <= top {
        return None;
    }
    Some(Rect::new(
        left as i32,
        top as i32,
        (right - left) as u32,
        (bottom - top) as u32,
    ))
}

fn read_pixel(buffer: PixelBuffer<'_>, x: usize, y: usize) -> u32 {
    let step = buffer.format.bytes_per_pixel as usize;
    let offset = y * buffer.stride + x * step;
    let bytes = &buffer.pixels[offset..offset + step];
    let raw = match step {
        1 => u32::from(bytes[0]),
        2 => u32::from(u16::from_le_bytes([bytes[0], bytes[1]])),
        3 => u32::from(bytes[0]) | u32::from(bytes[1]) << 8 | u32::from(bytes[2]) << 16,
        4 => u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
        _ => unreachable!("validated pixel format"),
    };
    let channel = |position: u8, size: u8| -> u32 {
        let mask = (1u32 << size) - 1;
        (raw >> position & mask) * 255 / mask
    };
    channel(buffer.format.red_pos, buffer.format.red_size) << 16
        | channel(buffer.format.green_pos, buffer.format.green_size) << 8
        | channel(buffer.format.blue_pos, buffer.format.blue_size)
}

fn read_target(target: &Target<'_>, x: usize, y: usize) -> u32 {
    let buffer = PixelBuffer {
        width: target.width,
        height: target.height,
        stride: target.stride,
        format: target.format,
        pixels: target.pixels,
    };
    read_pixel(buffer, x, y)
}

fn write_target(target: &mut Target<'_>, x: usize, y: usize, rgb: u32) {
    let step = target.format.bytes_per_pixel as usize;
    let offset = y * target.stride + x * step;
    let encoded = target.format.encode(rgb).to_le_bytes();
    target.pixels[offset..offset + step].copy_from_slice(&encoded[..step]);
}

fn blend(source: u32, destination: u32, opacity: u8) -> u32 {
    let alpha = u32::from(opacity);
    let inverse = 255 - alpha;
    let channel = |shift: u32| {
        ((((source >> shift) & 0xff) * alpha + ((destination >> shift) & 0xff) * inverse + 127)
            / 255)
            << shift
    };
    channel(16) | channel(8) | channel(0)
}

fn blit_scaled(
    source: PixelBuffer<'_>,
    destination: Rect,
    clip: Rect,
    opacity: u8,
    target: &mut Target<'_>,
) {
    if source.width == 0 || source.height == 0 || destination.width == 0 || destination.height == 0
    {
        return;
    }
    let Some(draw) = intersect(destination, clip) else {
        return;
    };
    // Existing full-frame producers can enter the scene cheaply: if their
    // packed pixels already match an opaque, unscaled destination, composition
    // is one row copy rather than a decode/encode pass over every pixel.
    if opacity == u8::MAX
        && source.format == target.format
        && destination == draw
        && destination.x >= 0
        && destination.y >= 0
        && source.width == destination.width as usize
        && source.height == destination.height as usize
    {
        let step = target.format.bytes_per_pixel as usize;
        let row_bytes = source.width * step;
        let left = destination.x as usize * step;
        let top = destination.y as usize;
        if left + row_bytes <= target.stride && top + source.height <= target.height {
            for row in 0..source.height {
                let source_start = row * source.stride;
                let target_start = (top + row) * target.stride + left;
                target.pixels[target_start..target_start + row_bytes]
                    .copy_from_slice(&source.pixels[source_start..source_start + row_bytes]);
            }
            return;
        }
    }
    let left = usize::try_from(draw.x).unwrap_or(0).min(target.width);
    let top = usize::try_from(draw.y).unwrap_or(0).min(target.height);
    let right = usize::try_from(i64::from(draw.x) + i64::from(draw.width))
        .unwrap_or(target.width)
        .min(target.width);
    let bottom = usize::try_from(i64::from(draw.y) + i64::from(draw.height))
        .unwrap_or(target.height)
        .min(target.height);
    for y in top..bottom {
        let local_y = i64::try_from(y).unwrap_or(i64::MAX) - i64::from(destination.y);
        let source_y = (local_y as u64 * source.height as u64 / u64::from(destination.height))
            .min(source.height as u64 - 1) as usize;
        for x in left..right {
            let local_x = i64::try_from(x).unwrap_or(i64::MAX) - i64::from(destination.x);
            let source_x = (local_x as u64 * source.width as u64 / u64::from(destination.width))
                .min(source.width as u64 - 1) as usize;
            let source_rgb = read_pixel(source, source_x, source_y);
            let rgb = if opacity == u8::MAX {
                source_rgb
            } else {
                blend(source_rgb, read_target(target, x, y), opacity)
            };
            write_target(target, x, y, rgb);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    const WINDOWS: EndpointId = EndpointId(1);
    const OS2: EndpointId = EndpointId(2);

    fn show(scene: &mut Scene, owner: EndpointId, node: NodeId) {
        let mut transaction = Transaction::new(owner);
        transaction.set_visible(node, true);
        scene.commit(transaction).unwrap();
    }

    fn native_pixels(output: &[u8]) -> Vec<u32> {
        output
            .chunks_exact(4)
            .map(|pixel| u32::from_le_bytes(pixel.try_into().unwrap()))
            .collect()
    }

    #[test]
    fn frontmost_child_receives_local_input() {
        let mut scene = Scene::new();
        let root = scene
            .create(WINDOWS, None, Rect::new(10, 20, 200, 100))
            .unwrap();
        let back = scene
            .create(WINDOWS, Some(root), Rect::new(5, 6, 40, 30))
            .unwrap();
        let front = scene
            .create(WINDOWS, Some(root), Rect::new(8, 9, 40, 30))
            .unwrap();
        let mut transaction = Transaction::new(WINDOWS);
        transaction
            .set_visible(root, true)
            .set_visible(back, true)
            .set_visible(front, true);
        scene.commit(transaction).unwrap();

        assert_eq!(
            scene.hit_test(Point { x: 20, y: 31 }),
            Some(Hit {
                node: front,
                endpoint: WINDOWS,
                local: Point { x: 2, y: 2 },
            })
        );
    }

    #[test]
    fn clip_and_input_regions_are_distinct() {
        let mut scene = Scene::new();
        let root = scene
            .create(WINDOWS, None, Rect::new(0, 0, 100, 100))
            .unwrap();
        let child = scene
            .create(WINDOWS, Some(root), Rect::new(50, 0, 100, 100))
            .unwrap();
        let mut transaction = Transaction::new(WINDOWS);
        transaction
            .set_visible(root, true)
            .set_visible(child, true)
            .set_clip(root, Some(Rect::new(0, 0, 60, 100)))
            .set_input(child, InputRegion::Rects(vec![Rect::new(0, 0, 20, 20)]));
        scene.commit(transaction).unwrap();

        assert_eq!(
            scene.hit_test(Point { x: 55, y: 5 }).map(|hit| hit.node),
            Some(child)
        );
        assert_eq!(scene.hit_test(Point { x: 65, y: 5 }), None);
    }

    #[test]
    fn failed_commit_changes_nothing() {
        let mut scene = Scene::new();
        let node = scene
            .create(WINDOWS, None, Rect::new(0, 0, 10, 10))
            .unwrap();
        let stale = NodeId {
            slot: 99,
            generation: 1,
        };
        let mut transaction = Transaction::new(WINDOWS);
        transaction
            .set_geometry(node, Rect::new(30, 40, 50, 60))
            .set_visible(stale, true);

        assert_eq!(scene.commit(transaction), Err(SceneError::StaleNode(stale)));
        assert_eq!(scene.node(node).unwrap().geometry, Rect::new(0, 0, 10, 10));
    }

    #[test]
    fn endpoint_cannot_mutate_another_personality() {
        let mut scene = Scene::new();
        let node = scene
            .create(WINDOWS, None, Rect::new(0, 0, 10, 10))
            .unwrap();
        let mut transaction = Transaction::new(OS2);
        transaction.set_visible(node, true);
        assert_eq!(scene.commit(transaction), Err(SceneError::NotOwner(node)));
    }

    #[test]
    fn stale_handle_does_not_alias_reused_slot() {
        let mut scene = Scene::new();
        let old = scene.create(WINDOWS, None, Rect::default()).unwrap();
        let mut transaction = Transaction::new(WINDOWS);
        transaction.destroy(old);
        scene.commit(transaction).unwrap();

        let new = scene.create(WINDOWS, None, Rect::default()).unwrap();
        assert_ne!(old, new);
        assert!(scene.node(old).is_none());
        assert!(scene.node(new).is_some());
    }

    #[test]
    fn cycles_are_rejected_atomically() {
        let mut scene = Scene::new();
        let parent = scene.create(WINDOWS, None, Rect::default()).unwrap();
        let child = scene
            .create(WINDOWS, Some(parent), Rect::default())
            .unwrap();
        let mut transaction = Transaction::new(WINDOWS);
        transaction.reparent(parent, Some(child));
        assert_eq!(scene.commit(transaction), Err(SceneError::Cycle));
        assert_eq!(scene.node(parent).unwrap().parent, None);
    }

    #[test]
    fn destroying_a_parent_retires_the_subtree() {
        let mut scene = Scene::new();
        let parent = scene.create(WINDOWS, None, Rect::default()).unwrap();
        let child = scene
            .create(WINDOWS, Some(parent), Rect::default())
            .unwrap();
        show(&mut scene, WINDOWS, parent);
        let mut transaction = Transaction::new(WINDOWS);
        transaction.destroy(parent);
        scene.commit(transaction).unwrap();
        assert!(scene.node(parent).is_none());
        assert!(scene.node(child).is_none());
    }

    #[test]
    fn compositor_honors_stacking_and_converts_formats() {
        let mut scene = Scene::new();
        let back = scene.create(WINDOWS, None, Rect::new(0, 0, 2, 1)).unwrap();
        let front = scene.create(WINDOWS, None, Rect::new(1, 0, 1, 1)).unwrap();
        let mut transaction = Transaction::new(WINDOWS);
        transaction
            .attach(back, Some(SurfaceId(10)))
            .set_visible(back, true)
            .attach(front, Some(SurfaceId(11)))
            .set_visible(front, true);
        scene.commit(transaction).unwrap();

        let red = vga::PixelFormat::NATIVE.encode(0x00ff_0000).to_le_bytes();
        let blue = vga::PixelFormat::NATIVE.encode(0x0000_00ff).to_le_bytes();
        let sources = [
            Content {
                id: SurfaceId(10),
                buffer: PixelBuffer::new(1, 1, 4, vga::PixelFormat::NATIVE, &red).unwrap(),
            },
            Content {
                id: SurfaceId(11),
                buffer: PixelBuffer::new(1, 1, 4, vga::PixelFormat::NATIVE, &blue).unwrap(),
            },
        ];
        let mut output = vec![];
        scene
            .compose(&sources, 2, 1, vga::PixelFormat::RGB565, &mut output)
            .unwrap();

        assert_eq!(output.len(), 4);
        assert_eq!(
            u16::from_le_bytes([output[0], output[1]]),
            vga::PixelFormat::RGB565.encode(0x00ff_0000) as u16
        );
        assert_eq!(
            u16::from_le_bytes([output[2], output[3]]),
            vga::PixelFormat::RGB565.encode(0x0000_00ff) as u16
        );
    }

    #[test]
    fn compositor_scales_content_and_applies_ancestor_clip() {
        let mut scene = Scene::new();
        let parent = scene.create(WINDOWS, None, Rect::new(0, 0, 4, 1)).unwrap();
        let child = scene
            .create(WINDOWS, Some(parent), Rect::new(0, 0, 4, 1))
            .unwrap();
        let mut transaction = Transaction::new(WINDOWS);
        transaction
            .set_visible(parent, true)
            .set_clip(parent, Some(Rect::new(0, 0, 3, 1)))
            .attach(child, Some(SurfaceId(20)))
            .set_visible(child, true);
        scene.commit(transaction).unwrap();

        let pixels = [0x00ff_0000u32.to_le_bytes(), 0x0000_ff00u32.to_le_bytes()].concat();
        let source = [Content {
            id: SurfaceId(20),
            buffer: PixelBuffer::new(2, 1, 8, vga::PixelFormat::NATIVE, &pixels).unwrap(),
        }];
        let mut output = vec![];
        scene
            .compose(&source, 4, 1, vga::PixelFormat::NATIVE, &mut output)
            .unwrap();
        let values: Vec<u32> = output
            .chunks_exact(4)
            .map(|pixel| u32::from_le_bytes(pixel.try_into().unwrap()))
            .collect();
        assert_eq!(values, vec![0x00ff_0000, 0x00ff_0000, 0x0000_ff00, 0]);
    }

    #[test]
    fn pixel_buffer_rejects_incomplete_storage() {
        assert_eq!(
            PixelBuffer::new(2, 2, 8, vga::PixelFormat::NATIVE, &[0; 15]).unwrap_err(),
            BufferError::TooShort
        );
    }

    #[test]
    fn focused_endpoint_rises_to_top_of_retained_stack() {
        let mut desktop = Desktop::new();
        let key = PresentationKey(1);
        let windows = desktop
            .ensure_node(WINDOWS, key, Rect::new(0, 0, 1, 1))
            .unwrap();
        let os2 = desktop
            .ensure_node(OS2, key, Rect::new(0, 0, 1, 1))
            .unwrap();
        assert_ne!(windows, os2);
        let windows_surface = desktop.ensure_surface(WINDOWS, SurfaceKey(1)).unwrap();
        let os2_surface = desktop.ensure_surface(OS2, SurfaceKey(1)).unwrap();

        let mut windows_tx = Transaction::new(WINDOWS);
        windows_tx
            .attach(windows, Some(windows_surface))
            .set_visible(windows, true);
        desktop.commit(windows_tx).unwrap();
        let mut os2_tx = Transaction::new(OS2);
        os2_tx
            .attach(os2, Some(os2_surface))
            .set_visible(os2, true);
        desktop.commit(os2_tx).unwrap();

        let red = 0x00ff_0000u32.to_le_bytes();
        let blue = 0x0000_00ffu32.to_le_bytes();
        let contents = [
            Content { id: windows_surface, buffer: PixelBuffer::new(
                1, 1, 4, vga::PixelFormat::NATIVE, &red,
            ).unwrap() },
            Content { id: os2_surface, buffer: PixelBuffer::new(
                1, 1, 4, vga::PixelFormat::NATIVE, &blue,
            ).unwrap() },
        ];
        let mut output = vec![];

        desktop
            .compose_surfaces(&contents, 1, 1, vga::PixelFormat::NATIVE, &mut output)
            .unwrap();
        assert_eq!(native_pixels(&output), vec![0x0000_00ff]);
        assert_eq!(desktop.hit_test(Point::default()).unwrap().endpoint, OS2);

        assert!(desktop.focus(WINDOWS));
        desktop
            .compose_surfaces(&contents, 1, 1, vga::PixelFormat::NATIVE, &mut output)
            .unwrap();
        assert_eq!(native_pixels(&output), vec![0x00ff_0000]);
        assert_eq!(desktop.focused(), Some(WINDOWS));
        assert_eq!(desktop.hit_test(Point::default()).unwrap().endpoint, WINDOWS);

        assert!(desktop.focus(OS2));
        desktop
            .compose_surfaces(&contents, 1, 1, vga::PixelFormat::NATIVE, &mut output)
            .unwrap();
        assert_eq!(native_pixels(&output), vec![0x0000_00ff]);
        assert_eq!(desktop.focused(), Some(OS2));
        assert_eq!(desktop.hit_test(Point::default()).unwrap().endpoint, OS2);

        assert_eq!(
            desktop
                .ensure_node(WINDOWS, key, Rect::new(99, 99, 9, 9))
                .unwrap(),
            windows
        );
    }

    #[test]
    fn surface_identity_is_independent_of_process_owned_buffer_size() {
        let mut desktop = Desktop::new();
        let surface = desktop.ensure_surface(WINDOWS, SurfaceKey(7)).unwrap();
        assert_eq!(
            desktop.ensure_surface(WINDOWS, SurfaceKey(7)).unwrap(),
            surface
        );
        let node = desktop
            .ensure_node(WINDOWS, PresentationKey(7), Rect::new(0, 0, 2, 1))
            .unwrap();
        let mut transaction = Transaction::new(WINDOWS);
        transaction
            .attach(node, Some(surface))
            .set_visible(node, true);
        desktop.commit(transaction).unwrap();
        desktop.focus(WINDOWS);

        let pixels = [0x0000_00ffu32.to_le_bytes(), 0x0000_ff00u32.to_le_bytes()].concat();
        let contents = [Content { id: surface, buffer: PixelBuffer::new(
            2, 1, 8, vga::PixelFormat::NATIVE, &pixels,
        ).unwrap() }];

        let mut output = vec![];
        desktop
            .compose_surfaces(&contents, 2, 1, vga::PixelFormat::NATIVE, &mut output)
            .unwrap();
        let values: Vec<u32> = output
            .chunks_exact(4)
            .map(|pixel| u32::from_le_bytes(pixel.try_into().unwrap()))
            .collect();
        assert_eq!(values, vec![0x0000_00ff, 0x0000_ff00]);
    }

    #[test]
    fn selecting_a_window_restores_its_remembered_presentation() {
        let windows = WindowManager::primary_window(WINDOWS);
        let os2 = WindowManager::primary_window(OS2);
        let mut manager = WindowManager::new(Presentation::Fullscreen(windows));

        assert_eq!(manager.presentation(), Presentation::Fullscreen(windows));
        assert!(!manager.uses_desktop());
        assert!(manager.select_window(os2));
        assert_eq!(manager.presentation(), Presentation::Desktop);
        assert_eq!(manager.focused(), Some(os2));
        assert_eq!(manager.desktop().focused(), Some(OS2));

        manager.select_window(windows);
        assert_eq!(manager.presentation(), Presentation::Fullscreen(windows));
        manager.enter_windowed(windows);
        manager.select_window(os2);
        manager.select_window(windows);
        assert_eq!(manager.presentation(), Presentation::Desktop);
    }

    #[test]
    fn retained_composition_draws_pointer_with_byte_stride() {
        let mut desktop = Desktop::new();
        desktop.set_pointer(Point { x: 1, y: 1 });
        let mut output = vec![];
        desktop
            .compose_surfaces(&[], 16, 20, vga::PixelFormat::NATIVE, &mut output)
            .unwrap();
        let pixel = |x: usize, y: usize| {
            let at = (y * 16 + x) * 4;
            u32::from_le_bytes(output[at..at + 4].try_into().unwrap())
        };
        assert_eq!(pixel(1, 1), 0x0000_0000);
        assert_eq!(pixel(2, 5), 0x00ff_ffff);
    }

    #[test]
    fn desktop_pointer_is_not_clamped_to_a_personality_window() {
        let mut desktop = Desktop::new();
        let background = desktop
            .ensure_node(OS2, PresentationKey(1), Rect::new(0, 0, 100, 80))
            .unwrap();
        let window = desktop
            .ensure_node(WINDOWS, PresentationKey(1), Rect::new(20, 10, 30, 20))
            .unwrap();
        let mut os2 = Transaction::new(OS2);
        os2.set_visible(background, true);
        desktop.commit(os2).unwrap();
        let mut windows = Transaction::new(WINDOWS);
        windows.set_visible(window, true);
        desktop.commit(windows).unwrap();

        assert_eq!(desktop.move_pointer(80, 60), Point { x: 80, y: 60 });
        assert_eq!(desktop.pointer_for(WINDOWS), Some(Point { x: 60, y: 50 }));
        assert_eq!(desktop.pointer_for(OS2), Some(Point { x: 80, y: 60 }));
    }

    #[test]
    fn fullscreen_is_presentation_not_window_identity() {
        let window = WindowManager::primary_window(WINDOWS);
        let mut manager = WindowManager::new(Presentation::Desktop);
        manager.enter_fullscreen(window);

        assert_eq!(manager.presentation(), Presentation::Fullscreen(window));
        assert_eq!(manager.focused(), Some(window));
        assert_eq!(WindowManager::window_endpoint(window), WINDOWS);
    }

    #[test]
    fn presentation_toggle_is_retained_per_window() {
        let windows = WindowManager::primary_window(WINDOWS);
        let os2 = WindowManager::primary_window(OS2);
        let mut manager = WindowManager::new(Presentation::Desktop);

        assert_eq!(manager.toggle_presentation(windows), WindowMode::Fullscreen);
        manager.select_window(os2);
        assert_eq!(manager.presentation(), Presentation::Desktop);
        manager.select_window(windows);
        assert_eq!(manager.presentation(), Presentation::Fullscreen(windows));
    }
}
