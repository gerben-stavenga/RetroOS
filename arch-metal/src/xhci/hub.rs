//! USB 1.x/2.0 hub discovery at boot. Route strings and TT ancestry follow the
//! xHCI slot-context format; single-TT mode uses a hub's default alternate 0.
//! SuperSpeed hubs and runtime topology changes require additional handling.
use super::{
    Controller, DEVICE_LANES, EpInfo, INCTX_OFF, PortDevice, XFER_OFF, device_context_off, port,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Route {
    pub root_port: u32,
    pub string: u32,
    depth: u32,
    pub tt_slot: u32,
    pub tt_port: u32,
}
impl Route {
    pub fn root(root_port: u32) -> Self {
        Self {
            root_port,
            string: 0,
            depth: 0,
            tt_slot: 0,
            tt_port: 0,
        }
    }
    pub(super) fn child(
        self,
        port: u32,
        parent_slot: u32,
        parent_speed: u32,
        speed: u32,
    ) -> Option<Self> {
        if self.depth == 5 || !(1..=15).contains(&port) {
            return None;
        }
        let (tt_slot, tt_port) = if speed <= 2 {
            if parent_speed == 3 {
                (parent_slot, port)
            } else {
                (self.tt_slot, self.tt_port)
            }
        } else {
            (0, 0)
        };
        Some(Self {
            root_port: self.root_port,
            string: self.string | (port << (self.depth * 4)),
            depth: self.depth + 1,
            tt_slot,
            tt_port,
        })
    }
}

pub(super) struct Inventory {
    pub keyboards: [Option<(u32, PortDevice, EpInfo)>; DEVICE_LANES],
    pub mouse: Option<(u32, PortDevice, EpInfo)>,
    pub devices: [Option<(u32, PortDevice)>; DEVICE_LANES],
    pub used: usize,
}
impl Inventory {
    pub fn new() -> Self {
        Self {
            keyboards: [None; DEVICE_LANES],
            mouse: None,
            devices: [None; DEVICE_LANES],
            used: 0,
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
struct Descriptor {
    ports: u32,
    power_ms: u64,
    think_time: u32,
}
impl Descriptor {
    fn parse(bytes: [u8; 7]) -> Option<Self> {
        if bytes[0] < 7 || bytes[1] != 0x29 || bytes[2] == 0 {
            return None;
        }
        Some(Self {
            ports: bytes[2] as u32,
            power_ms: u64::from(bytes[5]) * 2,
            think_time: ((u16::from_le_bytes([bytes[3], bytes[4]]) >> 5) & 3) as u32,
        })
    }
}

impl Controller {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn enumerate_device(
        &mut self,
        slot: u32,
        lane: usize,
        route: Route,
        speed: u32,
        stride: usize,
        inventory: &mut Inventory,
    ) {
        let dev = self.classify_addressed(slot, lane, route.root_port, speed);
        lib::compact_println!(
            "xHCI: port {} route {:#x} speed {} class {} keyboard={} mouse={}",
            route.root_port,
            route.string,
            speed,
            dev.dev_class,
            dev.keyboard.is_some(),
            dev.mouse.is_some()
        );
        if dev.dev_class == 9 {
            if speed >= 4 {
                lib::compact_println!("xHCI: SuperSpeed hub unsupported (slot {})", slot);
                self.disable_slot(slot);
                return;
            }
            let Some(ports) = self.configure_hub(slot, dev, stride) else {
                lib::compact_println!("xHCI: hub setup failed (slot {})", slot);
                self.disable_slot(slot);
                return;
            };
            inventory.devices[lane] = Some((slot, dev));
            inventory.used += 1;
            lib::compact_println!(
                "xHCI: hub ready (slot {} ports {} root {} route {:#x})",
                slot,
                ports,
                route.root_port,
                route.string
            );
            if route.depth == 5 {
                lib::compact_println!("xHCI: hub route depth limit reached");
                return;
            }
            if ports > 15 {
                lib::compact_println!("xHCI: hub ports above 15 unsupported");
            }
            for downstream in 1..=ports.min(15) {
                if inventory.used == DEVICE_LANES {
                    lib::compact_println!("xHCI: device limit reached (including hubs)");
                    break;
                }
                let Some(speed) = self.reset_hub_port(slot, lane, downstream) else {
                    continue;
                };
                let Some(child_route) = route.child(downstream, slot, dev.speed, speed) else {
                    continue;
                };
                let Some(child_slot) = self.enable_slot() else {
                    continue;
                };
                let child_lane = inventory.used;
                if !self.address_device(child_slot, child_lane, child_route, speed, stride)
                    || !self.read_device_header(child_slot, child_lane, speed, stride)
                {
                    lib::compact_println!(
                        "xHCI: hub {} port {} child address/descriptor failed",
                        slot,
                        downstream
                    );
                    self.disable_slot(child_slot);
                    continue;
                }
                self.enumerate_device(
                    child_slot,
                    child_lane,
                    child_route,
                    speed,
                    stride,
                    inventory,
                );
            }
            return;
        }
        let mut retained = false;
        if let Some(ep) = dev.keyboard
            && let Some(index) = inventory.keyboards.iter().position(Option::is_none)
        {
            inventory.keyboards[index] = Some((slot, dev, ep));
            retained = true;
        }
        if inventory.mouse.is_none()
            && let Some(ep) = dev.mouse
        {
            inventory.mouse = Some((slot, dev, ep));
            retained = true;
        }
        if retained {
            inventory.devices[lane] = Some((slot, dev));
            inventory.used += 1;
        } else {
            self.disable_slot(slot);
        }
    }

    fn configure_hub(&mut self, slot: u32, dev: PortDevice, stride: usize) -> Option<u32> {
        if dev.cfg_value == 0
            || !self.control(slot, dev.lane, 0, 9, dev.cfg_value, 0, 0)
            || !self.control(slot, dev.lane, 0xa0, 6, 0x2900, 0, 7)
        {
            return None;
        }
        let mut bytes = [0; 7];
        for (i, byte) in bytes.iter_mut().enumerate() {
            *byte = unsafe { core::ptr::read_volatile((self.dma_va + XFER_OFF + i) as *const u8) };
        }
        let descriptor = Descriptor::parse(bytes)?;
        // Linux xhci_update_hub_device: copy live Slot, mark Hub, configure
        // port count and TT think time. Keep default single-TT alternate setting.
        unsafe {
            let input = self.dma_va + INCTX_OFF;
            core::ptr::write_bytes(input as *mut u8, 0, 4096);
            core::ptr::write_volatile((input + 4) as *mut u32, 1);
            let ctx = input + stride;
            core::ptr::copy_nonoverlapping(
                (self.dma_va + device_context_off(dev.lane)) as *const u8,
                ctx as *mut u8,
                stride,
            );
            let dw0 = core::ptr::read_volatile(ctx as *const u32);
            core::ptr::write_volatile(ctx as *mut u32, (dw0 | (1 << 26)) & !(1 << 25));
            let dw1 = core::ptr::read_volatile((ctx + 4) as *const u32);
            core::ptr::write_volatile(
                (ctx + 4) as *mut u32,
                (dw1 & 0x00ff_ffff) | (descriptor.ports << 24),
            );
            let dw2 = core::ptr::read_volatile((ctx + 8) as *const u32) & !(3 << 16);
            core::ptr::write_volatile(
                (ctx + 8) as *mut u32,
                dw2 | if dev.speed == 3 {
                    descriptor.think_time << 16
                } else {
                    0
                },
            );
            core::ptr::write_volatile((ctx + 12) as *mut u32, 0);
        }
        self.ring_cmd(
            self.dma_phys + INCTX_OFF as u64,
            0,
            (12 << 10) | (slot << 24),
        );
        if !matches!(self.wait_event(33), Some((1, _))) {
            return None;
        }
        for port in 1..=descriptor.ports {
            if !self.control(slot, dev.lane, 0x23, 3, 8, port, 0) {
                return None;
            } // PORT_POWER
        }
        if !port::delay((descriptor.power_ms + 100) * 1_000_000, || {
            crate::irq::now(false)
        }) {
            return None;
        }
        Some(descriptor.ports)
    }

    fn hub_status(&mut self, slot: u32, lane: usize, port: u32) -> Option<u32> {
        if !self.control(slot, lane, 0xa3, 0, 0, port, 4) {
            return None;
        }
        Some(unsafe { core::ptr::read_volatile((self.dma_va + XFER_OFF) as *const u32) })
    }
    fn reset_hub_port(&mut self, slot: u32, lane: usize, downstream: u32) -> Option<u32> {
        let mut stable = 0;
        // Connection debounce: 100ms stable, at most 1.5 seconds per port.
        for _ in 0..60 {
            let state = self.hub_status(slot, lane, downstream)?;
            if state & 1 == 0 {
                return None;
            }
            if state & (1 << 16) != 0 {
                if !self.control(slot, lane, 0x23, 1, 16, downstream, 0) {
                    return None;
                }
                stable = 0;
            } else {
                stable += 25;
            }
            if stable >= 100 {
                break;
            }
            if !port::delay(25_000_000, || crate::irq::now(false)) {
                return None;
            }
        }
        if stable < 100 || !self.control(slot, lane, 0x23, 3, 4, downstream, 0) {
            return None;
        }
        for _ in 0..50 {
            if !port::delay(10_000_000, || crate::irq::now(false)) {
                return None;
            }
            let state = self.hub_status(slot, lane, downstream)?;
            if state & 1 == 0 {
                return None;
            }
            if state & 0x1b == 3 && state & (1 << 20) != 0 {
                // Acknowledge port change bits only after reset is complete.
                for feature in 16..=20 {
                    if state & (1 << feature) != 0
                        && !self.control(slot, lane, 0x23, 1, feature, downstream, 0)
                    {
                        return None;
                    }
                }
                if !port::delay(50_000_000, || crate::irq::now(false)) {
                    return None;
                }
                let state = self.hub_status(slot, lane, downstream)?;
                if state & 0x1b != 3 {
                    return None;
                }
                return Some(if state & (1 << 9) != 0 {
                    2
                } else if state & (1 << 10) != 0 {
                    3
                } else {
                    1
                });
            }
        }
        lib::compact_println!("xHCI: hub {} port {} reset timed out", slot, downstream);
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn nested_routes_keep_root_and_tt_ancestor() {
        let hs = Route::root(7);
        let fs_hub = hs.child(3, 9, 3, 1).unwrap();
        let keyboard = fs_hub.child(4, 10, 1, 2).unwrap();
        assert_eq!(keyboard.string, 0x43);
        assert_eq!(
            (keyboard.root_port, keyboard.tt_slot, keyboard.tt_port),
            (7, 9, 3)
        );
        let highspeed_child = hs.child(5, 9, 3, 3).unwrap();
        assert_eq!((highspeed_child.tt_slot, highspeed_child.tt_port), (0, 0));
        let mouse = highspeed_child.child(2, 11, 3, 2).unwrap();
        assert_eq!((mouse.tt_slot, mouse.tt_port), (11, 2));
    }
    #[test]
    fn routing_limits_do_not_wrap_into_speed_bits() {
        let mut route = Route::root(1);
        for _ in 0..5 {
            route = route.child(15, 1, 1, 1).unwrap();
        }
        assert_eq!(route.string, 0xfffff);
        assert!(route.child(1, 1, 1, 1).is_none());
        assert!(Route::root(1).child(0, 1, 1, 1).is_none());
        assert!(Route::root(1).child(16, 1, 1, 1).is_none());
    }
    #[test]
    fn validates_hub_descriptor_and_power_delay() {
        assert_eq!(
            Descriptor::parse([9, 0x29, 8, 0x60, 0, 50, 0]),
            Some(Descriptor {
                ports: 8,
                think_time: 3,
                power_ms: 100
            })
        );
        for data in [[0; 7], [9, 0x2a, 8, 0, 0, 0, 0], [9, 0x29, 0, 0, 0, 0, 0]] {
            assert!(Descriptor::parse(data).is_none());
        }
    }
}
