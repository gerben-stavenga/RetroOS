use super::*;

struct Fixture {
    controller: Controller,
    _dma: alloc::vec::Vec<u64>,
    _mmio: alloc::vec::Vec<u64>,
}

impl Fixture {
    fn new() -> Self {
        let mut dma = alloc::vec![0u64; DMA_PAGES * 4096 / 8];
        let mut mmio = alloc::vec![0u64; 4096 / 8];
        let mut controller = Controller::new(0, (0, 0, 0));
        controller.dma_va = dma.as_mut_ptr() as usize;
        controller.dma_phys = 0x100000;
        controller.mmio_va = mmio.as_mut_ptr() as usize;
        controller.rt = 0x100;
        controller.db = 0x200;
        Self {
            controller,
            _dma: dma,
            _mmio: mmio,
        }
    }

    fn pipe(&mut self, index: usize, slot: u32, dci: u32, len: usize) {
        let c = &mut self.controller;
        c.init_int_ring(index);
        c.pipes[index].ready = true;
        c.pipes[index].slot = slot;
        c.pipes[index].dci = dci;
        c.pipes[index].report_len = len;
    }

    fn event(&mut self, index: usize, kind: u32, slot: u32, dci: u32, cc: u32, residual: u32) {
        let c = &self.controller;
        unsafe {
            let trb = (c.dma_va + EVT_OFF + index * 16) as *mut u32;
            trb.add(2).write((cc << 24) | residual);
            trb.add(3)
                .write(1 | (kind << 10) | (dci << 16) | (slot << 24));
        }
    }

    fn report(&mut self, index: usize, bytes: &[u8]) {
        unsafe {
            core::ptr::copy_nonoverlapping(
                bytes.as_ptr(),
                (self.controller.dma_va + report_off(index)) as *mut u8,
                bytes.len(),
            );
        }
    }
}

#[test]
fn boot_mouse_report_preserves_signed_motion_and_buttons() {
    let mut report = [0u8; 16];
    report[..4].copy_from_slice(&[0b101, 0xfe, 0x7f, 1]);
    assert_eq!(decode_mouse_report(&report, 4), Some((-2, 127, 0b101)));
    assert_eq!(decode_mouse_report(&report, 2), None);
}

#[test]
fn setup_finishes_before_any_keyboard_or_mouse_transfer_is_published() {
    let mut f = Fixture::new();
    // A composite KVM uses one slot and separate keyboard/mouse endpoints.
    f.pipe(0, 1, 3, 8);
    f.pipe(2, 1, 5, 8);
    // Setup can consume command completions, but no report has been submitted.
    f.event(0, 33, 1, 0, 1, 0);
    assert_eq!(f.controller.wait_event(33), Some((1, 1)));
    assert!(f.controller.pipes.iter().all(|p| p.enq == 0));
    f.controller.start_pipes();
    assert_eq!(f.controller.pipes.map(|p| p.enq), [1, 0, 1]);
    f.report(0, &[0, 0, 4, 0, 0, 0, 0, 0]);
    f.report(2, &[1, 2, 3]);
    f.event(1, 32, 1, 3, 1, 0);
    f.event(2, 32, 1, 5, 13, 5);
    f.controller.poll();
    crate::irq::KEYS.with(|keys| assert_eq!(*keys.borrow(), [0x1e]));
    crate::irq::MOUSE.with(|events| assert_eq!(*events.borrow(), [(2, 3, 1)]));
    assert_eq!(f.controller.pipes.map(|p| p.enq), [2, 0, 2]);
}

#[test]
fn short_mouse_report_does_not_invent_motion_or_release_buttons() {
    let mut f = Fixture::new();
    f.pipe(2, 1, 5, 8);
    f.controller.start_pipes();
    f.report(2, &[1, 20]);
    f.event(0, 32, 1, 5, 13, 6); // only two bytes actually received
    f.controller.poll();
    crate::irq::MOUSE.with(|events| assert!(events.borrow().is_empty()));
    assert_eq!(f.controller.pipes[2].enq, 2);
}

#[test]
fn boot_keyboard_layout_is_independent_of_endpoint_packet_size() {
    let mut f = Fixture::new();
    f.pipe(0, 1, 3, 16);
    f.controller.start_pipes();
    // An eight-byte report on a sixteen-byte endpoint remains a boot report.
    f.report(0, &[2, 0, 4, 0, 0, 0, 0, 0]);
    f.event(0, 32, 1, 3, 13, 8);
    f.controller.poll();
    crate::irq::KEYS.with(|keys| assert_eq!(*keys.borrow(), [0x2a, 0x1e]));
    // A truncated next report must leave both held keys intact.
    f.report(0, &[0, 0]);
    f.event(1, 32, 1, 3, 13, 14);
    f.controller.poll();
    crate::irq::KEYS.with(|keys| assert_eq!(*keys.borrow(), [0x2a, 0x1e]));
    f.report(0, &[0; 8]);
    f.event(2, 32, 1, 3, 13, 8);
    f.controller.poll();
    crate::irq::KEYS.with(|keys| assert_eq!(*keys.borrow(), [0x2a, 0x1e, 0xaa, 0x9e]));
}

#[test]
fn legacy_report_id_keyboard_keeps_its_layout_for_short_packets() {
    let mut f = Fixture::new();
    f.pipe(0, 1, 3, 16);
    f.controller.pipes[0].keyboard_report_id = true;
    f.controller.start_pipes();
    f.report(0, &[1, 2, 4, 0, 0, 0, 0, 0]);
    f.event(0, 32, 1, 3, 13, 8);
    f.controller.poll();
    crate::irq::KEYS.with(|keys| assert_eq!(*keys.borrow(), [0x2a, 0x1e]));
    f.report(0, &[2, 0, 0, 0, 0, 0, 0, 0]); // unrelated consumer report
    f.event(1, 32, 1, 3, 13, 8);
    f.controller.poll();
    crate::irq::KEYS.with(|keys| assert_eq!(*keys.borrow(), [0x2a, 0x1e]));
}

#[test]
fn rollover_preserves_held_keys_until_a_valid_report() {
    let mut previous = [0; 16];
    let mut report = [0; 16];
    report[2] = 4;
    Controller::process_keyboard_report(&mut previous, &report, 8, false);
    report[2..8].fill(1);
    Controller::process_keyboard_report(&mut previous, &report, 8, false);
    crate::irq::KEYS.with(|keys| assert_eq!(*keys.borrow(), [0x1e]));
    Controller::process_keyboard_report(&mut previous, &[0; 16], 8, false);
    crate::irq::KEYS.with(|keys| assert_eq!(*keys.borrow(), [0x1e, 0x9e]));
}

#[test]
fn boot_interfaces_negotiate_protocol_before_configuring_endpoints() {
    for (role, pipe) in [(HidRole::Keyboard, 0), (HidRole::Mouse, 2)] {
        let mut f = Fixture::new();
        let ep = EpInfo {
            iface: 3,
            boot: true,
            ep: 1,
            mps: 16,
            interval: 10,
        };
        let dev = PortDevice {
            lane: 0,
            port: 1,
            speed: 2,
            dev_class: 0,
            cfg_value: 1,
            keyboard: None,
            mouse: None,
        };
        f.event(0, 32, 1, 1, 1, 0); // SET_PROTOCOL
        f.event(1, 32, 1, 1, 1, 0); // SET_IDLE
        f.event(2, 33, 1, 0, 1, 0); // Configure Endpoint
        assert!(f.controller.configure_hid(1, &dev, ep, role, pipe, 32));
        let setup = unsafe { *((f.controller.dma_va + ep0_off(0)) as *const u64) };
        assert_eq!(setup, 0x0000_0003_0000_0b21); // interface 3, protocol 0
        assert!(!f.controller.pipes[pipe].keyboard_report_id);
        assert_eq!(f.controller.pipes[pipe].enq, 0);
        assert_eq!(f.controller.evt_deq, 3);
    }
}

#[test]
fn failed_boot_protocol_request_does_not_publish_an_input_pipe() {
    let mut f = Fixture::new();
    let ep = EpInfo {
        iface: 0,
        boot: true,
        ep: 1,
        mps: 8,
        interval: 10,
    };
    let dev = PortDevice {
        lane: 0,
        port: 1,
        speed: 2,
        dev_class: 0,
        cfg_value: 1,
        keyboard: None,
        mouse: None,
    };
    f.event(0, 32, 1, 1, 6, 0); // Stall Error
    assert!(
        !f.controller
            .configure_hid(1, &dev, ep, HidRole::Keyboard, 0, 32)
    );
    assert_eq!(f.controller.cmd_enq, 0);
    assert!(!f.controller.pipes[0].ready);
}

#[test]
fn downstream_address_context_keeps_route_and_transaction_translator() {
    for stride in [32, 64] {
        let mut f = Fixture::new();
        let route = Route::root(7)
            .child(3, 4, 3, 1)
            .unwrap()
            .child(2, 5, 1, 2)
            .unwrap();
        f.event(0, 33, 6, 0, 1, 0);
        assert!(f.controller.address_device(6, 7, route, 2, stride));
        unsafe {
            let ctx = f.controller.dma_va + INCTX_OFF + stride;
            assert_eq!(*(ctx as *const u32), (1 << 27) | (2 << 20) | 0x23);
            assert_eq!(*((ctx + 4) as *const u32), 7 << 16);
            assert_eq!(*((ctx + 8) as *const u32), 4 | (3 << 8));
            assert_eq!(
                *((f.controller.dma_va + DCBAA_OFF + 6 * 8) as *const u64),
                f.controller.dma_phys + device_context_off(7) as u64
            );
        }
    }
}
