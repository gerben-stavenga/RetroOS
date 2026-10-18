// SPDX-License-Identifier: BSD-3-Clause-Clear
// PCI register sequencing adapted from ath12k.
// Copyright (c) 2019-2021 The Linux Foundation. All rights reserved.
// Copyright (c) 2021-2023 Qualcomm Innovation Center, Inc. All rights reserved.
//! Qualcomm WCN7850 hw2.0 (PCI 17cb:1107) firmware/control bring-up.
//! Hardware register sequencing references Linux v6.8 ath12k (BSD-3-Clause-Clear).
//! DMA remains resident for the boot lifetime, including on failure.
mod control;
mod hardware;
mod packets;
mod reset;
mod wlanfw;
use super::mhi::dma::{Dma, Image};
use super::{dma::Mmio, mhi};
use crate::kernel::{firmware, pci, portio, qrtr};
use mhi::Registers;

const WINDOW: u32 = 0x80000;
const MSI_SOURCE: u8 = 1;

pub struct Device {
    transport: mhi::Transport<Soc, Dma>,
    _image: Image,
    _control_memory: alloc::vec::Vec<wlanfw::HostMemory>,
    _firmware_topology: Option<wlanfw::FirmwareTopology>,
    router: qrtr::Router,
    address: (u8, u8, u8),
    failed: bool,
    ce: crate::kernel::drivers::ce::Engine<Dma>,
    control: control::Control,
    _dump: mhi::dump::CrashDump<Dma>,
    packet_engine: super::qca_dp::Bootstrap<Dma>,
}

struct Soc {
    registers: Mmio,
    window: Option<u32>,
    shadows: Option<super::srng::ShadowMap>,
}
impl Soc {
    fn offset(&mut self, offset: u32) -> mhi::Result<usize> {
        if !offset.is_multiple_of(4) || offset > 0x01ff_fffc {
            return Err(mhi::Error::Registers);
        }
        if offset < WINDOW {
            return Ok(offset as usize);
        }
        let window = 0x4000_0000 | ((offset >> 19) & 0x3f);
        if self.window != Some(window) {
            self.registers.write(0x310c, window);
            if self.registers.read(0x310c) == u32::MAX {
                crate::compact_println!(
                    "WiFi: register window unavailable selecting SoC address={:08x}",
                    offset
                );
                return Err(mhi::Error::Link);
            }
            self.window = Some(window);
        }
        Ok((WINDOW + (offset & (WINDOW - 1))) as usize)
    }
    fn delay(&mut self, milliseconds: u64) -> mhi::Result<()> {
        reset::delay(self, milliseconds)
    }
}
impl Registers for Soc {
    fn read(&mut self, offset: u32) -> mhi::Result<u32> {
        let mapped = self.offset(offset)?;
        let value = self.registers.read(mapped);
        if value == u32::MAX {
            self.window = None;
            crate::compact_println!(
                "WiFi: register read returned ffffffff: SoC address={:08x}, BAR offset={:06x}",
                offset,
                mapped
            );
            Err(mhi::Error::Link)
        } else {
            Ok(value)
        }
    }
    fn write(&mut self, offset: u32, value: u32) -> mhi::Result<()> {
        if let Some(alias) = self.shadows.and_then(|map| map.write_alias(offset)) {
            self.registers.write(alias, value);
            return Ok(());
        }
        let offset = self.offset(offset)?;
        self.registers.write(offset, value);
        Ok(())
    }
    fn now(&mut self) -> u64 {
        portio::now_ns()
    }
}

fn prepare_pci<A: crate::Arch>(machine: &mut A, address: (u8, u8, u8)) -> Option<(u64, u32)> {
    let (bus, dev, func) = address;
    let read = |machine: &mut A, off| pci::read32(machine, bus, dev, func, off);
    let bar = read(machine, 0x10);
    if bar & 1 != 0 || bar & !15 == 0 {
        return None;
    }
    let upper = if bar & 6 == 4 { read(machine, 0x14) } else { 0 };
    let base = u64::from(bar & !15) | (u64::from(upper) << 32);
    let command = read(machine, 4) & 0xffff;
    pci::write32(machine, bus, dev, func, 4, (command | 2) & !4);
    // Bound the capability walk; malformed firmware/device data must not loop.
    let mut offset = (read(machine, 0x34) & 0xfc) as u8;
    for _ in 0..48 {
        if !(0x40..=0xf0).contains(&offset) {
            break;
        }
        let header = read(machine, offset);
        match header & 255 {
            1 => {
                // Bring the function to D0 before MMIO/reset.
                let value = read(machine, offset + 4) & !0x8003;
                pci::write32(machine, bus, dev, func, offset + 4, value);
            }
            5 => {
                // Disarm stale MSI until the new message is installed.
                pci::write32(machine, bus, dev, func, offset, header & !(1 << 16));
            }
            0x10 if offset <= 0xec => {
                // Keep the link awake throughout firmware loading.
                let value = read(machine, offset + 0x10) & 0xfffc;
                pci::write32(machine, bus, dev, func, offset + 0x10, value);
            }
            _ => {}
        }
        let next = ((header >> 8) & 0xfc) as u8;
        if next == offset {
            break;
        }
        offset = next;
    }
    Some((base, command))
}

pub fn probe<A: crate::Arch>(machine: &mut A) -> Option<Device> {
    let (address, chip) =
        pci::find_classes(machine, 2, 0x80)
            .into_iter()
            .find_map(|address @ (b, d, f)| {
                let id = pci::read32(machine, b, d, f, 0);
                hardware::SUPPORTED
                    .iter()
                    .find(|chip| chip.pci_id == id)
                    .map(|chip| (address, chip))
            })?;
    let (bus, dev, func) = address;
    let subsystem = pci::read32(machine, bus, dev, func, 0x2c);
    crate::compact_println!(
        "WiFi: {} {:02x}:{:02x}.{} subsystem={:08x}",
        chip.name,
        bus,
        dev,
        func,
        subsystem
    );
    crate::kernel::wifi::report("WCN785x detected; loading firmware");
    let bytes = match firmware::request(chip.firmware, chip.firmware_limit) {
        Ok(bytes) => bytes,
        Err(_) => {
            crate::kernel::wifi::report("WCN785x firmware missing or unreadable; install amss.bin");
            return None;
        }
    };
    if bytes.len() < 64 || &bytes[..4] != b"\x7fELF" {
        crate::kernel::wifi::report(
            "WCN785x invalid AMSS image (requires uncompressed ELF firmware)",
        );
        return None;
    }
    let Some((base, command)) = prepare_pci(machine, address) else {
        crate::kernel::wifi::report("WCN785x invalid or unassigned PCI BAR");
        return None;
    };
    let mut stage = "PCI BAR mapping";
    let result: core::result::Result<Device, wlanfw::Error> = (|| {
        let registers = Mmio::map(machine, base, chip.bar_bytes).ok_or(mhi::Error::Registers)?;
        let mut soc = Soc {
            registers,
            window: None,
            shadows: None,
        };
        let shadows =
            super::srng::ShadowMap::new(chip.shadow_base, chip.shadow_targets, WINDOW as usize)?;
        soc.delay(10)?;
        let version = soc.read(0x01b0_0000)?;
        crate::compact_println!(
            "WiFi: WCN785x SoC version={:08x}, AMSS bytes={}",
            version,
            bytes.len()
        );
        if (version >> 8) & 15 != chip.soc_major {
            return Err(mhi::Error::State.into());
        }
        stage = "firmware DMA allocation";
        let image =
            Image::allocate(machine, &bytes, chip.dma_bits).ok_or(mhi::Error::Allocation)?;
        stage = "MHI context allocation";
        let mut contexts = Dma::allocate(machine, mhi::CONTEXT_BYTES, chip.dma_bits)
            .ok_or(mhi::Error::Allocation)?;
        stage = "IPCR packet allocation";
        let packets = Dma::allocate(machine, mhi::PACKET_STORAGE, chip.dma_bits)
            .ok_or(mhi::Error::Allocation)?;
        reset::run(&mut soc, &mut stage, chip.hot_reset)?;
        soc.window = None;
        stage = "MSI setup";
        let (msi_address, msi_data) = machine.msi_alloc(MSI_SOURCE).ok_or(mhi::Error::Registers)?;
        if !pci::msi_enable(machine, bus, dev, func, msi_address, msi_data) {
            return Err(mhi::Error::Registers.into());
        }
        pci::write32(machine, bus, dev, func, 4, command | 6 | (1 << 10));
        let layout = mhi::Layout::read(&mut soc, chip.bar_bytes as u32)?;
        crate::compact_println!(
            "WiFi: BHI={:x} BHIE={:x} CHDB={:x} ERDB={:x}",
            layout.bhi,
            layout.bhie,
            layout.channel_db,
            layout.event_db
        );
        stage = "BHI/BHIE firmware boot";
        crate::kernel::wifi::report("WCN785x booting AMSS firmware");
        let boot_result = mhi::boot(
            &mut soc,
            &mut contexts,
            layout,
            chip.channels,
            image.firmware(),
        );
        if boot_result.is_err() {
            crate::compact_println!(
                "WiFi: MHI status={:08x} EE={:08x} BHI status={:08x} error={:08x}",
                soc.read(0x48).unwrap_or(u32::MAX),
                soc.read(layout.bhi + 0x28).unwrap_or(u32::MAX),
                soc.read(layout.bhi + 0x2c).unwrap_or(u32::MAX),
                soc.read(layout.bhi + 0x30).unwrap_or(u32::MAX)
            );
        }
        boot_result?;
        // A visible AMSS EE need not mean its command handler is ready yet.
        // Follow the settling interval used by OpenBSD if_qwx_pci.c before START.
        stage = "AMSS firmware settling";
        soc.delay(chip.mission_settle_ms)?;
        crate::compact_println!("WiFi: AMSS settling delay={} ms", chip.mission_settle_ms);
        stage = "IPCR channel start";
        let mut transport = mhi::Transport::new(soc, contexts, packets, layout, chip.channels);
        let started = transport.start();
        if started.is_err() {
            transport.log_state();
        }
        started?;
        let mut router = qrtr::Router::new(1, chip.control_service);
        transport.send(&router.hello())?;
        transport.send(&router.lookup())?;
        crate::kernel::wifi::report("WCN785x firmware booted; discovering WLAN control service");
        let initialized = wlanfw::initialize(
            machine,
            &mut transport,
            &mut router,
            chip,
            subsystem,
            &mut stage,
            layout,
        );
        if initialized.is_err() {
            transport.log_state();
        }
        let boot = initialized?;
        // WLAN_CONFIG and mission mode have completed successfully. Initial
        // CE posting used direct doorbells; subsequent writes use the same
        // ordered aliases now installed by firmware. Reads remain direct.
        transport.io.shadows = Some(shadows);
        crate::compact_println!(
            "WiFi: shadow-v3 doorbells={} base={:x}",
            chip.shadow_targets.len(),
            chip.shadow_base
        );
        let mut ce = boot.ce;
        let mut dump = boot.dump;
        stage = "packet engine DMA allocation";
        let needed = super::qca_dp::Bootstrap::<Dma>::required_bytes(chip.packet_engine)?;
        let memory =
            Dma::allocate_aligned(machine, needed, chip.dma_bits).ok_or(mhi::Error::Allocation)?;
        let mut packet_engine = super::qca_dp::Bootstrap::new(chip.packet_engine, memory, needed)?;
        stage = "packet engine rings";
        packet_engine.start(&mut transport.io)?;
        let started = (|| -> core::result::Result<_, wlanfw::Error> {
            stage = "packet engine cookie table";
            let cmem = boot.cmem.ok_or(mhi::Error::Registers)?;
            let needed = super::qca_dp::cookie::Table::<Dma>::required_bytes(chip.cookies)?;
            let memory = Dma::allocate_aligned(machine, needed, chip.dma_bits)
                .ok_or(mhi::Error::Allocation)?;
            let cookies = super::qca_dp::cookie::Table::new(chip.cookies, memory, needed, cmem)?;
            packet_engine.install_cookies(&mut transport.io, cookies)?;
            stage = "receive buffer allocation";
            let needed = super::qca_dp::rx::Receive::<Dma>::required_bytes(chip.receive)?;
            let memory =
                Dma::allocate(machine, needed, chip.dma_bits).ok_or(mhi::Error::Allocation)?;
            let receive = super::qca_dp::rx::Receive::new(
                chip.receive,
                memory,
                needed,
                chip.cookies.rx_range()?,
            )?;
            stage = "station frame DMA allocation";
            let frames = Dma::allocate(machine, super::qca_dp::frames::BYTES, chip.dma_bits)
                .ok_or(mhi::Error::Allocation)?;
            let frames = super::qca_dp::frames::Frames::new(frames);
            control::Control::start(
                &mut transport,
                &mut router,
                &mut ce,
                &mut packet_engine,
                control::Buffers { receive, frames },
                chip,
                &mut stage,
            )
        })();
        if started.is_err() {
            match dump.collect(&mut transport.io, layout) {
                Ok(Some(mut bytes)) => {
                    let (physical, snapshot) = ce.snapshot();
                    wlanfw::append_paging_dump(
                        &mut bytes,
                        &boot.memory,
                        Some((physical, &snapshot)),
                    );
                    match crate::kernel::wifi::save_dump(machine, &bytes) {
                        Ok(path) => {
                            let path = alloc::string::String::from_utf8_lossy(&path);
                            crate::compact_println!(
                                "WiFi: firmware crash dump saved to {}",
                                path.as_ref()
                            );
                        }
                        Err(error) => crate::compact_println!(
                            "WiFi: saving firmware crash dump failed: {}",
                            error
                        ),
                    }
                }
                Ok(None) => {}
                Err(error) => {
                    crate::compact_println!("WiFi: firmware crash dump failed: {}", error.message())
                }
            }
            transport.log_state();
            ce.log_state(&mut transport.io);
            packet_engine.log_state(&mut transport.io);
        }
        let control = started?;
        crate::kernel::wifi::report("WCN785x firmware ready; disconnected");
        Ok(Device {
            transport,
            _image: image,
            _control_memory: boot.memory,
            _firmware_topology: boot.topology,
            router,
            address,
            failed: false,
            ce,
            control,
            _dump: dump,
            packet_engine,
        })
    })();
    match result {
        Ok(device) => Some(device),
        Err(error) => {
            pci::disable_bus_master(address);
            crate::kernel::wifi::report(&alloc::format!(
                "WCN785x {} failed: {}",
                stage,
                error.message()
            ));
            None
        }
    }
}

impl Device {
    pub fn poll(&mut self) {
        if self.failed {
            return;
        }
        if let Err(error) = self.poll_inner() {
            self.transport.log_state();
            self.ce.log_state(&mut self.transport.io);
            self.packet_engine.log_state(&mut self.transport.io);
            self.transport.reset();
            pci::disable_bus_master(self.address);
            self.failed = true;
            crate::kernel::wifi::event(crate::kernel::wifi::link::Event::Disconnected);
            let message = error.message();
            crate::compact_println!("WiFi: control transport stopped: {}", message.as_str());
            crate::kernel::wifi::report("WCN785x control transport failed; see kernel log");
        }
    }
    fn poll_inner(&mut self) -> core::result::Result<(), wlanfw::Error> {
        self.control
            .poll(&mut self.transport, &mut self.router, &mut self.ce)?;
        self.control
            .packet_poll(&mut self.packet_engine, &mut self.transport.io)
    }
}

impl crate::kernel::wifi::Radio for Device {
    fn transmit(&mut self, frame: &[u8]) -> bool {
        !self.failed
            && self
                .control
                .ethernet(&mut self.packet_engine, &mut self.transport.io, frame, None)
                .is_ok()
    }
    fn mac_address(&self) -> Option<[u8; 6]> {
        (!self.failed).then(|| self.control.mac_address())
    }
    fn action(&mut self, action: crate::kernel::wifi::link::Action) -> Result<(), i32> {
        if self.failed {
            return Err(-19);
        }
        if matches!(&action, crate::kernel::wifi::link::Action::StartChannel(_))
            && !self.packet_engine.transmit_idle()
        {
            return Err(-16);
        }
        if let crate::kernel::wifi::link::Action::Eapol { id, bytes } = action {
            let Some(peer) = self.control.peer_address() else {
                return Err(-107);
            };
            let mut frame = peer.to_vec();
            frame.extend_from_slice(&self.control.mac_address());
            frame.extend_from_slice(&[0x88, 0x8e]);
            frame.extend_from_slice(&bytes);
            return self
                .control
                .ethernet(
                    &mut self.packet_engine,
                    &mut self.transport.io,
                    &frame,
                    Some(id),
                )
                .map_err(|_| -5);
        }
        self.control
            .action(action, &mut self.transport, &mut self.router, &mut self.ce)
            .map_err(|e| {
                let message = e.message();
                crate::compact_println!("WiFi: station command failed: {}", message.as_str());
                -5
            })
    }
    fn poll(&mut self) {
        Device::poll(self);
    }
    fn scan(&mut self) -> core::result::Result<(), i32> {
        if self.failed {
            return Err(-19);
        }
        match self
            .control
            .scan(&mut self.transport, &mut self.router, &mut self.ce)
        {
            Ok(true) => Ok(()),
            Ok(false) => Err(-16),
            Err(error) => {
                let message = error.message();
                crate::compact_println!("WiFi: starting scan failed: {}", message.as_str());
                crate::kernel::wifi::scan_phase(crate::kernel::wifi::scan::Phase::Failed(4));
                Err(-5)
            }
        }
    }
}
