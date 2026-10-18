//! Driver startup coordinator; protocol framing lives in shared HTC/WMI modules.
use super::{Dma, hardware::Chip, mhi, wlanfw::Error};
use crate::kernel::{
    drivers::{ce, qca_dp},
    htc, htt, qrtr, wifi, wmi,
};
use mhi::Registers;
const TIMEOUT: u64 = 10_000_000_000;
const MAX_SPINS: usize = 5_000_000;
type Result<T> = core::result::Result<T, Error>;

pub(super) struct Control {
    htc: htc::State,
    htt: htt::State,
    receive: qca_dp::rx::Receive<Dma>,
    wmi: wmi::State,
    config: ce::Config,
    radio: wmi::scan::RadioConfig,
    station_created: bool,
    scan: Option<wmi::scan::Session>,
    scan_sequence: u32,
}
impl Control {
    pub(super) fn start<R: Registers>(
        transport: &mut mhi::Transport<R, Dma>,
        router: &mut qrtr::Router,
        ce: &mut ce::Engine<Dma>,
        packet_engine: &mut crate::kernel::drivers::qca_dp::Bootstrap<Dma>,
        receive: qca_dp::rx::Receive<Dma>,
        chip: &Chip,
        stage: &mut &'static str,
    ) -> Result<Self> {
        let mut this = Self {
            htc: htc::State::new(),
            htt: htt::State::default(),
            receive,
            wmi: wmi::State::new(),
            config: chip.ce,
            radio: chip.radio,
            station_created: false,
            scan: None,
            scan_sequence: 0,
        };
        *stage = "HTC target ready";
        this.wait(transport, router, ce, |this| this.htc.ready)?;
        crate::compact_println!(
            "WiFi: HTC target ready credit size={}",
            this.htc.credit_size
        );
        *stage = "HTC HTT service connection";
        let bytes = this.htc.connect(htc::HTT_DATA)?;
        this.send_control(transport, router, ce, &bytes)?;
        this.wait(transport, router, ce, |this| {
            this.htc.endpoint(htc::HTT_DATA).is_some()
        })?;
        crate::compact_println!(
            "WiFi: HTC HTT endpoint={}",
            this.htc.endpoint(htc::HTT_DATA).unwrap()
        );
        *stage = "HTC WMI service connection";
        let bytes = this.htc.connect(htc::WMI_CONTROL)?;
        this.send_control(transport, router, ce, &bytes)?;
        this.wait(transport, router, ce, |this| {
            this.htc.endpoint(htc::WMI_CONTROL).is_some()
        })?;
        crate::compact_println!(
            "WiFi: HTC WMI endpoint={}",
            this.htc.endpoint(htc::WMI_CONTROL).unwrap()
        );
        *stage = "HTC setup complete";
        let bytes = this.htc.setup_complete()?;
        this.send_control(transport, router, ce, &bytes)?;
        *stage = "WMI service ready";
        this.wait(transport, router, ce, |this| this.wmi.services_ready())?;
        *stage = "packet engine REO destinations";
        packet_engine.start_receive(&mut transport.io)?;
        *stage = "WMI resource initialization";
        let command = this
            .wmi
            .initialize_command(&(chip.wmi_resources)(this.wmi.rf_chains()))?;
        this.send_wmi(transport, router, ce, &command)?;
        this.wmi.mark_init_sent()?;
        *stage = "WMI unified ready";
        this.wait(transport, router, ce, |this| this.wmi.ready)?;
        let mac = this.wmi.mac;
        crate::compact_println!(
            "WiFi: WMI ready MAC={:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            mac[0],
            mac[1],
            mac[2],
            mac[3],
            mac[4],
            mac[5]
        );
        *stage = "HTT version negotiation";
        this.send_service(
            htc::HTT_DATA,
            transport,
            router,
            ce,
            &htt::version_request(),
        )?;
        this.wait(transport, router, ce, |this| this.htt.version.is_some())?;
        *stage = "HTT receive ring registration";
        this.receive.start()?;
        for packet in this.receive.commands()? {
            this.send_service(htc::HTT_DATA, transport, router, ce, &packet)?;
        }
        *stage = "HTT receive filters";
        for ring in chip.receive.rings {
            let packet = match ring.role {
                qca_dp::rx::Role::Mac => {
                    htt::rx_filter(ring.pdev, chip.receive.buffer_bytes, chip.rx_layout)?
                }
                qca_dp::rx::Role::Monitor => {
                    htt::disable_monitor(ring.pdev, chip.receive.buffer_bytes)?
                }
                _ => continue,
            };
            this.send_service(htc::HTT_DATA, transport, router, ce, &packet)?;
        }
        *stage = "WMI radio configuration";
        crate::compact_println!(
            "WiFi: configuring radio RF-kill support={}",
            this.wmi.rfkill_supported
        );
        for packet in wmi::radio::commands(
            chip.radio.pdev,
            chip.radio_setup,
            this.wmi.rf_chains(),
            this.wmi.rfkill_supported,
        )? {
            this.send_wmi(transport, router, ce, &packet)?;
        }
        this.receive.log_state();
        Ok(this)
    }
    fn route(&self, service: u16, direction: u32) -> Result<u8> {
        let route = self
            .config
            .services
            .iter()
            .find(|entry| entry[0] == u32::from(service) && entry[1] == direction)
            .ok_or(Error::State)?;
        u8::try_from(route[2]).map_err(|_| Error::State)
    }
    pub(super) fn poll<R: Registers>(
        &mut self,
        transport: &mut mhi::Transport<R, Dma>,
        router: &mut qrtr::Router,
        ce: &mut ce::Engine<Dma>,
    ) -> Result<()> {
        self.receive.poll()?;
        transport.poll()?;
        for _ in 0..32 {
            let Some(bytes) = transport.receive() else {
                break;
            };
            for reply in router.receive(&bytes).map_err(|_| Error::State)? {
                transport.send(&reply)?;
            }
        }
        ce.poll(&mut transport.io)?;
        for _ in 0..64 {
            let Some((pipe, bytes)) = ce.receive() else {
                break;
            };
            let frame = htc::Frame::parse(&bytes)?;
            if frame.endpoint == 0 {
                // Firmware boot control can arrive on CE1 or the reserved-control mapping (CE2).
                if !self.config.control_receive.contains(&pipe) {
                    return Err(Error::State);
                }
            } else if Some(frame.endpoint) == self.htc.endpoint(htc::WMI_CONTROL) {
                if pipe != self.route(htc::WMI_CONTROL, 1)? {
                    return Err(Error::State);
                }
            } else if Some(frame.endpoint) == self.htc.endpoint(htc::HTT_DATA) {
                if pipe != self.route(htc::HTT_DATA, 1)? {
                    return Err(Error::State);
                }
            } else {
                return Err(Error::State);
            }
            if let Some(frame) = self.htc.receive(&bytes)? {
                if Some(frame.endpoint) == self.htc.endpoint(htc::WMI_CONTROL) {
                    self.wmi.receive(frame.payload)?;
                    while let Some(event) = self.wmi.next_event() {
                        self.radio_event(event);
                    }
                } else if Some(frame.endpoint) == self.htc.endpoint(htc::HTT_DATA) {
                    self.htt.receive(frame.payload)?;
                }
            }
        }
        if self
            .scan
            .as_ref()
            .is_some_and(|scan| transport.io.now() >= scan.deadline)
        {
            let scan = self.scan.take().unwrap();
            self.wmi.management_stats.log();
            self.receive.log_state();
            wifi::scan_phase(wifi::scan::Phase::Failed(3)); // timed out
            // Clear the session before sending: send_wmi polls recursively
            // while waiting for credits and must not cancel the same scan twice.
            let stop = wmi::scan::stop(self.radio, 0, scan.id)?;
            self.send_wmi(transport, router, ce, &stop)?;
        }
        Ok(())
    }
    fn radio_event(&mut self, event: wmi::scan::Event) {
        let Some(session) = &self.scan else {
            return;
        };
        match event {
            wmi::scan::Event::Network(network) => wifi::scan_observe(network),
            wmi::scan::Event::Scan(event) => {
                let Some(phase) = session.phase(event) else {
                    return;
                };
                if !matches!(phase, wifi::scan::Phase::Running) {
                    self.scan = None;
                    self.wmi.management_stats.log();
                    self.receive.log_state();
                }
                wifi::scan_phase(phase);
            }
        }
    }
    pub(super) fn scan<R: Registers>(
        &mut self,
        transport: &mut mhi::Transport<R, Dma>,
        router: &mut qrtr::Router,
        ce: &mut ce::Engine<Dma>,
    ) -> Result<bool> {
        if self.scan.is_some() {
            return Ok(false);
        }
        if self.wmi.radio_on == Some(false) {
            return Err(Error::State);
        }
        let report = self
            .wmi
            .regulatory
            .iter()
            .find(|r| r.phy == self.radio.regulatory_phy)
            .ok_or(Error::State)?;
        let channels = wmi::scan::channels(report);
        if channels.is_empty() {
            return Err(Error::State);
        }
        crate::compact_println!(
            "WiFi: passive scan channels={} pdev={}",
            channels.len(),
            self.radio.pdev
        );
        if !self.station_created {
            let bytes =
                wmi::scan::create_station(self.radio, 0, self.wmi.mac, self.wmi.rf_chains())?;
            self.send_wmi(transport, router, ce, &bytes)?;
            self.station_created = true;
            crate::compact_println!(
                "WiFi: station interface created vdev=0 pdev={}",
                self.radio.pdev
            );
        }
        for bytes in wmi::scan::station_awake(0, self.wmi.rf_chains())? {
            self.send_wmi(transport, router, ce, &bytes)?;
        }
        let bytes = wmi::scan::channel_list(self.radio, &channels)?;
        self.send_wmi(transport, router, ce, &bytes)?;
        self.scan_sequence = (self.scan_sequence + 1) & 0xfff;
        let id = 0xa000 | self.scan_sequence;
        let bytes = wmi::scan::start(0, id, &channels)?;
        wifi::scan_begin();
        self.wmi.management_stats = wmi::ManagementStats::default();
        self.scan = Some(wmi::scan::Session {
            id,
            vdev: 0,
            deadline: transport
                .io
                .now()
                .saturating_add(u64::from(wmi::scan::MAX_SCAN_MS + 5000) * 1_000_000),
        });
        if let Err(error) = self.send_wmi(transport, router, ce, &bytes) {
            self.scan = None;
            wifi::scan_phase(wifi::scan::Phase::Failed(4));
            return Err(error);
        }
        Ok(true)
    }
    fn wait<R: Registers>(
        &mut self,
        transport: &mut mhi::Transport<R, Dma>,
        router: &mut qrtr::Router,
        ce: &mut ce::Engine<Dma>,
        condition: impl Fn(&Self) -> bool,
    ) -> Result<()> {
        let deadline = transport.io.now().saturating_add(TIMEOUT);
        for _ in 0..MAX_SPINS {
            self.poll(transport, router, ce)?;
            if condition(self) {
                return Ok(());
            }
            if transport.io.now() >= deadline {
                break;
            }
            core::hint::spin_loop();
        }
        Err(mhi::Error::Timeout.into())
    }
    fn send_control<R: Registers>(
        &mut self,
        transport: &mut mhi::Transport<R, Dma>,
        router: &mut qrtr::Router,
        ce: &mut ce::Engine<Dma>,
        bytes: &[u8],
    ) -> Result<()> {
        let pipe = self.route(1, 2)?;
        let deadline = transport.io.now().saturating_add(TIMEOUT);
        for _ in 0..MAX_SPINS {
            match ce.send(&mut transport.io, pipe, bytes) {
                Ok(()) => return Ok(()),
                Err(mhi::Error::Full) => {}
                Err(error) => return Err(error.into()),
            }
            self.poll(transport, router, ce)?;
            if transport.io.now() >= deadline {
                break;
            }
        }
        Err(mhi::Error::Timeout.into())
    }
    fn send_wmi<R: Registers>(
        &mut self,
        transport: &mut mhi::Transport<R, Dma>,
        router: &mut qrtr::Router,
        ce: &mut ce::Engine<Dma>,
        bytes: &[u8],
    ) -> Result<()> {
        self.send_service(htc::WMI_CONTROL, transport, router, ce, bytes)
    }
    fn send_service<R: Registers>(
        &mut self,
        service: u16,
        transport: &mut mhi::Transport<R, Dma>,
        router: &mut qrtr::Router,
        ce: &mut ce::Engine<Dma>,
        bytes: &[u8],
    ) -> Result<()> {
        let pipe = self.route(service, 2)?;
        let deadline = transport.io.now().saturating_add(TIMEOUT);
        for _ in 0..MAX_SPINS {
            match self.htc.prepare(service, bytes) {
                Ok(packet) => match ce.send(&mut transport.io, pipe, &packet.bytes) {
                    Ok(()) => {
                        self.htc.commit(&packet)?;
                        return Ok(());
                    }
                    Err(mhi::Error::Full) => {}
                    Err(error) => return Err(error.into()),
                },
                Err(htc::Error::Full) => {}
                Err(error) => return Err(error.into()),
            }
            self.poll(transport, router, ce)?;
            if transport.io.now() >= deadline {
                break;
            }
        }
        Err(mhi::Error::Timeout.into())
    }
}
