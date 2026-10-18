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

pub(super) struct Buffers {
    pub receive: qca_dp::rx::Receive<Dma>,
    pub frames: qca_dp::frames::Frames<Dma>,
}
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
    frames: qca_dp::frames::Frames<Dma>,
    pub(super) authorized: bool,
    replay: wifi::auth::Replay,
    pending_keys: alloc::vec::Vec<(wifi::auth::KeyId, u64)>,
    data_sequence: u16,
    peer: Option<[u8; 6]>,
    aid: u16,
    starting: bool,
    associating: bool,
    stopping: bool,
    running: bool,
    station_events: alloc::collections::VecDeque<wmi::station::Event>,
}
impl Control {
    pub(super) fn start<R: Registers>(
        transport: &mut mhi::Transport<R, Dma>,
        router: &mut qrtr::Router,
        ce: &mut ce::Engine<Dma>,
        packet_engine: &mut crate::kernel::drivers::qca_dp::Bootstrap<Dma>,
        buffers: Buffers,
        chip: &Chip,
        stage: &mut &'static str,
    ) -> Result<Self> {
        let Buffers { receive, frames } = buffers;
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
            frames,
            authorized: false,
            replay: wifi::auth::Replay::default(),
            pending_keys: alloc::vec::Vec::new(),
            data_sequence: 0,
            peer: None,
            aid: 0,
            starting: false,
            associating: false,
            stopping: false,
            running: false,
            station_events: alloc::collections::VecDeque::new(),
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
        self.station_poll(transport, router, ce)?;
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
        let event = match event {
            wmi::scan::Event::Station(event) => {
                self.station_events.push_back(event);
                return;
            }
            other => other,
        };
        let Some(session) = &self.scan else {
            return;
        };
        match event {
            wmi::scan::Event::Station(_) => unreachable!(),
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
    pub(super) fn packet_poll<R: Registers>(
        &mut self,
        engine: &mut qca_dp::Bootstrap<Dma>,
        io: &mut R,
    ) -> Result<()> {
        let packets = engine.packets(io, &mut self.receive)?;
        for (id, success) in packets.transmitted {
            crate::compact_println!("WiFi: EAPOL TX completed id={} success={}", id, success);
            wifi::event(wifi::link::Event::EapolSent { id, success });
        }
        for bytes in packets.frames {
            let Some(peer) = self.peer else {
                continue;
            };
            let Some(packet) = super::packets::decode(&bytes, self.wmi.mac, peer) else {
                continue;
            };
            let frame = packet.ethernet;
            if packet.protected {
                let id = wifi::auth::KeyId {
                    pairwise: frame[0] & 1 == 0,
                    index: packet.key,
                };
                if !self.replay.accept(id, packet.pn) {
                    continue;
                }
            }
            if frame[12..14] == [0x88, 0x8e] && frame[6..12] == peer {
                crate::compact_println!(
                    "WiFi: EAPOL RX bytes={} encrypted={}",
                    frame.len() - 14,
                    packet.protected
                );
                wifi::event(wifi::link::Event::Eapol {
                    source: peer,
                    bytes: frame[14..].to_vec(),
                });
            } else if self.authorized && packet.protected {
                wifi::ethernet_receive(frame);
            }
        }
        Ok(())
    }
    pub(super) fn ethernet<R: Registers>(
        &mut self,
        engine: &mut qca_dp::Bootstrap<Dma>,
        io: &mut R,
        frame: &[u8],
        completion: Option<u64>,
    ) -> Result<()> {
        if !self.running || self.stopping || (completion.is_none() && !self.authorized) {
            return Err(Error::State);
        }
        let peer = self.peer.ok_or(Error::State)?;
        let Some((mac, index, hash)) = self.htt.peer else {
            return Err(Error::State);
        };
        if mac != peer {
            return Err(Error::State);
        }
        self.data_sequence = self.data_sequence.wrapping_add(1);
        let bytes = super::packets::encapsulate(
            frame,
            self.wmi.mac,
            peer,
            self.data_sequence,
            completion.is_none(),
        )
        .ok_or(Error::State)?;
        engine.transmit(io, &bytes, completion, (index, hash))?;
        Ok(())
    }
    pub(super) fn peer_address(&self) -> Option<[u8; 6]> {
        self.peer
    }
    pub(super) fn mac_address(&self) -> [u8; 6] {
        self.wmi.mac
    }
    fn station_poll<R: Registers>(
        &mut self,
        transport: &mut mhi::Transport<R, Dma>,
        router: &mut qrtr::Router,
        ce: &mut ce::Engine<Dma>,
    ) -> Result<()> {
        use wmi::station::Event;
        while let Some(event) = self.station_events.pop_front() {
            match event {
                Event::Management(frame) if self.peer.is_some() => {
                    wifi::event(wifi::link::Event::Management(frame))
                }
                Event::ManagementSent { id, status } => {
                    self.frames.complete(id)?;
                    if status != 0 {
                        crate::compact_println!("WiFi: management TX failed status={}", status);
                    }
                }
                Event::Started { request, status } if self.starting => {
                    // Only one start can be outstanding on vdev 0. Stop and
                    // peer-delete completion gate reuse; requestor is not a
                    // firmware-guaranteed sequence echo (Linux sends zero).
                    crate::compact_println!(
                        "WiFi: station start response requestor={} status={}",
                        request,
                        status
                    );
                    self.starting = false;
                    if status == 0 {
                        self.running = true;
                        wifi::event(wifi::link::Event::ChannelReady);
                    } else {
                        crate::compact_println!("WiFi: station start rejected status={}", status);
                        wifi::event(wifi::link::Event::Disconnected);
                    }
                }
                Event::Associated { peer } if self.associating && self.peer == Some(peer) => {
                    self.associating = false;
                    self.send_wmi(transport, router, ce, &wmi::station::up(0, peer, self.aid)?)?;
                    wifi::event(wifi::link::Event::Associated);
                }
                Event::Key {
                    peer,
                    index,
                    flags,
                    status,
                } if self.peer == Some(peer) && index <= 3 && flags <= 1 => {
                    crate::compact_println!(
                        "WiFi: key ACK index={} flags={} status={}",
                        index,
                        flags,
                        status
                    );
                    let id = wifi::auth::KeyId {
                        pairwise: flags == 0,
                        index: index as u8,
                    };
                    if let Some(at) = self.pending_keys.iter().position(|(k, _)| *k == id) {
                        let (_, counter) = self.pending_keys.remove(at);
                        if status == 0 {
                            self.replay.install(id, counter);
                        }
                    } else {
                        continue;
                    }
                    wifi::event(wifi::link::Event::KeyInstalled {
                        id: wifi::auth::KeyId {
                            pairwise: flags == 0,
                            index: index as u8,
                        },
                        success: status == 0,
                    });
                }
                Event::Stopped if self.stopping => {
                    self.running = false;
                    self.send_wmi(transport, router, ce, &wmi::station::down(0)?)?;
                    if let Some(peer) = self.peer {
                        self.send_wmi(transport, router, ce, &wmi::station::peer(0, peer, false)?)?;
                    }
                }
                Event::PeerDeleted { peer } if self.stopping && self.peer == Some(peer) => {
                    self.peer = None;
                    self.stopping = false;
                }
                _ => {}
            }
        }
        Ok(())
    }
    pub(super) fn action<R: Registers>(
        &mut self,
        action: wifi::link::Action,
        transport: &mut mhi::Transport<R, Dma>,
        router: &mut qrtr::Router,
        ce: &mut ce::Engine<Dma>,
    ) -> Result<()> {
        use wifi::link::Action;
        match action {
            Action::StartChannel(network) => {
                if self.scan.is_some() || self.peer.is_some() || self.stopping || self.frames.busy()
                {
                    return Err(mhi::Error::Full.into());
                }
                let report = self
                    .wmi
                    .regulatory
                    .iter()
                    .find(|r| r.phy == self.radio.regulatory_phy)
                    .ok_or(Error::State)?;
                let channel = wmi::scan::channels(report)
                    .into_iter()
                    .find(|c| c.frequency == network.frequency)
                    .ok_or(Error::State)?;
                let start = wmi::station::start(0, &network, &channel)?;
                self.htt.peer = None;
                self.peer = Some(network.bssid);
                self.starting = true;
                self.send_wmi(
                    transport,
                    router,
                    ce,
                    &wmi::station::peer(0, network.bssid, true)?,
                )?;
                for param in [48u32, 91u32] {
                    let mut cmd = 0x5008u32.to_le_bytes().to_vec();
                    let body: alloc::vec::Vec<_> = [0, param, 1]
                        .into_iter()
                        .flat_map(u32::to_le_bytes)
                        .collect();
                    wmi::tlv(&mut cmd, 95, &body)?;
                    self.send_wmi(transport, router, ce, &cmd)?;
                }
                self.send_wmi(transport, router, ce, &start)?;
            }
            Action::Management(frame) => {
                if !self.running || self.stopping {
                    return Err(Error::State);
                }
                let (id, address) = self.frames.insert(&frame)?;
                self.send_wmi(
                    transport,
                    router,
                    ce,
                    &wmi::station::management(0, id, address, &frame)?,
                )?;
            }
            Action::Associate { network, aid } => {
                if self.peer != Some(network.bssid) || !self.running {
                    return Err(Error::State);
                }
                self.aid = aid;
                self.associating = true;
                self.send_wmi(
                    transport,
                    router,
                    ce,
                    &wmi::station::associate(0, &network, aid)?,
                )?;
            }
            Action::InstallKey(key) => {
                if self.peer.is_none() || self.stopping {
                    return Err(Error::State);
                }
                let mut counter = [0; 8];
                counter[..6].copy_from_slice(&key.receive_counter);
                self.pending_keys
                    .push((key.id, u64::from_le_bytes(counter)));
                let command = wmi::station::key(0, &key)?;
                self.send_wmi(transport, router, ce, &command)?;
            }
            Action::Authorize => {
                let peer = self.peer.ok_or(Error::State)?;
                self.send_wmi(
                    transport,
                    router,
                    ce,
                    &wmi::station::authorize(0, peer, true)?,
                )?;
                self.authorized = true;
                wifi::event(wifi::link::Event::Authorized);
            }
            Action::Disconnect => {
                self.authorized = false;
                self.replay = wifi::auth::Replay::default();
                self.pending_keys.clear();
                if !self.stopping
                    && let Some(peer) = self.peer
                {
                    let stop = self.running || self.starting;
                    self.stopping = true;
                    self.associating = false;
                    self.starting = false;
                    self.send_wmi(
                        transport,
                        router,
                        ce,
                        &wmi::station::authorize(0, peer, false)?,
                    )?;
                    if stop {
                        self.send_wmi(transport, router, ce, &wmi::station::stop(0)?)?;
                    } else {
                        self.send_wmi(transport, router, ce, &wmi::station::peer(0, peer, false)?)?;
                    }
                }
            }
            Action::Eapol { .. } => return Err(Error::State),
        }
        Ok(())
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
                Ok(mut packet) => {
                    let sensitive = service == htc::WMI_CONTROL
                        && bytes.get(..4) == Some(&0x5009u32.to_le_bytes());
                    let result = if sensitive {
                        ce.send_sensitive(&mut transport.io, pipe, &packet.bytes)
                    } else {
                        ce.send(&mut transport.io, pipe, &packet.bytes)
                    };
                    if sensitive {
                        use zeroize::Zeroize;
                        packet.bytes.zeroize();
                    }
                    match result {
                        Ok(()) => {
                            self.htc.commit(&packet)?;
                            return Ok(());
                        }
                        Err(mhi::Error::Full) => {}
                        Err(error) => return Err(error.into()),
                    }
                }
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
