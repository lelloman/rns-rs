//! Point-to-point UDP direct interface.
//!
//! After hole punching succeeds, this module wraps the punched UDP socket
//! as a Reticulum interface (implementing Writer + reader thread).
//! No HDLC framing needed — one datagram = one packet (same as UdpInterface).
//!
//! The interface belongs to one link and carries only that link's packets:
//! it is not an outbound interface for the transport engine (no announces,
//! path requests or broadcasts are routed to it), and its reader and writer
//! drop any frame that is not a link DATA or PROOF packet addressed to the
//! link. Nothing else can reach the peer through it, or the node through it.
//!
//! Liveness: each side sends an authenticated keepalive every
//! [`KEEPALIVE_INTERVAL`]; the interface goes down when no valid, fresh
//! keepalive has arrived for [`INACTIVITY_TIMEOUT`] (three missed), and the
//! driver then moves the link back to its original path.
//!
//! MTU: the interface starts at [`DIRECT_MTU`] and probes its path for a
//! larger one (see [`super::path_mtu`]), reporting the result with
//! `Event::DirectPathMtu`.

use std::io;
use std::net::{SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use rns_core::transport::types::{InterfaceId, InterfaceInfo};

use crate::event::{Event, EventSender, LoopContext, LoopSource, SourceStatus};
use crate::interface::Writer;

/// Interval between keepalives. It also keeps the NAT mappings of the path
/// open: NATs commonly forget an idle UDP mapping after 30 seconds, the
/// shortest seen, so a keepalive every 15 seconds refreshes it even when
/// one is lost.
pub(crate) const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(15);

/// Without a valid keepalive for this long (three missed) the direct path
/// is dead. A link with traffic notices sooner, by going stale.
pub(crate) const INACTIVITY_TIMEOUT: Duration = Duration::from_secs(45);

/// MTU a direct interface starts with, until its path MTU discovery (see
/// [`super::path_mtu`]) finds a larger one.
pub(crate) const DIRECT_MTU: u32 = super::path_mtu::MTU_FLOOR;

const KEEPALIVE_MAGIC: &[u8; 4] = b"RNSK";
const KEEPALIVE_TAG_LEN: usize = 16;
const KEEPALIVE_LEN: usize = 4 + 16 + 8 + KEEPALIVE_TAG_LEN;

/// Authenticated keepalives of one direct path:
/// `"RNSK" | session id (16) | counter (u64 BE) | HMAC-SHA256(key, preceding 28 bytes)[..16]`.
/// The key is derived from the link key and the session (see
/// `rns_core::holepunch::derive_keepalive_key`) and never sent; a counter
/// not above the last one accepted is a replay and does not count.
struct Keepalives {
    key: [u8; 32],
    session_id: [u8; 16],
    sent: u64,
    seen: u64,
}

impl Keepalives {
    fn new(key: [u8; 32], session_id: [u8; 16]) -> Self {
        Keepalives {
            key,
            session_id,
            sent: 0,
            seen: 0,
        }
    }

    fn next_packet(&mut self) -> Vec<u8> {
        self.sent += 1;
        let mut packet = Vec::with_capacity(KEEPALIVE_LEN);
        packet.extend_from_slice(KEEPALIVE_MAGIC);
        packet.extend_from_slice(&self.session_id);
        packet.extend_from_slice(&self.sent.to_be_bytes());
        let tag = rns_crypto::hmac::hmac_sha256(&self.key, &packet);
        packet.extend_from_slice(&tag[..KEEPALIVE_TAG_LEN]);
        packet
    }

    /// Whether `data` is a valid keepalive newer than any seen before.
    fn accept(&mut self, data: &[u8]) -> bool {
        if data.len() != KEEPALIVE_LEN {
            return false;
        }
        // [magic:4][session id:16][counter:8][tag]
        let Some((signed, received_tag)) = data.split_last_chunk::<KEEPALIVE_TAG_LEN>() else {
            return false;
        };
        let Some((magic, rest)) = signed.split_first_chunk::<4>() else {
            return false;
        };
        let Some((session_id, rest)) = rest.split_first_chunk::<16>() else {
            return false;
        };
        if magic != KEEPALIVE_MAGIC || *session_id != self.session_id {
            return false;
        }
        let tag = rns_crypto::hmac::hmac_sha256(&self.key, signed);
        if !super::constant_time_eq(&tag[..KEEPALIVE_TAG_LEN], received_tag) {
            return false;
        }
        let Some(counter) = rest.first_chunk() else {
            return false;
        };
        let counter = u64::from_be_bytes(*counter);
        if counter <= self.seen {
            return false;
        }
        self.seen = counter;
        true
    }
}

/// Datagrams that are not Reticulum packets: keepalives, and punch packets
/// and acknowledgements still arriving after the punch.
fn is_control_datagram(data: &[u8]) -> bool {
    matches!(
        data.first_chunk::<4>(),
        Some(b"RNSK" | b"RNSH" | b"RNSA" | b"RNSM" | b"RNSN")
    )
}

/// Whether `frame` is a packet of the link the direct interface belongs to:
/// a HEADER_1 link DATA or PROOF packet whose destination is `link_id`.
pub(crate) fn carries_link(frame: &[u8], link_id: &[u8; 16]) -> bool {
    use rns_core::constants::{DESTINATION_LINK, HEADER_1, PACKET_TYPE_DATA, PACKET_TYPE_PROOF};
    let Some(flags) = frame.first() else {
        return false;
    };
    let header_type = (flags >> 6) & 0x01;
    let destination_type = (flags >> 2) & 0x03;
    let packet_type = flags & 0x03;
    header_type == HEADER_1
        && destination_type == DESTINATION_LINK
        && (packet_type == PACKET_TYPE_DATA || packet_type == PACKET_TYPE_PROOF)
        && frame.get(2..18) == Some(&link_id[..])
}

/// What a direct interface needs to know about its upgrade.
pub(crate) struct DirectPathParams {
    /// Link the path carries; only frames of this link pass.
    pub link_id: [u8; 16],
    /// Hole punching session, carried in keepalives.
    pub session_id: [u8; 16],
    /// Key that authenticates keepalives.
    pub keepalive_key: [u8; 32],
    /// Set to make the path silently drop everything in both directions,
    /// as a network that stopped carrying it would (for tests).
    pub blackhole: Arc<AtomicBool>,
}

/// Writer for a direct UDP peer-to-peer connection.
///
/// When dropped, signals the reader thread to stop.
pub(crate) struct UdpDirectWriter {
    socket: Arc<UdpSocket>,
    peer_addr: SocketAddr,
    /// The link this interface belongs to; other frames are not sent.
    link_id: [u8; 16],
    running: Arc<AtomicBool>,
    blackhole: Arc<AtomicBool>,
    /// Called by the driver directly on a non-blocking socket, with
    /// interface I/O folded (see [`crate::engine::FOLD_IO`]).
    inline: bool,
}

impl UdpDirectWriter {
    /// Frames of other traffic are dropped, as a link that cannot carry
    /// them would.
    fn admits(&self, data: &[u8]) -> bool {
        if self.blackhole.load(Ordering::Relaxed) {
            return false;
        }
        let ok = carries_link(data, &self.link_id);
        if !ok {
            log::trace!("Direct UDP interface dropped a frame not of its link");
        }
        ok
    }
}

impl Writer for UdpDirectWriter {
    fn send_frame(&mut self, data: &[u8]) -> io::Result<()> {
        if !self.admits(data) {
            return Ok(());
        }
        match self.socket.send_to(data, self.peer_addr) {
            // A datagram the socket buffer cannot take is dropped, as the
            // network may drop it.
            Err(e) if self.inline && e.kind() == io::ErrorKind::WouldBlock => Ok(()),
            result => result.map(|_| ()),
        }
    }

    fn send_frame_confirmed(&mut self, data: &[u8]) -> io::Result<()> {
        if !self.admits(data) {
            return Ok(());
        }
        self.socket.send_to(data, self.peer_addr).map(|_| ())
    }

    fn enqueue_confirmed(
        &mut self,
        data: &[u8],
        completion: &mut Option<crate::link_send::Completion>,
    ) -> io::Result<()> {
        // A full buffer returns WouldBlock with the completion untouched,
        // and the driver retries the frame.
        if self.admits(data) {
            self.socket.send_to(data, self.peer_addr)?;
        }
        if let Some(completion) = completion.take() {
            completion.finish(Ok(()));
        }
        Ok(())
    }

    fn sends_inline(&self) -> bool {
        self.inline
    }
}

impl Drop for UdpDirectWriter {
    fn drop(&mut self) {
        self.running.store(false, Ordering::Relaxed);
    }
}

/// Start a direct UDP interface from a punched socket.
///
/// Returns `(writer, InterfaceInfo)` and spawns a reader thread (or, with
/// interface I/O folded, registers a source on the driver loop). The reader
/// sends `Event::Frame` for the link's packets and `Event::InterfaceDown`
/// when the keepalives stop.
pub(crate) fn start_direct_interface(
    socket: UdpSocket,
    peer_addr: SocketAddr,
    interface_id: InterfaceId,
    params: DirectPathParams,
    tx: EventSender,
) -> io::Result<(Box<dyn Writer>, InterfaceInfo)> {
    let socket = Arc::new(socket);
    let inline = crate::engine::FOLD_IO;
    if inline {
        socket.set_nonblocking(true)?;
    } else {
        socket.set_read_timeout(Some(READ_TIMEOUT))?;
    }

    let running = Arc::new(AtomicBool::new(true));

    let writer = UdpDirectWriter {
        socket: socket.clone(),
        peer_addr,
        link_id: params.link_id,
        running: running.clone(),
        blackhole: params.blackhole.clone(),
        inline,
    };

    let session_id = params.session_id;
    let name = format!(
        "DirectPeer/{:02x}{:02x}{:02x}{:02x}",
        session_id[0], session_id[1], session_id[2], session_id[3]
    );

    let info = InterfaceInfo {
        stamp_costs: Default::default(),
        id: interface_id,
        name: name.clone(),
        mode: rns_core::constants::MODE_FULL,
        gravity: 0,
        recursive_prs: false,
        announces_from_internal: true,
        announces_to_internal: None,
        // Only its link's packets, sent to it by the link's route, go out
        // on it: the engine never picks it for announces, path requests
        // or broadcasts.
        out_capable: false,
        in_capable: true,
        bitrate: None,
        airtime_profile: None,
        announce_rate_target: None,
        announce_rate_grace: 0,
        announce_rate_penalty: 0.0,
        announce_cap: 1.0,
        is_local_client: false,
        wants_tunnel: false,
        shared_medium: false,
        hop_limiter: None,
        tunnel_id: None,
        mtu: DIRECT_MTU,
        mtu_upgradable: false,
        ia_freq: 0.0,
        ia_samples: 0,
        ip_freq: 0.0,
        op_freq: 0.0,
        op_samples: 0,
        started: 0.0,
        ingress_control: rns_core::transport::types::IngressControlConfig::disabled(),
    };

    // Probes go out unfragmented until discovery ends.
    super::path_mtu::set_probing(&socket, true);
    let reader = DirectReader {
        pmtu: super::path_mtu::PathMtu::new(
            params.keepalive_key,
            session_id,
            peer_addr,
            std::time::Instant::now(),
        ),
        pending: Vec::new(),
        socket,
        peer_addr,
        interface_id,
        link_id: params.link_id,
        keepalives: Keepalives::new(params.keepalive_key, session_id),
        last_inbound: std::time::Instant::now(),
        last_keepalive: None,
        tx: tx.clone(),
        running,
        blackhole: params.blackhole,
    };

    if inline {
        tx.register_source(
            crate::interface::loop_writer::read_key(interface_id),
            Box::new(DirectSource(reader)),
        )?;
        return Ok((Box::new(writer), info));
    }

    // Spawn reader + keepalive thread
    thread::Builder::new()
        .name(format!("direct-udp-{}", &name))
        .spawn(move || run_reader(reader))?;

    Ok((Box::new(writer), info))
}

/// The receiving side of a direct path, with its keepalives and liveness.
struct DirectReader {
    socket: Arc<UdpSocket>,
    peer_addr: SocketAddr,
    interface_id: InterfaceId,
    link_id: [u8; 16],
    keepalives: Keepalives,
    pmtu: super::path_mtu::PathMtu,
    /// Events for the driver other than received frames.
    pending: Vec<Event>,
    /// When the last valid keepalive arrived (or the path came up).
    last_inbound: std::time::Instant,
    last_keepalive: Option<std::time::Instant>,
    tx: EventSender,
    /// Cleared when the writer is dropped with the interface.
    running: Arc<AtomicBool>,
    blackhole: Arc<AtomicBool>,
}

impl DirectReader {
    fn stopped(&self) -> bool {
        !self.running.load(Ordering::Relaxed)
    }

    /// A datagram read from the socket: the frame to deliver, if any.
    fn receive(&mut self, data: &[u8], src: SocketAddr) -> Option<Event> {
        // Only our verified peer, and nothing at all while blackholed.
        if src != self.peer_addr || self.blackhole.load(Ordering::Relaxed) {
            return None;
        }
        if super::path_mtu::is_pmtu_datagram(data) {
            let out = self.pmtu.receive(data);
            self.apply_pmtu(out);
            return None;
        }
        if is_control_datagram(data) {
            if self.keepalives.accept(data) {
                self.last_inbound = std::time::Instant::now();
            }
            return None;
        }
        carries_link(data, &self.link_id).then(|| Event::Frame {
            interface_id: self.interface_id,
            data: data.into(),
            rssi: None,
            snr: None,
        })
    }

    /// Carry out what path MTU discovery asks for.
    fn apply_pmtu(&mut self, out: Vec<super::path_mtu::PmtuOutput>) {
        for output in out {
            match output {
                super::path_mtu::PmtuOutput::Send(packet) => {
                    if !self.blackhole.load(Ordering::Relaxed) {
                        let _ = self.socket.send_to(&packet, self.peer_addr);
                    }
                }
                super::path_mtu::PmtuOutput::Discovered(mtu) => {
                    super::path_mtu::set_probing(&self.socket, false);
                    log::info!("[{}] Direct UDP path MTU is {}", self.interface_id.0, mtu);
                    self.pending.push(Event::DirectPathMtu {
                        interface_id: self.interface_id,
                        mtu,
                    });
                }
            }
        }
    }

    /// Send a keepalive if one is due; whether the path timed out.
    fn on_timer(&mut self) -> bool {
        let now = std::time::Instant::now();
        let out = self.pmtu.on_timer(now);
        self.apply_pmtu(out);
        if now >= self.last_inbound + INACTIVITY_TIMEOUT {
            log::info!(
                "[{}] Direct UDP interface timed out: no keepalive for {:?}",
                self.interface_id.0,
                INACTIVITY_TIMEOUT
            );
            return true;
        }
        let due = self
            .last_keepalive
            .is_none_or(|last| now >= last + KEEPALIVE_INTERVAL);
        if due {
            self.last_keepalive = Some(now);
            if !self.blackhole.load(Ordering::Relaxed) {
                let packet = self.keepalives.next_packet();
                let _ = self.socket.send_to(&packet, self.peer_addr);
            }
        }
        false
    }

    fn next_deadline(&self) -> std::time::Instant {
        let keepalive = self
            .last_keepalive
            .map_or_else(std::time::Instant::now, |last| last + KEEPALIVE_INTERVAL);
        let deadline = keepalive.min(self.last_inbound + INACTIVITY_TIMEOUT);
        self.pmtu
            .deadline()
            .map_or(deadline, |pmtu| pmtu.min(deadline))
    }
}

/// How long the reader thread waits for a datagram before it checks its
/// timers.
const READ_TIMEOUT: Duration = Duration::from_millis(500);

fn run_reader(mut reader: DirectReader) {
    let mut buf = [0u8; rns_core::holepunch::DIRECT_MAX_PACKET as usize];
    let mut read_timeout = READ_TIMEOUT;
    while !reader.stopped() {
        if reader.on_timer() {
            let _ = reader.tx.send(Event::InterfaceDown(reader.interface_id));
            break;
        }
        for event in reader.pending.drain(..) {
            let _ = reader.tx.send(event);
        }
        // Wake for each path MTU round while probing.
        let wait = if reader.pmtu.probing() {
            reader
                .next_deadline()
                .saturating_duration_since(std::time::Instant::now())
                .clamp(Duration::from_millis(10), READ_TIMEOUT)
        } else {
            READ_TIMEOUT
        };
        if wait != read_timeout {
            read_timeout = wait;
            let _ = reader.socket.set_read_timeout(Some(wait));
        }

        match reader.socket.recv_from(&mut buf) {
            Ok((len, src)) => {
                if let Some(frame) = reader.receive(buf.get(..len).unwrap_or_default(), src) {
                    let _ = reader.tx.send(frame);
                }
                for event in reader.pending.drain(..) {
                    let _ = reader.tx.send(event);
                }
            }
            Err(ref e)
                if e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::TimedOut =>
            {
                continue;
            }
            Err(e) => {
                log::warn!("[{}] Direct UDP recv error: {}", reader.interface_id.0, e);
                let _ = reader.tx.send(Event::InterfaceDown(reader.interface_id));
                break;
            }
        }
    }
}

/// Datagrams read per readiness before other sources get a turn.
const READ_BUDGET: usize = 64;

/// A direct UDP link, read on the driver thread, with its keepalive and
/// inactivity timeout on timers.
struct DirectSource(DirectReader);

impl LoopSource for DirectSource {
    fn fd(&self) -> std::os::fd::BorrowedFd<'_> {
        std::os::fd::AsFd::as_fd(&self.0.socket)
    }

    fn stopped(&self) -> bool {
        self.0.stopped()
    }

    fn on_ready(&mut self, cx: &mut LoopContext<'_>) -> SourceStatus {
        let reader = &mut self.0;
        if reader.stopped() {
            return SourceStatus::Remove;
        }
        if !reader.tx.inbound_data_has_room() {
            return SourceStatus::Suspend;
        }
        let mut frames = Vec::new();
        for _ in 0..READ_BUDGET {
            let (len, src) = match reader.socket.recv_from(cx.buf) {
                Ok(received) => received,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => {
                    log::warn!("[{}] Direct UDP recv error: {}", reader.interface_id.0, e);
                    let _ = reader.tx.push_from_loop(frames);
                    let _ = reader
                        .tx
                        .push_from_loop([Event::InterfaceDown(reader.interface_id)]);
                    return SourceStatus::Remove;
                }
            };
            if let Some(frame) = reader.receive(cx.buf.get(..len).unwrap_or_default(), src) {
                frames.push(frame);
            }
            frames.append(&mut reader.pending);
        }
        match reader.tx.push_from_loop(frames) {
            Ok(true) => SourceStatus::Rearm,
            Ok(false) => SourceStatus::Suspend,
            Err(_) => SourceStatus::Remove,
        }
    }

    fn deadline(&self) -> Option<std::time::Instant> {
        Some(self.0.next_deadline())
    }

    fn on_timer(&mut self, _cx: &mut LoopContext<'_>) -> SourceStatus {
        let reader = &mut self.0;
        if reader.stopped() {
            return SourceStatus::Remove;
        }
        if reader.on_timer() {
            let _ = reader
                .tx
                .push_from_loop([Event::InterfaceDown(reader.interface_id)]);
            return SourceStatus::Remove;
        }
        if !reader.pending.is_empty() {
            let pending = std::mem::take(&mut reader.pending);
            let _ = reader.tx.push_from_loop(pending);
        }
        SourceStatus::Rearm
    }
}

/// Take `data` as a keepalive, raw and with a valid tag over its first 28
/// bytes. For fuzzing.
pub(crate) fn fuzz_keepalive(data: &[u8]) {
    let key = [0x3c; 32];
    let session_id = [0x4d; 16];
    let mut keepalives = Keepalives::new(key, session_id);
    let _ = keepalives.accept(data);
    if let Some(signed) = data.get(..KEEPALIVE_LEN - KEEPALIVE_TAG_LEN) {
        let mut packet = signed.to_vec();
        let tag = rns_crypto::hmac::hmac_sha256(&key, &packet);
        packet.extend_from_slice(&tag[..KEEPALIVE_TAG_LEN]);
        let _ = keepalives.accept(&packet);
        let _ = keepalives.accept(&packet);
    }
    let _ = is_control_datagram(data);
    let _ = carries_link(data, &[0x4c; 16]);
}

#[cfg(test)]
mod tests {
    use super::*;
    use rns_core::constants;

    const LINK: [u8; 16] = [0x4C; 16];

    /// A HEADER_1 packet with the given destination type, packet type and
    /// destination.
    fn frame(destination_type: u8, packet_type: u8, destination: &[u8; 16]) -> Vec<u8> {
        let mut frame = vec![(destination_type << 2) | packet_type, 0];
        frame.extend_from_slice(destination);
        frame.push(constants::CONTEXT_NONE);
        frame.extend_from_slice(b"payload");
        frame
    }

    fn link_data(destination: &[u8; 16], text: &[u8]) -> Vec<u8> {
        let mut frame = frame(
            constants::DESTINATION_LINK,
            constants::PACKET_TYPE_DATA,
            destination,
        );
        frame.extend_from_slice(text);
        frame
    }

    #[test]
    fn only_packets_of_its_link_are_carried() {
        assert!(carries_link(
            &frame(
                constants::DESTINATION_LINK,
                constants::PACKET_TYPE_DATA,
                &LINK
            ),
            &LINK
        ));
        assert!(carries_link(
            &frame(
                constants::DESTINATION_LINK,
                constants::PACKET_TYPE_PROOF,
                &LINK
            ),
            &LINK
        ));
        // Another link, announces, link requests, path requests (plain
        // data), single-destination data: not carried.
        assert!(!carries_link(&link_data(&[0x11; 16], b""), &LINK));
        for (destination_type, packet_type) in [
            (
                constants::DESTINATION_SINGLE,
                constants::PACKET_TYPE_ANNOUNCE,
            ),
            (
                constants::DESTINATION_SINGLE,
                constants::PACKET_TYPE_LINKREQUEST,
            ),
            (constants::DESTINATION_PLAIN, constants::PACKET_TYPE_DATA),
            (constants::DESTINATION_SINGLE, constants::PACKET_TYPE_DATA),
            (constants::DESTINATION_LINK, constants::PACKET_TYPE_ANNOUNCE),
        ] {
            assert!(!carries_link(
                &frame(destination_type, packet_type, &LINK),
                &LINK
            ));
        }
        // A transported (HEADER_2) packet is never for a direct path.
        let mut transported = vec![0x40 | 0x0C, 1];
        transported.extend_from_slice(&[0x99; 16]);
        transported.extend_from_slice(&LINK);
        transported.push(0);
        assert!(!carries_link(&transported, &LINK));
        assert!(!carries_link(&[], &LINK));
        assert!(!carries_link(&[0x0C, 0, 0x4C], &LINK));
    }

    #[test]
    fn test_udp_direct_writer() {
        // Create a pair of sockets
        let sock_a = UdpSocket::bind("127.0.0.1:0").unwrap();
        let sock_b = UdpSocket::bind("127.0.0.1:0").unwrap();
        let addr_b = sock_b.local_addr().unwrap();
        sock_b
            .set_read_timeout(Some(Duration::from_millis(300)))
            .unwrap();

        let blackhole = Arc::new(AtomicBool::new(false));
        let mut writer = UdpDirectWriter {
            socket: Arc::new(sock_a),
            peer_addr: addr_b,
            link_id: LINK,
            running: Arc::new(AtomicBool::new(true)),
            blackhole: blackhole.clone(),
            inline: false,
        };

        // Frames of other traffic are dropped without an error.
        let announce = frame(
            constants::DESTINATION_SINGLE,
            constants::PACKET_TYPE_ANNOUNCE,
            &[0x22; 16],
        );
        writer.send_frame(&announce).unwrap();
        writer.send_frame_confirmed(&announce).unwrap();

        // A frame of the link goes out.
        let data = link_data(&LINK, b"hello direct peer");
        writer.send_frame(&data).unwrap();

        // Receive on other end: only the link's frame.
        let mut buf = [0u8; 128];
        let (len, _src) = sock_b.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..len], &data[..]);
        assert!(sock_b.recv_from(&mut buf).is_err());

        // A blackholed path sends nothing.
        blackhole.store(true, Ordering::Relaxed);
        writer.send_frame(&data).unwrap();
        assert!(sock_b.recv_from(&mut buf).is_err());
    }

    fn params() -> DirectPathParams {
        DirectPathParams {
            link_id: LINK,
            session_id: [1; 16],
            keepalive_key: [2; 32],
            blackhole: Arc::new(AtomicBool::new(false)),
        }
    }

    #[test]
    fn keepalives_are_authenticated_and_fresh() {
        let mut ours = Keepalives::new([7; 32], [1; 16]);
        let mut theirs = Keepalives::new([7; 32], [1; 16]);
        let first = ours.next_packet();
        let second = ours.next_packet();
        assert_eq!(first.len(), KEEPALIVE_LEN);
        assert!(is_control_datagram(&first));
        assert!(theirs.accept(&first));
        // A replay, or an older one, does not count.
        assert!(!theirs.accept(&first));
        assert!(theirs.accept(&second));
        assert!(!theirs.accept(&first));
        // Another key or session, or a tampered packet: rejected.
        let mut stranger = Keepalives::new([8; 32], [1; 16]);
        stranger.sent = 10;
        assert!(!theirs.accept(&stranger.next_packet()));
        let mut other_session = Keepalives::new([7; 32], [2; 16]);
        other_session.sent = 10;
        assert!(!theirs.accept(&other_session.next_packet()));
        let mut forged = ours.next_packet();
        forged[27] ^= 1;
        assert!(!theirs.accept(&forged));
        assert!(!theirs.accept(&forged[..KEEPALIVE_LEN - 1]));
        // The punch's own packets are control traffic, not frames.
        assert!(is_control_datagram(b"RNSH...."));
        assert!(is_control_datagram(b"RNSA...."));
    }

    #[test]
    fn only_valid_keepalives_keep_the_path_alive() {
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").unwrap());
        let peer: SocketAddr = "127.0.0.1:9".parse().unwrap();
        let (tx, _rx) = crate::event::channel();
        let params = params();
        let mut reader = DirectReader {
            pmtu: super::super::path_mtu::PathMtu::new(
                params.keepalive_key,
                params.session_id,
                peer,
                std::time::Instant::now(),
            ),
            pending: Vec::new(),
            socket,
            peer_addr: peer,
            interface_id: InterfaceId(911),
            link_id: LINK,
            keepalives: Keepalives::new(params.keepalive_key, params.session_id),
            last_inbound: std::time::Instant::now() - INACTIVITY_TIMEOUT / 2,
            last_keepalive: None,
            tx,
            running: Arc::new(AtomicBool::new(true)),
            blackhole: params.blackhole.clone(),
        };
        let stale = reader.last_inbound;
        // The link's own frames and forged keepalives do not refresh it.
        assert!(reader.receive(&link_data(&LINK, b"data"), peer).is_some());
        let mut forged = Keepalives::new([9; 32], params.session_id);
        assert!(reader.receive(&forged.next_packet(), peer).is_none());
        assert_eq!(reader.last_inbound, stale);
        // A valid keepalive from the peer does; from anyone else it does not.
        let mut peer_keepalives = Keepalives::new(params.keepalive_key, params.session_id);
        let valid = peer_keepalives.next_packet();
        assert!(reader
            .receive(&valid, "127.0.0.1:10".parse().unwrap())
            .is_none());
        assert_eq!(reader.last_inbound, stale);
        assert!(reader.receive(&valid, peer).is_none());
        assert!(reader.last_inbound > stale);
        assert!(!reader.on_timer());
        // Silence for the timeout takes the path down.
        reader.last_inbound = std::time::Instant::now() - INACTIVITY_TIMEOUT;
        assert!(reader.on_timer());
        // A blackholed path ignores even valid keepalives and frames.
        reader.last_inbound = stale;
        params.blackhole.store(true, Ordering::Relaxed);
        assert!(reader
            .receive(&peer_keepalives.next_packet(), peer)
            .is_none());
        assert!(reader.receive(&link_data(&LINK, b"data"), peer).is_none());
        assert_eq!(reader.last_inbound, stale);
    }

    #[test]
    fn keepalives_refresh_a_30_second_nat_mapping_and_allow_two_losses() {
        assert!(KEEPALIVE_INTERVAL * 2 <= Duration::from_secs(30));
        assert_eq!(INACTIVITY_TIMEOUT, KEEPALIVE_INTERVAL * 3);
    }

    #[test]
    fn keepalives_of_another_session_or_direction_do_not_count() {
        let params = params();
        let mut ours = Keepalives::new(params.keepalive_key, params.session_id);
        // Another session's keepalives, even under the same key.
        let mut other_session = Keepalives::new(params.keepalive_key, [0x77; 16]);
        assert!(!ours.accept(&other_session.next_packet()));
        // A path MTU probe under the same key is not a keepalive.
        let mut probe = ours.next_packet();
        probe[..4].copy_from_slice(b"RNSM");
        assert!(!ours.accept(&probe));
        // A keepalive whose counter was altered fails its tag.
        let mut peer = Keepalives::new(params.keepalive_key, params.session_id);
        let mut bumped = peer.next_packet();
        bumped[27] ^= 0x01;
        assert!(!ours.accept(&bumped));
        assert!(ours.accept(&peer.next_packet()));
    }

    #[test]
    fn folded_direct_link_runs_on_the_driver_loop() {
        if !crate::engine::FOLD_IO {
            return;
        }
        let local = UdpSocket::bind("127.0.0.1:0").unwrap();
        let peer = UdpSocket::bind("127.0.0.1:0").unwrap();
        let peer_addr = peer.local_addr().unwrap();
        let local_addr = local.local_addr().unwrap();
        let (tx, rx) = crate::event::channel();
        let (writer, info) =
            start_direct_interface(local, peer_addr, InterfaceId(910), params(), tx.clone())
                .unwrap();
        assert!(!info.out_capable);
        assert!(writer.sends_inline());
        // Served on the driver loop: no reader thread.
        assert!(!std::fs::read_dir("/proc/self/task").unwrap().any(|task| {
            std::fs::read_to_string(task.unwrap().path().join("comm"))
                .is_ok_and(|comm| comm.starts_with("direct-udp-"))
        }));
        let (mut writer, _) =
            crate::interface::wrap_async_writer(writer, InterfaceId(910), "direct", tx, 16);

        // Inbound from the peer; keepalives, strangers and other traffic
        // are skipped.
        let stranger = UdpSocket::bind("127.0.0.1:0").unwrap();
        stranger
            .send_to(&link_data(&LINK, b"not from the peer"), local_addr)
            .unwrap();
        peer.send_to(b"RNSH keepalive", local_addr).unwrap();
        peer.send_to(
            &frame(
                constants::DESTINATION_SINGLE,
                constants::PACKET_TYPE_ANNOUNCE,
                &[0x22; 16],
            ),
            local_addr,
        )
        .unwrap();
        let from_peer = link_data(&LINK, b"from the peer");
        peer.send_to(&from_peer, local_addr).unwrap();
        match rx.recv_timeout(Duration::from_secs(2)).unwrap() {
            Event::Frame {
                interface_id, data, ..
            } => {
                assert_eq!(interface_id, InterfaceId(910));
                assert_eq!(&*data, &from_peer[..]);
            }
            other => panic!("expected Frame, got {other:?}"),
        }
        assert!(rx.recv_timeout(Duration::from_millis(100)).is_err());

        // Outbound, sent by the driver directly.
        let to_peer = link_data(&LINK, b"to the peer");
        writer.send_frame(&to_peer).unwrap();
        let mut buf = [0u8; 64];
        peer.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
        // Keepalives go out too, the first one right away, and so do path
        // MTU probes.
        let mut keepalives = 0;
        let n = loop {
            let (n, _) = peer.recv_from(&mut buf).unwrap();
            if buf.starts_with(b"RNSM") {
                continue;
            }
            if !buf.starts_with(KEEPALIVE_MAGIC) {
                break n;
            }
            keepalives += 1;
        };
        assert_eq!(&buf[..n], &to_peer[..]);
        assert!(keepalives >= 1);
    }

    #[test]
    fn direct_interfaces_discover_their_path_mtu() {
        let a = UdpSocket::bind("127.0.0.1:0").unwrap();
        let b = UdpSocket::bind("127.0.0.1:0").unwrap();
        let (a_addr, b_addr) = (a.local_addr().unwrap(), b.local_addr().unwrap());
        let (tx, rx) = crate::event::channel();
        let (_a_writer, a_info) =
            start_direct_interface(a, b_addr, InterfaceId(920), params(), tx.clone()).unwrap();
        let (_b_writer, _) =
            start_direct_interface(b, a_addr, InterfaceId(921), params(), tx.clone()).unwrap();
        assert_eq!(a_info.mtu, super::super::path_mtu::MTU_FLOOR);
        let mut discovered = Vec::new();
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while discovered.len() < 2 && std::time::Instant::now() < deadline {
            if let Ok(Event::DirectPathMtu { interface_id, mtu }) =
                rx.recv_timeout(Duration::from_millis(50))
            {
                discovered.push((interface_id.0, mtu));
            }
        }
        discovered.sort();
        // Loopback carries the largest size probed.
        assert_eq!(discovered, vec![(920, 1472), (921, 1472)]);
    }
}
