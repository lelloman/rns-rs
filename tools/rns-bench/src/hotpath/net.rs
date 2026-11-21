//! Hot-path cases at the `rns-net` level: frames through the driver, a
//! link's `LinkManager` receiving data and a Resource, and RPC pickles.
//!
//! The driver runs without its event loop: each frame goes through
//! `Driver::handle_event_for_bench`, the handling one loop turn gives an
//! `Event::Frame`, into writers that drop what they are given. Links are
//! set up with a real handshake during setup; every key except the driver's
//! own link keys comes from `FixedRng`.
use super::{bytes, data_flags, fail, interface, rng, transport_config, Op, DEST, TRANSPORT_ID};
use anyhow::{ensure, Context, Result};
use rns_core::constants;
use rns_core::link::LinkState;
use rns_core::packet::RawPacket;
use rns_core::transport::types::{InterfaceId, PacketBytes, TransportConfig};
use rns_crypto::ed25519::Ed25519PrivateKey;
use rns_crypto::FixedRng;
use rns_net::event::Event;
use rns_net::testing::Driver;
use rns_net::{
    testing::{LinkManager, LinkManagerAction},
    ResourceStrategy,
};
use std::hint::black_box;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

/// The interface frames arrive on; the forward case sends out of 1.
const INBOUND: InterfaceId = InterfaceId(2);
const LINK_DEST: [u8; 16] = [0x1d; 16];

/// What the driver wrote to its interfaces.
#[derive(Clone, Default)]
struct Output {
    /// Frames written while `recording` is set (setup only).
    frames: Arc<Mutex<Vec<Vec<u8>>>>,
    recording: Arc<AtomicBool>,
    /// Frames written in all.
    sent: Arc<AtomicU64>,
}

impl Output {
    fn take(&self) -> Vec<Vec<u8>> {
        std::mem::take(&mut *self.frames.lock().unwrap_or_else(|e| e.into_inner()))
    }
}

/// A writer the driver calls inline (no worker thread) that keeps nothing
/// once setup is over.
struct SinkWriter(Output);

impl rns_net::interface::Writer for SinkWriter {
    fn send_frame(&mut self, data: &[u8]) -> std::io::Result<()> {
        self.0.sent.fetch_add(1, Ordering::Relaxed);
        if self.0.recording.load(Ordering::Relaxed) {
            self.0
                .frames
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push(data.to_vec());
        }
        Ok(())
    }

    fn sends_inline(&self) -> bool {
        true
    }
}

/// Application callbacks that count link data and ignore everything else.
struct BenchCallbacks {
    link_data: Arc<AtomicU64>,
    local: Arc<AtomicU64>,
}

impl rns_net::Callbacks for BenchCallbacks {
    fn on_local_delivery(
        &mut self,
        _dest_hash: rns_core::types::DestHash,
        raw: Vec<u8>,
        _packet_hash: rns_core::types::PacketHash,
    ) {
        black_box(raw);
        self.local.fetch_add(1, Ordering::Relaxed);
    }

    fn on_link_data(&mut self, _link_id: rns_core::types::LinkId, _context: u8, data: Vec<u8>) {
        black_box(data);
        self.link_data.fetch_add(1, Ordering::Relaxed);
    }
}

struct BenchDriver {
    driver: Driver,
    output: Output,
    local: Arc<AtomicU64>,
    link_data: Arc<AtomicU64>,
}

impl BenchDriver {
    /// A driver with interfaces 1 and 2 up, its table hashing seeded from
    /// `FixedRng`.
    fn new(config: TransportConfig) -> Result<Self> {
        let (tx, rx) = rns_net::event::channel();
        let local = Arc::new(AtomicU64::new(0));
        let link_data = Arc::new(AtomicU64::new(0));
        let callbacks = BenchCallbacks {
            link_data: link_data.clone(),
            local: local.clone(),
        };
        let mut driver = Driver::new(config, rx, tx, Box::new(callbacks));
        driver
            .transport_engine_for_bench()
            .seed_table_hashing(&mut rng());
        let output = Output::default();
        let mut bench = BenchDriver {
            driver,
            output,
            local,
            link_data,
        };
        for id in [1, 2] {
            let writer = Box::new(SinkWriter(bench.output.clone()));
            bench.event(Event::InterfaceUp(
                InterfaceId(id),
                Some(writer),
                Some(Box::new(interface(id))),
            ))?;
        }
        Ok(bench)
    }

    fn event(&mut self, event: Event) -> Result<()> {
        ensure!(self.driver.handle_event_for_bench(event), "driver stopped");
        Ok(())
    }

    /// One received frame, copied into fresh frame bytes as an interface
    /// reader hands it over.
    fn frame(&mut self, raw: &[u8]) -> bool {
        let data: PacketBytes = PacketBytes::from(raw);
        self.driver.handle_event_for_bench(Event::Frame {
            interface_id: INBOUND,
            data,
            rssi: None,
            snr: None,
        })
    }

    fn forget(&mut self, packet_hash: &[u8; 32]) -> bool {
        self.driver
            .transport_engine_for_bench()
            .forget_packet_hash(packet_hash)
    }
}

/// Measure `raw` arriving at `bench` over and over: the engine forgets the
/// packet after each, so every frame is new to it. `handled` reads how many
/// frames reached their end so far, to check each one did.
fn driver_frame_op(
    mut bench: BenchDriver,
    raw: Vec<u8>,
    handled: impl Fn(&BenchDriver) -> u64 + 'static,
) -> Result<Op> {
    let packet_hash = RawPacket::unpack(&raw).map_err(fail)?.packet_hash;
    for round in 1..=2 {
        bench.frame(&raw);
        ensure!(
            handled(&bench) == round,
            "frame {round} was not handled through to its end"
        );
        // A link packet may not be remembered; anything else must be.
        bench.forget(&packet_hash);
    }
    Ok(Box::new(move || {
        let before = handled(&bench);
        black_box(bench.frame(black_box(&raw)));
        assert_eq!(handled(&bench), before + 1, "frame not handled");
        // Steady state: the same packet again, not a growing duplicate table.
        bench.forget(&packet_hash);
    }))
}

/// A data packet for a destination registered on the driver, delivered to
/// the application raw (the driver decrypts only for destinations that ask).
pub(super) fn driver_inbound_local() -> Result<Op> {
    let mut config = transport_config();
    config.transport_enabled = false;
    let mut bench = BenchDriver::new(config)?;
    bench.event(Event::RegisterDestination {
        dest_hash: DEST,
        dest_type: constants::DESTINATION_SINGLE,
    })?;
    let raw = RawPacket::pack(
        data_flags(constants::HEADER_1),
        0,
        &DEST,
        None,
        constants::CONTEXT_NONE,
        &bytes(128, 0xda7b),
    )
    .map_err(fail)?
    .raw;
    driver_frame_op(bench, raw, |b| b.local.load(Ordering::Relaxed))
}

/// A HEADER_2 data packet addressed to this transport node for a known
/// path, forwarded out of the other interface.
pub(super) fn driver_inbound_forward() -> Result<Op> {
    let mut bench = BenchDriver::new(transport_config())?;
    let engine = bench.driver.transport_engine_for_bench();
    for i in 0..256 {
        engine.inject_path(super::path_dest(i), super::path(i, [0x77; 16], 2));
    }
    engine.inject_path(DEST, super::path(0, [0x77; 16], 2));
    let raw = RawPacket::pack(
        data_flags(constants::HEADER_2),
        3,
        &DEST,
        Some(&TRANSPORT_ID),
        constants::CONTEXT_NONE,
        &bytes(128, 0xda7a),
    )
    .map_err(fail)?
    .raw;
    driver_frame_op(bench, raw, |b| b.output.sent.load(Ordering::Relaxed))
}

fn active(manager: &LinkManager, link_id: &[u8; 16]) -> bool {
    manager.link_state(link_id) == Some(LinkState::Active)
}

fn link_dest_keys(rng: &mut FixedRng) -> (Ed25519PrivateKey, [u8; 32]) {
    let sig_prv = Ed25519PrivateKey::generate(rng);
    let sig_pub = sig_prv.public_key().public_bytes();
    (sig_prv, sig_pub)
}

fn sent_packets(actions: &[LinkManagerAction]) -> impl Iterator<Item = &PacketBytes> {
    actions.iter().filter_map(|a| match a {
        LinkManagerAction::SendPacket { raw, .. } => Some(raw),
        _ => None,
    })
}

/// Hand `raw` to `manager` as the driver does for a local packet.
fn deliver(
    manager: &mut LinkManager,
    raw: &[u8],
    rng: &mut FixedRng,
) -> Result<Vec<LinkManagerAction>> {
    let packet = RawPacket::unpack(raw).map_err(fail)?;
    Ok(manager.handle_local_delivery(
        packet.destination_hash,
        raw,
        packet.packet_hash,
        INBOUND,
        rng,
    ))
}

/// Run packets between two link managers until neither sends any more.
/// Returns the packets `from` sent, in order.
fn exchange(
    from: &mut LinkManager,
    to: &mut LinkManager,
    first: Vec<PacketBytes>,
    rng: &mut FixedRng,
) -> Result<(Vec<PacketBytes>, Vec<LinkManagerAction>)> {
    let mut sent = Vec::new();
    let mut received = Vec::new();
    let mut outbound = first;
    while !outbound.is_empty() {
        ensure!(sent.len() < 10_000, "link exchange does not converge");
        let mut replies = Vec::new();
        for raw in outbound {
            let actions = deliver(to, &raw, rng)?;
            replies.extend(sent_packets(&actions).cloned());
            received.extend(actions);
            sent.push(raw);
        }
        outbound = Vec::new();
        for raw in replies {
            outbound.extend(sent_packets(&deliver(from, &raw, rng)?).cloned());
        }
    }
    Ok((sent, received))
}

/// An established link between an initiator and a responder that accepts
/// every Resource.
fn active_link() -> Result<(LinkManager, LinkManager, [u8; 16], FixedRng)> {
    let mut rng = rng();
    let (sig_prv, sig_pub) = link_dest_keys(&mut rng);
    let mut responder = LinkManager::new();
    responder.register_link_destination(LINK_DEST, sig_prv, sig_pub, ResourceStrategy::AcceptAll);
    let mut initiator = LinkManager::new();
    let (link_id, actions) =
        initiator.create_link(&LINK_DEST, &sig_pub, 1, constants::MTU as u32, &mut rng);
    let request = sent_packets(&actions).cloned().collect();
    exchange(&mut initiator, &mut responder, request, &mut rng)?;
    ensure!(
        active(&responder, &link_id) && active(&initiator, &link_id),
        "link not established"
    );
    Ok((initiator, responder, link_id, rng))
}

/// A link DATA packet of 256 B on an established link: decrypted and handed
/// on as link data.
pub(super) fn link_data_receive() -> Result<Op> {
    let (initiator, mut responder, link_id, mut rng) = active_link()?;
    let actions = initiator.send_on_link(
        &link_id,
        &bytes(256, 0x11da),
        constants::CONTEXT_NONE,
        &mut rng,
    );
    let raw = sent_packets(&actions)
        .next()
        .context("link data not sent")?
        .to_vec();
    let packet = RawPacket::unpack(&raw).map_err(fail)?;
    let (dest, hash) = (packet.destination_hash, packet.packet_hash);
    let received = |actions: &[LinkManagerAction]| {
        actions
            .iter()
            .any(|a| matches!(a, LinkManagerAction::LinkDataReceived { .. }))
    };
    ensure!(
        received(&deliver(&mut responder, &raw, &mut rng)?),
        "link data not received"
    );
    let mut out = Vec::new();
    Ok(Box::new(move || {
        responder.handle_local_delivery_into(
            dest,
            black_box(&raw),
            hash,
            INBOUND,
            &mut rng,
            &mut out,
        );
        assert!(received(&out), "link data not received");
        black_box(&out);
        out.clear();
    }))
}

/// One 8 KiB Resource (incompressible, so stored, in 18 parts)
/// replayed into the responder of an established link: the advertisement,
/// every part, assembly with the hash check, then a tick, which forgets the
/// concluded Resource so the same one can be advertised again.
pub(super) fn link_resource_receive() -> Result<Op> {
    let (mut initiator, mut responder, link_id, mut rng) = active_link()?;
    let data = bytes(8 * 1024, 0x5e50);
    let advertisement = sent_packets(&initiator.send_resource(&link_id, &data, None, &mut rng))
        .cloned()
        .collect();
    let (recorded, received) = exchange(&mut initiator, &mut responder, advertisement, &mut rng)?;
    let complete = |actions: &[LinkManagerAction]| {
        actions.iter().any(|a| {
            matches!(a, LinkManagerAction::ResourceReceived { data: got, .. } if got.len() == 8 * 1024)
        })
    };
    ensure!(complete(&received), "recorded Resource not received");
    let parts = recorded
        .iter()
        .filter(|raw| raw.get(18) == Some(&constants::CONTEXT_RESOURCE))
        .count();
    ensure!(parts >= 16, "the Resource took only {parts} parts");
    let recorded: Vec<(Vec<u8>, [u8; 16], [u8; 32])> = recorded
        .iter()
        .map(|raw| {
            let packet = RawPacket::unpack(raw).map_err(fail)?;
            Ok((raw.to_vec(), packet.destination_hash, packet.packet_hash))
        })
        .collect::<Result<_>>()?;
    black_box(responder.tick(&mut rng));
    let mut out = Vec::new();
    let mut replay = move || {
        for (raw, dest, hash) in &recorded {
            responder.handle_local_delivery_into(
                *dest,
                black_box(raw),
                *hash,
                INBOUND,
                &mut rng,
                &mut out,
            );
        }
        let done = complete(&out);
        black_box(&out);
        out.clear();
        black_box(responder.tick(&mut rng));
        done
    };
    ensure!(replay(), "replayed Resource not received");
    Ok(Box::new(move || {
        assert!(replay(), "replayed Resource not received")
    }))
}

/// Link DATA arriving at a driver that answered the link request: the
/// driver's frame handling, the engine's delivery, the link manager and the
/// link-action dispatch to the application callback.
pub(super) fn driver_inbound_link_data() -> Result<Op> {
    let mut config = transport_config();
    config.transport_enabled = false;
    let mut bench = BenchDriver::new(config)?;
    let mut rng = rng();
    let (sig_prv, sig_pub) = link_dest_keys(&mut rng);
    bench.event(Event::RegisterLinkDestination {
        dest_hash: LINK_DEST,
        sig_prv_bytes: sig_prv.private_bytes(),
        sig_pub_bytes: sig_pub,
        resource_strategy: 0,
        max_request_size: None,
    })?;
    let mut initiator = LinkManager::new();
    let (link_id, actions) =
        initiator.create_link(&LINK_DEST, &sig_pub, 1, constants::MTU as u32, &mut rng);
    let mut outbound: Vec<PacketBytes> = sent_packets(&actions).cloned().collect();
    bench.output.recording.store(true, Ordering::Relaxed);
    for _ in 0..4 {
        if active(&initiator, &link_id) && outbound.is_empty() {
            break;
        }
        for raw in std::mem::take(&mut outbound) {
            bench.frame(&raw);
        }
        for raw in bench.output.take() {
            outbound.extend(sent_packets(&deliver(&mut initiator, &raw, &mut rng)?).cloned());
        }
    }
    bench.output.recording.store(false, Ordering::Relaxed);
    ensure!(
        active(&initiator, &link_id) && outbound.is_empty(),
        "link to the driver not established"
    );
    let actions = initiator.send_on_link(
        &link_id,
        &bytes(256, 0x11db),
        constants::CONTEXT_NONE,
        &mut rng,
    );
    let raw = sent_packets(&actions)
        .next()
        .context("link data not sent")?
        .to_vec();
    driver_frame_op(bench, raw, |b| b.link_data.load(Ordering::Relaxed))
}

/// `{"get": "path_table", "max_hops": None}` as `pickle::encode` writes it.
///
/// The fixtures are fixed bytes, so a change to the encoder does not change
/// what is decoded. They come from this crate's encoder, which writes no
/// memo opcodes. Pickles from Python clients memoize every string, and the
/// decoder's memo (a `HashMap` with a random seed) drops its entries in a
/// different order in every process, which moves the allocator's instruction
/// count between runs by about 1 %.
const PICKLE_REQUEST: &str = "80027d288c036765748c0a706174685f7461626c658c086d61785f686f70734e752e";

/// A six-entry path table (`hash`, `timestamp`, `via`, `hops`, `expires`,
/// `interface` per entry) as `pickle::encode` writes it, bytes through
/// `_codecs.encode` as protocol 2 has them.
const PICKLE_RESPONSE: &str = concat!(
    "80025d287d288c0468617368635f636f646563730a656e636f64650a8c186e340bc29cc3bfc2b37ac298c29c",
    "c2a544c3a6c2bb780a2c8c076c6174696e2d3186528c0974696d657374616d704741d954fc400000008c0376",
    "6961635f636f646563730a656e636f64650a8c1518c2ac3e7343c3b016c2890c510ec293c3b93526118c076c",
    "6174696e2d3186528c04686f70734b018c07657870697265734741d9574ae00000008c09696e746572666163",
    "658c24544350496e746572666163655b4261636b626f6e652f31302e302e302e313a343234325d757d288c04",
    "68617368635f636f646563730a656e636f64650a8c184bc3b5122f344554c3853bc39e2ec2bbc28cc392c2b7",
    "c3a38c076c6174696e2d3186528c0974696d657374616d704741d954fc435000008c03766961635f636f6465",
    "63730a656e636f64650a8c163f79c2bb7b435b05321651c39ac3afc39374c38dc3868c076c6174696e2d3186",
    "528c04686f70734b028c07657870697265734741d9574ae35000008c09696e746572666163658c2454435049",
    "6e746572666163655b4261636b626f6e652f31302e302e302e323a343234325d757d288c0468617368635f63",
    "6f646563730a656e636f64650a8c19c39bc381c2b4c38900c3bfc3a4c28d575b5dc2a5c3863804018c076c61",
    "74696e2d3186528c0974696d657374616d704741d954fc46a000008c03766961635f636f646563730a656e63",
    "6f64650a8c1518c2ac3e7343c3b016c2890c510ec293c3b93526118c076c6174696e2d3186528c04686f7073",
    "4b038c07657870697265734741d9574ae6a000008c09696e746572666163658c24544350496e746572666163",
    "655b4261636b626f6e652f31302e302e302e313a343234325d757d288c0468617368635f636f646563730a65",
    "6e636f64650a8c14084fc3ad08c2b978c2af4d7d196a7446c2a86b588c076c6174696e2d3186528c0974696d",
    "657374616d704741d954fc49f000008c03766961635f636f646563730a656e636f64650a8c163f79c2bb7b43",
    "5b05321651c39ac3afc39374c38dc3868c076c6174696e2d3186528c04686f70734b048c0765787069726573",
    "4741d9574ae9f000008c09696e746572666163658c24544350496e746572666163655b4261636b626f6e652f",
    "31302e302e302e323a343234325d757d288c0468617368635f636f646563730a656e636f64650a8c18c3a52d",
    "c29c50c28c502347344dc28c07c2adc291c38bc3968c076c6174696e2d3186528c0974696d657374616d7047",
    "41d954fc4d4000008c03766961635f636f646563730a656e636f64650a8c1518c2ac3e7343c3b016c2890c51",
    "0ec293c3b93526118c076c6174696e2d3186528c04686f70734b018c07657870697265734741d9574aed4000",
    "008c09696e746572666163658c24544350496e746572666163655b4261636b626f6e652f31302e302e302e31",
    "3a343234325d757d288c0468617368635f636f646563730a656e636f64650a8c1bc3a77bc29ac29ac3a9c3a3",
    "0b0dc2bdc2b6c3b510c2a264c3afc29d8c076c6174696e2d3186528c0974696d657374616d704741d954fc50",
    "9000008c03766961635f636f646563730a656e636f64650a8c163f79c2bb7b435b05321651c39ac3afc39374",
    "c38dc3868c076c6174696e2d3186528c04686f70734b028c07657870697265734741d9574af09000008c0969",
    "6e746572666163658c24544350496e746572666163655b4261636b626f6e652f31302e302e302e323a343234",
    "325d75652e",
);

fn unhex(hex: &str) -> Result<Vec<u8>> {
    ensure!(hex.len().is_multiple_of(2), "odd hex length");
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).context("bad hex"))
        .collect()
}

/// `pickle::decode` of an RPC request and of its response.
pub(super) fn pickle_decode_rpc() -> Result<Op> {
    use rns_net::pickle::{self, PickleValue};
    let request = unhex(PICKLE_REQUEST)?;
    let response = unhex(PICKLE_RESPONSE)?;
    let decoded = pickle::decode(&request).map_err(fail)?;
    ensure!(
        decoded.get("get").and_then(PickleValue::as_str) == Some("path_table"),
        "request decoded wrongly: {decoded:?}"
    );
    let decoded = pickle::decode(&response).map_err(fail)?;
    let entries = decoded.as_list().context("response is not a list")?;
    ensure!(
        entries.len() == 6
            && entries.iter().all(|e| e
                .get("via")
                .and_then(PickleValue::as_bytes)
                .map(<[u8]>::len)
                == Some(16)),
        "response decoded wrongly: {decoded:?}"
    );
    Ok(Box::new(move || {
        black_box(pickle::decode(black_box(&request))).expect("request");
        black_box(pickle::decode(black_box(&response))).expect("response");
    }))
}
