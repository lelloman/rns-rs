//! Fixed hot-path operations for the instruction and allocation invariance gate.
//!
//! Each case prepares fixed inputs (fixed keys, `FixedRng`), runs its
//! operation a few times to settle lazy state, then runs it `iterations`
//! times inside [`rns_bench_hotpath_measured`]. Allocations are counted
//! around that call only; `scripts/hotpath` runs the process under callgrind
//! with collection toggled on that function, so setup is excluded from both.
use crate::heap::COUNTERS;
use anyhow::{bail, ensure, Context, Result};
use rns_core::buffer::NoopCompressor;
use rns_core::constants;
use rns_core::msgpack::{self, Value};
use rns_core::packet::{PacketFlags, RawPacket};
use rns_core::resource::{ResourceAction, ResourceAdvertisement, ResourceReceiver, ResourceSender};
use rns_core::transport::tables::PathEntry;
use rns_core::transport::types::{
    InterfaceId, InterfaceInfo, PacketHashlistAllocation, TransportAction, TransportConfig,
    DEFAULT_MAX_PATH_DESTINATIONS,
};
use rns_core::transport::{InboundFrame, TransportEngine};
use rns_crypto::identity::Identity;
use rns_crypto::FixedRng;
use std::hint::black_box;

mod net;

/// Iterations run before the measured window: first-use initialisation
/// (lazy statics, buffer growth in reused state) stays out of the numbers.
const WARMUP: u64 = 3;

type Op = Box<dyn FnMut()>;

pub(crate) struct Case {
    pub name: &'static str,
    /// Iterations a baseline records; a check re-runs the baseline's count.
    pub iterations: u64,
    pub about: &'static str,
    build: fn() -> Result<Op>,
}

pub(crate) const CASES: &[Case] = &[
    Case {
        name: "packet_pack",
        iterations: 2000,
        about: "RawPacket::pack, HEADER_2 data, 128 B payload",
        build: packet_pack,
    },
    Case {
        name: "packet_unpack",
        iterations: 2000,
        about: "RawPacket::unpack of a HEADER_2 data packet (parse, copy, hash)",
        build: packet_unpack,
    },
    Case {
        name: "packet_hash",
        iterations: 2000,
        about: "RawPacket::packet_hash_of a HEADER_2 data packet (SHA-256 of the hashable part)",
        build: packet_hash,
    },
    Case {
        name: "hdlc_roundtrip",
        iterations: 2000,
        about: "hdlc::frame + Decoder::feed of a 500 B packet with escapes",
        build: hdlc_roundtrip,
    },
    Case {
        name: "kiss_roundtrip",
        iterations: 2000,
        about: "kiss::frame + Decoder::feed of a 500 B packet with escapes",
        build: kiss_roundtrip,
    },
    Case {
        name: "ifac_roundtrip",
        iterations: 200,
        about: "ifac::mask_outbound + unmask_inbound, 16 B IFAC, 200 B packet",
        build: ifac_roundtrip,
    },
    Case {
        name: "announce_create",
        iterations: 200,
        about: "AnnounceData::pack (Ed25519 sign) + RawPacket::pack, 32 B app data",
        build: announce_create,
    },
    Case {
        name: "announce_validate",
        iterations: 200,
        about: "AnnounceData::unpack + validate (Ed25519 verify)",
        build: announce_validate,
    },
    Case {
        name: "transport_forward",
        iterations: 1000,
        about: "TransportEngine::handle_inbound of a data packet for a known path (forwarded)",
        build: transport_forward,
    },
    Case {
        name: "path_lookup",
        iterations: 20000,
        about: "TransportEngine::next_hop_interface over 1024 known paths",
        build: path_lookup,
    },
    Case {
        name: "link_encrypt",
        iterations: 1000,
        about: "link_encrypt (Token, AES-256), 400 B plaintext",
        build: link_encrypt,
    },
    Case {
        name: "link_decrypt",
        iterations: 1000,
        about: "link_decrypt (Token, AES-256), 400 B plaintext",
        build: link_decrypt,
    },
    Case {
        name: "resource_adv_roundtrip",
        iterations: 1000,
        about: "ResourceAdvertisement::pack + unpack, full hashmap segment",
        build: resource_adv_roundtrip,
    },
    Case {
        name: "resource_assembly_64k",
        iterations: 10,
        about: "ResourceReceiver for 64 KiB: advertisement, parts, HMU, assemble + hash check",
        build: resource_assembly_64k,
    },
    Case {
        name: "msgpack_roundtrip",
        iterations: 2000,
        about: "msgpack::pack + unpack_exact of a request-like structure",
        build: msgpack_roundtrip,
    },
    Case {
        name: "channel_envelope_roundtrip",
        iterations: 5000,
        about: "channel pack_envelope + unpack_envelope, 200 B payload",
        build: channel_envelope_roundtrip,
    },
    Case {
        name: "driver_inbound_local",
        iterations: 1000,
        about: "Driver: Frame event of a data packet for a registered destination, to the callback",
        build: net::driver_inbound_local,
    },
    Case {
        name: "driver_inbound_forward",
        iterations: 1000,
        about: "Driver: Frame event of a HEADER_2 data packet for a known path, forwarded",
        build: net::driver_inbound_forward,
    },
    Case {
        name: "driver_inbound_link_data",
        iterations: 1000,
        about: "Driver: Frame event of link DATA, 256 B, through LinkManager to the callback",
        build: net::driver_inbound_link_data,
    },
    Case {
        name: "link_data_receive",
        iterations: 1000,
        about: "LinkManager::handle_local_delivery of link DATA, 256 B, on an active link",
        build: net::link_data_receive,
    },
    Case {
        name: "link_resource_receive",
        iterations: 20,
        about: "LinkManager: 8 KiB Resource replayed into a link: advertisement, parts, assembly",
        build: net::link_resource_receive,
    },
    Case {
        name: "pickle_decode_rpc",
        iterations: 2000,
        about: "pickle::decode of an RPC request and a six-entry path table response",
        build: net::pickle_decode_rpc,
    },
];

/// The measured window. Not inlined and not mangled, so callgrind can toggle
/// collection on exactly this function.
#[allow(unsafe_code, reason = "unmangled so callgrind can find it by name")]
#[no_mangle]
#[inline(never)]
pub(crate) fn rns_bench_hotpath_measured(op: &mut dyn FnMut(), iterations: u64) {
    for _ in 0..iterations {
        op();
    }
}

pub(crate) fn list() -> Result<()> {
    let cases: Vec<_> = CASES
        .iter()
        .map(|c| serde_json::json!({"name":c.name,"iterations":c.iterations,"about":c.about}))
        .collect();
    println!("{}", serde_json::to_string_pretty(&cases)?);
    Ok(())
}

pub(crate) fn run(name: &str, iterations: Option<u64>) -> Result<()> {
    ensure!(
        !cfg!(debug_assertions),
        "hot-path measurement requires a release build"
    );
    let case = CASES
        .iter()
        .find(|c| c.name == name)
        .with_context(|| format!("unknown hot-path case {name}"))?;
    let iterations = iterations.unwrap_or(case.iterations);
    ensure!(iterations > 0, "iterations must be positive");
    let mut op = (case.build)()?;
    for _ in 0..WARMUP {
        op();
    }
    let before = COUNTERS.snapshot();
    rns_bench_hotpath_measured(&mut *op, iterations);
    let after = COUNTERS.snapshot();
    drop(op);
    println!(
        "{}",
        serde_json::json!({
            "case": case.name,
            "iterations": iterations,
            "allocations": after.allocation_calls - before.allocation_calls,
            "reallocations": after.reallocation_calls - before.reallocation_calls,
            "bytes": after.allocated_bytes - before.allocated_bytes,
        })
    );
    Ok(())
}

fn fail<E: std::fmt::Debug>(e: E) -> anyhow::Error {
    anyhow::anyhow!("{e:?}")
}

// ---------------------------------------------------------------------------
// Fixed inputs
// ---------------------------------------------------------------------------

/// Deterministic, incompressible-looking bytes (xorshift64*).
fn bytes(len: usize, seed: u64) -> Vec<u8> {
    let mut state = seed | 1;
    (0..len)
        .map(|_| {
            state ^= state >> 12;
            state ^= state << 25;
            state ^= state >> 27;
            (state.wrapping_mul(0x2545_F491_4F6C_DD1D) >> 56) as u8
        })
        .collect()
}

fn identity() -> Identity {
    let mut key = [0u8; 64];
    key.copy_from_slice(&bytes(64, 0x1d));
    Identity::from_private_key(&key)
}

fn rng() -> FixedRng {
    FixedRng::new(&bytes(251, 0x5eed))
}

fn data_flags(header_type: u8) -> PacketFlags {
    PacketFlags {
        header_type,
        context_flag: constants::FLAG_UNSET,
        transport_type: if header_type == constants::HEADER_2 {
            constants::TRANSPORT_TRANSPORT
        } else {
            constants::TRANSPORT_BROADCAST
        },
        destination_type: constants::DESTINATION_SINGLE,
        packet_type: constants::PACKET_TYPE_DATA,
    }
}

const DEST: [u8; 16] = [0xd5; 16];
const TRANSPORT_ID: [u8; 16] = [0x42; 16];

fn data_packet(len: usize) -> Result<RawPacket> {
    RawPacket::pack(
        data_flags(constants::HEADER_2),
        3,
        &DEST,
        Some(&TRANSPORT_ID),
        constants::CONTEXT_NONE,
        &bytes(len, 0xda7a),
    )
    .map_err(fail)
}

/// A packet-sized frame payload with framing bytes of both protocols in it.
fn framed_payload() -> Vec<u8> {
    let mut data = bytes(500, 0xf4a3);
    for (i, special) in [0x7e, 0x7d, 0xc0, 0xdb].into_iter().enumerate() {
        for j in 0..4 {
            if let Some(byte) = data.get_mut(17 + i * 113 + j * 7) {
                *byte = special;
            }
        }
    }
    data
}

// ---------------------------------------------------------------------------
// Cases
// ---------------------------------------------------------------------------

fn packet_pack() -> Result<Op> {
    let payload = bytes(128, 0xda7a);
    Ok(Box::new(move || {
        let packet = RawPacket::pack(
            black_box(data_flags(constants::HEADER_2)),
            3,
            black_box(&DEST),
            Some(&TRANSPORT_ID),
            constants::CONTEXT_NONE,
            black_box(&payload),
        );
        black_box(packet).expect("pack");
    }))
}

fn packet_unpack() -> Result<Op> {
    let raw = data_packet(128)?.raw;
    Ok(Box::new(move || {
        black_box(RawPacket::unpack(black_box(&raw))).expect("unpack");
    }))
}

fn packet_hash() -> Result<Op> {
    let packet = data_packet(128)?;
    ensure!(
        RawPacket::packet_hash_of(constants::HEADER_2, &packet.raw) == packet.get_hash(),
        "packet hash differs from the unpacked one"
    );
    let raw = packet.raw;
    Ok(Box::new(move || {
        black_box(RawPacket::packet_hash_of(
            black_box(constants::HEADER_2),
            black_box(&raw),
        ));
    }))
}

fn hdlc_roundtrip() -> Result<Op> {
    let data = framed_payload();
    let mut decoder = rns_net::hdlc::Decoder::new();
    Ok(Box::new(move || {
        let framed = rns_net::hdlc::frame(black_box(&data));
        let frames = decoder.feed(&framed);
        assert_eq!(frames.len(), 1);
        black_box(frames);
    }))
}

fn kiss_roundtrip() -> Result<Op> {
    let data = framed_payload();
    let mut decoder = rns_net::kiss::Decoder::new();
    Ok(Box::new(move || {
        let framed = rns_net::kiss::frame(black_box(&data));
        let events = decoder.feed(&framed);
        assert_eq!(events.len(), 1);
        black_box(events);
    }))
}

fn ifac_roundtrip() -> Result<Op> {
    let state = rns_net::ifac::derive_ifac(Some("hotpath"), Some("fixed passphrase"), 16)
        .map_err(anyhow::Error::msg)?;
    let packet = RawPacket::pack(
        data_flags(constants::HEADER_1),
        0,
        &DEST,
        None,
        constants::CONTEXT_NONE,
        &bytes(200, 0x1fac),
    )
    .map_err(fail)?;
    let raw = packet.raw;
    let check = rns_net::ifac::unmask_inbound(&rns_net::ifac::mask_outbound(&raw, &state), &state);
    ensure!(check.as_deref() == Some(&raw[..]), "IFAC round trip failed");
    Ok(Box::new(move || {
        let masked = rns_net::ifac::mask_outbound(black_box(&raw), &state);
        black_box(rns_net::ifac::unmask_inbound(&masked, &state)).expect("unmask");
    }))
}

struct AnnounceFixture {
    identity: Identity,
    dest: [u8; 16],
    name_hash: [u8; 10],
    random_hash: [u8; 10],
    app_data: Vec<u8>,
}

fn announce_fixture() -> AnnounceFixture {
    let identity = identity();
    let name_hash = rns_core::hash::name_hash("hotpath", &["bench", "announce"]);
    let mut material = name_hash.to_vec();
    material.extend_from_slice(identity.hash());
    let dest = rns_core::hash::truncated_hash(&material);
    let mut random_hash = [0u8; 10];
    random_hash.copy_from_slice(&bytes(10, 0x7a4d));
    AnnounceFixture {
        identity,
        dest,
        name_hash,
        random_hash,
        app_data: bytes(32, 0xa99d),
    }
}

fn announce_flags() -> PacketFlags {
    PacketFlags {
        header_type: constants::HEADER_1,
        context_flag: constants::FLAG_UNSET,
        transport_type: constants::TRANSPORT_BROADCAST,
        destination_type: constants::DESTINATION_SINGLE,
        packet_type: constants::PACKET_TYPE_ANNOUNCE,
    }
}

fn announce_create() -> Result<Op> {
    let f = announce_fixture();
    Ok(Box::new(move || {
        let (data, _) = rns_core::announce::AnnounceData::pack(
            &f.identity,
            black_box(&f.dest),
            &f.name_hash,
            &f.random_hash,
            None,
            Some(&f.app_data),
        )
        .expect("announce pack");
        let packet = RawPacket::pack(
            announce_flags(),
            0,
            &f.dest,
            None,
            constants::CONTEXT_NONE,
            &data,
        );
        black_box(packet).expect("packet pack");
    }))
}

fn announce_validate() -> Result<Op> {
    let f = announce_fixture();
    let (data, has_ratchet) = rns_core::announce::AnnounceData::pack(
        &f.identity,
        &f.dest,
        &f.name_hash,
        &f.random_hash,
        None,
        Some(&f.app_data),
    )
    .map_err(fail)?;
    let dest = f.dest;
    rns_core::announce::AnnounceData::unpack(&data, has_ratchet)
        .map_err(fail)?
        .validate(&dest)
        .map_err(fail)?;
    Ok(Box::new(move || {
        let announce = rns_core::announce::AnnounceData::unpack(black_box(&data), has_ratchet)
            .expect("unpack");
        black_box(announce.validate(black_box(&dest))).expect("validate");
    }))
}

fn transport_config() -> TransportConfig {
    TransportConfig {
        transport_enabled: true,
        identity_hash: Some(TRANSPORT_ID),
        local_hops_delta: 0,
        prefer_shorter_path: false,
        max_paths_per_destination: 1,
        unresponsive_path_recovery: rns_core::transport::types::UnresponsivePathRecovery::Native,
        packet_hashlist_max_entries: constants::HASHLIST_MAXSIZE,
        packet_hashlist_allocation: PacketHashlistAllocation::default(),
        max_discovery_pr_tags: constants::MAX_PR_TAGS,
        max_path_destinations: DEFAULT_MAX_PATH_DESTINATIONS,
        max_tunnel_destinations_total: usize::MAX,
        destination_timeout_secs: constants::DESTINATION_TIMEOUT,
        announce_table_ttl_secs: constants::ANNOUNCE_TABLE_TTL,
        announce_table_max_bytes: constants::ANNOUNCE_TABLE_MAX_BYTES,
        announce_sig_cache_enabled: true,
        announce_sig_cache_max_entries: constants::ANNOUNCE_SIG_CACHE_MAXSIZE,
        announce_sig_cache_ttl_secs: constants::ANNOUNCE_SIG_CACHE_TTL,
        announce_queue_max_entries: 256,
        announce_queue_max_interfaces: 1024,
    }
}

fn interface(id: u64) -> InterfaceInfo {
    InterfaceInfo {
        stamp_costs: Default::default(),
        id: InterfaceId(id),
        name: format!("hotpath-{id}"),
        mode: constants::MODE_FULL,
        gravity: 0,
        recursive_prs: false,
        announces_from_internal: true,
        announces_to_internal: None,
        out_capable: true,
        in_capable: true,
        bitrate: None,
        airtime_profile: None,
        announce_rate_target: None,
        announce_rate_grace: 0,
        announce_rate_penalty: 0.0,
        announce_cap: constants::ANNOUNCE_CAP,
        is_local_client: false,
        wants_tunnel: false,
        shared_medium: false,
        hop_limiter: None,
        tunnel_id: None,
        mtu: constants::MTU as u32,
        mtu_upgradable: false,
        ingress_control: rns_core::transport::types::IngressControlConfig::disabled(),
        ia_freq: 0.0,
        ia_samples: 0,
        ip_freq: 0.0,
        op_freq: 0.0,
        op_samples: 0,
        started: 0.0,
    }
}

const NOW: f64 = 1_000_000.0;

fn path(dest_index: u32, next_hop: [u8; 16], hops: u8) -> PathEntry {
    PathEntry {
        timestamp: NOW,
        next_hop,
        hops,
        expires: NOW + 7.0 * 24.0 * 3600.0,
        random_blobs: vec![[dest_index as u8; 10]],
        receiving_interface: InterfaceId(1),
        packet_hash: [0x11; 32],
        used: 0.0,
        announce_raw: None,
    }
}

fn path_dest(i: u32) -> [u8; 16] {
    let mut dest = [0u8; 16];
    dest.copy_from_slice(&rns_core::hash::full_hash(&i.to_be_bytes())[..16]);
    dest
}

fn transport_forward() -> Result<Op> {
    let mut engine = TransportEngine::new(transport_config());
    engine.register_interface(interface(1));
    engine.register_interface(interface(2));
    for i in 0..256 {
        engine.inject_path(path_dest(i), path(i, [0x77; 16], 2));
    }
    engine.inject_path(DEST, path(0, [0x77; 16], 2));
    let packet = data_packet(128)?;
    let raw = packet.raw;
    let hash = packet.packet_hash;
    let mut rng = rng();
    let actions = engine.handle_inbound(InboundFrame::new(&raw, InterfaceId(2), NOW), &mut rng);
    ensure!(
        actions.iter().any(|a| matches!(
            a,
            TransportAction::SendOnInterface {
                interface: InterfaceId(1),
                ..
            }
        )),
        "data packet was not forwarded: {actions:?}"
    );
    ensure!(
        engine.forget_packet_hash(&hash),
        "packet hash not remembered"
    );
    let again = engine.handle_inbound(InboundFrame::new(&raw, InterfaceId(2), NOW), &mut rng);
    ensure!(
        again.len() == actions.len() && engine.forget_packet_hash(&hash),
        "a repeated, forgotten packet is handled differently: {again:?}"
    );
    Ok(Box::new(move || {
        let actions = engine.handle_inbound(
            InboundFrame::new(black_box(&raw), InterfaceId(2), NOW),
            &mut rng,
        );
        black_box(actions);
        // Steady state: the same packet again, not a growing duplicate table.
        engine.forget_packet_hash(&hash);
    }))
}

fn path_lookup() -> Result<Op> {
    let mut engine = TransportEngine::new(transport_config());
    engine.register_interface(interface(1));
    let dests: Vec<_> = (0..1024).map(path_dest).collect();
    for (i, dest) in dests.iter().enumerate() {
        engine.inject_path(*dest, path(i as u32, [0x77; 16], 2));
    }
    let mut next = 0usize;
    Ok(Box::new(move || {
        // The measured loop, kept as recorded in the baseline.
        #[allow(
            clippy::indexing_slicing,
            reason = "next stays below dests.len(); the hotpath baseline measures this loop as written"
        )]
        let dest = &dests[next];
        next = (next + 97) % dests.len();
        black_box(engine.next_hop_interface(black_box(dest))).expect("known path");
    }))
}

fn link_token() -> Result<rns_crypto::token::Token> {
    rns_core::link::crypto::create_session_token(&bytes(64, 0x70c3))
        .map_err(|e| anyhow::anyhow!("session token: {e:?}"))
}

fn link_encrypt() -> Result<Op> {
    let token = link_token()?;
    let plaintext = bytes(400, 0x9a1e);
    let mut rng = rng();
    Ok(Box::new(move || {
        black_box(rns_core::link::crypto::link_encrypt(
            &token,
            black_box(&plaintext),
            &mut rng,
        ));
    }))
}

fn link_decrypt() -> Result<Op> {
    let token = link_token()?;
    let plaintext = bytes(400, 0x9a1e);
    let ciphertext = rns_core::link::crypto::link_encrypt(&token, &plaintext, &mut rng());
    Ok(Box::new(move || {
        let out = rns_core::link::crypto::link_decrypt(&token, black_box(&ciphertext));
        assert_eq!(out.as_deref(), Ok(&plaintext[..]));
        black_box(out).ok();
    }))
}

fn resource_sender(data: &[u8]) -> Result<ResourceSender> {
    ResourceSender::new(
        data,
        None,
        constants::RESOURCE_SDU,
        &|d: &[u8]| d.to_vec(),
        &NoopCompressor,
        &mut rng(),
        NOW,
        false,
        false,
        None,
        1,
        1,
        None,
        0.5,
        6.0,
    )
    .map_err(|e| anyhow::anyhow!("resource sender: {e:?}"))
}

fn resource_adv_roundtrip() -> Result<Op> {
    let sender = resource_sender(&bytes(64 * 1024, 0x6400))?;
    let adv = ResourceAdvertisement::unpack(&sender.get_advertisement(0))
        .map_err(|e| anyhow::anyhow!("advertisement: {e:?}"))?;
    ensure!(
        adv.hashmap.len() == constants::RESOURCE_HASHMAP_MAX_LEN * constants::RESOURCE_MAPHASH_LEN,
        "advertisement hashmap segment is not full"
    );
    Ok(Box::new(move || {
        let packed = black_box(&adv).pack(0);
        black_box(ResourceAdvertisement::unpack(&packed)).expect("unpack");
    }))
}

/// Inputs a receiver gets during one transfer, recorded against a live sender.
enum Event {
    Part(Vec<u8>),
    Hmu(Vec<u8>),
}

fn identity_decrypt(parts: &[&[u8]], skip: usize) -> std::result::Result<Vec<u8>, ()> {
    let mut out = Vec::with_capacity(parts.iter().map(|p| p.len()).sum());
    for part in parts {
        out.extend_from_slice(part);
    }
    out.drain(..skip.min(out.len()));
    Ok(out)
}

fn requests(actions: &[ResourceAction]) -> impl Iterator<Item = Vec<u8>> + '_ {
    actions.iter().filter_map(|a| match a {
        ResourceAction::SendRequest(d) => Some(d.clone()),
        _ => None,
    })
}

fn new_receiver(adv: &[u8]) -> ResourceReceiver {
    ResourceReceiver::from_advertisement(adv, constants::RESOURCE_SDU, 0.5, NOW, None, None)
        .expect("receiver")
}

fn event_time(i: usize) -> f64 {
    NOW + 1.0 + i as f64 * 0.01
}

fn resource_assembly_64k() -> Result<Op> {
    let data = bytes(64 * 1024, 0x6401);
    let mut sender = resource_sender(&data)?;
    let adv = sender.get_advertisement(0);
    let mut receiver = new_receiver(&adv);
    let mut pending: std::collections::VecDeque<_> =
        requests(&receiver.accept(NOW + 0.5)).collect();
    let mut events = Vec::new();
    while let Some(request) = pending.pop_front() {
        ensure!(events.len() < 10_000, "resource transfer does not converge");
        for action in sender.handle_request(&request, event_time(events.len())) {
            let (event, out) = match action {
                ResourceAction::SendPart(part) => {
                    let out = receiver.receive_part(&part, event_time(events.len()));
                    (Event::Part(part), out)
                }
                ResourceAction::SendHmu(hmu) => {
                    let out = receiver.handle_hashmap_update(&hmu, event_time(events.len()));
                    (Event::Hmu(hmu), out)
                }
                _ => continue,
            };
            events.push(event);
            pending.extend(requests(&out));
        }
    }
    ensure!(
        receiver.received_count == receiver.total_parts,
        "recorded transfer incomplete: {}/{}",
        receiver.received_count,
        receiver.total_parts
    );
    ensure!(
        events.iter().any(|e| matches!(e, Event::Hmu(_))),
        "transfer did not exercise a hashmap update"
    );
    let replay = move |check: bool| {
        let mut receiver = new_receiver(black_box(&adv));
        black_box(receiver.accept(NOW + 0.5));
        for (i, event) in events.iter().enumerate() {
            black_box(match event {
                Event::Part(part) => receiver.receive_part(part, event_time(i)),
                Event::Hmu(hmu) => receiver.handle_hashmap_update(hmu, event_time(i)),
            });
        }
        let actions = receiver.assemble(&identity_decrypt, &NoopCompressor);
        let received = actions.iter().any(|a| match a {
            ResourceAction::DataReceived { data: got, .. } => !check || got == &data,
            _ => false,
        });
        assert!(received, "replayed transfer did not assemble");
        black_box(actions);
    };
    replay(true);
    Ok(Box::new(move || replay(false)))
}

fn msgpack_value() -> Value {
    Value::Array(vec![
        Value::Float(1_700_000_000.25),
        Value::Str("/page/index.mu".into()),
        Value::Bin(bytes(64, 0x3a9c)),
        Value::Map(vec![
            (Value::Str("id".into()), Value::UInt(4_294_967_311)),
            (Value::Str("name".into()), Value::Str("hotpath node".into())),
            (Value::Str("hops".into()), Value::UInt(3)),
            (Value::Str("offset".into()), Value::Int(-1200)),
            (
                Value::Str("flags".into()),
                Value::Array(vec![Value::Bool(true), Value::Nil, Value::Bool(false)]),
            ),
        ]),
    ])
}

fn msgpack_roundtrip() -> Result<Op> {
    let value = msgpack_value();
    ensure!(
        msgpack::unpack_exact(&msgpack::pack(&value)).map_err(fail)? == value,
        "msgpack round trip failed"
    );
    Ok(Box::new(move || {
        let packed = msgpack::pack(black_box(&value));
        black_box(msgpack::unpack_exact(&packed)).expect("unpack");
    }))
}

fn channel_envelope_roundtrip() -> Result<Op> {
    use rns_core::channel::envelope::{pack_envelope, unpack_envelope};
    let payload = bytes(200, 0xc4a7);
    Ok(Box::new(move || {
        let raw = pack_envelope(black_box(0xabcd), black_box(17), black_box(&payload));
        let (msgtype, sequence, body) = unpack_envelope(&raw).expect("unpack");
        black_box((msgtype, sequence, body.len()));
    }))
}

pub(crate) fn main(args: &[String]) -> Result<()> {
    match args {
        [cmd] if cmd == "list" => list(),
        [cmd, name] if cmd == "run" => run(name, None),
        [cmd, name, n] if cmd == "run" => run(name, Some(n.parse()?)),
        _ => bail!("hotpath list | hotpath run CASE [ITERATIONS]  (use ./scripts/hotpath)"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_case_builds_and_runs() {
        let mut names = std::collections::BTreeSet::new();
        for case in CASES {
            assert!(names.insert(case.name), "duplicate case {}", case.name);
            assert!(case.iterations > 0);
            let mut op = (case.build)().unwrap_or_else(|e| panic!("{}: {e:#}", case.name));
            rns_bench_hotpath_measured(&mut *op, 2);
        }
    }
}
