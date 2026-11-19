//! Builders shared by the transport engine's per-module tests.

use super::*;

pub(super) use super::fuzz::{config, interface};

pub(super) fn engine(transport_enabled: bool) -> TransportEngine {
    TransportEngine::new(config(transport_enabled))
}

/// A HEADER_1 announce frame for `destination_hash` carrying `payload`.
pub(super) fn announce_raw(destination_hash: &[u8; 16], payload: &[u8]) -> Vec<u8> {
    let mut raw = vec![constants::PACKET_TYPE_ANNOUNCE, 0x02];
    raw.extend_from_slice(destination_hash);
    raw.push(constants::CONTEXT_NONE);
    raw.extend_from_slice(payload);
    raw
}

/// A path through `next_hop` on `receiving_interface`, with a cached
/// announce to answer path requests from.
pub(super) fn path_entry(
    destination_hash: &[u8; 16],
    timestamp: f64,
    hops: u8,
    receiving_interface: InterfaceId,
    next_hop: [u8; 16],
) -> PathEntry {
    PathEntry {
        timestamp,
        next_hop,
        hops,
        expires: timestamp + constants::DESTINATION_TIMEOUT,
        random_blobs: Vec::new(),
        receiving_interface,
        packet_hash: [0; 32],
        used: 0.0,
        announce_raw: Some(announce_raw(destination_hash, &[0xAB; 32])),
    }
}

/// Path request data: destination hash, the optional requesting transport
/// id, the tag and the optional stamp extension.
pub(super) fn path_request(
    destination_hash: &[u8; 16],
    transport_id: Option<&[u8; 16]>,
    tag: &[u8],
    ext_payload: Option<&[u8]>,
) -> Vec<u8> {
    let mut data = destination_hash.to_vec();
    if let Some(id) = transport_id {
        data.extend_from_slice(id);
    }
    data.extend_from_slice(tag);
    if let Some(ext) = ext_payload {
        data.extend_from_slice(ext);
    }
    data
}
