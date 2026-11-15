//! Remote management destinations for the Reticulum transport node.
//!
//! Implements the server-side handlers for:
//! - `/status` on `rnstransport.remote.management` destination
//! - `/path` on `rnstransport.remote.management` destination
//! - `/list` on `rnstransport.info.blackhole` destination
//!
//! Python reference: Transport.py:220-241, 2591-2643, 3243-3249

use rns_core::constants;
use rns_core::destination::destination_hash;
use rns_core::hash::truncated_hash;
use rns_core::msgpack::{self, Value};
use rns_core::transport::TransportEngine;

/// Get the path hash for "/status".
pub fn status_path_hash() -> [u8; 16] {
    truncated_hash(b"/status")
}

/// Get the path hash for "/path".
pub fn path_path_hash() -> [u8; 16] {
    truncated_hash(b"/path")
}

/// Get the path hash for "/list".
pub fn list_path_hash() -> [u8; 16] {
    truncated_hash(b"/list")
}

/// Check if a path hash matches a known management path.
pub fn is_management_path(path_hash: &[u8; 16]) -> bool {
    *path_hash == status_path_hash()
        || *path_hash == path_path_hash()
        || *path_hash == list_path_hash()
}

/// Compute the remote management destination hash.
///
/// Destination: `rnstransport.remote.management` with transport identity.
pub fn management_dest_hash(transport_identity_hash: &[u8; 16]) -> [u8; 16] {
    destination_hash(
        "rnstransport",
        &["remote", "management"],
        Some(transport_identity_hash),
    )
}

/// Compute the blackhole info destination hash.
///
/// Destination: `rnstransport.info.blackhole` with transport identity.
pub fn blackhole_dest_hash(transport_identity_hash: &[u8; 16]) -> [u8; 16] {
    destination_hash(
        "rnstransport",
        &["info", "blackhole"],
        Some(transport_identity_hash),
    )
}

/// Compute the probe responder destination hash.
///
/// Destination: `rnstransport.probe` with transport identity.
pub fn probe_dest_hash(transport_identity_hash: &[u8; 16]) -> [u8; 16] {
    destination_hash("rnstransport", &["probe"], Some(transport_identity_hash))
}

/// Build the 10-byte random blob carried by an announce.
///
/// Matches Python `Destination.announce()`: 5 random bytes followed by the
/// emission time in whole seconds, big-endian, truncated to 5 bytes. Path
/// update rules compare this emission time, so it must be a real timestamp.
pub fn announce_random_blob(rng: &mut dyn rns_crypto::Rng, now: f64) -> [u8; 10] {
    let mut random_hash = [0u8; 10];
    rng.fill_bytes(&mut random_hash[..5]);
    let now_secs = if now.is_finite() && now > 0.0 {
        now as u64
    } else {
        0
    };
    random_hash[5..10].copy_from_slice(&now_secs.to_be_bytes()[3..8]);
    random_hash
}

/// Packet context for a built-in announce: `PATH_RESPONSE` when it answers
/// a path request, as Python `Destination.announce(path_response=True)`.
fn announce_context(path_response: bool) -> u8 {
    if path_response {
        constants::CONTEXT_PATH_RESPONSE
    } else {
        constants::CONTEXT_NONE
    }
}

/// A destination this node announces under its transport identity and
/// answers itself (`Transport.mgmt_destinations`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BuiltinDestination {
    /// `rnstransport.remote.management`
    RemoteManagement,
    /// `rnstransport.info.blackhole`
    Blackhole,
    /// `rnstransport.probe`
    Probe,
}

impl BuiltinDestination {
    pub const ALL: [BuiltinDestination; 3] = [
        BuiltinDestination::RemoteManagement,
        BuiltinDestination::Blackhole,
        BuiltinDestination::Probe,
    ];

    pub fn aspects(self) -> &'static [&'static str] {
        match self {
            BuiltinDestination::RemoteManagement => &["remote", "management"],
            BuiltinDestination::Blackhole => &["info", "blackhole"],
            BuiltinDestination::Probe => &["probe"],
        }
    }

    pub fn dest_hash(self, transport_identity_hash: &[u8; 16]) -> [u8; 16] {
        destination_hash(
            "rnstransport",
            self.aspects(),
            Some(transport_identity_hash),
        )
    }

    pub fn name_hash(self) -> [u8; 10] {
        rns_core::destination::name_hash("rnstransport", self.aspects())
    }

    /// The destination as the stamper sees it, for grinding its stamp.
    pub fn destination(self, transport_identity_hash: [u8; 16]) -> crate::destination::Destination {
        crate::destination::Destination::single_in(
            "rnstransport",
            self.aspects(),
            rns_core::types::IdentityHash(transport_identity_hash),
        )
    }

    pub fn label(self) -> &'static str {
        match self {
            BuiltinDestination::RemoteManagement => "management destination",
            BuiltinDestination::Blackhole => "blackhole info",
            BuiltinDestination::Probe => "probe responder",
        }
    }
}

/// Build an announce packet for a built-in destination, with `app_data`
/// (the stamp extension, when destinations are stamped) appended.
///
/// Returns raw packet bytes ready for `engine.handle_outbound()`.
pub fn build_builtin_announce(
    destination: BuiltinDestination,
    identity: &rns_crypto::identity::Identity,
    rng: &mut dyn rns_crypto::Rng,
    now: f64,
    path_response: bool,
    app_data: Option<&[u8]>,
) -> Option<Vec<u8>> {
    let dest_hash = destination.dest_hash(identity.hash());
    let name_hash = destination.name_hash();
    let random_hash = announce_random_blob(rng, now);

    let (announce_data, _has_ratchet) = rns_core::announce::AnnounceData::pack(
        identity,
        &dest_hash,
        &name_hash,
        &random_hash,
        None, // no ratchet
        app_data,
    )
    .ok()?;

    let flags = rns_core::packet::PacketFlags {
        header_type: constants::HEADER_1,
        context_flag: constants::FLAG_UNSET,
        transport_type: constants::TRANSPORT_BROADCAST,
        destination_type: constants::DESTINATION_SINGLE,
        packet_type: constants::PACKET_TYPE_ANNOUNCE,
    };

    let packet = rns_core::packet::RawPacket::pack(
        flags,
        0,
        &dest_hash,
        None,
        announce_context(path_response),
        &announce_data,
    )
    .ok()?;

    Some(packet.raw)
}

/// Build an unstamped announce packet for the probe responder destination.
pub fn build_probe_announce(
    identity: &rns_crypto::identity::Identity,
    rng: &mut dyn rns_crypto::Rng,
    now: f64,
    path_response: bool,
) -> Option<Vec<u8>> {
    build_builtin_announce(
        BuiltinDestination::Probe,
        identity,
        rng,
        now,
        path_response,
        None,
    )
}

/// Management configuration.
#[derive(Debug, Clone, Default)]
pub struct ManagementConfig {
    /// Enable remote management destination.
    pub enable_remote_management: bool,
    /// Identity hashes allowed to query management.
    pub remote_management_allowed: Vec<[u8; 16]>,
    /// Enable blackhole list publication.
    pub publish_blackhole: bool,
    /// Transport identities whose published blackhole lists are fetched.
    pub blackhole_sources: Vec<[u8; 16]>,
    /// Seconds between fetches from each source; `None` for an hour.
    pub blackhole_update_interval: Option<f64>,
}

/// Handle a `/status` request as upstream's `remote_status_handler` does:
/// for request data `[include_lstats, include_profiling?]` answer
/// `[interface_stats, link_count?, profiling_results?]`, where
/// `interface_stats` is the dict the shared-instance RPC returns for
/// `interface_stats`. Anything but a non-empty list gets no answer.
pub fn handle_status_request(
    data: &[u8],
    interface_stats: Value,
    link_count: usize,
) -> Option<Vec<u8>> {
    let Ok(Value::Array(request)) = msgpack::unpack_exact(data) else {
        return None;
    };
    let flag = |i: usize| match request.get(i) {
        Some(Value::Bool(b)) => *b,
        Some(Value::UInt(1)) | Some(Value::Int(1)) => true,
        _ => false,
    };
    if request.is_empty() {
        return None;
    }
    let mut response = vec![interface_stats];
    if flag(0) {
        response.push(Value::UInt(link_count as u64));
    }
    if request.len() >= 2 && flag(1) {
        response.push(crate::profiling::results_msgpack());
    }
    Some(msgpack::pack(&Value::Array(response)))
}

/// Handle a `/path` request.
///
/// Request data: msgpack([command, destination_hash?, max_hops?])
/// - command = "table" → returns path table entries
/// - command = "rates" → returns rate table entries
pub fn handle_path_request(data: &[u8], engine: &TransportEngine) -> Option<Vec<u8>> {
    let arr = match msgpack::unpack_exact(data) {
        Ok(Value::Array(arr)) if !arr.is_empty() => arr,
        _ => return None,
    };

    let command = match &arr[0] {
        Value::Str(s) => s.as_str(),
        _ => return None,
    };

    let dest_filter: Option<[u8; 16]> = if arr.len() > 1 {
        match &arr[1] {
            Value::Bin(b) if b.len() == 16 => {
                let mut h = [0u8; 16];
                h.copy_from_slice(b);
                Some(h)
            }
            _ => None,
        }
    } else {
        None
    };

    let max_hops: Option<u8> = if arr.len() > 2 {
        arr[2].as_uint().map(|v| v as u8)
    } else {
        None
    };

    match command {
        "table" => {
            let paths = engine.get_path_table(max_hops);
            let mut entries = Vec::new();
            for p in &paths {
                if let Some(ref filter) = dest_filter {
                    if p.0 != *filter {
                        continue;
                    }
                }
                // p = (dest_hash, timestamp, next_hop, hops, expires, interface)
                let entry = vec![
                    (Value::Str("hash".into()), Value::Bin(p.0.to_vec())),
                    (Value::Str("timestamp".into()), Value::Float(p.1)),
                    (Value::Str("via".into()), Value::Bin(p.2.to_vec())),
                    (Value::Str("hops".into()), Value::UInt(p.3 as u64)),
                    (Value::Str("expires".into()), Value::Float(p.4)),
                    (Value::Str("used".into()), Value::Float(p.5)),
                    (Value::Str("interface".into()), Value::Str(p.6.clone())),
                ];
                entries.push(Value::Map(entry));
            }
            Some(msgpack::pack(&Value::Array(entries)))
        }
        "rates" => {
            let rates = engine.get_rate_table();
            let mut entries = Vec::new();
            for r in &rates {
                if let Some(ref filter) = dest_filter {
                    if r.0 != *filter {
                        continue;
                    }
                }
                // r = (dest_hash, last, rate_violations, blocked_until, timestamps)
                let timestamps: Vec<Value> = r.4.iter().map(|t| Value::Float(*t)).collect();
                let entry = vec![
                    (Value::Str("hash".into()), Value::Bin(r.0.to_vec())),
                    (Value::Str("last".into()), Value::Float(r.1)),
                    (
                        Value::Str("rate_violations".into()),
                        Value::UInt(r.2 as u64),
                    ),
                    (Value::Str("blocked_until".into()), Value::Float(r.3)),
                    (Value::Str("timestamps".into()), Value::Array(timestamps)),
                ];
                entries.push(Value::Map(entry));
            }
            Some(msgpack::pack(&Value::Array(entries)))
        }
        _ => None,
    }
}

/// Handle a `/list` (blackhole list) request.
///
/// Returns the blackholed_identities dict as msgpack, in upstream's format
/// (`Transport.blackhole_list_handler`): identity hash to `{"source",
/// "until", "reason"}`, with this node's transport identity as the source
/// of its own entries. `created` is kept as an extra field, which upstream
/// readers ignore.
pub fn handle_blackhole_list_request(engine: &TransportEngine) -> Option<Vec<u8>> {
    let local = engine.identity_hash();
    let mut map_entries = Vec::new();
    for (hash, entry) in engine.blackholed_entries() {
        let Value::Map(mut fields) = crate::blackhole_store::entry_value(entry, local) else {
            continue;
        };
        fields.push((Value::Str("created".into()), Value::Float(entry.created)));
        map_entries.push((Value::Bin(hash.to_vec()), Value::Map(fields)));
    }
    Some(msgpack::pack(&Value::Map(map_entries)))
}

/// Build an unstamped announce packet for the management destination.
pub fn build_management_announce(
    identity: &rns_crypto::identity::Identity,
    rng: &mut dyn rns_crypto::Rng,
    now: f64,
    path_response: bool,
) -> Option<Vec<u8>> {
    build_builtin_announce(
        BuiltinDestination::RemoteManagement,
        identity,
        rng,
        now,
        path_response,
        None,
    )
}

/// Build an unstamped announce packet for the blackhole info destination.
pub fn build_blackhole_announce(
    identity: &rns_crypto::identity::Identity,
    rng: &mut dyn rns_crypto::Rng,
    now: f64,
    path_response: bool,
) -> Option<Vec<u8>> {
    build_builtin_announce(
        BuiltinDestination::Blackhole,
        identity,
        rng,
        now,
        path_response,
        None,
    )
}
