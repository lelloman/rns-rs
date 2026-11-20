//! Tags of the actions a hook injects.
//!
//! An injected action is encoded as one tag byte followed by the variant's
//! fields, little-endian, in declaration order. Variable-length data is
//! given as a `u32` offset and a `u32` length; for a WASM hook the offset is
//! an address in its linear memory, for a native hook it is relative to the
//! start of the buffer passed to `inject_action`. The fields of each tag are
//! listed with it, and an encoding shorter than that is rejected.

/// Send a packet on one interface: interface `u64`, data offset and length.
pub const TAG_SEND_ON_INTERFACE: u8 = 0;
/// Broadcast a packet on every outbound interface: data offset and length,
/// excluded interface `u64`, `u8` set to 1 if the exclusion applies.
pub const TAG_BROADCAST: u8 = 1;
/// Deliver a packet to a local destination: destination hash (16), data
/// offset and length, packet hash (32), receiving interface `u64`.
pub const TAG_DELIVER_LOCAL: u8 = 2;
/// Report a validated announce: destination hash (16), identity hash (16),
/// public key (64), name hash (10), random hash (10), hops `u8`, receiving
/// interface `u64`, `u8` set to 1 if app data follows as offset and length.
pub const TAG_ANNOUNCE_RECEIVED: u8 = 3;
/// Report a path table update: destination hash (16), hops `u8`, next hop
/// (16), interface `u64`.
pub const TAG_PATH_UPDATED: u8 = 4;
/// Forward a packet to the local client interfaces: data offset and length,
/// excluded interface `u64`, `u8` set to 1 if the exclusion applies.
pub const TAG_FORWARD_LOCAL_CLIENTS: u8 = 5;
/// Forward a plain or group broadcast: data offset and length, `u8` set to
/// 1 to send to the local clients (0 for the other interfaces), excluded
/// interface `u64`, `u8` set to 1 if the exclusion applies.
pub const TAG_FORWARD_PLAIN_BROADCAST: u8 = 6;
/// Cache an announce packet: packet hash (32), data offset and length.
pub const TAG_CACHE_ANNOUNCE: u8 = 7;
/// Send tunnel synthesis data: interface `u64`, data offset and length,
/// destination hash (16).
pub const TAG_TUNNEL_SYNTHESIZE: u8 = 8;
/// Report an established tunnel: tunnel id (32), interface `u64`.
pub const TAG_TUNNEL_ESTABLISHED: u8 = 9;
