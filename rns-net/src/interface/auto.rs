//! AutoInterface: Zero-configuration LAN auto-discovery via IPv6 multicast.
//!
//! Matches Python `AutoInterface` from `RNS/Interfaces/AutoInterface.py`.
//!
//! Thread model (per adopted network interface):
//!   - Discovery sender: periodically sends discovery token via multicast
//!   - Discovery receiver (multicast): validates tokens, adds peers
//!   - Discovery receiver (unicast): validates reverse-peering tokens
//!   - Data receiver: UDP server receiving unicast data from peers
//!
//! Additionally one shared thread:
//!   - Peer jobs: periodically culls timed-out peers

mod addresses;
mod data;
mod discovery;
mod factory;
mod host_interfaces;
mod peers;
mod runtime;
mod sockets;
mod startup;
#[cfg(test)]
mod tests;
mod workers;

pub use addresses::*;
use data::*;
use discovery::*;
pub use factory::*;
pub use host_interfaces::*;
use peers::*;
pub use runtime::*;
use sockets::*;
pub use startup::*;
use workers::*;

use std::collections::{HashMap, HashSet, VecDeque};
use std::io;
use std::net::{Ipv6Addr, SocketAddrV6, UdpSocket};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use rns_core::transport::types::InterfaceId;

use crate::event::{Event, EventSender};
use crate::interface::{lock_or_recover, Writer};

// ── Constants (matching Python AutoInterface) ──────────────────────────────

/// Default UDP port for multicast discovery.
pub const DEFAULT_DISCOVERY_PORT: u16 = 29716;

/// Default UDP port for unicast data exchange.
pub const DEFAULT_DATA_PORT: u16 = 42671;

/// Default group identifier.
pub const DEFAULT_GROUP_ID: &[u8] = b"reticulum";

/// Default IFAC size for AutoInterface (bytes).
pub const DEFAULT_IFAC_SIZE: usize = 16;

/// Hardware MTU for AutoInterface packets.
pub const HW_MTU: usize = 1196;

/// Multicast scope: link-local.
pub const SCOPE_LINK: &str = "2";
/// Multicast scope: admin-local.
pub const SCOPE_ADMIN: &str = "4";
/// Multicast scope: site-local.
pub const SCOPE_SITE: &str = "5";
/// Multicast scope: organization-local.
pub const SCOPE_ORGANISATION: &str = "8";
/// Multicast scope: global.
pub const SCOPE_GLOBAL: &str = "e";

/// Permanent multicast address type.
pub const MULTICAST_PERMANENT_ADDRESS_TYPE: &str = "0";
/// Temporary multicast address type.
pub const MULTICAST_TEMPORARY_ADDRESS_TYPE: &str = "1";

/// How long before a peer is considered timed out (seconds).
pub const PEERING_TIMEOUT: f64 = 22.0;

/// How often to send multicast discovery announcements (seconds).
pub const ANNOUNCE_INTERVAL: f64 = 1.6;

/// How often to run peer maintenance jobs (seconds).
pub const PEER_JOB_INTERVAL: f64 = 4.0;

/// Multicast echo timeout (seconds). Used for carrier detection.
pub const MCAST_ECHO_TIMEOUT: f64 = 6.5;

/// Default bitrate guess for AutoInterface (10 Mbps).
pub const BITRATE_GUESS: u64 = 10_000_000;

/// Deduplication deque size.
pub const MULTI_IF_DEQUE_LEN: usize = 48;

/// Deduplication deque entry TTL (seconds).
pub const MULTI_IF_DEQUE_TTL: f64 = 0.75;

/// Reverse peering interval multiplier (announce_interval * 3.25).
pub const REVERSE_PEERING_MULTIPLIER: f64 = 3.25;

/// How often AutoInterface rescans local link-local interfaces.
pub const AUTO_RESCAN_INTERVAL: f64 = 1.25;

/// Default cap on active peers per discovery worker (one adopted network
/// interface). Discovery tokens from further sources are ignored until an
/// existing peer times out. Configurable with `max_peers`.
pub const DEFAULT_MAX_PEERS: usize = 128;

/// New peers each discovery worker admits within one
/// [`PEER_ADMISSION_WINDOW`].
pub const MAX_NEW_PEERS_PER_WINDOW: usize = 32;

/// Length of the window over which [`MAX_NEW_PEERS_PER_WINDOW`] applies.
pub const PEER_ADMISSION_WINDOW: Duration = Duration::from_secs(10);

/// Minimum spacing between warnings about ignored discovery sources, per worker.
const PEER_REFUSAL_LOG_INTERVAL: Duration = Duration::from_secs(10);

/// Interfaces always ignored.
pub const ALL_IGNORE_IFS: &[&str] = &["lo0"];

#[cfg_attr(not(any(target_os = "android", test)), allow(dead_code))]
const ANDROID_IGNORE_IFS: &[&str] = &[
    "dummy0", "lo", "tun0", "rmnet0", "rmnet1", "rmnet2", "rmnet3", "rmnet4", "rmnet5", "rmnet6",
    "rmnet7",
];

// ── Configuration ──────────────────────────────────────────────────────────

/// Configuration for an AutoInterface.
#[derive(Debug, Clone)]
pub struct AutoConfig {
    /// Interface name from the config section.
    pub name: String,
    /// Group identifier (`group_id`); only peers with the same group discover each other.
    pub group_id: Vec<u8>,
    /// IPv6 multicast scope digit for discovery (`discovery_scope`), one of the `SCOPE_*` values.
    pub discovery_scope: String,
    /// UDP port for multicast discovery (`discovery_port`).
    pub discovery_port: u16,
    /// UDP port for unicast data between peers (`data_port`).
    pub data_port: u16,
    /// Multicast address type digit (`multicast_address_type`), one of the `MULTICAST_*_ADDRESS_TYPE` values.
    pub multicast_address_type: String,
    /// Host network interfaces to adopt (`devices`); empty adopts all that are not ignored.
    pub allowed_interfaces: Vec<String>,
    /// Host network interfaces never to adopt (`ignored_devices`).
    pub ignored_interfaces: Vec<String>,
    /// Bitrate reported for each peer interface, in bits per second (`configured_bitrate`).
    pub configured_bitrate: u64,
    /// Maximum number of active peers per adopted network interface
    /// (`max_peers`, default [`DEFAULT_MAX_PEERS`]). Discovery tokens from
    /// further sources are ignored until an existing peer times out.
    pub max_peers: usize,
    /// Base interface ID. Per-peer IDs will be assigned dynamically.
    pub interface_id: InterfaceId,
    /// Timing settings shared with the running interface, adjustable at runtime.
    pub runtime: Arc<Mutex<AutoRuntime>>,
}

impl Default for AutoConfig {
    fn default() -> Self {
        AutoConfig {
            name: String::new(),
            group_id: DEFAULT_GROUP_ID.to_vec(),
            discovery_scope: SCOPE_LINK.to_string(),
            discovery_port: DEFAULT_DISCOVERY_PORT,
            data_port: DEFAULT_DATA_PORT,
            multicast_address_type: MULTICAST_TEMPORARY_ADDRESS_TYPE.to_string(),
            allowed_interfaces: Vec::new(),
            ignored_interfaces: Vec::new(),
            configured_bitrate: BITRATE_GUESS,
            max_peers: DEFAULT_MAX_PEERS,
            interface_id: InterfaceId(0),
            runtime: Arc::new(Mutex::new(AutoRuntime::default())),
        }
    }
}

mod folded;

use super::{InterfaceConfigData, InterfaceFactory, StartContext, StartResult};
