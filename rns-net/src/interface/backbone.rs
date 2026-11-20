//! Backbone TCP mesh interface using cross-platform polling.
//!
//! Server mode: listens on a TCP port, accepts peer connections, spawns
//! dynamic per-peer interfaces. Uses a single poll thread to multiplex
//! all client sockets. HDLC framing for packet boundaries.
//!
//! Client mode: connects to a remote backbone server, single TCP connection
//! with HDLC framing. Reconnects on disconnect.
//!
//! Matches Python `BackboneInterface.py`.

mod abuse;
mod client;
mod factory;
mod runtime;
mod server;
#[cfg(test)]
mod tests;

pub use abuse::*;
pub use client::*;
pub use factory::*;
pub use runtime::*;
pub use server::*;

use std::collections::{HashMap, HashSet};
use std::hash::{BuildHasher, Hasher};
use std::io;
#[cfg(test)]
use std::io::Write;
use std::net::{IpAddr, Shutdown, TcpListener, TcpStream, ToSocketAddrs};
use std::os::unix::io::AsRawFd;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::thread;
use std::time::{Duration, Instant};

use socket2::{SockRef, TcpKeepalive};

use rns_core::constants;
use rns_core::transport::types::{IngressControlConfig, InterfaceId, InterfaceInfo};

use crate::event::{Event, EventSender};
use crate::event::{LoopContext, LoopSource, SourceStatus};
use crate::hdlc;
use crate::interface::loop_writer::LoopEgress;
use crate::interface::stream_read::{read_stream_frames, StreamRead};
use crate::interface::transmit_buffer::{
    EgressController, TransmitBuffer, EGRESS_DEAD_TIME, EGRESS_HIGH_WATERMARK,
};
use crate::interface::{
    auto_mtu_for_bitrate, lock_or_recover, wait_while_active, DynamicInterfaceTemplate,
    EgressControl, InterfaceConfigData, InterfaceFactory, ListenerControl, StartContext,
    StartResult, Writer,
};
use crate::BackbonePeerStateEntry;

/// Upstream listener bitrate estimate used for accepted peers.
pub(crate) const SERVER_BITRATE_GUESS: u64 = 100_000_000;
/// Standalone Backbone client bitrate estimate.
pub(crate) const CLIENT_BITRATE_GUESS: u64 = 100_000_000;

/// Effective frame size selected by upstream autoconfiguration at 100 Mbps.
pub(crate) const HW_MTU: usize = match auto_mtu_for_bitrate(CLIENT_BITRATE_GUESS) {
    Some(mtu) => mtu as usize,
    None => 1_048_576,
};
/// MTU selected for listener-accepted peers at the listener bitrate estimate.
pub(crate) const SERVER_PEER_MTU: u32 = match auto_mtu_for_bitrate(SERVER_BITRATE_GUESS) {
    Some(mtu) => mtu,
    None => 1_048_576,
};

const DP_IC_HIGH_WM_PCT: usize = 90;
const DP_IC_MID_WM_PCT: usize = 68;
const DP_IC_LOW_WM_PCT: usize = 10;
const DP_IC_INTERVAL: Duration = Duration::from_millis(250);
const DP_IC_RCVBUF: usize = 32_768;
const DP_IC_IF_HEADROOM: usize = 32;
const DP_IC_PENALTY: f64 = 1.5;

/// Configuration for a backbone interface.
#[derive(Debug, Clone)]
pub struct BackboneConfig {
    /// Interface name.
    pub name: String,
    /// Local address the listener binds to (`listen_on`, `listen_ip` or `device`); default
    /// `0.0.0.0`.
    pub listen_ip: String,
    /// TCP port the listener binds to (`listen_port` or `port`); default 4242.
    pub listen_port: u16,
    /// ID of the listener interface; accepted peers get dynamic IDs of their own.
    pub interface_id: InterfaceId,
    /// Mode of accepted peers, one of `constants::MODE_*`; set from the interface's config at
    /// start.
    pub mode: u8,
    /// Gravity of accepted peers; set from the interface's config at start.
    pub gravity: i64,
    /// `recursive_prs` of accepted peers; set from the interface's config at start.
    pub recursive_prs: bool,
    /// `announces_from_internal` of accepted peers; set from the interface's config at start.
    pub announces_from_internal: bool,
    /// `announces_to_internal` of accepted peers; set from the interface's config at start.
    pub announces_to_internal: Option<bool>,
    /// Startup limit on concurrent clients (`client_limit`, or `max_connections` which takes
    /// precedence); `None` for no limit.
    pub max_connections: Option<usize>,
    /// Startup idle timeout (`idle_timeout`, seconds): a client that sends nothing this long after
    /// connecting is disconnected.
    pub idle_timeout: Option<Duration>,
    /// Startup write stall timeout (`write_stall_timeout`, seconds); `None` uses the default egress
    /// dead time.
    pub write_stall_timeout: Option<Duration>,
    /// Startup abuse handling settings.
    pub abuse: BackboneAbuseConfig,
    /// Blocking of addresses whose connections keep closing quickly.
    pub fast_flap: BackboneFastFlapConfig,
    /// Fast-flap history; by default the table shared by every listener in the process.
    pub fast_flap_state: Arc<Mutex<BackboneFastFlapMonitor>>,
    /// Ingress control of accepted peers; set from the interface's config at start.
    pub ingress_control: IngressControlConfig,
    /// Live settings the listener reads, which can be changed while it runs.
    pub runtime: Arc<Mutex<BackboneServerRuntime>>,
    /// Per-address peer state, shared with the driver.
    pub peer_state: Arc<Mutex<BackbonePeerMonitor>>,
}

impl Default for BackboneConfig {
    fn default() -> Self {
        let mut config = BackboneConfig {
            name: String::new(),
            listen_ip: "0.0.0.0".into(),
            listen_port: 0,
            interface_id: InterfaceId(0),
            mode: constants::MODE_FULL,
            gravity: 0,
            recursive_prs: false,
            announces_from_internal: true,
            announces_to_internal: None,
            max_connections: None,
            idle_timeout: None,
            write_stall_timeout: None,
            abuse: BackboneAbuseConfig::default(),
            fast_flap: BackboneFastFlapConfig::default(),
            fast_flap_state: shared_fast_flap_monitor(),
            ingress_control: IngressControlConfig::enabled(),
            runtime: Arc::new(Mutex::new(BackboneServerRuntime {
                max_connections: None,
                idle_timeout: None,
                write_stall_timeout: None,
                abuse: BackboneAbuseConfig::default(),
            })),
            peer_state: Arc::new(Mutex::new(BackbonePeerMonitor::new())),
        };
        let startup = BackboneServerRuntime::from_config(&config);
        config.runtime = Arc::new(Mutex::new(startup));
        config
    }
}
