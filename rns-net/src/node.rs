//! RnsNode: high-level lifecycle management.
//!
//! Wires together the driver, interfaces, and timer thread.

mod announce;
mod control;
mod destinations;
mod hooks;
mod identity;
mod interface_config;
mod interface_display;
mod known_destinations;
mod links;
mod packets;
mod settings;
mod startup;
#[cfg(test)]
mod tests;

pub(crate) use announce::*;
pub(crate) use identity::*;
pub(crate) use interface_config::*;
pub(crate) use interface_display::*;
pub use settings::*;

use std::collections::{HashMap, HashSet};
use std::io::{self, Read};
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::Duration;

use rns_core::transport::announce_verify_queue::OverflowPolicy as AnnounceQueueOverflowPolicy;
use rns_core::transport::types::TransportConfig;
use rns_crypto::identity::Identity;
use rns_crypto::{OsRng, Rng};

use crate::config;
use crate::driver::{AnnounceRateDefaults, Callbacks, Driver};
#[cfg(feature = "iface-backbone")]
use crate::driver::{BackbonePeerPoolCandidateConfig, BackbonePeerPoolSettings};
use crate::event::{self, Event, EventSender};
use crate::ifac;
#[cfg(feature = "iface-auto")]
use crate::interface::auto::{auto_runtime_handle_from_config, AutoConfig};
#[cfg(feature = "iface-backbone")]
use crate::interface::backbone::{
    client_config_from_mode, client_priority_from_mode, client_runtime_handle_from_mode,
    peer_state_handle_from_mode, runtime_handle_from_mode, BackboneMode,
};
#[cfg(feature = "iface-i2p")]
use crate::interface::i2p::{i2p_runtime_handle_from_config, I2pConfig};
#[cfg(feature = "iface-local")]
use crate::interface::local::LocalServerConfig;
#[cfg(feature = "iface-pipe")]
use crate::interface::pipe::{pipe_runtime_handle_from_config, PipeConfig};
#[cfg(feature = "iface-rnode")]
use crate::interface::rnode::{rnode_runtime_handle_from_config, RNodeConfig};
#[cfg(feature = "iface-tcp")]
use crate::interface::tcp::{tcp_client_runtime_handle_from_config, TcpClientConfig};
#[cfg(feature = "iface-tcp")]
use crate::interface::tcp_server::{
    runtime_handle_from_config as tcp_runtime_handle_from_config, TcpServerConfig,
};
#[cfg(feature = "iface-udp")]
use crate::interface::udp::{udp_runtime_handle_from_config, UdpConfig};
use crate::interface::{InterfaceEntry, InterfaceStats};
use crate::storage;
use crate::time;

static NEXT_RESOURCE_TRANSFER_ID: AtomicU64 = AtomicU64::new(1);

#[cfg(test)]
const DEFAULT_KNOWN_DESTINATIONS_TTL: Duration = Duration::from_secs(48 * 60 * 60);
const DEFAULT_KNOWN_DESTINATIONS_MAX_ENTRIES: usize = 8192;

use crate::event::{QueryRequest, QueryResponse};

/// Error returned when the driver thread has shut down.
#[derive(Debug)]
pub struct SendError;

impl std::fmt::Display for SendError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "driver shut down")
    }
}

impl std::error::Error for SendError {}

/// Why a channel message was not sent. Only [`ChannelSendError::NotReady`]
/// is temporary: the channel's window is full, and the same message can be
/// sent again once it has room.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChannelSendError {
    /// The channel's send window is full.
    NotReady,
    /// The message does not fit in one packet of the link.
    MessageTooBig,
    /// The message could not be packed into an envelope.
    InvalidEnvelope,
    /// No link with that id.
    UnknownLink,
    /// The link has no channel open.
    NoChannel,
    /// The driver is stopped or draining.
    Unavailable,
}

impl From<rns_core::channel::ChannelError> for ChannelSendError {
    fn from(error: rns_core::channel::ChannelError) -> Self {
        match error {
            rns_core::channel::ChannelError::NotReady => Self::NotReady,
            rns_core::channel::ChannelError::MessageTooBig => Self::MessageTooBig,
            rns_core::channel::ChannelError::InvalidEnvelope => Self::InvalidEnvelope,
        }
    }
}

impl std::fmt::Display for ChannelSendError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotReady => write!(f, "channel is not ready to send"),
            Self::MessageTooBig => write!(f, "Message too big for packet"),
            Self::InvalidEnvelope => write!(f, "Invalid envelope data"),
            Self::UnknownLink => write!(f, "unknown link"),
            Self::NoChannel => write!(f, "link has no active channel"),
            Self::Unavailable => write!(f, "driver is stopped or draining"),
        }
    }
}

impl std::error::Error for ChannelSendError {}

/// A running RNS node.
pub struct RnsNode {
    tx: EventSender,
    driver_handle: Option<JoinHandle<()>>,
    verify_handle: Option<JoinHandle<()>>,
    verify_shutdown: Arc<crate::driver::WorkSignal>,
    persist_handle: Option<JoinHandle<()>>,
    persist_stop: Option<std::sync::mpsc::Sender<()>>,
    /// Upstream's periodic flush of changed known destinations.
    kd_flush_handle: Option<JoinHandle<()>>,
    kd_flush_stop: Option<std::sync::mpsc::Sender<()>>,
    rpc_server: Option<crate::rpc::RpcServer>,
    #[cfg(target_os = "linux")]
    rpc_unix_server: Option<crate::rpc::RpcServer>,
    tick_interval_ms: Arc<AtomicU64>,
    /// The next [`SendTicket`](crate::SendTicket) number.
    next_send_ticket: AtomicU64,
    /// Whether deferred sends are encrypted on the caller's thread: when
    /// this process may run on one CPU only, another thread would share it.
    encrypt_deferred_inline: bool,
    /// Cleared by the driver when it stops accepting new work.
    accepting_work: Arc<AtomicBool>,
    #[allow(dead_code)]
    probe_server: Option<crate::holepunch::probe::ProbeServerHandle>,
    known_destinations_path: Option<std::path::PathBuf>,
    known_destinations_store: Option<Arc<crate::storage_sqlite::KnownDestinationsStore>>,
    stamp_store: Option<crate::stamps::DestinationStampStore>,
    /// `Transport.STAMP_DESTINATIONS`: whether announces from this node carry
    /// a destination stamp. Defaults to the compile-time constant; shared
    /// with the driver, which applies the `global.stamp_destinations`
    /// runtime config key.
    stamp_destinations: Arc<AtomicBool>,
    stamp_targets: crate::stamper::StampTargets,
    /// Shared with the driver; grinds stamps off the calling thread.
    stamper: Option<Arc<crate::stamper::Stamper>>,
    transport_state_dir: Option<std::path::PathBuf>,
    pub(crate) ratchet_store: Option<Arc<dyn storage::RatchetStore>>,
    ratchet_expiry: Duration,
    /// Destination types this application needs (upstream 825c2e19).
    #[cfg(feature = "iface-local")]
    pub(crate) destination_types: crate::shared_client::DestinationTypeRequester,
}

impl RnsNode {
    /// Construct an RnsNode from its constituent parts.
    /// Used by `shared_client` to build a client-mode node.
    #[cfg(any(feature = "iface-local", test))]
    pub(crate) fn from_parts(
        tx: EventSender,
        driver_handle: thread::JoinHandle<()>,
        rpc_server: Option<crate::rpc::RpcServer>,
        tick_interval_ms: Arc<AtomicU64>,
        accepting_work: Arc<AtomicBool>,
    ) -> Self {
        RnsNode {
            tx,
            driver_handle: Some(driver_handle),
            verify_handle: None,
            verify_shutdown: Arc::default(),
            persist_handle: None,
            persist_stop: None,
            kd_flush_handle: None,
            kd_flush_stop: None,
            rpc_server,
            #[cfg(target_os = "linux")]
            rpc_unix_server: None,
            tick_interval_ms,
            next_send_ticket: AtomicU64::new(0),
            encrypt_deferred_inline: std::thread::available_parallelism()
                .map_or(true, |cpus| cpus.get() == 1),
            accepting_work,
            probe_server: None,
            known_destinations_path: None,
            known_destinations_store: None,
            stamp_store: None,
            stamp_destinations: Arc::new(AtomicBool::new(rns_core::constants::STAMP_DESTINATIONS)),
            stamp_targets: crate::stamper::StampTargets::default(),
            stamper: None,
            transport_state_dir: None,
            ratchet_store: None,
            ratchet_expiry: Duration::from_secs(rns_core::constants::RATCHET_EXPIRY),
            #[cfg(feature = "iface-local")]
            destination_types: Default::default(),
        }
    }

    /// Get the event sender for direct event injection.
    pub fn event_sender(&self) -> &EventSender {
        &self.tx
    }

    /// Set the tick interval in milliseconds.
    /// Default is 1000 (1 second). Changes take effect on the next tick cycle.
    /// Values are clamped to the range 100..=10000.
    /// Returns the actual stored value (which may differ from `ms` if clamped).
    pub fn set_tick_interval(&self, ms: u64) -> u64 {
        let clamped = ms.clamp(100, 10_000);
        if clamped != ms {
            log::warn!(
                "tick interval {}ms out of range, clamped to {}ms",
                ms,
                clamped
            );
        }
        self.tick_interval_ms.store(clamped, Ordering::Relaxed);
        clamped
    }

    /// Get the current tick interval in milliseconds.
    pub fn tick_interval(&self) -> u64 {
        self.tick_interval_ms.load(Ordering::Relaxed)
    }

    /// Shut down the node. Blocks until the driver thread exits.
    pub fn shutdown(mut self) {
        self.shutdown_inner();
    }

    fn shutdown_inner(&mut self) {
        #[cfg(feature = "iface-local")]
        self.destination_types.withdraw_from_shared_instance();
        if self.driver_handle.is_none()
            && self.verify_handle.is_none()
            && self.persist_handle.is_none()
            && self.rpc_server.is_none()
            && {
                #[cfg(target_os = "linux")]
                {
                    self.rpc_unix_server.is_none()
                }
                #[cfg(not(target_os = "linux"))]
                {
                    true
                }
            }
        {
            return;
        }
        // Stop RPC server first
        if let Some(mut rpc) = self.rpc_server.take() {
            rpc.stop();
        }
        #[cfg(target_os = "linux")]
        if let Some(mut rpc) = self.rpc_unix_server.take() {
            rpc.stop();
        }
        if let Some(stop) = self.kd_flush_stop.take() {
            let _ = stop.send(());
        }
        if let Some(handle) = self.kd_flush_handle.take() {
            let _ = handle.join();
        }
        self.persist_known_destinations();
        self.persist_transport_state();
        if let Some(stop) = self.persist_stop.take() {
            let _ = stop.send(());
        }
        if let Some(handle) = self.persist_handle.take() {
            let _ = handle.join();
        }
        self.verify_shutdown.stop();
        let _ = self.tx.send(Event::Shutdown);
        if let Some(handle) = self.driver_handle.take() {
            let _ = handle.join();
        }
        // Reader/ticker EventSender clones may outlive the driver. They must not
        // retain private owners (and their file locks) after node shutdown.
        crate::sync::lock_or_recover(self.tx.local_ratchets(), "local ratchets").clear();
        if let Some(handle) = self.verify_handle.take() {
            let _ = handle.join();
        }
    }
}

impl Drop for RnsNode {
    fn drop(&mut self) {
        self.shutdown_inner();
    }
}

pub(crate) use rns_core::display::hex;
