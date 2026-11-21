//! rns-net: Network node for Reticulum.
//!
//! Drives `rns-core::TransportEngine` with real TCP/UDP sockets and threads.
//! Reads standard Python RNS config files, opens TCP server/client, UDP, and
//! Local interfaces, persists identity and known destinations.

// A type in the public API that downstream code cannot name is either
// API to export or a detail to keep out of public signatures.
#![warn(unnameable_types)]
// Test code is outside the code-quality lints' scope.
#![cfg_attr(test, allow(unsafe_code, clippy::undocumented_unsafe_blocks))]

#[cfg(feature = "hooks")]
extern crate rns_hooks_crate as rns_hooks;

mod action_pool;
mod announce_cache;
mod blackhole_store;
mod common;
mod destination_types;
mod driver;
mod engine;
mod holepunch;
mod link_send;
mod listen;
mod local_ratchet;
mod node;
mod poll;
mod resource;
#[cfg(feature = "iface-local")]
mod shared_client;
mod stamper;
mod stamps;
mod state_snapshot;
mod storage_sqlite;
mod sync;
#[cfg(unix)]
mod sys;

// Internal paths the crate's modules use; these modules are not public.
use common::{destination, link_manager};

pub use common::{config, time};
pub mod discovery;
pub mod event;
pub mod hdlc;
pub mod ifac;
pub mod interface;
pub mod kiss;
pub mod logging;
pub mod management;
pub mod pickle;
/// Process-global live profiling.
///
/// Unlike Python's package imports, Rust module declarations are resolved
/// statically and do not execute in source order. The profiler can therefore
/// stay in the normal crate module graph without a late-import workaround for
/// circular initialization.
pub mod profiling;
/// Hook events for consumers on a Unix socket.
#[cfg(feature = "hooks")]
pub mod provider_bridge;
#[cfg(feature = "iface-local")]
pub mod remote_management;
pub mod rnode_kiss;
pub mod rpc;
pub mod serial;
pub mod storage;

pub use common::callbacks::{Callbacks, SendTicket};
pub use common::compressor::Bzip2Compressor;
pub use common::destination::{AnnouncedIdentity, Destination, GroupKeyError, MaxRequestSizeError};
pub use common::link_manager::{
    ProofVerifyThreads, RequestFailure, RequestResponse, ResourceStrategy,
};
pub use driver::AnnounceRateDefaults;
#[cfg(feature = "iface-backbone")]
pub use driver::BackbonePeerPoolSettings;
pub use link_send::{LinkSendError, LinkSendReceipt, PacketSendReceipt};
pub use local_ratchet::{FileRatchetStore, LocalRatchetStore, LocalRatchets, MemoryRatchetStore};
pub use node::{
    ChannelSendError, DiscoverySettings, IfacConfig, InterfaceAnnounceLimits, InterfaceConfig,
    NodeConfig, RnsNode, SendError, SharedInstanceSettings,
};
pub use resource::{
    ReceivedResourceFile, ReceivedResourceStream, ResourceReceiveMode, ResourceSendOptions,
    ResourceTransferError, ResourceTransferId,
};
#[cfg(feature = "iface-local")]
pub use shared_client::SharedClientConfig;
pub use state_snapshot::StateSnapshot;

// Re-export commonly used types from rns-core
pub use rns_core::constants::{
    MODE_ACCESS_POINT, MODE_BOUNDARY, MODE_FULL, MODE_GATEWAY, MODE_INTERNAL, MODE_POINT_TO_POINT,
    MODE_ROAMING,
};
pub use rns_core::link::TeardownReason;
pub use rns_core::transport::types::InterfaceId;
pub use rns_core::types::{
    DestHash, DestinationType, Direction, IdentityHash, LinkId, PacketHash, ProofStrategy,
};

/// Internals that benchmarks (`benches/`, `tools/rns-bench`) and the
/// integration tests drive directly. Not a stable API.
#[doc(hidden)]
pub mod testing {
    pub use crate::driver::Driver;
    #[cfg(feature = "iface-local")]
    pub use crate::interface::local::start_client as start_local_client;
    pub use crate::link_manager::{LinkManager, LinkManagerAction};
    #[cfg(feature = "iface-local")]
    pub use crate::shared_client::bench_shared_client_replay_once;
    pub use crate::stamper::{StampTargets, Stamper};
}

/// Entry points for the fuzz targets in `fuzz/` (the RPC ones are
/// `rpc::fuzz`). Not a stable API.
#[doc(hidden)]
pub mod fuzz {
    pub use crate::holepunch::fuzz as holepunch;
}

#[cfg(test)]
mod test_support;

#[cfg(test)]
mod module_initialization_tests {
    #[test]
    fn profiler_is_available_from_the_crate_root_without_late_imports() {
        let sample = crate::profiling::profile("entry117.crate-root");
        drop(sample);
        assert_eq!(
            crate::profiling::results()["entry117.crate-root"]
                .stats_all
                .count,
            1
        );
    }
}
