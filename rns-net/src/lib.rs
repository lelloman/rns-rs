//! rns-net: Network node for Reticulum.
//!
//! Drives `rns-core::TransportEngine` with real TCP/UDP sockets and threads.
//! Reads standard Python RNS config files, opens TCP server/client, UDP, and
//! Local interfaces, persists identity and known destinations.

pub mod hdlc;
pub mod event;
pub mod time;
pub mod interface;
pub mod driver;
pub mod node;
pub mod config;
pub mod storage;

pub use driver::Callbacks;
pub use event::Event;
pub use node::{InterfaceConfig, InterfaceVariant, NodeConfig, RnsNode};
pub use interface::tcp::TcpClientConfig;
pub use interface::tcp_server::TcpServerConfig;
pub use interface::udp::UdpConfig;
pub use interface::local::{LocalServerConfig, LocalClientConfig};
pub use config::RnsConfig;
pub use storage::{StoragePaths, KnownDestination};

// Re-export commonly used types from rns-core
pub use rns_core::transport::types::InterfaceId;
pub use rns_core::constants::{
    MODE_FULL, MODE_POINT_TO_POINT, MODE_ACCESS_POINT,
    MODE_ROAMING, MODE_BOUNDARY, MODE_GATEWAY,
};
