//! rns-net: Network node for Reticulum.
//!
//! Drives `rns-core::TransportEngine` with real TCP/UDP sockets and threads.
//! Reads standard Python RNS config files, opens TCP server/client, UDP, and
//! Local interfaces, persists identity and known destinations.

pub mod hdlc;
pub mod kiss;
pub mod rnode_kiss;
pub mod event;
pub mod time;
pub mod interface;
pub mod driver;
pub mod node;
pub mod config;
pub mod storage;
pub mod ifac;
pub mod serial;
pub mod md5;
pub mod pickle;
pub mod rpc;

pub use driver::Callbacks;
pub use event::{
    Event, QueryRequest, QueryResponse,
    InterfaceStatsResponse, SingleInterfaceStat,
    PathTableEntry, RateTableEntry, NextHopResponse, BlackholeInfo,
};
pub use node::{IfacConfig, InterfaceConfig, InterfaceVariant, NodeConfig, RnsNode, SendError};
pub use interface::tcp::TcpClientConfig;
pub use interface::tcp_server::TcpServerConfig;
pub use interface::udp::UdpConfig;
pub use interface::local::{LocalServerConfig, LocalClientConfig};
pub use interface::serial_iface::SerialIfaceConfig;
pub use interface::kiss_iface::KissIfaceConfig;
pub use interface::pipe::PipeConfig;
pub use interface::rnode::{RNodeConfig, RNodeSubConfig};
pub use interface::backbone::BackboneConfig;
pub use config::RnsConfig;
pub use ifac::IfacState;
pub use serial::Parity;
pub use storage::{StoragePaths, KnownDestination};
pub use rpc::{RpcAddr, RpcServer, RpcClient};

// Re-export commonly used types from rns-core
pub use rns_core::transport::types::InterfaceId;
pub use rns_core::constants::{
    MODE_FULL, MODE_POINT_TO_POINT, MODE_ACCESS_POINT,
    MODE_ROAMING, MODE_BOUNDARY, MODE_GATEWAY,
};
