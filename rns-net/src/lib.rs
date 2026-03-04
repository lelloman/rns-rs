//! rns-net: Network node for Reticulum.
//!
//! Drives `rns-core::TransportEngine` with real TCP/UDP sockets and threads.
//! Reads standard Python RNS config files, opens TCP server/client, UDP, and
//! Local interfaces, persists identity and known destinations.

pub mod common;
pub mod hdlc;
pub mod kiss;
pub mod rnode_kiss;
pub mod event;
pub use common::time;
pub mod interface;
pub mod driver;
pub mod node;
pub use common::config;
pub mod storage;
pub mod ifac;
pub mod serial;
pub mod md5;
pub mod pickle;
pub mod rpc;
pub mod announce_cache;
pub use common::compressor;
pub use common::link_manager;
pub mod management;
#[cfg(feature = "iface-local")]
pub mod shared_client;
pub use common::destination;
pub mod holepunch;
pub mod discovery;

pub use driver::Callbacks;
pub use event::{
    Event, QueryRequest, QueryResponse,
    InterfaceStatsResponse, SingleInterfaceStat,
    PathTableEntry, RateTableEntry, NextHopResponse, BlackholeInfo,
    LocalDestinationEntry, LinkInfoEntry, ResourceInfoEntry,
};
pub use node::{IfacConfig, InterfaceConfig, NodeConfig, RnsNode, SendError};
pub use interface::{
    InterfaceConfigData, InterfaceFactory, StartContext, StartResult, SubInterface,
};
pub use interface::registry::InterfaceRegistry;
#[cfg(feature = "iface-tcp")]
pub use interface::tcp::{TcpClientFactory, TcpClientConfig};
#[cfg(feature = "iface-tcp")]
pub use interface::tcp_server::{TcpServerFactory, TcpServerConfig};
#[cfg(feature = "iface-udp")]
pub use interface::udp::{UdpFactory, UdpConfig};
#[cfg(feature = "iface-serial")]
pub use interface::serial_iface::{SerialFactory, SerialIfaceConfig};
#[cfg(feature = "iface-kiss")]
pub use interface::kiss_iface::{KissFactory, KissIfaceConfig};
#[cfg(feature = "iface-pipe")]
pub use interface::pipe::{PipeFactory, PipeConfig};
#[cfg(feature = "iface-local")]
pub use interface::local::{LocalServerFactory, LocalClientFactory, LocalServerConfig, LocalClientConfig};
#[cfg(feature = "iface-backbone")]
pub use interface::backbone::{BackboneInterfaceFactory, BackboneConfig, BackboneClientConfig};
#[cfg(feature = "iface-auto")]
pub use interface::auto::{AutoFactory, AutoConfig};
#[cfg(feature = "iface-i2p")]
pub use interface::i2p::{I2pFactory, I2pConfig};
#[cfg(feature = "iface-rnode")]
pub use interface::rnode::{RNodeFactory, RNodeConfig, RNodeSubConfig};
#[cfg(feature = "iface-local")]
pub use shared_client::SharedClientConfig;
pub use config::RnsConfig;
pub use ifac::IfacState;
pub use serial::Parity;
pub use storage::{StoragePaths, KnownDestination};
pub use rpc::{RpcAddr, RpcServer, RpcClient};
pub use link_manager::{LinkManager, LinkManagerAction};
pub use management::ManagementConfig;
pub use destination::{Destination, AnnouncedIdentity, GroupKeyError};

// Re-export commonly used types from rns-core
pub use rns_core::transport::types::InterfaceId;
pub use rns_core::types::{DestHash, IdentityHash, LinkId, PacketHash, DestinationType, Direction, ProofStrategy};
pub use rns_core::constants::{
    MODE_FULL, MODE_POINT_TO_POINT, MODE_ACCESS_POINT,
    MODE_ROAMING, MODE_BOUNDARY, MODE_GATEWAY,
};
