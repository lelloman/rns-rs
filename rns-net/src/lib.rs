//! rns-net: Network node for Reticulum.
//!
//! Drives `rns-core::TransportEngine` with real TCP/UDP sockets and threads.
//! Reads standard Python RNS config files, opens TCP server/client, UDP, and
//! Local interfaces, persists identity and known destinations.

pub mod common;
pub mod event;
pub mod hdlc;
pub mod kiss;
pub mod rnode_kiss;
pub use common::time;
pub mod driver;
pub mod interface;
pub mod node;
pub use common::config;
pub mod announce_cache;
pub mod ifac;
pub mod md5;
pub mod pickle;
pub mod rpc;
pub mod serial;
pub mod storage;
pub use common::compressor;
pub use common::link_manager;
pub mod management;
#[cfg(feature = "iface-local")]
pub mod shared_client;
pub use common::destination;
pub mod discovery;
pub mod holepunch;
#[cfg(feature = "rns-hooks")]
pub mod provider_bridge;

pub use config::RnsConfig;
pub use destination::{AnnouncedIdentity, Destination, GroupKeyError};
pub use driver::Callbacks;
pub use event::{
    BackbonePeerStateEntry, BlackholeInfo, Event, HookInfo, InterfaceStatsResponse, LinkInfoEntry,
    LocalDestinationEntry, NextHopResponse, PathTableEntry, QueryRequest, QueryResponse,
    RateTableEntry, ResourceInfoEntry, RuntimeConfigApplyMode, RuntimeConfigEntry,
    RuntimeConfigError, RuntimeConfigErrorCode, RuntimeConfigSource, RuntimeConfigValue,
    SingleInterfaceStat,
};
pub use ifac::IfacState;
#[cfg(feature = "iface-auto")]
pub use interface::auto::{AutoConfig, AutoFactory};
#[cfg(feature = "iface-backbone")]
pub use interface::backbone::{BackboneClientConfig, BackboneConfig, BackboneInterfaceFactory};
#[cfg(feature = "iface-i2p")]
pub use interface::i2p::{I2pConfig, I2pFactory};
#[cfg(feature = "iface-kiss")]
pub use interface::kiss_iface::{KissFactory, KissIfaceConfig};
#[cfg(feature = "iface-local")]
pub use interface::local::{
    LocalClientConfig, LocalClientFactory, LocalServerConfig, LocalServerFactory,
};
#[cfg(feature = "iface-pipe")]
pub use interface::pipe::{PipeConfig, PipeFactory};
pub use interface::registry::InterfaceRegistry;
#[cfg(feature = "iface-rnode")]
pub use interface::rnode::{RNodeConfig, RNodeFactory, RNodeSubConfig};
#[cfg(feature = "iface-serial")]
pub use interface::serial_iface::{SerialFactory, SerialIfaceConfig};
#[cfg(feature = "iface-tcp")]
pub use interface::tcp::{TcpClientConfig, TcpClientFactory};
#[cfg(feature = "iface-tcp")]
pub use interface::tcp_server::{TcpServerConfig, TcpServerFactory};
#[cfg(feature = "iface-udp")]
pub use interface::udp::{UdpConfig, UdpFactory};
pub use interface::{
    InterfaceConfigData, InterfaceFactory, StartContext, StartResult, SubInterface,
};
pub use link_manager::{LinkManager, LinkManagerAction};
pub use management::ManagementConfig;
pub use node::{IfacConfig, InterfaceConfig, NodeConfig, RnsNode, SendError};
#[cfg(feature = "rns-hooks")]
pub use provider_bridge::{
    HookProviderEventEnvelope, OverflowPolicy, ProviderBridge, ProviderBridgeConfig,
    ProviderEnvelope, ProviderMessage,
};
pub use rpc::{RpcAddr, RpcClient, RpcServer};
pub use serial::Parity;
#[cfg(feature = "iface-local")]
pub use shared_client::SharedClientConfig;
pub use storage::{KnownDestination, StoragePaths};

// Re-export commonly used types from rns-core
pub use rns_core::constants::{
    MODE_ACCESS_POINT, MODE_BOUNDARY, MODE_FULL, MODE_GATEWAY, MODE_POINT_TO_POINT, MODE_ROAMING,
};
pub use rns_core::link::TeardownReason;
pub use rns_core::transport::types::InterfaceId;
pub use rns_core::types::{
    DestHash, DestinationType, Direction, IdentityHash, LinkId, PacketHash, ProofStrategy,
};
