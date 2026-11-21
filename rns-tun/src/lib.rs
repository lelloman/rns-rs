//! Authenticated IPv4 tunnelling over a private Reticulum node.

#[cfg(target_os = "linux")]
pub mod client;
pub mod config;
#[cfg(target_os = "linux")]
pub mod gateway;
pub mod identity;
#[cfg(target_os = "linux")]
pub mod linux;
pub mod packet;
pub mod platform;
pub mod policy;
pub mod protocol;
pub mod reticulum;
pub mod runtime;
pub mod session;
pub mod status;
pub mod transport;

pub use config::{Config, ConfigError};
pub use packet::{PacketError, Reassembler, ValidatedIpv4};
pub use platform::{AppliedTunnelConfig, PacketDevice, TunnelConfig, TunnelConfigurator};
pub use policy::{Cidr, ClientGrant, GatewayPolicy, PolicyError};
pub use protocol::{ControlMessage, PacketFragment, ProtocolError};
pub use rns_net::node::SendError as RnsSendError;
pub use rns_net::{install_socket_protector, SocketProtector, SocketProtectorGuard};
pub use session::{ClientSession, ClientState, GatewaySession, GatewayState, SessionError};
pub use transport::{PacketDirection, PacketTransport, TransportError};

/// Reticulum Channel message type reserved for all rntun control frames.
pub const RNTUN_CHANNEL_MSGTYPE: u16 = 0x5254;

/// Direct Link context reserved for rntun packet fragments.
pub const RNTUN_LINK_CONTEXT: u8 = 0x0f;
