//! The operating-system side of a tunnel: a packet device and the code that
//! sets up addresses, routes and DNS around it.

use std::io;
use std::net::Ipv4Addr;

use crate::policy::Cidr;

/// The host network configuration a session needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TunnelConfig {
    /// Requested TUN interface name.
    pub interface_name: String,
    /// This host's tunnel address.
    pub address: Ipv4Addr,
    /// Prefix length of the tunnel subnet.
    pub prefix_len: u8,
    /// The gateway's tunnel address.
    pub gateway: Ipv4Addr,
    /// Interface MTU in bytes.
    pub mtu: u16,
    /// Networks to route through the tunnel.
    pub routes: Vec<Cidr>,
    /// Resolvers to use for all lookups; applied only for a full tunnel.
    pub dns_servers: Vec<Ipv4Addr>,
    /// Route all traffic, and DNS, through the tunnel, except the node's
    /// own underlay traffic.
    pub full_tunnel: bool,
}
/// What [`TunnelConfigurator::apply`] actually set up.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppliedTunnelConfig {
    /// Name the kernel gave the interface.
    pub interface_name: String,
    /// Interface index, when the backend knows it.
    pub ifindex: Option<u32>,
    /// Resolvers that were installed.
    pub dns_servers: Vec<Ipv4Addr>,
    /// Whether full-tunnel routing and DNS were set up and verified.
    pub full_tunnel_verified: bool,
}

/// A layer-3 packet device carrying raw IPv4 packets, one per read or
/// write.
pub trait PacketDevice: Send {
    /// Read one packet into `buffer` and return its length. Blocks unless
    /// the device is non-blocking, in which case it may fail with
    /// [`io::ErrorKind::WouldBlock`].
    fn read_packet(&mut self, buffer: &mut [u8]) -> io::Result<usize>;
    /// Write one whole packet.
    fn write_packet(&mut self, packet: &[u8]) -> io::Result<()>;
    /// Release the device; the host configuration is undone separately by
    /// [`TunnelConfigurator::teardown`].
    fn close(&mut self) -> io::Result<()>;
}
/// Creates a [`PacketDevice`] and configures the host around it.
pub trait TunnelConfigurator: Send {
    /// The device this backend creates.
    type Device: PacketDevice;
    /// Create the device and apply `config`. On failure every change made so
    /// far is undone.
    fn apply(&mut self, config: &TunnelConfig) -> io::Result<(Self::Device, AppliedTunnelConfig)>;
    /// Check that a full-tunnel setup is still in place; a no-op otherwise.
    fn verify(&self, applied: &AppliedTunnelConfig) -> io::Result<()>;
    /// Undo everything [`TunnelConfigurator::apply`] changed.
    fn teardown(&mut self, applied: &AppliedTunnelConfig) -> io::Result<()>;
}
