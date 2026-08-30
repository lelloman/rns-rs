use std::io;
use std::net::Ipv4Addr;

use crate::policy::Cidr;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TunnelConfig {
    pub interface_name: String,
    pub address: Ipv4Addr,
    pub prefix_len: u8,
    pub gateway: Ipv4Addr,
    pub mtu: u16,
    pub routes: Vec<Cidr>,
    pub dns_servers: Vec<Ipv4Addr>,
    pub full_tunnel: bool,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppliedTunnelConfig {
    pub interface_name: String,
    pub ifindex: Option<u32>,
    pub dns_servers: Vec<Ipv4Addr>,
    pub full_tunnel_verified: bool,
}

pub trait PacketDevice: Send {
    fn read_packet(&mut self, buffer: &mut [u8]) -> io::Result<usize>;
    fn write_packet(&mut self, packet: &[u8]) -> io::Result<()>;
    fn close(&mut self) -> io::Result<()>;
}
pub trait TunnelConfigurator: Send {
    type Device: PacketDevice;
    fn apply(&mut self, config: &TunnelConfig) -> io::Result<(Self::Device, AppliedTunnelConfig)>;
    fn verify(&self, applied: &AppliedTunnelConfig) -> io::Result<()>;
    fn teardown(&mut self, applied: &AppliedTunnelConfig) -> io::Result<()>;
}
