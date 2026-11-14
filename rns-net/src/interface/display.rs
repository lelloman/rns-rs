//! Upstream's display names for interfaces: `str(interface)` in Python RNS.
//!
//! Upstream reports this string as an interface's `name` in its interface
//! statistics, and `rnstatus` keys its output on it: it hides spawned and
//! local client interfaces by their name prefix and treats `Shared
//! Instance[...]` specially. The config name stays the interface's
//! `InterfaceInfo::name`; these names are only for reporting.

use std::net::IpAddr;

/// An address as upstream formats it inside a display name: IPv6 in
/// brackets.
fn host(ip: &str) -> String {
    if ip.contains(':') {
        format!("[{ip}]")
    } else {
        ip.to_string()
    }
}

/// The default `{type}[{name}]` of most upstream interface classes
/// (`KISSInterface[name]`, `RNodeInterface[name]`, ...).
pub fn typed(interface_type: &str, name: &str) -> String {
    format!("{interface_type}[{name}]")
}

/// `TCPClientInterface`: `TCPInterface[{name}/{target_ip}:{target_port}]`.
pub fn tcp_client(name: &str, target_host: &str, target_port: u16) -> String {
    format!("TCPInterface[{name}/{}:{target_port}]", host(target_host))
}

/// `TCPServerInterface`: `TCPServerInterface[{name}/{bind_ip}:{bind_port}]`.
pub fn tcp_server(name: &str, bind_ip: &str, bind_port: u16) -> String {
    format!("TCPServerInterface[{name}/{}:{bind_port}]", host(bind_ip))
}

/// A client a TCP server accepted: upstream spawns a `TCPClientInterface`
/// named `Client on {listener}` that targets the peer.
pub fn tcp_server_client(listener_name: &str, peer_ip: IpAddr, peer_port: u16) -> String {
    tcp_client(
        &format!("Client on {listener_name}"),
        &peer_ip.to_string(),
        peer_port,
    )
}

/// `UDPInterface`: `UDPInterface[{name}/{bind_ip}:{bind_port}]`.
pub fn udp(name: &str, bind_ip: Option<&str>, bind_port: Option<u16>) -> String {
    let bind_ip = bind_ip.unwrap_or("None");
    let bind_port = bind_port.map_or_else(|| "None".to_string(), |port| port.to_string());
    format!("UDPInterface[{name}/{bind_ip}:{bind_port}]")
}

/// A `BackboneInterface` listener or client: the listener shows its bind
/// address, a client its target.
pub fn backbone(name: &str, ip: &str, port: u16) -> String {
    format!("BackboneInterface[{name}/{}:{port}]", host(ip))
}

/// A client a `BackboneInterface` listener accepted: upstream names it
/// `Client on {listener}`, targeting the peer.
pub fn backbone_server_client(listener_name: &str, peer_ip: IpAddr, peer_port: u16) -> String {
    backbone(
        &format!("Client on {listener_name}"),
        &peer_ip.to_string(),
        peer_port,
    )
}

/// The shared instance listener, upstream's `LocalServerInterface`:
/// `Shared Instance[rns/{instance}]` on the abstract Unix socket, else
/// `Shared Instance[{port}]`.
pub fn shared_instance(endpoint: &LocalEndpoint) -> String {
    format!("Shared Instance[{}]", endpoint.label())
}

/// A local client interface, on either end of a shared instance
/// connection: `LocalInterface[rns/{instance}]` on the abstract Unix
/// socket, else `LocalInterface[{port}]`.
pub fn local_client(endpoint: &LocalEndpoint) -> String {
    format!("LocalInterface[{}]", endpoint.label())
}

/// Where a shared instance is served, as its display names show it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LocalEndpoint {
    /// The abstract Unix socket `\0rns/{instance}`.
    Unix(String),
    /// A TCP port on localhost.
    Tcp(u16),
}

impl LocalEndpoint {
    /// Where a client connects: the abstract Unix socket of `instance`
    /// when it uses one (Linux only), else TCP `port`.
    pub fn for_client(use_af_unix: bool, instance: &str, port: u16) -> Self {
        if use_af_unix && cfg!(target_os = "linux") {
            LocalEndpoint::Unix(instance.to_string())
        } else {
            LocalEndpoint::Tcp(port)
        }
    }

    fn label(&self) -> String {
        match self {
            LocalEndpoint::Unix(instance) => format!("rns/{instance}"),
            LocalEndpoint::Tcp(port) => port.to_string(),
        }
    }
}

/// An `AutoInterface` peer: `AutoInterfacePeer[{ifname}/{addr}]`.
pub fn auto_peer(ifname: &str, addr: &str) -> String {
    format!("AutoInterfacePeer[{ifname}/{addr}]")
}

/// An `I2PInterface` peer: `I2PInterfacePeer[{name} to {peer}]` when this
/// node connected out, `I2PInterfacePeer[Connected peer on {name}]` when it
/// accepted the connection.
pub fn i2p_peer(interface_name: &str, peer: &str, outbound: bool) -> String {
    if outbound {
        format!("I2PInterfacePeer[{interface_name} to {peer}]")
    } else {
        format!("I2PInterfacePeer[Connected peer on {interface_name}]")
    }
}

/// A `WeaveInterface` peer: `WeaveInterfacePeer[{RNS.hexrep(endpoint)}]`,
/// colon-delimited.
pub fn weave_peer(endpoint: &[u8]) -> String {
    let hexrep = endpoint
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<Vec<_>>()
        .join(":");
    format!("WeaveInterfacePeer[{hexrep}]")
}

/// A subinterface of an `RNodeMultiInterface`: `{parent name}[{sub name}]`.
pub fn rnode_multi_sub(parent_name: &str, sub_name: &str) -> String {
    format!("{parent_name}[{sub_name}]")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_match_upstream_str() {
        assert_eq!(
            tcp_client("Peer", "10.0.0.1", 4242),
            "TCPInterface[Peer/10.0.0.1:4242]"
        );
        assert_eq!(
            tcp_client("Peer", "example.org", 4242),
            "TCPInterface[Peer/example.org:4242]"
        );
        assert_eq!(
            tcp_client("Peer", "2001:db8::1", 4242),
            "TCPInterface[Peer/[2001:db8::1]:4242]"
        );
        assert_eq!(
            tcp_server("Server", "0.0.0.0", 4242),
            "TCPServerInterface[Server/0.0.0.0:4242]"
        );
        assert_eq!(
            tcp_server("Server", "::", 4242),
            "TCPServerInterface[Server/[::]:4242]"
        );
        assert_eq!(
            tcp_server_client("Server", "127.0.0.1".parse().unwrap(), 50000),
            "TCPInterface[Client on Server/127.0.0.1:50000]"
        );
        assert_eq!(
            tcp_server_client("Server", "::1".parse().unwrap(), 50000),
            "TCPInterface[Client on Server/[::1]:50000]"
        );
        assert_eq!(
            udp("UDP", Some("0.0.0.0"), Some(4242)),
            "UDPInterface[UDP/0.0.0.0:4242]"
        );
        assert_eq!(udp("UDP", None, None), "UDPInterface[UDP/None:None]");
        assert_eq!(
            backbone("Backbone", "0.0.0.0", 4242),
            "BackboneInterface[Backbone/0.0.0.0:4242]"
        );
        assert_eq!(
            backbone_server_client("Backbone", "10.0.0.2".parse().unwrap(), 51000),
            "BackboneInterface[Client on Backbone/10.0.0.2:51000]"
        );
        let unix = LocalEndpoint::Unix("default".into());
        let tcp = LocalEndpoint::Tcp(37428);
        assert_eq!(shared_instance(&unix), "Shared Instance[rns/default]");
        assert_eq!(shared_instance(&tcp), "Shared Instance[37428]");
        assert_eq!(local_client(&unix), "LocalInterface[rns/default]");
        assert_eq!(local_client(&tcp), "LocalInterface[37428]");
        assert_eq!(
            auto_peer("eth0", "fe80::1"),
            "AutoInterfacePeer[eth0/fe80::1]"
        );
        assert_eq!(
            i2p_peer("I2P", "abc.b32.i2p", true),
            "I2PInterfacePeer[I2P to abc.b32.i2p]"
        );
        assert_eq!(
            i2p_peer("I2P", "abc.b32.i2p", false),
            "I2PInterfacePeer[Connected peer on I2P]"
        );
        assert_eq!(typed("KISSInterface", "Radio"), "KISSInterface[Radio]");
        assert_eq!(
            weave_peer(&[0x01, 0xab, 0x00, 0xff]),
            "WeaveInterfacePeer[01:ab:00:ff]"
        );
        assert_eq!(rnode_multi_sub("Multi", "LoRa A"), "Multi[LoRa A]");
    }
}
