//! Upstream's display names for interfaces: `str(interface)` in Python RNS.
//!
//! Upstream reports this string as an interface's `name` in its interface
//! statistics, and `rnstatus` keys its output on it: it hides spawned and
//! local client interfaces by their name prefix and treats `Shared
//! Instance[...]` specially. The config name stays the interface's
//! `InterfaceInfo::name`; these names are only for reporting.

#[cfg(any(feature = "iface-tcp", feature = "iface-backbone"))]
use std::net::IpAddr;

/// An address as upstream formats it inside a display name: IPv6 in
/// brackets.
#[cfg(any(feature = "iface-tcp", feature = "iface-backbone"))]
fn host(ip: &str) -> String {
    if ip.contains(':') {
        format!("[{ip}]")
    } else {
        ip.to_string()
    }
}

/// The default `{type}[{name}]` of most upstream interface classes
/// (`KISSInterface[name]`, `RNodeInterface[name]`, ...).
pub(crate) fn typed(interface_type: &str, name: &str) -> String {
    format!("{interface_type}[{name}]")
}

/// The `interface.name` of an upstream interface class that never sets
/// one (`AutoInterfacePeer`, `WeaveInterfacePeer`): `str(None)`.
#[cfg(any(
    feature = "iface-auto",
    all(feature = "iface-weave", target_os = "linux")
))]
pub(crate) const UNNAMED: &str = "None";

/// The name upstream gives a client a TCP or Backbone listener accepted:
/// `Client on {listener}`, the same for every client of the listener.
#[cfg(any(feature = "iface-tcp", feature = "iface-backbone"))]
pub(crate) fn spawned_client_name(listener_name: &str) -> String {
    format!("Client on {listener_name}")
}

/// `TCPClientInterface`: `TCPInterface[{name}/{target_ip}:{target_port}]`.
#[cfg(feature = "iface-tcp")]
pub(crate) fn tcp_client(name: &str, target_host: &str, target_port: u16) -> String {
    format!("TCPInterface[{name}/{}:{target_port}]", host(target_host))
}

/// `TCPServerInterface`: `TCPServerInterface[{name}/{bind_ip}:{bind_port}]`.
#[cfg(feature = "iface-tcp")]
pub(crate) fn tcp_server(name: &str, bind_ip: &str, bind_port: u16) -> String {
    format!("TCPServerInterface[{name}/{}:{bind_port}]", host(bind_ip))
}

/// A client a TCP server accepted: upstream spawns a `TCPClientInterface`
/// named `Client on {listener}` that targets the peer.
#[cfg(feature = "iface-tcp")]
pub(crate) fn tcp_server_client(listener_name: &str, peer_ip: IpAddr, peer_port: u16) -> String {
    tcp_client(
        &spawned_client_name(listener_name),
        &peer_ip.to_string(),
        peer_port,
    )
}

/// `UDPInterface`: `UDPInterface[{name}/{bind_ip}:{bind_port}]`.
#[cfg(feature = "iface-udp")]
pub(crate) fn udp(name: &str, bind_ip: Option<&str>, bind_port: Option<u16>) -> String {
    let bind_ip = bind_ip.unwrap_or("None");
    let bind_port = bind_port.map_or_else(|| "None".to_string(), |port| port.to_string());
    format!("UDPInterface[{name}/{bind_ip}:{bind_port}]")
}

/// A `BackboneInterface` listener or client: the listener shows its bind
/// address, a client its target.
#[cfg(feature = "iface-backbone")]
pub(crate) fn backbone(name: &str, ip: &str, port: u16) -> String {
    format!("BackboneInterface[{name}/{}:{port}]", host(ip))
}

/// A client a `BackboneInterface` listener accepted: upstream names it
/// `Client on {listener}`, targeting the peer.
#[cfg(feature = "iface-backbone")]
pub(crate) fn backbone_server_client(
    listener_name: &str,
    peer_ip: IpAddr,
    peer_port: u16,
) -> String {
    backbone(
        &spawned_client_name(listener_name),
        &peer_ip.to_string(),
        peer_port,
    )
}

/// The shared instance listener, upstream's `LocalServerInterface`:
/// `Shared Instance[rns/{instance}]` on the abstract Unix socket, else
/// `Shared Instance[{port}]`.
#[cfg(feature = "iface-local")]
pub(crate) fn shared_instance(endpoint: &LocalEndpoint) -> String {
    format!("Shared Instance[{}]", endpoint.label())
}

/// A local client interface, on either end of a shared instance
/// connection: `LocalInterface[rns/{instance}]` on the abstract Unix
/// socket, else `LocalInterface[{port}]`.
#[cfg(feature = "iface-local")]
pub(crate) fn local_client(endpoint: &LocalEndpoint) -> String {
    format!("LocalInterface[{}]", endpoint.label())
}

/// Where a shared instance is served, as its display names show it.
#[cfg(feature = "iface-local")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum LocalEndpoint {
    /// The abstract Unix socket `\0rns/{instance}`.
    Unix(String),
    /// A TCP port on localhost.
    Tcp(u16),
}

#[cfg(feature = "iface-local")]
impl LocalEndpoint {
    /// Where a client connects: the abstract Unix socket of `instance`
    /// when it uses one (Linux only), else TCP `port`.
    pub(crate) fn for_client(use_af_unix: bool, instance: &str, port: u16) -> Self {
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
#[cfg(feature = "iface-auto")]
pub(crate) fn auto_peer(ifname: &str, addr: &str) -> String {
    format!("AutoInterfacePeer[{ifname}/{addr}]")
}

/// The `interface.name` of an `I2PInterface` peer: `{name} to {peer}` when
/// this node connected out, `Connected peer on {name}` when it accepted the
/// connection. Its display name is `I2PInterfacePeer[{that name}]`.
#[cfg(feature = "iface-i2p")]
pub(crate) fn i2p_peer_name(interface_name: &str, peer: &str, outbound: bool) -> String {
    if outbound {
        format!("{interface_name} to {peer}")
    } else {
        format!("Connected peer on {interface_name}")
    }
}

/// A `WeaveInterface` peer: `WeaveInterfacePeer[{RNS.hexrep(endpoint)}]`,
/// colon-delimited.
#[cfg(all(feature = "iface-weave", target_os = "linux"))]
pub(crate) fn weave_peer(endpoint: &[u8]) -> String {
    let hexrep = endpoint
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<Vec<_>>()
        .join(":");
    format!("WeaveInterfacePeer[{hexrep}]")
}

/// A subinterface of an `RNodeMultiInterface`: `{parent name}[{sub name}]`.
pub(crate) fn rnode_multi_sub(parent_name: &str, sub_name: &str) -> String {
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
            i2p_peer_name("I2P", "abc.b32.i2p", true),
            "I2P to abc.b32.i2p"
        );
        assert_eq!(
            i2p_peer_name("I2P", "abc.b32.i2p", false),
            "Connected peer on I2P"
        );
        assert_eq!(spawned_client_name("Server"), "Client on Server");
        assert_eq!(typed("KISSInterface", "Radio"), "KISSInterface[Radio]");
        assert_eq!(
            weave_peer(&[0x01, 0xab, 0x00, 0xff]),
            "WeaveInterfacePeer[01:ab:00:ff]"
        );
        assert_eq!(rnode_multi_sub("Multi", "LoRa A"), "Multi[LoRa A]");
    }
}
