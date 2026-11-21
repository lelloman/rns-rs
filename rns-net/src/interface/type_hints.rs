//! Interface types and the properties their type implies.

/// An interface type, by the type name upstream's classes and the config
/// file's `type` key use. The names are matched exactly, as upstream
/// matches class names.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum InterfaceKind {
    /// `AutoInterface`.
    Auto,
    /// `AutoInterfacePeer`.
    AutoPeer,
    /// `AX25KISSInterface`.
    Ax25Kiss,
    /// `BackboneInterface`.
    Backbone,
    /// `BackboneClientInterface`.
    BackboneClient,
    /// `BackboneInterfacePeer`.
    BackbonePeer,
    /// `I2PInterface`.
    I2p,
    /// `I2PInterfacePeer`.
    I2pPeer,
    /// `KISSInterface`.
    Kiss,
    /// `LocalInterface`.
    Local,
    /// `LocalClientInterface`.
    LocalClient,
    /// `LocalServerInterface`.
    LocalServer,
    /// `LocalServerClientInterface`.
    LocalServerClient,
    /// `PipeInterface`.
    Pipe,
    /// `RNodeInterface`.
    RNode,
    /// `RNodeMultiInterface`.
    RNodeMulti,
    /// `SerialInterface`.
    Serial,
    /// `TCPClientInterface`.
    TcpClient,
    /// `TCPServerInterface`.
    TcpServer,
    /// `TCPServerClientInterface`.
    TcpServerClient,
    /// `UDPInterface`.
    Udp,
    /// `WeaveInterface`.
    Weave,
    /// `WeaveInterfacePeer`.
    WeavePeer,
}

impl InterfaceKind {
    /// The kind named `type_name`, or `None` for a name that is not an
    /// interface type of this stack.
    pub fn from_type_name(type_name: &str) -> Option<Self> {
        Some(match type_name {
            "AutoInterface" => Self::Auto,
            "AutoInterfacePeer" => Self::AutoPeer,
            "AX25KISSInterface" => Self::Ax25Kiss,
            "BackboneInterface" => Self::Backbone,
            "BackboneClientInterface" => Self::BackboneClient,
            "BackboneInterfacePeer" => Self::BackbonePeer,
            "I2PInterface" => Self::I2p,
            "I2PInterfacePeer" => Self::I2pPeer,
            "KISSInterface" => Self::Kiss,
            "LocalInterface" => Self::Local,
            "LocalClientInterface" => Self::LocalClient,
            "LocalServerInterface" => Self::LocalServer,
            "LocalServerClientInterface" => Self::LocalServerClient,
            "PipeInterface" => Self::Pipe,
            "RNodeInterface" => Self::RNode,
            "RNodeMultiInterface" => Self::RNodeMulti,
            "SerialInterface" => Self::Serial,
            "TCPClientInterface" => Self::TcpClient,
            "TCPServerInterface" => Self::TcpServer,
            "TCPServerClientInterface" => Self::TcpServerClient,
            "UDPInterface" => Self::Udp,
            "WeaveInterface" => Self::Weave,
            "WeaveInterfacePeer" => Self::WeavePeer,
            _ => return None,
        })
    }

    /// The type name, as upstream and the config file spell it.
    pub const fn type_name(self) -> &'static str {
        match self {
            Self::Auto => "AutoInterface",
            Self::AutoPeer => "AutoInterfacePeer",
            Self::Ax25Kiss => "AX25KISSInterface",
            Self::Backbone => "BackboneInterface",
            Self::BackboneClient => "BackboneClientInterface",
            Self::BackbonePeer => "BackboneInterfacePeer",
            Self::I2p => "I2PInterface",
            Self::I2pPeer => "I2PInterfacePeer",
            Self::Kiss => "KISSInterface",
            Self::Local => "LocalInterface",
            Self::LocalClient => "LocalClientInterface",
            Self::LocalServer => "LocalServerInterface",
            Self::LocalServerClient => "LocalServerClientInterface",
            Self::Pipe => "PipeInterface",
            Self::RNode => "RNodeInterface",
            Self::RNodeMulti => "RNodeMultiInterface",
            Self::Serial => "SerialInterface",
            Self::TcpClient => "TCPClientInterface",
            Self::TcpServer => "TCPServerInterface",
            Self::TcpServerClient => "TCPServerClientInterface",
            Self::Udp => "UDPInterface",
            Self::Weave => "WeaveInterface",
            Self::WeavePeer => "WeaveInterfacePeer",
        }
    }

    /// Whether an interface of this type normally operates on a shared
    /// medium. This is a type-level hint: runtime configuration can still
    /// describe links with different physical properties. It mirrors
    /// Reticulum's interface-class defaults and is suitable for
    /// discovery/capability metadata.
    pub const fn shared_medium(self) -> bool {
        matches!(
            self,
            Self::Ax25Kiss
                | Self::Kiss
                | Self::Pipe
                | Self::RNode
                | Self::RNodeMulti
                | Self::Serial
                | Self::Udp
        )
    }

    /// Whether a tunnel may be synthesized over an interface of this type
    /// (upstream 464e7598 `tunnels_allowed`): TCP, Backbone and I2P
    /// connections.
    pub const fn tunnels_allowed(self) -> bool {
        matches!(
            self,
            Self::TcpClient
                | Self::TcpServerClient
                | Self::Backbone
                | Self::BackboneClient
                | Self::BackbonePeer
                | Self::I2pPeer
        )
    }

    /// Whether an interface of this type is on a lossless medium (upstream
    /// 8e7dc8b7 `Interface.lossless_medium`): `True` on the TCP, Backbone
    /// and I2P classes, so also on the clients a TCP or Backbone server
    /// spawns and on I2P peers, and `False` on every other class.
    #[allow(
        dead_code,
        reason = "upstream 8e7dc8b7 adds the flag with no reader yet; it is kept for parity, so a later upstream reader has the per-class values here"
    )]
    pub(crate) const fn lossless_medium(self) -> bool {
        matches!(
            self,
            Self::TcpClient
                | Self::TcpServer
                | Self::TcpServerClient
                | Self::Backbone
                | Self::BackboneClient
                | Self::BackbonePeer
                | Self::I2p
                | Self::I2pPeer
        )
    }

    /// Whether ingress control is on for this type unless the config says
    /// otherwise, as upstream's interface classes default it.
    pub(crate) const fn ingress_control_by_default(self) -> bool {
        matches!(
            self,
            Self::Auto | Self::Backbone | Self::TcpClient | Self::TcpServer | Self::Udp | Self::I2p
        )
    }
}

impl std::fmt::Display for InterfaceKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.type_name())
    }
}

/// Return whether an interface type normally operates on a shared medium;
/// see [`InterfaceKind::shared_medium`]. `false` for an unknown type.
pub(crate) fn shared_medium_hint(interface_type: &str) -> bool {
    InterfaceKind::from_type_name(interface_type).is_some_and(InterfaceKind::shared_medium)
}

/// Whether a tunnel may be synthesized over an interface of this type; see
/// [`InterfaceKind::tunnels_allowed`]. `false` for an unknown type.
pub(crate) fn tunnels_allowed(interface_type: &str) -> bool {
    InterfaceKind::from_type_name(interface_type).is_some_and(InterfaceKind::tunnels_allowed)
}

/// Whether an interface of this type is on a lossless medium; see
/// [`InterfaceKind::lossless_medium`]. `false` for an unknown type.
#[cfg(test)]
pub(crate) fn lossless_medium(interface_type: &str) -> bool {
    InterfaceKind::from_type_name(interface_type).is_some_and(InterfaceKind::lossless_medium)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lossless_medium_matches_upstreams_interface_classes() {
        for interface_type in [
            "TCPClientInterface",
            "TCPServerInterface",
            "TCPServerClientInterface",
            "BackboneInterface",
            "BackboneClientInterface",
            "BackboneInterfacePeer",
            "I2PInterface",
            "I2PInterfacePeer",
        ] {
            assert!(lossless_medium(interface_type), "{interface_type}");
        }
        for interface_type in [
            "AutoInterface",
            "AutoInterfacePeer",
            "AX25KISSInterface",
            "KISSInterface",
            "LocalInterface",
            "LocalClientInterface",
            "LocalServerInterface",
            "LocalServerClientInterface",
            "PipeInterface",
            "RNodeInterface",
            "RNodeMultiInterface",
            "SerialInterface",
            "UDPInterface",
            "WeaveInterface",
            "WeaveInterfacePeer",
        ] {
            assert!(!lossless_medium(interface_type), "{interface_type}");
        }
    }

    #[test]
    fn shared_medium_hint_matches_interface_class_defaults() {
        for interface_type in [
            "AX25KISSInterface",
            "KISSInterface",
            "PipeInterface",
            "RNodeInterface",
            "RNodeMultiInterface",
            "SerialInterface",
            "UDPInterface",
        ] {
            assert!(shared_medium_hint(interface_type), "{interface_type}");
        }
        for interface_type in [
            "AutoInterface",
            "BackboneInterface",
            "I2PInterface",
            "LocalInterface",
            "TCPClientInterface",
            "TCPServerInterface",
        ] {
            assert!(!shared_medium_hint(interface_type), "{interface_type}");
        }
    }
}
