//! Properties implied by an interface type name.

/// Return whether an interface type normally operates on a shared medium.
///
/// This is a type-level hint: runtime configuration can still describe links
/// with different physical properties. It mirrors Reticulum's interface-class
/// defaults and is suitable for discovery/capability metadata.
pub fn shared_medium_hint(interface_type: &str) -> bool {
    matches!(
        interface_type,
        "AX25KISSInterface"
            | "KISSInterface"
            | "PipeInterface"
            | "RNodeInterface"
            | "RNodeMultiInterface"
            | "SerialInterface"
            | "UDPInterface"
    )
}

/// Whether a tunnel may be synthesized over an interface of this type
/// (upstream 464e7598 `tunnels_allowed`): TCP, Backbone and I2P connections.
pub fn tunnels_allowed(interface_type: &str) -> bool {
    matches!(
        interface_type,
        "TCPClientInterface"
            | "TCPServerClientInterface"
            | "BackboneInterface"
            | "BackboneClientInterface"
            | "BackboneInterfacePeer"
            | "I2PInterfacePeer"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

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
