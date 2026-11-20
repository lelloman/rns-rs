//! The destinations transport serves itself.

use super::*;

/// The destinations transport itself serves, and the links to them.
pub(crate) struct BuiltinDestinations {
    /// Destination hash for rnstransport.tunnel.synthesize (PLAIN).
    pub(crate) tunnel_synth: [u8; 16],
    /// Destination hash for rnstransport.path.request (PLAIN).
    pub(crate) path_request: [u8; 16],
    /// Destination hash for the probe responder (if respond_to_probes is enabled).
    pub(crate) probe_responder: Option<[u8; 16]>,
    /// The built-in destinations links are accepted to (remote management,
    /// the blackhole list, the network identity's): upstream keeps them
    /// inside Transport, so the application never hears of those links.
    pub(crate) link_destinations: HashSet<[u8; 16]>,
    /// Links established to `link_destinations`, whose events are not
    /// reported to the callbacks.
    pub(crate) links: HashSet<[u8; 16]>,
}

impl BuiltinDestinations {
    pub(crate) fn new(tunnel_synth: [u8; 16], path_request: [u8; 16]) -> Self {
        Self {
            tunnel_synth,
            path_request,
            probe_responder: None,
            link_destinations: HashSet::new(),
            links: HashSet::new(),
        }
    }
}
