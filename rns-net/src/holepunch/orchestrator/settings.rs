//! The manager's settings and what they allow.

use super::*;

impl HolePunchManager {
    pub fn new(
        probe_addrs: Vec<SocketAddr>,
        probe_protocol: ProbeProtocol,
        device: Option<String>,
    ) -> Self {
        let probe_addrs = usable_probe_servers(probe_addrs);
        HolePunchManager {
            sessions: HashMap::new(),
            link_to_session: HashMap::new(),
            peer_support: HashMap::new(),
            direct: HashMap::new(),
            retiring: Vec::new(),
            policy: HolePunchPolicy::default(),
            probe_addrs,
            probe_protocol,
            device,
            underlay_mark: None,
            next_interface_id: 50000, // start high to avoid collision with regular interfaces
            allow_private_endpoints: false,
            own_ports: Vec::new(),
            probe_server_counters: None,
            allowed_identities: Vec::new(),
            inbound_limiter: InboundRequestLimiter::new(INBOUND_REQUEST_WINDOW),
            reupgrade_config: DirectReupgradeConfig::default(),
            reupgrades: HashMap::new(),
            spawn_workers: true,
            event_tx: None,
            totals: Counters::default(),
            history: HashMap::new(),
            #[cfg(test)]
            networks: None,
        }
    }

    /// Replace the probe servers, their protocol and the device probes and
    /// punches are bound to, keeping every other setting.
    pub fn set_probe_config(
        &mut self,
        probe_addrs: Vec<SocketAddr>,
        probe_protocol: ProbeProtocol,
        device: Option<String>,
    ) {
        self.probe_addrs = usable_probe_servers(probe_addrs);
        self.probe_protocol = probe_protocol;
        self.device = device;
    }

    /// Run probes and punches on the loop of the driver that `tx` feeds,
    /// when services are folded.
    pub(crate) fn set_event_sender(&mut self, tx: EventSender) {
        self.event_tx = Some(tx);
    }

    pub fn set_policy(&mut self, policy: HolePunchPolicy) {
        self.policy = policy;
    }

    pub fn policy(&self) -> HolePunchPolicy {
        self.policy
    }

    pub fn set_underlay_mark(&mut self, underlay_mark: Option<u32>) {
        self.underlay_mark = underlay_mark;
    }

    /// Identities whose proposals are accepted whatever the policy, once
    /// they have identified on the link.
    pub fn set_allowed_identities(&mut self, identities: Vec<[u8; 16]>) {
        self.allowed_identities = identities;
    }

    /// Whether `identity` is on the allowlist.
    pub fn identity_allowed(&self, identity: &[u8; 16]) -> bool {
        self.allowed_identities.contains(identity)
    }

    /// Accept peer-supplied endpoints in private, shared, link-local,
    /// and unique-local ranges (for LAN-only deployments).
    pub fn set_allow_private_endpoints(&mut self, allow: bool) {
        self.allow_private_endpoints = allow;
    }

    pub fn allow_private_endpoints(&self) -> bool {
        self.allow_private_endpoints
    }

    pub fn set_reupgrade_config(&mut self, config: DirectReupgradeConfig) {
        self.reupgrade_config = config;
        if !config.enabled {
            self.reupgrades.clear();
        }
    }

    pub fn reupgrade_config(&self) -> DirectReupgradeConfig {
        self.reupgrade_config
    }

    /// UDP ports this node listens on, which it never punches toward at
    /// its own public address.
    /// Report the counters of this node's own probe server.
    pub fn set_probe_server_counters(
        &mut self,
        counters: std::sync::Arc<crate::holepunch::probe::ProbeServerCounters>,
    ) {
        self.probe_server_counters = Some(counters);
    }

    pub fn set_own_listen_ports(&mut self, ports: Vec<u16>) {
        self.own_ports = ports;
    }

    pub fn own_listen_ports(&self) -> &[u16] {
        &self.own_ports
    }

    /// The networks of this host's interfaces.
    pub(super) fn local_networks(&self) -> Vec<crate::holepunch::candidates::LocalNetwork> {
        #[cfg(test)]
        if let Some(networks) = &self.networks {
            return networks.clone();
        }
        crate::holepunch::candidates::local_networks()
    }

    /// Whether a peer-supplied endpoint may be probed or punched.
    pub(super) fn endpoint_allowed(&self, ep: &Endpoint) -> Option<SocketAddr> {
        endpoint_to_socket_addr(ep)
            .filter(|addr| endpoint_is_acceptable(addr, self.allow_private_endpoints))
    }

    /// Whether this node takes part in Direct Link at all: it can propose
    /// (a probe server is configured) or may accept proposals. A node that
    /// does neither ignores all signalling, as a node without Direct Link
    /// support does.
    pub fn enabled(&self) -> bool {
        !self.probe_addrs.is_empty()
            || self.policy != HolePunchPolicy::Reject
            || !self.allowed_identities.is_empty()
    }

    /// Whether the link peer is known to implement Direct Link.
    pub fn peer_supported(&self, link_id: &[u8; 16]) -> bool {
        self.peer_support.get(link_id) == Some(&PeerSupport::Supported)
    }
}
