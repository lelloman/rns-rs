//! Upstream's auto-connecting of discovered interfaces
//! (`autoconnect_policy = upstream`, the default).
//!
//! With `autoconnect_discovered_interfaces = N`, a qualified discovered
//! Backbone interface is connected as it is heard, until `N` auto-connected
//! interfaces exist; at startup the stored discoveries are connected the
//! same way. Interfaces from the configuration file connect as usual and do
//! not count against `N`. Once the first interface is auto-connected, a
//! monitor runs every 5 seconds, as upstream's `InterfaceDiscovery` does:
//!
//! - an auto-connected interface down for 12 seconds is detached;
//! - when more than a quarter of the `N` slots are free, one random
//!   available transport discovery is connected;
//! - `bootstrap_only` interfaces are detached while `N` auto-connected
//!   interfaces are online, and attached again when none is.
//!
//! The rns-rs Backbone peer pool (`autoconnect_policy = pool`) is the other
//! behaviour; the two are never active together.

use super::*;

/// Seconds between monitor runs (`MONITOR_INTERVAL`).
pub(crate) const MONITOR_INTERVAL: f64 = 5.0;
/// Seconds an auto-connected interface may stay down before it is
/// detached (`DETACH_THRESHOLD`).
pub(crate) const DETACH_THRESHOLD: f64 = 12.0;

/// The bitrate upstream configures on an auto-connected interface
/// (`_add_interface(..., configured_bitrate=5E6)`).
#[cfg(feature = "iface-backbone")]
pub(crate) const AUTOCONNECT_BITRATE: u64 = 5_000_000;

/// Addresses upstream never auto-connects to (`INVALID_IP_ADDRESSES`).
#[cfg(feature = "iface-backbone")]
const INVALID_IP_ADDRESSES: [&str; 2] = ["127.0.0.1", "0.0.0.0"];

pub(crate) struct UpstreamAutoconnect {
    /// `autoconnect_discovered_interfaces`.
    max: usize,
    /// The auto-connected interfaces.
    members: Vec<AutoconnectMember>,
    /// The initial connection of stored discoveries has run.
    initial_ran: bool,
    /// The monitor has started (with the first auto-connected interface).
    monitoring: bool,
    last_monitor: f64,
    /// Names of the configured `bootstrap_only` interfaces.
    bootstrap_interfaces: Vec<String>,
    /// Targets of the configured client interfaces, which an auto-connect
    /// must not duplicate.
    #[cfg(feature = "iface-backbone")]
    configured_targets: Vec<(String, u16)>,
}

struct AutoconnectMember {
    id: InterfaceId,
    name: String,
    /// `endpoint_hash`: the SHA-256 of `reachable_on:port`.
    #[cfg(feature = "iface-backbone")]
    endpoint_hash: [u8; 32],
    /// `autoconnect_source`: the network that announced it, as hex.
    source: String,
    #[cfg(feature = "iface-backbone")]
    target: (String, u16),
    #[cfg(feature = "iface-backbone")]
    control: Option<crate::interface::ListenerControl>,
    /// When the monitor first saw it down.
    down_since: Option<f64>,
}

impl UpstreamAutoconnect {
    pub(crate) fn new(
        max: usize,
        bootstrap_interfaces: Vec<String>,
        #[cfg(feature = "iface-backbone")] configured_targets: Vec<(String, u16)>,
    ) -> Self {
        Self {
            max,
            members: Vec::new(),
            initial_ran: false,
            monitoring: false,
            last_monitor: 0.0,
            bootstrap_interfaces,
            #[cfg(feature = "iface-backbone")]
            configured_targets,
        }
    }

    /// How many interfaces are auto-connected (`autoconnect_count`).
    pub(crate) fn count(&self) -> usize {
        self.members.len()
    }

    /// Whether interface `id` was auto-connected from a discovery.
    pub(crate) fn is_member(&self, id: InterfaceId) -> bool {
        self.members.iter().any(|member| member.id == id)
    }

    /// The network auto-connected interface `id` was discovered from.
    fn member_source(&self, id: InterfaceId) -> Option<&str> {
        self.members
            .iter()
            .find(|member| member.id == id)
            .map(|member| member.source.as_str())
    }

    /// Keep an auto-connected interface, starting the monitor with the
    /// first.
    #[cfg(feature = "iface-backbone")]
    fn add_member(&mut self, member: AutoconnectMember) {
        self.members.push(member);
        if !self.monitoring {
            self.monitoring = true;
            self.last_monitor = time::now();
        }
    }

    /// Whether the monitor runs now, then not again for an interval.
    fn monitor_due(&mut self, now: f64) -> bool {
        if !self.monitoring || now < self.last_monitor + MONITOR_INTERVAL {
            return false;
        }
        self.last_monitor = now;
        true
    }

    /// Note which members are online and which went down, as the monitor
    /// sees them in `interfaces`. Returns how many are online, and those
    /// to detach: gone some other way, or down too long.
    fn check_members(&mut self, interfaces: &Interfaces, now: f64) -> (usize, Vec<InterfaceId>) {
        let mut online = 0usize;
        let mut detach: Vec<InterfaceId> = Vec::new();
        for member in &mut self.members {
            match interfaces.get(&member.id) {
                // Detached some other way.
                None => detach.push(member.id),
                Some(entry) if entry.online => {
                    online += 1;
                    if member.down_since.take().is_some() {
                        log::info!("Auto-discovered interface {} reconnected", member.name);
                    }
                }
                Some(_) => match member.down_since {
                    None => {
                        log::debug!("Auto-discovered interface {} disconnected", member.name);
                        member.down_since = Some(now);
                    }
                    Some(since) if now - since >= DETACH_THRESHOLD => {
                        log::debug!(
                            "Auto-discovered interface {} has been down for {:.0}s, detaching",
                            member.name,
                            now - since
                        );
                        detach.push(member.id);
                    }
                    Some(_) => {}
                },
            }
        }
        (online, detach)
    }

    /// Whether an interface already reaches the discovered endpoint
    /// (`interface_exists`).
    #[cfg(feature = "iface-backbone")]
    fn endpoint_exists(&self, reachable_on: &str, port: Option<u16>) -> bool {
        let hash = endpoint_hash(reachable_on, port);
        self.members.iter().any(|member| {
            member.endpoint_hash == hash
                || member.target.0 == reachable_on
                    && port.is_none_or(|port| member.target.1 == port)
        }) || self.configured_targets.iter().any(|(host, target_port)| {
            host == reachable_on && port.is_none_or(|port| *target_port == port)
        })
    }
}

/// upstream `endpoint_hash`: the SHA-256 of `reachable_on` followed by
/// `:port`.
#[cfg(feature = "iface-backbone")]
fn endpoint_hash(reachable_on: &str, port: Option<u16>) -> [u8; 32] {
    let mut specifier = reachable_on.to_string();
    if let Some(port) = port {
        specifier.push_str(&format!(":{port}"));
    }
    rns_crypto::sha256::sha256(specifier.as_bytes())
}

/// Addresses upstream does not auto-connect to: Yggdrasil and onion
/// addresses, whose networks it cannot tell are reachable, and the invalid
/// IP addresses.
#[cfg(feature = "iface-backbone")]
fn unreachable_address(reachable_on: &str) -> bool {
    if reachable_on.to_ascii_lowercase().ends_with(".onion") {
        return true;
    }
    if let Ok(ip) = reachable_on.parse::<std::net::IpAddr>() {
        if let std::net::IpAddr::V6(v6) = ip {
            // Yggdrasil's 200::/7.
            if v6.segments()[0] & 0xfe00 == 0x0200 {
                return true;
            }
        }
        return INVALID_IP_ADDRESSES.contains(&reachable_on);
    }
    false
}

impl Driver {
    /// Turn on upstream's auto-connecting with `max` slots.
    pub(crate) fn enable_upstream_autoconnect(
        &mut self,
        max: usize,
        bootstrap_interfaces: Vec<String>,
        #[cfg(feature = "iface-backbone")] configured_targets: Vec<(String, u16)>,
    ) {
        if max == 0 {
            return;
        }
        log::info!("Auto-connecting up to {max} discovered interfaces");
        self.discovery.upstream_autoconnect = Some(UpstreamAutoconnect::new(
            max,
            bootstrap_interfaces,
            #[cfg(feature = "iface-backbone")]
            configured_targets,
        ));
    }

    /// upstream `connect_discovered`: connect stored transport discoveries,
    /// best first, until the slots are full.
    pub(crate) fn autoconnect_stored_discoveries(&mut self) {
        let Some(autoconnect) = self.discovery.upstream_autoconnect.as_ref() else {
            return;
        };
        let max = autoconnect.max;
        let mut interfaces = self.discovery.storage.list().unwrap_or_default();
        interfaces.retain(|iface| self.discovery.source_allowed(&iface.network_id));
        crate::discovery::filter_and_sort_interfaces(&mut interfaces, false, true);
        for iface in interfaces {
            if self
                .discovery
                .upstream_autoconnect
                .as_ref()
                .is_some_and(|autoconnect| autoconnect.count() >= max)
            {
                break;
            }
            self.autoconnect_discovered(&iface);
        }
        if let Some(autoconnect) = self.discovery.upstream_autoconnect.as_mut() {
            autoconnect.initial_ran = true;
        }
    }

    /// upstream `autoconnect`: connect a discovered interface if a slot is
    /// free and it qualifies.
    #[cfg(not(feature = "iface-backbone"))]
    pub(crate) fn autoconnect_discovered(&mut self, iface: &crate::discovery::DiscoveredInterface) {
        if self.discovery.upstream_autoconnect.is_some() {
            log::warn!(
                "Not auto-connecting discovered interface {}: this build has no Backbone interface",
                iface.name
            );
        }
    }

    /// upstream `autoconnect`: connect a discovered interface if a slot is
    /// free and it qualifies.
    #[cfg(feature = "iface-backbone")]
    pub(crate) fn autoconnect_discovered(&mut self, iface: &crate::discovery::DiscoveredInterface) {
        let Some(autoconnect) = self.discovery.upstream_autoconnect.as_ref() else {
            return;
        };
        if autoconnect.count() >= autoconnect.max {
            return;
        }
        // Upstream auto-connects only Backbone interfaces.
        if crate::interface::InterfaceKind::from_type_name(&iface.interface_type)
            != Some(crate::interface::InterfaceKind::Backbone)
        {
            return;
        }
        if !Self::autoconnect_qualified(
            iface,
            self.discovery.autoconnect_unverified_implementations,
        ) {
            log::debug!(
                "Not auto-connecting discovered {} {}, auto-connect criteria not satisfied",
                iface.interface_type,
                iface.name
            );
            return;
        }
        if !self.discovered_costs_affordable(iface) {
            return;
        }
        let Some(reachable_on) = iface.reachable_on.clone() else {
            return;
        };
        if autoconnect.endpoint_exists(&reachable_on, iface.port) {
            log::debug!(
                "Discovered {} already exists, not auto-connecting",
                iface.interface_type
            );
            return;
        }
        if unreachable_address(&reachable_on) {
            log::debug!("Not auto-connecting discovered interface at {reachable_on}");
            return;
        }
        if !(crate::discovery::is_ip_address(&reachable_on)
            || crate::discovery::is_hostname(&reachable_on))
        {
            return;
        }
        self.start_autoconnect(iface, reachable_on);
    }

    #[cfg(feature = "iface-backbone")]
    fn start_autoconnect(
        &mut self,
        iface: &crate::discovery::DiscoveredInterface,
        reachable_on: String,
    ) {
        use crate::interface::backbone::{BackboneClientConfig, BackboneClientRuntime};

        let port = iface.port.unwrap_or(4242);
        // `autoconnect_interface_name`: the discovered name, numbered on a
        // collision.
        let taken = |name: &str| {
            self.interfaces
                .values()
                .any(|entry| entry.info.name == name)
        };
        let mut name = iface.name.clone();
        let mut n = 2;
        while taken(&name) {
            name = format!("{} ({n})", iface.name);
            n += 1;
        }
        if name != iface.name {
            log::info!(
                "Auto-connect name collision for \"{}\", connecting as \"{name}\"",
                iface.name
            );
        }
        let id = InterfaceId(
            self.registry
                .next_dynamic_id
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed),
        );
        let mut client = BackboneClientConfig {
            name: name.clone(),
            target_host: reachable_on.clone(),
            target_port: port,
            interface_id: id,
            transport_identity: Some(rns_core::encoding::hex(&iface.transport_id)),
            // Upstream adds it with `configured_bitrate=5E6`, which also
            // sets its hardware MTU (8192).
            bitrate: AUTOCONNECT_BITRATE,
            ..BackboneClientConfig::default()
        };
        client.runtime = Arc::new(Mutex::new(BackboneClientRuntime::from_config(&client)));
        let ifac_runtime = IfacRuntimeConfig {
            netname: iface.ifac_netname.clone(),
            netkey: iface.ifac_netkey.clone(),
            size: 16,
        };
        let ifac_enabled = ifac_runtime.netname.is_some() || ifac_runtime.netkey.is_some();
        // Upstream: the configured mode, else gateway on a transport node.
        let mode = self.discovery.autoconnect_mode.unwrap_or_else(|| {
            if self.engine.transport_enabled() {
                rns_core::constants::MODE_GATEWAY
            } else {
                rns_core::constants::MODE_FULL
            }
        });
        let config = BackbonePeerPoolCandidateConfig {
            client,
            mode,
            gravity: self.discovery.autoconnect_gravity,
            recursive_prs: false,
            announces_from_internal: true,
            announces_to_internal: self.discovery.autoconnect_announces_to_internal,
            ingress_control: self.interface_settings.ingress_control,
            stamp_costs: Default::default(),
            ifac_runtime,
            ifac_enabled,
            // Upstream auto-connects a BackboneClientInterface.
            interface_kind: crate::interface::InterfaceKind::BackboneClient,
            source: BackbonePeerPoolCandidateSource::Discovered,
            priority: BACKBONE_PEER_POOL_DISCOVERED_PRIORITY,
            discovery: None,
        };
        // The client reconnects on its own, as upstream's does; the monitor
        // detaches it if it stays down.
        match self.start_dynamic_backbone_client(&config, None) {
            Ok(control) => {
                log::info!("Auto-connecting discovered BackboneInterface {name}");
                // Kept while it is down, so the monitor can time it out.
                if let Some(entry) = self.interfaces.get_mut(&id) {
                    entry.dynamic = false;
                }
                if let Some(autoconnect) = self.discovery.upstream_autoconnect.as_mut() {
                    autoconnect.add_member(AutoconnectMember {
                        id,
                        name,
                        endpoint_hash: endpoint_hash(&reachable_on, iface.port),
                        source: rns_core::encoding::hex(&iface.network_id),
                        target: (reachable_on, port),
                        control: Some(control),
                        down_since: None,
                    });
                }
            }
            Err(error) => {
                log::error!("Error while auto-connecting discovered interface {name}: {error}")
            }
        }
    }

    /// Run the monitor when it is due.
    pub(crate) fn tick_upstream_autoconnect(&mut self, now: f64) {
        if self
            .discovery
            .upstream_autoconnect
            .as_mut()
            .is_some_and(|autoconnect| autoconnect.monitor_due(now))
        {
            self.run_autoconnect_monitor(now);
        }
    }

    /// upstream `__monitor_job`, one pass.
    fn run_autoconnect_monitor(&mut self, now: f64) {
        let Some(autoconnect) = self.discovery.upstream_autoconnect.as_mut() else {
            return;
        };
        let max = autoconnect.max;
        let autoconnected = autoconnect.members.len();
        let (online, detach) = autoconnect.check_members(&self.interfaces, now);
        let free_slots = max.saturating_sub(autoconnected);
        let reserved_slots = max / 4;
        let initial_ran = autoconnect.initial_ran;
        let bootstrap = autoconnect.bootstrap_interfaces.clone();

        if online >= max {
            for name in &bootstrap {
                if self
                    .interfaces
                    .values()
                    .any(|entry| &entry.info.name == name)
                    || self.registry.managed.contains_key(name)
                {
                    log::info!(
                        "Tearing down bootstrap-only interface {name} since target connected auto-discovered interface count has been reached"
                    );
                    self.manage_bootstrap_interface(name, false);
                }
            }
        }
        if online == 0 {
            let bootstrap_up = bootstrap.iter().any(|name| {
                self.interfaces
                    .values()
                    .any(|entry| &entry.info.name == name)
                    || self.registry.managed.contains_key(name)
            });
            if !bootstrap.is_empty() && !bootstrap_up {
                log::info!(
                    "No auto-discovered interfaces connected, re-enabling bootstrap interfaces"
                );
                for name in &bootstrap {
                    self.manage_bootstrap_interface(name, true);
                }
            }
        }

        if initial_ran && free_slots > reserved_slots {
            let mut candidates = self.discovery.storage.list().unwrap_or_default();
            candidates.retain(|iface| self.discovery.source_allowed(&iface.network_id));
            crate::discovery::filter_and_sort_interfaces(&mut candidates, true, true);
            if !candidates.is_empty() {
                let mut random = [0u8; 8];
                rns_crypto::Rng::fill_bytes(&mut self.rng, &mut random);
                let pick = (u64::from_le_bytes(random) % candidates.len() as u64) as usize;
                let selected = candidates.swap_remove(pick);
                self.autoconnect_discovered(&selected);
            }
        }

        for id in detach {
            self.teardown_autoconnected(id);
        }
    }

    /// The network an auto-connected interface was discovered from, as
    /// upstream reports it (`autoconnect_source`): the hex of the
    /// announcing network's identity hash.
    pub(crate) fn autoconnect_source(&self, id: InterfaceId) -> Option<String> {
        if let Some(source) = self
            .discovery
            .upstream_autoconnect
            .as_ref()
            .and_then(|autoconnect| autoconnect.member_source(id))
        {
            return Some(source.to_string());
        }
        #[cfg(feature = "iface-backbone")]
        if let Some(network_id) = self.backbone_peer_pool_discovery_network(id) {
            return Some(rns_core::encoding::hex(&network_id));
        }
        None
    }

    /// Detach an auto-connected interface (`teardown_interface`).
    pub(crate) fn teardown_autoconnected(&mut self, id: InterfaceId) {
        let Some(autoconnect) = self.discovery.upstream_autoconnect.as_mut() else {
            return;
        };
        let Some(index) = autoconnect
            .members
            .iter()
            .position(|member| member.id == id)
        else {
            return;
        };
        let member = autoconnect.members.remove(index);
        #[cfg(feature = "iface-backbone")]
        {
            let control = member.control;
            if self.interfaces.contains_key(&id) {
                self.stop_dynamic_backbone_client(id, control, member.name.clone());
                self.callbacks.on_interface_down(id);
            }
        }
        log::info!("Detached auto-connected interface {}", member.name);
    }

    /// Detach or attach a configured `bootstrap_only` interface.
    fn manage_bootstrap_interface(&mut self, name: &str, attach: bool) {
        let operation = if attach {
            crate::event::InterfaceManagementOperation::Attach
        } else {
            crate::event::InterfaceManagementOperation::Detach
        };
        if self.registry.management.is_none() {
            log::warn!(
                "Cannot {} bootstrap interface {name}: interface management needs a config file",
                if attach { "attach" } else { "detach" }
            );
            return;
        }
        if self.manage_interface(operation, name) != Some(true) {
            log::warn!(
                "Could not {} bootstrap interface {name}",
                if attach { "attach" } else { "detach" }
            );
        }
    }
}

#[cfg(all(test, feature = "iface-backbone"))]
mod tests {
    use super::*;

    #[test]
    fn endpoint_hash_matches_upstream_specifier() {
        assert_eq!(
            endpoint_hash("node.example.com", Some(4242)),
            rns_crypto::sha256::sha256(b"node.example.com:4242")
        );
        assert_eq!(
            endpoint_hash("node.example.com", None),
            rns_crypto::sha256::sha256(b"node.example.com")
        );
    }

    #[test]
    fn unreachable_addresses_follow_upstream() {
        assert!(unreachable_address("127.0.0.1"));
        assert!(unreachable_address("0.0.0.0"));
        assert!(unreachable_address("abcdefghijklmnop.onion"));
        assert!(unreachable_address("200:1234::1"));
        assert!(unreachable_address("3ff:1::1"));
        assert!(!unreachable_address("192.0.2.10"));
        assert!(!unreachable_address("2001:db8::1"));
        assert!(!unreachable_address("localhost"));
        assert!(!unreachable_address("node.example.com"));
    }
}
