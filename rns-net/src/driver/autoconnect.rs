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

/// Addresses upstream never auto-connects to (`INVALID_IP_ADDRESSES`).
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
    configured_targets: Vec<(String, u16)>,
}

struct AutoconnectMember {
    id: InterfaceId,
    name: String,
    /// `endpoint_hash`: the SHA-256 of `reachable_on:port`.
    endpoint_hash: [u8; 32],
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
        configured_targets: Vec<(String, u16)>,
    ) -> Self {
        Self {
            max,
            members: Vec::new(),
            initial_ran: false,
            monitoring: false,
            last_monitor: 0.0,
            bootstrap_interfaces,
            configured_targets,
        }
    }

    /// How many interfaces are auto-connected (`autoconnect_count`).
    pub(crate) fn count(&self) -> usize {
        self.members.len()
    }
}

/// upstream `endpoint_hash`: the SHA-256 of `reachable_on` followed by
/// `:port`.
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
        configured_targets: Vec<(String, u16)>,
    ) {
        if max == 0 {
            return;
        }
        log::info!("Auto-connecting up to {max} discovered interfaces");
        self.upstream_autoconnect = Some(UpstreamAutoconnect::new(
            max,
            bootstrap_interfaces,
            configured_targets,
        ));
    }

    /// upstream `connect_discovered`: connect stored transport discoveries,
    /// best first, until the slots are full.
    pub(crate) fn autoconnect_stored_discoveries(&mut self) {
        let Some(autoconnect) = self.upstream_autoconnect.as_ref() else {
            return;
        };
        let max = autoconnect.max;
        let mut interfaces = self.discovered_interfaces.list().unwrap_or_default();
        interfaces.retain(|iface| self.discovery_source_allowed(&iface.network_id));
        crate::discovery::filter_and_sort_interfaces(&mut interfaces, false, true);
        for iface in interfaces {
            if self
                .upstream_autoconnect
                .as_ref()
                .is_some_and(|autoconnect| autoconnect.count() >= max)
            {
                break;
            }
            self.autoconnect_discovered(&iface);
        }
        if let Some(autoconnect) = self.upstream_autoconnect.as_mut() {
            autoconnect.initial_ran = true;
        }
    }

    /// Whether an interface already reaches the discovered endpoint
    /// (`interface_exists`).
    fn autoconnect_endpoint_exists(&self, reachable_on: &str, port: Option<u16>) -> bool {
        let Some(autoconnect) = self.upstream_autoconnect.as_ref() else {
            return false;
        };
        let hash = endpoint_hash(reachable_on, port);
        autoconnect.members.iter().any(|member| {
            member.endpoint_hash == hash
                || member.target.0 == reachable_on
                    && port.is_none_or(|port| member.target.1 == port)
        }) || autoconnect
            .configured_targets
            .iter()
            .any(|(host, target_port)| {
                host == reachable_on && port.is_none_or(|port| *target_port == port)
            })
    }

    /// upstream `autoconnect`: connect a discovered interface if a slot is
    /// free and it qualifies.
    #[cfg(not(feature = "iface-backbone"))]
    pub(crate) fn autoconnect_discovered(&mut self, iface: &crate::discovery::DiscoveredInterface) {
        if self.upstream_autoconnect.is_some() {
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
        let Some(autoconnect) = self.upstream_autoconnect.as_ref() else {
            return;
        };
        if autoconnect.count() >= autoconnect.max {
            return;
        }
        // Upstream auto-connects only Backbone interfaces.
        if iface.interface_type != "BackboneInterface" {
            return;
        }
        if !Self::autoconnect_qualified(iface, self.autoconnect_unverified_implementations) {
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
        if self.autoconnect_endpoint_exists(&reachable_on, iface.port) {
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
            self.next_dynamic_interface_id
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed),
        );
        let mut client = BackboneClientConfig {
            name: name.clone(),
            target_host: reachable_on.clone(),
            target_port: port,
            interface_id: id,
            transport_identity: Some(crate::discovery::hex_encode(&iface.transport_id)),
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
        let mode = self.autoconnect_interface_mode.unwrap_or_else(|| {
            if self.engine.transport_enabled() {
                rns_core::constants::MODE_GATEWAY
            } else {
                rns_core::constants::MODE_FULL
            }
        });
        let config = BackbonePeerPoolCandidateConfig {
            client,
            mode,
            gravity: self.autoconnect_interface_gravity,
            recursive_prs: false,
            announces_from_internal: true,
            announces_to_internal: self.autoconnect_announces_to_internal,
            ingress_control: self.ingress_control_defaults,
            stamp_costs: Default::default(),
            ifac_runtime,
            ifac_enabled,
            interface_type_name: "BackboneInterface".to_string(),
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
                if let Some(autoconnect) = self.upstream_autoconnect.as_mut() {
                    autoconnect.members.push(AutoconnectMember {
                        id,
                        name,
                        endpoint_hash: endpoint_hash(&reachable_on, iface.port),
                        target: (reachable_on, port),
                        control: Some(control),
                        down_since: None,
                    });
                    if !autoconnect.monitoring {
                        autoconnect.monitoring = true;
                        autoconnect.last_monitor = time::now();
                    }
                }
            }
            Err(error) => {
                log::error!("Error while auto-connecting discovered interface {name}: {error}")
            }
        }
    }

    /// Run the monitor when it is due.
    pub(crate) fn tick_upstream_autoconnect(&mut self, now: f64) {
        let Some(autoconnect) = self.upstream_autoconnect.as_mut() else {
            return;
        };
        if !autoconnect.monitoring || now < autoconnect.last_monitor + MONITOR_INTERVAL {
            return;
        }
        autoconnect.last_monitor = now;
        self.run_autoconnect_monitor(now);
    }

    /// upstream `__monitor_job`, one pass.
    fn run_autoconnect_monitor(&mut self, now: f64) {
        let Some(autoconnect) = self.upstream_autoconnect.as_mut() else {
            return;
        };
        let max = autoconnect.max;
        let autoconnected = autoconnect.members.len();
        let mut online = 0usize;
        let mut detach: Vec<InterfaceId> = Vec::new();
        for member in &mut autoconnect.members {
            match self.interfaces.get(&member.id) {
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
                    || self.managed_interfaces.contains_key(name)
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
                    || self.managed_interfaces.contains_key(name)
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
            let mut candidates = self.discovered_interfaces.list().unwrap_or_default();
            candidates.retain(|iface| self.discovery_source_allowed(&iface.network_id));
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

    /// Whether an interface was auto-connected from a discovery.
    pub(crate) fn is_autoconnected(&self, id: InterfaceId) -> bool {
        self.upstream_autoconnect
            .as_ref()
            .is_some_and(|autoconnect| autoconnect.members.iter().any(|member| member.id == id))
    }

    /// Detach an auto-connected interface (`teardown_interface`).
    pub(crate) fn teardown_autoconnected(&mut self, id: InterfaceId) {
        let Some(autoconnect) = self.upstream_autoconnect.as_mut() else {
            return;
        };
        let Some(index) = autoconnect
            .members
            .iter()
            .position(|member| member.id == id)
        else {
            return;
        };
        #[cfg_attr(not(feature = "iface-backbone"), allow(unused_mut))]
        let mut member = autoconnect.members.remove(index);
        #[cfg(feature = "iface-backbone")]
        {
            let control = member.control.take();
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
        if self.interface_management.is_none() {
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

#[cfg(test)]
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
