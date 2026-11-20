//! Running hooks against the transport engine and turning what they
//! inject into actions.

use super::*;

/// The programmable hook system's driver-side state.
pub(crate) struct Hooks {
    /// Hook slots, one per [`HookPoint`].
    pub(crate) slots: [HookSlot; HookPoint::COUNT],
    /// Hook manager. None if initialization failed.
    pub(crate) manager: Option<HookManager>,
    /// Hands the events hooks emit to connected consumers, when enabled.
    pub(crate) provider_bridge: Option<ProviderBridge>,
    /// Per hook point count of `Modify` replacements that failed validation
    /// and were therefore treated as `Drop`.
    pub(crate) rejected_modifications: [u64; HookPoint::COUNT],
}

impl Hooks {
    pub(crate) fn new() -> Self {
        Self {
            slots: create_hook_slots(),
            manager: HookManager::new().ok(),
            provider_bridge: None,
            rejected_modifications: [0; HookPoint::COUNT],
        }
    }
}

/// Thin wrapper providing `EngineAccess` for a `TransportEngine` + Driver interfaces.
#[cfg(feature = "hooks")]
pub(super) struct EngineRef<'a> {
    pub(super) engine: &'a TransportEngine,
    pub(super) interfaces: &'a crate::interface::InterfaceMap<InterfaceEntry>,
    pub(super) link_manager: &'a LinkManager,
    pub(super) now: f64,
}

#[cfg(feature = "hooks")]
impl<'a> EngineAccess for EngineRef<'a> {
    fn has_path(&self, dest: &[u8; 16]) -> bool {
        self.engine.has_path(dest)
    }
    fn hops_to(&self, dest: &[u8; 16]) -> Option<u8> {
        self.engine.hops_to(dest)
    }
    fn next_hop(&self, dest: &[u8; 16]) -> Option<[u8; 16]> {
        self.engine.next_hop(dest)
    }
    fn is_blackholed(&self, identity: &[u8; 16]) -> bool {
        self.engine.is_blackholed(identity, self.now)
    }
    fn interface_name(&self, id: u64) -> Option<String> {
        self.interfaces
            .get(&InterfaceId(id))
            .map(|e| e.info.name.clone())
    }
    fn interface_mode(&self, id: u64) -> Option<u8> {
        self.interfaces.get(&InterfaceId(id)).map(|e| e.info.mode)
    }
    fn identity_hash(&self) -> Option<[u8; 16]> {
        self.engine.identity_hash().copied()
    }
    fn announce_rate(&self, id: u64) -> Option<i32> {
        self.interfaces
            .get(&InterfaceId(id))
            .map(|e| (e.stats.outgoing_announce_freq(time::now()) * 1000.0) as i32)
    }
    fn link_state(&self, link_hash: &[u8; 16]) -> Option<u8> {
        use rns_core::link::types::LinkState;
        self.link_manager.link_state(link_hash).map(|s| match s {
            LinkState::Pending => 0,
            LinkState::Handshake => 1,
            LinkState::Active => 2,
            LinkState::Stale => 3,
            LinkState::Closed => 4,
        })
    }
}

/// Execute a hook chain on disjoint Driver fields (avoids &mut self borrow conflict).
#[cfg(feature = "hooks")]
pub(super) fn run_hook_inner(
    programs: &mut [rns_hooks::LoadedProgram],
    hook_manager: &Option<HookManager>,
    engine_access: &dyn EngineAccess,
    ctx: &HookContext,
    now: f64,
    provider_events_enabled: bool,
) -> Option<rns_hooks::ExecuteResult> {
    if programs.is_empty() {
        return None;
    }
    let mgr = hook_manager.as_ref()?;
    mgr.run_chain_with_provider_events(programs, ctx, engine_access, now, provider_events_enabled)
}

/// What a packet hook point does after its hook chain ran.
///
/// Only hook points that hold the raw packet bytes before acting on them apply
/// a `Modify` verdict (`PreIngress`, `SendOnInterface`,
/// `BroadcastOnAllInterfaces`, `DeliverLocal`). Every other hook point treats
/// `Modify` as `Continue` and ignores the replacement bytes.
#[cfg(feature = "hooks")]
pub(crate) enum PacketHookOutcome {
    /// Carry on with the bytes the hook point already holds.
    Keep,
    /// Stop processing this packet.
    Drop,
    /// Carry on with the replacement bytes, decoded with the same decoder the
    /// normal path uses. Hashes and header fields come from the replacement.
    Replace(RawPacket),
}

/// Validate replacement bytes from a `Modify` verdict: they must be non-empty,
/// fit within `max_len`, and decode as a packet.
#[cfg(feature = "hooks")]
pub(super) fn validate_hook_replacement(
    data: &[u8],
    max_len: usize,
) -> Result<RawPacket, &'static str> {
    if data.is_empty() {
        return Err("replacement is empty");
    }
    if data.len() > max_len {
        return Err("replacement exceeds the packet size limit");
    }
    RawPacket::unpack(data).map_err(|_| "replacement does not decode as a packet")
}

#[cfg(feature = "hooks")]
pub(super) fn backbone_peer_hook_context(event: &BackbonePeerHookEvent) -> HookContext<'_> {
    HookContext::BackbonePeer {
        server_interface_id: event.server_interface_id.0,
        peer_interface_id: event.peer_interface_id.map(|id| id.0),
        peer_ip: event.peer_ip,
        peer_port: event.peer_port,
        connected_for: event.connected_for,
        had_received_data: event.had_received_data,
        penalty_level: event.penalty_level,
        blacklist_for: event.blacklist_for,
    }
}

/// Convert a Vec of ActionWire into TransportActions for dispatch.
#[cfg(feature = "hooks")]
pub(super) fn convert_injected_actions(
    actions: Vec<rns_hooks::ActionWire>,
) -> Vec<TransportAction> {
    actions
        .into_iter()
        .map(|a| {
            use rns_hooks::ActionWire;
            match a {
                ActionWire::SendOnInterface { interface, raw } => {
                    TransportAction::SendOnInterface {
                        interface: InterfaceId(interface),
                        raw: raw.into(),
                    }
                }
                ActionWire::BroadcastOnAllInterfaces {
                    raw,
                    exclude,
                    has_exclude,
                } => TransportAction::BroadcastOnAllInterfaces {
                    raw: raw.into(),
                    exclude: if has_exclude != 0 {
                        Some(InterfaceId(exclude))
                    } else {
                        None
                    },
                },
                ActionWire::DeliverLocal {
                    destination_hash,
                    raw,
                    packet_hash,
                    receiving_interface,
                } => TransportAction::DeliverLocal {
                    destination_hash,
                    raw: raw.into(),
                    packet_hash,
                    receiving_interface: InterfaceId(receiving_interface),
                },
                ActionWire::PathUpdated {
                    destination_hash,
                    hops,
                    next_hop,
                    interface,
                } => TransportAction::PathUpdated {
                    destination_hash,
                    hops,
                    next_hop,
                    interface: InterfaceId(interface),
                },
                ActionWire::CacheAnnounce { packet_hash, raw } => TransportAction::CacheAnnounce {
                    packet_hash,
                    raw: raw.into(),
                },
                ActionWire::TunnelEstablished {
                    tunnel_id,
                    interface,
                } => TransportAction::TunnelEstablished {
                    tunnel_id,
                    interface: InterfaceId(interface),
                },
                ActionWire::TunnelSynthesize {
                    interface,
                    data,
                    dest_hash,
                } => TransportAction::TunnelSynthesize {
                    interface: InterfaceId(interface),
                    data,
                    dest_hash,
                },
                ActionWire::ForwardToLocalClients {
                    raw,
                    exclude,
                    has_exclude,
                } => TransportAction::ForwardToLocalClients {
                    raw: raw.into(),
                    exclude: if has_exclude != 0 {
                        Some(InterfaceId(exclude))
                    } else {
                        None
                    },
                },
                ActionWire::ForwardPlainBroadcast {
                    raw,
                    to_local,
                    exclude,
                    has_exclude,
                } => TransportAction::ForwardPlainBroadcast {
                    raw: raw.into(),
                    to_local: to_local != 0,
                    exclude: if has_exclude != 0 {
                        Some(InterfaceId(exclude))
                    } else {
                        None
                    },
                },
                ActionWire::AnnounceReceived {
                    destination_hash,
                    identity_hash,
                    public_key,
                    name_hash,
                    random_hash,
                    app_data,
                    hops,
                    receiving_interface,
                } => TransportAction::AnnounceReceived(Box::new(ReceivedAnnounce {
                    // A hook-injected announce came in no packet.
                    packet_hash: [0u8; 32],
                    destination_hash,
                    identity_hash,
                    public_key,
                    name_hash,
                    random_hash,
                    ratchet: None,
                    app_data,
                    stamp: None,
                    stamp_value: rns_core::stamp::StampValue::ZERO,
                    lr_cost: None,
                    hops,
                    receiving_interface: InterfaceId(receiving_interface),
                    rx: rns_core::transport::RxMetadata::default(),
                })),
            }
        })
        .collect()
}
