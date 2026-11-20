//! Starting the configured interfaces and registering them with the
//! driver.

use super::*;

/// What starting the configured interfaces leaves for the later startup
/// steps.
pub(super) struct StartedInterfaces {
    /// The discoverable interfaces, for the interface announcer.
    pub(super) discoverable: Vec<crate::discovery::DiscoverableInterface>,
    /// Backbone interfaces left to the peer pool instead of started.
    #[cfg(feature = "iface-backbone")]
    pub(super) backbone_peer_pool_candidates: Vec<BackbonePeerPoolCandidateConfig>,
    /// The hosts and ports the configured client interfaces connect to.
    #[cfg(feature = "iface-backbone")]
    pub(super) configured_client_targets: Vec<(String, u16)>,
}

/// Start the configured interfaces through their registry factories and
/// register them with the driver, which takes over `interface_management`.
/// An interface that fails to start is logged and skipped, unless the
/// config panics on interface errors, when its error fails startup.
pub(super) fn start_interfaces(
    driver: &mut Driver,
    tx: &EventSender,
    next_dynamic_id: &Arc<AtomicU64>,
    config: &NodeConfig,
    interfaces: Vec<InterfaceConfig>,
    registry: Option<crate::interface::registry::InterfaceRegistry>,
    interface_management: Option<InterfaceManagementConfig>,
) -> io::Result<StartedInterfaces> {
    let initial_managed_ids = interface_management
        .as_ref()
        .map(|management| management.initial_ids.clone())
        .unwrap_or_default();
    driver.interface_management = interface_management;

    let mut starter = InterfaceStarter {
        driver,
        tx,
        next_dynamic_id,
        config,
        initial_managed_ids,
        started: StartedInterfaces {
            discoverable: Vec::new(),
            #[cfg(feature = "iface-backbone")]
            backbone_peer_pool_candidates: Vec::new(),
            #[cfg(feature = "iface-backbone")]
            configured_client_targets: Vec::new(),
        },
    };
    let registry =
        registry.unwrap_or_else(crate::interface::registry::InterfaceRegistry::with_builtins);
    for iface_config in interfaces {
        starter.start(&registry, iface_config)?;
    }
    Ok(starter.started)
}

/// Starts configured interfaces one at a time, collecting what the later
/// startup steps need of them.
struct InterfaceStarter<'a> {
    driver: &'a mut Driver,
    tx: &'a EventSender,
    next_dynamic_id: &'a Arc<AtomicU64>,
    config: &'a NodeConfig,
    initial_managed_ids: HashMap<String, rns_core::transport::types::InterfaceId>,
    started: StartedInterfaces,
}

/// A configured interface that started, as its registration needs it once
/// its factory consumed its config data.
struct Registration<'c> {
    name: &'c str,
    type_name: &'c str,
    managed_id: Option<rns_core::transport::types::InterfaceId>,
    ifac: Option<&'c IfacConfig>,
    ifac_state: Option<crate::ifac::IfacState>,
    ifac_runtime: crate::driver::IfacRuntimeConfig,
    stamp_costs: rns_core::transport::types::InterfaceStampCosts,
    hop_limiter: Option<u8>,
    display: ConfiguredDisplay,
}

impl InterfaceStarter<'_> {
    /// Start one configured interface and register it with the driver.
    fn start(
        &mut self,
        registry: &crate::interface::registry::InterfaceRegistry,
        iface_config: InterfaceConfig,
    ) -> io::Result<()> {
        let transport_enabled = self.config.transport_enabled;
        self.driver
            .set_interface_announce_limits(&iface_config.name, iface_config.announce_limits);
        let managed_id = self.initial_managed_ids.get(&iface_config.name).copied();
        #[cfg(runtime_config_ifaces)]
        register_interface_runtime(
            self.driver,
            &iface_config,
            #[cfg(any(feature = "iface-tcp", feature = "iface-backbone"))]
            transport_enabled,
        );
        #[cfg(feature = "iface-backbone")]
        self.started
            .configured_client_targets
            .extend(configured_client_target(&iface_config));

        let factory = match registry.get(&iface_config.type_name) {
            Some(f) => f,
            None => {
                log::warn!(
                    "No factory registered for interface type '{}'",
                    iface_config.type_name
                );
                return Ok(());
            }
        };

        let ifac_state = derive_ifac_state(iface_config.ifac.as_ref(), &iface_config.name)?;
        let ifac_runtime =
            ifac_runtime_from_config(iface_config.ifac.as_ref(), factory.default_ifac_size());

        #[cfg(feature = "iface-backbone")]
        if self.add_backbone_peer_pool_candidate(&iface_config, &ifac_runtime, ifac_state.is_some())
        {
            return Ok(());
        }

        let ctx = crate::interface::StartContext {
            tx: self.tx.clone(),
            next_dynamic_id: self.next_dynamic_id.clone(),
            mode: iface_config.mode,
            gravity: iface_config.gravity,
            hop_limiter: iface_config.hop_limiter,
            recursive_prs: iface_config.recursive_prs,
            announces_from_internal: iface_config.announces_from_internal,
            announces_to_internal: iface_config.announces_to_internal,
            ingress_control: iface_config.ingress_control,
            stamp_costs: iface_config.stamp_costs,
            announce_limits: iface_config.announce_limits,
            ifac: ifac_state.clone(),
            underlay_mark: self.config.underlay_mark,
        };

        let display = ConfiguredDisplay::of(&iface_config, ifac_state.as_ref());
        let result = match factory.start(iface_config.config_data, ctx) {
            Ok(r) => r,
            Err(e) => {
                if self.config.panic_on_interface_error {
                    return Err(e);
                }
                log::error!(
                    "Interface '{}' ({}) failed to start: {}",
                    iface_config.name,
                    iface_config.type_name,
                    e
                );
                return Ok(());
            }
        };

        if let Some(ref disc) = iface_config.discovery {
            self.started
                .discoverable
                .push(discoverable_interface_from_config(
                    &iface_config.name,
                    disc,
                    transport_enabled,
                    iface_config.ifac.as_ref(),
                ));
        }

        self.register(
            result,
            Registration {
                name: &iface_config.name,
                type_name: &iface_config.type_name,
                managed_id,
                ifac: iface_config.ifac.as_ref(),
                ifac_state,
                ifac_runtime,
                stamp_costs: iface_config.stamp_costs,
                hop_limiter: iface_config.hop_limiter,
                display,
            },
        )
    }

    /// Leave a Backbone interface with a target host to the peer pool, when
    /// the pool runs, instead of starting it; whether it was left to it.
    #[cfg(feature = "iface-backbone")]
    fn add_backbone_peer_pool_candidate(
        &mut self,
        iface_config: &InterfaceConfig,
        ifac_runtime: &crate::driver::IfacRuntimeConfig,
        ifac_enabled: bool,
    ) -> bool {
        if self.config.backbone_peer_pool.is_none() || iface_config.type_name != "BackboneInterface"
        {
            return false;
        }
        let Some(mode) = iface_config
            .config_data
            .as_any()
            .downcast_ref::<BackboneMode>()
        else {
            return false;
        };
        let Some(client) = client_config_from_mode(mode) else {
            return false;
        };
        let priority = client_priority_from_mode(mode)
            .unwrap_or(crate::driver::BACKBONE_PEER_POOL_CONFIGURED_DEFAULT_PRIORITY);
        self.started
            .backbone_peer_pool_candidates
            .push(BackbonePeerPoolCandidateConfig {
                client,
                mode: iface_config.mode,
                gravity: iface_config.gravity,
                recursive_prs: iface_config.recursive_prs,
                announces_from_internal: iface_config.announces_from_internal,
                announces_to_internal: iface_config.announces_to_internal,
                ingress_control: iface_config.ingress_control,
                stamp_costs: iface_config.stamp_costs,
                ifac_runtime: ifac_runtime.clone(),
                ifac_enabled,
                // Upstream starts a BackboneClientInterface for a Backbone
                // interface with a target host.
                interface_type_name: "BackboneClientInterface".to_string(),
                source: crate::driver::BackbonePeerPoolCandidateSource::Configured,
                priority,
                discovery: None,
            });
        if let Some(ref disc) = iface_config.discovery {
            self.started
                .discoverable
                .push(discoverable_interface_from_config(
                    &iface_config.name,
                    disc,
                    self.config.transport_enabled,
                    iface_config.ifac.as_ref(),
                ));
        }
        true
    }

    /// Record a started interface among the managed ones, under the id
    /// interface management gave it.
    fn insert_managed(
        &mut self,
        name: &str,
        type_name: &str,
        parent_id: rns_core::transport::types::InterfaceId,
        control: Option<crate::interface::ListenerControl>,
        static_ids: Vec<rns_core::transport::types::InterfaceId>,
    ) {
        self.driver.managed_interfaces.insert(
            name.to_string(),
            crate::driver::ManagedInterface {
                parent_id,
                type_name: type_name.to_string(),
                control,
                static_ids,
            },
        );
    }

    /// Register what an interface's factory started: its writers, its
    /// listener control, and its entry among the managed interfaces.
    fn register(
        &mut self,
        result: crate::interface::StartResult,
        registration: Registration<'_>,
    ) -> io::Result<()> {
        let Registration {
            name,
            type_name,
            managed_id,
            ifac,
            mut ifac_state,
            ifac_runtime,
            stamp_costs,
            hop_limiter,
            mut display,
        } = registration;
        let queue_capacity = self.config.interface_writer_queue_capacity;
        match result {
            crate::interface::StartResult::Simple {
                id,
                info,
                writer,
                interface_type_name,
                control,
            } => {
                let managed_control = control.clone();
                if let Some(control) = control {
                    self.driver.register_listener_control(control);
                }
                if let Some(parent_id) = managed_id {
                    self.insert_managed(name, type_name, parent_id, managed_control, vec![id]);
                } else {
                    self.driver
                        .unmanaged_static_interfaces
                        .insert(id, managed_control);
                }
                register_started_interface(StartedInterface {
                    driver: self.driver,
                    tx: self.tx,
                    queue_capacity,
                    id,
                    info,
                    writer,
                    interface_type_name,
                    ifac_state,
                    ifac_runtime: &ifac_runtime,
                    stamp_costs,
                    hop_limiter,
                    display_name: display.interface.take(),
                });
            }
            crate::interface::StartResult::Listener { control } => {
                // Listener-type interface (TcpServer, Auto, I2P, etc.)
                // registers dynamic interfaces via InterfaceUp events.
                display.register_listener(self.driver);
                let managed_control = control.clone();
                if let Some(control) = control {
                    self.driver.register_listener_control(control);
                }
                if let Some(parent_id) = managed_id {
                    self.insert_managed(name, type_name, parent_id, managed_control, Vec::new());
                }
            }
            crate::interface::StartResult::Multi {
                subinterfaces: subs,
                control,
            } => {
                let managed_control = control.clone();
                if let Some(control) = control {
                    self.driver.register_listener_control(control);
                }
                let static_ids: Vec<_> = subs.iter().map(|sub| sub.id).collect();
                display.register_subinterfaces(self.driver, static_ids.clone());
                if let Some(parent_id) = managed_id {
                    self.insert_managed(name, type_name, parent_id, managed_control, static_ids);
                }
                let mut first = true;
                for sub in subs {
                    let sub_ifac = if first {
                        first = false;
                        ifac_state.take()
                    } else {
                        derive_ifac_state(ifac, &sub.info.name)?
                    };
                    let display_name = subinterface_display_name(name, &sub);
                    register_started_interface(StartedInterface {
                        driver: self.driver,
                        tx: self.tx,
                        queue_capacity,
                        id: sub.id,
                        info: sub.info,
                        writer: sub.writer,
                        interface_type_name: sub.interface_type_name,
                        ifac_state: sub_ifac,
                        ifac_runtime: &ifac_runtime,
                        stamp_costs,
                        hop_limiter,
                        display_name,
                    });
                }
            }
        }
        Ok(())
    }
}
