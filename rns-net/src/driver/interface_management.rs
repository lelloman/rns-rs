use std::io;
use std::sync::atomic::Ordering;

use rns_core::transport::types::InterfaceId;

use super::{Driver, ManagedInterface};
use crate::event::InterfaceManagementOperation;
use crate::interface::{registry::InterfaceRegistry, StartContext, StartResult};
use crate::node::{
    derive_ifac_state, discoverable_interface_from_config, ifac_runtime_from_config,
    parse_managed_interface, register_started_interface, StartedInterface,
};

impl Driver {
    pub(crate) fn manage_interface(
        &mut self,
        operation: InterfaceManagementOperation,
        name: &str,
    ) -> Option<bool> {
        if self.interface_management.is_none() || self.is_draining() {
            return Some(false);
        }
        match operation {
            InterfaceManagementOperation::Attach => self.attach_interface(name),
            InterfaceManagementOperation::Detach => self.detach_interface(name),
            InterfaceManagementOperation::Reload => {
                if !self.managed_interfaces.contains_key(name) {
                    return None;
                }
                if self.detach_interface(name) == Some(true) {
                    self.attach_interface(name)
                } else {
                    Some(false)
                }
            }
        }
    }

    fn detach_interface(&mut self, name: &str) -> Option<bool> {
        let managed = self.managed_interfaces.get(name)?;
        if matches!(
            managed.type_name.as_str(),
            "I2PInterface" | "LocalClientInterface" | "LocalServerInterface"
        ) {
            return Some(false);
        }
        let managed = self.managed_interfaces.remove(name).expect("checked above");
        self.retired_interface_parents.insert(managed.parent_id);
        if let Some(control) = &managed.control {
            control.request_stop();
            self.listener_controls
                .retain(|candidate| !candidate.same_instance(control));
        }
        let child_ids: Vec<_> = self
            .dynamic_interface_parents
            .iter()
            .filter_map(|(id, parent)| (*parent == managed.parent_id).then_some(*id))
            .collect();
        for id in child_ids {
            self.handle_interface_down_event(id);
            self.traffic_samples.remove(&id);
        }
        for id in managed.static_ids {
            let entry_name = self
                .interfaces
                .get(&id)
                .map(|entry| entry.info.name.clone());
            if self.interfaces.contains_key(&id) {
                self.handle_interface_down_event(id);
                self.interfaces.remove(&id);
            }
            if let Some(entry_name) = entry_name {
                self.interface_runtime_defaults.remove(&entry_name);
                self.interface_ifac_runtime.remove(&entry_name);
                self.interface_ifac_runtime_defaults.remove(&entry_name);
            }
            self.event_tx.remove_interface(id);
            if self.engine.interface_info(&id).is_some() {
                self.engine.deregister_interface(id);
            }
            self.traffic_samples.remove(&id);
        }
        self.interface_runtime_defaults.remove(name);
        self.interface_ifac_runtime.remove(name);
        self.interface_ifac_runtime_defaults.remove(name);
        self.remove_managed_runtime(name);
        if let Some(announcer) = self.interface_announcer.as_mut() {
            announcer.remove_interface(name);
        }
        log::info!("Interface '{name}' was detached");
        Some(true)
    }

    fn attach_interface(&mut self, name: &str) -> Option<bool> {
        if self.managed_interfaces.contains_key(name)
            || self
                .interfaces
                .values()
                .any(|entry| entry.info.name == name)
        {
            return Some(false);
        }
        let management = self.interface_management.as_ref()?;
        let content = match std::fs::read_to_string(&management.config_file) {
            Ok(content) => content,
            Err(error) => {
                log::error!("cannot read interface config for '{name}': {error}");
                return None;
            }
        };
        let parsed = match crate::config::parse(&content) {
            Ok(parsed) => parsed,
            Err(error) => {
                log::error!("cannot parse interface config for '{name}': {error}");
                return None;
            }
        };
        let iface = parsed.interfaces.iter().find(|iface| iface.name == name)?;
        let registry = InterfaceRegistry::with_builtins();
        let reserved_ids = iface.subinterfaces.len().max(1) as u64;
        let id = InterfaceId(
            self.next_dynamic_interface_id
                .fetch_add(reserved_ids, Ordering::Relaxed),
        );
        let config =
            match parse_managed_interface(iface, &parsed, &management.storage_dir, id, &registry) {
                Ok(config) => config,
                Err(error) => {
                    log::error!("cannot attach interface '{name}': {error}");
                    return Some(false);
                }
            };
        match self.start_managed_interface(config, id, &registry) {
            Ok(()) => {
                log::info!("Interface '{name}' was attached");
                Some(true)
            }
            Err(error) => {
                log::error!("cannot attach interface '{name}': {error}");
                Some(false)
            }
        }
    }

    fn start_managed_interface(
        &mut self,
        config: crate::node::InterfaceConfig,
        parent_id: InterfaceId,
        registry: &InterfaceRegistry,
    ) -> io::Result<()> {
        let management = self
            .interface_management
            .as_ref()
            .expect("checked by manage_interface");
        let queue_capacity = management.queue_capacity;
        let transport_enabled = management.transport_enabled;
        let underlay_mark = management.underlay_mark;
        let factory = registry.get(&config.type_name).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "interface factory is unavailable",
            )
        })?;
        let mut ifac_state = derive_ifac_state(config.ifac.as_ref(), &config.name)?;
        let ifac_runtime =
            ifac_runtime_from_config(config.ifac.as_ref(), factory.default_ifac_size());
        self.register_managed_runtime(&config, transport_enabled);
        let ctx = StartContext {
            tx: self.event_tx.clone(),
            next_dynamic_id: self.next_dynamic_interface_id.clone(),
            mode: config.mode,
            gravity: config.gravity,
            recursive_prs: config.recursive_prs,
            announces_from_internal: config.announces_from_internal,
            announces_to_internal: config.announces_to_internal,
            ingress_control: config.ingress_control,
            ifac: ifac_state.clone(),
            underlay_mark,
        };
        let result = match factory.start(config.config_data, ctx) {
            Ok(result) => result,
            Err(error) => {
                self.remove_managed_runtime(&config.name);
                return Err(error);
            }
        };
        let tx = self.event_tx.clone();
        let (control, static_ids) = match result {
            StartResult::Simple {
                id,
                info,
                writer,
                interface_type_name,
                control,
            } => {
                register_started_interface(StartedInterface {
                    driver: self,
                    tx: &tx,
                    queue_capacity,
                    id,
                    info,
                    writer,
                    interface_type_name,
                    ifac_state,
                    ifac_runtime: &ifac_runtime,
                });
                (control, vec![id])
            }
            StartResult::Listener { control } => (control, Vec::new()),
            StartResult::Multi {
                subinterfaces,
                control,
            } => {
                let mut ids = Vec::with_capacity(subinterfaces.len());
                for sub in subinterfaces {
                    let sub_ifac = if ids.is_empty() {
                        ifac_state.take()
                    } else {
                        derive_ifac_state(config.ifac.as_ref(), &sub.info.name)?
                    };
                    ids.push(sub.id);
                    register_started_interface(StartedInterface {
                        driver: self,
                        tx: &tx,
                        queue_capacity,
                        id: sub.id,
                        info: sub.info,
                        writer: sub.writer,
                        interface_type_name: sub.interface_type_name,
                        ifac_state: sub_ifac,
                        ifac_runtime: &ifac_runtime,
                    });
                }
                (control, ids)
            }
        };
        if let Some(control) = &control {
            self.register_listener_control(control.clone());
        }
        if let Some(discovery) = config.discovery.as_ref() {
            let discoverable = discoverable_interface_from_config(
                &config.name,
                discovery,
                transport_enabled,
                config.ifac.as_ref(),
            );
            if let Some(announcer) = self.interface_announcer.as_mut() {
                announcer.upsert_interface(discoverable);
            } else if let Some(identity) = self.transport_identity.as_ref() {
                self.interface_announcer = Some(crate::discovery::InterfaceAnnouncer::new(
                    *identity.hash(),
                    vec![discoverable],
                ));
            }
        }
        self.managed_interfaces.insert(
            config.name,
            ManagedInterface {
                parent_id,
                type_name: config.type_name,
                control,
                static_ids,
            },
        );
        Ok(())
    }

    fn remove_managed_runtime(&mut self, name: &str) {
        #[cfg(feature = "iface-backbone")]
        {
            self.backbone_runtime.remove(name);
            self.backbone_peer_state.remove(name);
            self.backbone_client_runtime.remove(name);
            self.backbone_discovery_runtime.remove(name);
        }
        #[cfg(feature = "iface-tcp")]
        {
            self.tcp_client_runtime.remove(name);
            self.tcp_server_runtime.remove(name);
            self.tcp_server_discovery_runtime.remove(name);
        }
        #[cfg(feature = "iface-udp")]
        {
            self.udp_runtime.remove(name);
        }
        #[cfg(feature = "iface-auto")]
        {
            self.auto_runtime.remove(name);
        }
        #[cfg(feature = "iface-i2p")]
        {
            self.i2p_runtime.remove(name);
        }
        #[cfg(feature = "iface-pipe")]
        {
            self.pipe_runtime.remove(name);
        }
        #[cfg(feature = "iface-rnode")]
        {
            self.rnode_runtime.remove(name);
        }
    }

    fn register_managed_runtime(
        &mut self,
        config: &crate::node::InterfaceConfig,
        transport_enabled: bool,
    ) {
        #[cfg(feature = "iface-backbone")]
        if let Some(mode) = config
            .config_data
            .as_any()
            .downcast_ref::<crate::interface::backbone::BackboneMode>()
        {
            use crate::interface::backbone::{
                client_runtime_handle_from_mode, peer_state_handle_from_mode,
                runtime_handle_from_mode,
            };
            if let Some(handle) = runtime_handle_from_mode(mode) {
                self.register_backbone_runtime(handle);
            }
            if let Some(handle) = peer_state_handle_from_mode(mode) {
                self.register_backbone_peer_state(handle);
            }
            if let Some(handle) = client_runtime_handle_from_mode(mode) {
                self.register_backbone_client_runtime(handle);
            }
            if let Some(handle) = crate::node::backbone_discovery_runtime_from_interface(
                &config.name,
                mode,
                config.discovery.as_ref(),
                transport_enabled,
                config.ifac.as_ref(),
            ) {
                self.register_backbone_discovery_runtime(handle);
            }
        }
        #[cfg(feature = "iface-tcp")]
        {
            if let Some(value) = config
                .config_data
                .as_any()
                .downcast_ref::<crate::interface::tcp::TcpClientConfig>()
            {
                self.register_tcp_client_runtime(
                    crate::interface::tcp::tcp_client_runtime_handle_from_config(value),
                );
            }
            if let Some(value) = config
                .config_data
                .as_any()
                .downcast_ref::<crate::interface::tcp_server::TcpServerConfig>()
            {
                self.register_tcp_server_runtime(
                    crate::interface::tcp_server::runtime_handle_from_config(value),
                );
                self.register_tcp_server_discovery_runtime(
                    crate::node::tcp_server_discovery_runtime_from_interface(
                        &config.name,
                        value,
                        config.discovery.as_ref(),
                        transport_enabled,
                        config.ifac.as_ref(),
                    ),
                );
            }
        }
        #[cfg(feature = "iface-udp")]
        if let Some(value) = config
            .config_data
            .as_any()
            .downcast_ref::<crate::interface::udp::UdpConfig>()
        {
            self.register_udp_runtime(crate::interface::udp::udp_runtime_handle_from_config(value));
        }
        #[cfg(feature = "iface-auto")]
        if let Some(value) = config
            .config_data
            .as_any()
            .downcast_ref::<crate::interface::auto::AutoConfig>()
        {
            self.register_auto_runtime(crate::interface::auto::auto_runtime_handle_from_config(
                value,
            ));
        }
        #[cfg(feature = "iface-i2p")]
        if let Some(value) = config
            .config_data
            .as_any()
            .downcast_ref::<crate::interface::i2p::I2pConfig>()
        {
            self.register_i2p_runtime(crate::interface::i2p::i2p_runtime_handle_from_config(value));
        }
        #[cfg(feature = "iface-pipe")]
        if let Some(value) = config
            .config_data
            .as_any()
            .downcast_ref::<crate::interface::pipe::PipeConfig>()
        {
            self.register_pipe_runtime(crate::interface::pipe::pipe_runtime_handle_from_config(
                value,
            ));
        }
        #[cfg(feature = "iface-rnode")]
        if let Some(value) = config
            .config_data
            .as_any()
            .downcast_ref::<crate::interface::rnode::RNodeConfig>()
        {
            self.register_rnode_runtime(crate::interface::rnode::rnode_runtime_handle_from_config(
                value,
            ));
        }
    }
}
