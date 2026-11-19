//! Discovery settings of backbone and TCP server interfaces, which the
//! driver shares with them and keeps in step.

use super::*;

#[cfg(feature = "iface-backbone")]
#[derive(Debug, Clone)]
pub(crate) struct BackboneDiscoveryRuntime {
    pub(crate) discoverable: bool,
    pub(crate) config: crate::discovery::DiscoveryConfig,
    pub(crate) transport_enabled: bool,
    pub(crate) ifac_netname: Option<String>,
    pub(crate) ifac_netkey: Option<String>,
}

#[cfg(feature = "iface-backbone")]
#[derive(Debug, Clone)]
pub(crate) struct BackboneDiscoveryRuntimeHandle {
    pub(crate) interface_name: String,
    pub(crate) current: BackboneDiscoveryRuntime,
    pub(crate) startup: BackboneDiscoveryRuntime,
}

#[cfg(feature = "iface-tcp")]
#[derive(Debug, Clone)]
pub(crate) struct TcpServerDiscoveryRuntime {
    pub(crate) discoverable: bool,
    pub(crate) config: crate::discovery::DiscoveryConfig,
    pub(crate) transport_enabled: bool,
    pub(crate) ifac_netname: Option<String>,
    pub(crate) ifac_netkey: Option<String>,
}

#[cfg(feature = "iface-tcp")]
#[derive(Debug, Clone)]
pub(crate) struct TcpServerDiscoveryRuntimeHandle {
    pub(crate) interface_name: String,
    pub(crate) current: TcpServerDiscoveryRuntime,
    pub(crate) startup: TcpServerDiscoveryRuntime,
}

#[cfg(feature = "iface-backbone")]
impl BackboneDiscoveryRuntimeHandle {
    pub(crate) fn from_parts(
        interface_name: String,
        startup_config: crate::discovery::DiscoveryConfig,
        transport_enabled: bool,
        ifac_netname: Option<String>,
        ifac_netkey: Option<String>,
        discoverable: bool,
    ) -> Self {
        let startup = BackboneDiscoveryRuntime {
            discoverable,
            config: startup_config,
            transport_enabled,
            ifac_netname,
            ifac_netkey,
        };
        Self {
            interface_name,
            current: startup.clone(),
            startup,
        }
    }
}

#[cfg(feature = "iface-tcp")]
impl TcpServerDiscoveryRuntimeHandle {
    pub(crate) fn from_parts(
        interface_name: String,
        startup_config: crate::discovery::DiscoveryConfig,
        transport_enabled: bool,
        ifac_netname: Option<String>,
        ifac_netkey: Option<String>,
        discoverable: bool,
    ) -> Self {
        let startup = TcpServerDiscoveryRuntime {
            discoverable,
            config: startup_config,
            transport_enabled,
            ifac_netname,
            ifac_netkey,
        };
        Self {
            interface_name,
            current: startup.clone(),
            startup,
        }
    }
}

impl Driver {
    #[cfg(feature = "iface-backbone")]
    pub(super) fn make_discoverable_interface(
        runtime: &BackboneDiscoveryRuntimeHandle,
    ) -> crate::discovery::DiscoverableInterface {
        crate::discovery::DiscoverableInterface {
            interface_name: runtime.interface_name.clone(),
            config: runtime.current.config.clone(),
            transport_enabled: runtime.current.transport_enabled,
            ifac_netname: runtime.current.ifac_netname.clone(),
            ifac_netkey: runtime.current.ifac_netkey.clone(),
        }
    }

    #[cfg(feature = "iface-backbone")]
    pub(super) fn sync_backbone_discovery_runtime(
        &mut self,
        interface_name: &str,
    ) -> Result<(), RuntimeConfigError> {
        let handle = self
            .backbone_discovery_runtime
            .get(interface_name)
            .ok_or(RuntimeConfigError {
                code: RuntimeConfigErrorCode::NotFound,
                message: format!("backbone interface '{}' not found", interface_name),
            })?
            .clone();

        if handle.current.discoverable {
            let iface = Self::make_discoverable_interface(&handle);
            if let Some(announcer) = self.interface_announcer.as_mut() {
                announcer.upsert_interface(iface);
            } else if let Some(identity) = self.transport_identity.as_ref() {
                self.interface_announcer =
                    Some(self.new_interface_announcer(*identity.hash(), vec![iface]));
            }
        } else if let Some(announcer) = self.interface_announcer.as_mut() {
            announcer.remove_interface(interface_name);
            if announcer.is_empty() {
                self.interface_announcer = None;
            }
        }

        Ok(())
    }

    #[cfg(feature = "iface-tcp")]
    pub(super) fn make_tcp_server_discoverable_interface(
        runtime: &TcpServerDiscoveryRuntimeHandle,
    ) -> crate::discovery::DiscoverableInterface {
        crate::discovery::DiscoverableInterface {
            interface_name: runtime.interface_name.clone(),
            config: runtime.current.config.clone(),
            transport_enabled: runtime.current.transport_enabled,
            ifac_netname: runtime.current.ifac_netname.clone(),
            ifac_netkey: runtime.current.ifac_netkey.clone(),
        }
    }

    #[cfg(feature = "iface-tcp")]
    pub(super) fn sync_tcp_server_discovery_runtime(
        &mut self,
        interface_name: &str,
    ) -> Result<(), RuntimeConfigError> {
        let handle = self
            .tcp_server_discovery_runtime
            .get(interface_name)
            .ok_or(RuntimeConfigError {
                code: RuntimeConfigErrorCode::NotFound,
                message: format!("tcp server interface '{}' not found", interface_name),
            })?
            .clone();

        if handle.current.discoverable {
            let iface = Self::make_tcp_server_discoverable_interface(&handle);
            if let Some(announcer) = self.interface_announcer.as_mut() {
                announcer.upsert_interface(iface);
            } else if let Some(identity) = self.transport_identity.as_ref() {
                self.interface_announcer =
                    Some(self.new_interface_announcer(*identity.hash(), vec![iface]));
            }
        } else if let Some(announcer) = self.interface_announcer.as_mut() {
            announcer.remove_interface(interface_name);
            if announcer.is_empty() {
                self.interface_announcer = None;
            }
        }

        Ok(())
    }
}
