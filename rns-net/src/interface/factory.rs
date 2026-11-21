//! Interface factories and what they are given and return.

use std::any::Any;
use std::collections::HashMap;
use std::io;
use std::sync::atomic::AtomicU64;
use std::sync::Arc;

use super::{ListenerControl, Writer};
use crate::event::EventSender;
use crate::ifac::IfacState;
use rns_core::transport::types::{InterfaceId, InterfaceInfo};

/// Result of starting an interface via a factory.
// Boxing `Simple` would change the published factory result representation.
#[allow(clippy::large_enum_variant)]
pub enum StartResult {
    /// One writer, registered immediately (TcpClient, Udp, Serial, etc.)
    Simple {
        /// Interface ID.
        id: InterfaceId,
        /// Transport-level description of the interface.
        info: InterfaceInfo,
        /// Writer for the interface.
        writer: Box<dyn Writer>,
        /// Interface type name, e.g. "TCPClientInterface".
        interface_type_name: String,
        /// Stop handle for the interface's threads, if it has any.
        control: Option<ListenerControl>,
    },
    /// Spawns a listener; dynamic interfaces arrive via Event::InterfaceUp (TcpServer, Auto, I2P, etc.)
    Listener {
        /// Stop handle for the listener's threads, if it has any.
        control: Option<ListenerControl>,
    },
    /// Multiple subinterfaces from one config (RNode).
    Multi {
        /// Subinterfaces to register.
        subinterfaces: Vec<SubInterface>,
        /// Stop handle shared by the subinterfaces' threads, if any.
        control: Option<ListenerControl>,
    },
}

/// A single subinterface returned from a multi-interface factory.
pub struct SubInterface {
    /// Interface ID.
    pub id: InterfaceId,
    /// Transport-level description of the subinterface.
    pub info: InterfaceInfo,
    /// Writer for the subinterface.
    pub writer: Box<dyn Writer>,
    /// Interface type name, e.g. "RNodeMultiInterface".
    pub interface_type_name: String,
}

/// Context passed to [`InterfaceFactory::start()`].
pub struct StartContext {
    /// Sender for events to the driver.
    pub tx: EventSender,
    /// Counter that dynamically spawned interfaces take their IDs from.
    pub next_dynamic_id: Arc<AtomicU64>,
    /// Interface mode, one of the `constants::MODE_*` values.
    pub mode: u8,
    /// Signed interface preference used by path selection.
    pub gravity: i64,
    /// The interface's own `hop_limiter` (upstream bb63dd44). TCP server,
    /// Backbone, I2P and Weave peers inherit it.
    pub hop_limiter: Option<u8>,
    /// Upstream `recursive_prs` option of the interface.
    pub recursive_prs: bool,
    /// Upstream `announces_from_internal` option of the interface.
    pub announces_from_internal: bool,
    /// Upstream `announces_to_internal` option of the interface.
    pub announces_to_internal: Option<bool>,
    /// Ingress control settings of the interface.
    pub ingress_control: rns_core::transport::types::IngressControlConfig,
    /// Per-interface stamp costs, inherited by spawned interfaces.
    pub stamp_costs: rns_core::transport::types::InterfaceStampCosts,
    /// Per-interface announce rate and cap options, inherited by spawned
    /// interfaces.
    pub announce_limits: crate::node::InterfaceAnnounceLimits,
    /// IFAC state, if access codes are enabled.
    pub ifac: Option<IfacState>,
    /// Linux `SO_MARK` value applied to IP underlay sockets before connect.
    pub underlay_mark: Option<u32>,
}

/// A start context with default options, for factory tests.
#[cfg(all(test, any(feature = "iface-tcp", feature = "iface-backbone")))]
pub(crate) fn test_start_context(tx: EventSender) -> StartContext {
    StartContext {
        tx,
        next_dynamic_id: Arc::new(AtomicU64::new(1000)),
        mode: rns_core::constants::MODE_FULL,
        gravity: 0,
        hop_limiter: None,
        recursive_prs: false,
        announces_from_internal: true,
        announces_to_internal: None,
        ingress_control: rns_core::transport::types::IngressControlConfig::enabled(),
        stamp_costs: Default::default(),
        announce_limits: Default::default(),
        ifac: None,
        underlay_mark: None,
    }
}

/// Opaque interface config data. Each factory downcasts to its concrete type.
pub trait InterfaceConfigData: Send + Any {
    /// Borrow as [`Any`] for downcasting.
    fn as_any(&self) -> &dyn Any;
    /// Convert into a boxed [`Any`] for downcasting.
    fn into_any(self: Box<Self>) -> Box<dyn Any>;
}

/// A parsed interface config of one of the types the node reads after
/// parsing (for display names, runtime settings and auto-connects), so those
/// readers match on it instead of downcasting each type in turn.
#[derive(Clone, Copy)]
pub(crate) enum KnownConfig<'a> {
    /// A `TCPClientInterface`.
    #[cfg(feature = "iface-tcp")]
    TcpClient(&'a super::tcp::TcpClientConfig),
    /// A `TCPServerInterface`.
    #[cfg(feature = "iface-tcp")]
    TcpServer(&'a super::tcp_server::TcpServerConfig),
    /// A `UDPInterface`.
    #[cfg(feature = "iface-udp")]
    Udp(&'a super::udp::UdpConfig),
    /// An `AutoInterface`.
    #[cfg(feature = "iface-auto")]
    Auto(&'a super::auto::AutoConfig),
    /// An `I2PInterface`.
    #[cfg(feature = "iface-i2p")]
    I2p(&'a super::i2p::I2pConfig),
    /// A `PipeInterface`.
    #[cfg(feature = "iface-pipe")]
    Pipe(&'a super::pipe::PipeConfig),
    /// An `RNodeInterface` or `RNodeMultiInterface`.
    #[cfg(feature = "iface-rnode")]
    RNode(&'a super::rnode::RNodeConfig),
    /// A `BackboneInterface`, listening or connecting.
    #[cfg(feature = "iface-backbone")]
    Backbone(&'a super::backbone::BackboneMode),
    /// A `LocalClientInterface`.
    #[cfg(feature = "iface-local")]
    LocalClient(&'a super::local::LocalClientConfig),
    /// Any other config.
    Other(std::marker::PhantomData<&'a ()>),
}

impl dyn InterfaceConfigData {
    /// This config as one of the [`KnownConfig`] types, if it is one.
    pub(crate) fn known(&self) -> KnownConfig<'_> {
        let any = self.as_any();
        #[cfg(feature = "iface-tcp")]
        if let Some(config) = any.downcast_ref() {
            return KnownConfig::TcpClient(config);
        }
        #[cfg(feature = "iface-tcp")]
        if let Some(config) = any.downcast_ref() {
            return KnownConfig::TcpServer(config);
        }
        #[cfg(feature = "iface-udp")]
        if let Some(config) = any.downcast_ref() {
            return KnownConfig::Udp(config);
        }
        #[cfg(feature = "iface-auto")]
        if let Some(config) = any.downcast_ref() {
            return KnownConfig::Auto(config);
        }
        #[cfg(feature = "iface-i2p")]
        if let Some(config) = any.downcast_ref() {
            return KnownConfig::I2p(config);
        }
        #[cfg(feature = "iface-pipe")]
        if let Some(config) = any.downcast_ref() {
            return KnownConfig::Pipe(config);
        }
        #[cfg(feature = "iface-rnode")]
        if let Some(config) = any.downcast_ref() {
            return KnownConfig::RNode(config);
        }
        #[cfg(feature = "iface-backbone")]
        if let Some(config) = any.downcast_ref() {
            return KnownConfig::Backbone(config);
        }
        #[cfg(feature = "iface-local")]
        if let Some(config) = any.downcast_ref() {
            return KnownConfig::LocalClient(config);
        }
        let _ = any;
        KnownConfig::Other(std::marker::PhantomData)
    }

    /// Take this config back as `T`, the config type of the factory that
    /// parsed it, as that factory starts its interface.
    #[cfg(any(
        feature = "iface-auto",
        feature = "iface-i2p",
        feature = "iface-kiss",
        feature = "iface-local",
        feature = "iface-pipe",
        feature = "iface-rnode",
        feature = "iface-serial",
        feature = "iface-tcp",
        feature = "iface-udp"
    ))]
    pub(crate) fn into_own<T: Any>(self: Box<Self>) -> io::Result<T> {
        self.into_any()
            .downcast::<T>()
            .map(|config| *config)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "wrong config type"))
    }
}

/// ConfigObj section passed to factories that need nested `[[[sections]]]`.
pub struct ConfigSection<'a> {
    /// Key-value parameters of the section.
    pub params: &'a HashMap<String, String>,
    /// Nested subsections.
    pub children: &'a [crate::config::ParsedSubinterface],
}

/// Settings a listener copies from its own interface to each peer interface
/// it spawns.
#[derive(Debug, Clone)]
pub struct DynamicInterfaceTemplate {
    /// ID of the spawning interface.
    pub parent_id: InterfaceId,
    /// Interface type name given to spawned interfaces.
    pub interface_type: String,
    /// IFAC state, if access codes are enabled.
    pub ifac: Option<IfacState>,
    /// Interface mode, one of the `constants::MODE_*` values.
    pub mode: u8,
    /// Signed interface preference used by path selection.
    pub gravity: i64,
    /// The parent's `hop_limiter`, for the peer types that inherit it
    /// upstream (bb63dd44); `None` for the others.
    pub hop_limiter: Option<u8>,
    /// Upstream `recursive_prs` option of the parent.
    pub recursive_prs: bool,
    /// Upstream `announces_from_internal` option of the parent.
    pub announces_from_internal: bool,
    /// Upstream `announces_to_internal` option of the parent.
    pub announces_to_internal: Option<bool>,
    /// Per-interface stamp costs of the parent.
    pub stamp_costs: rns_core::transport::types::InterfaceStampCosts,
    /// Announce rate and cap options of the parent.
    pub announce_limits: crate::node::InterfaceAnnounceLimits,
}

impl DynamicInterfaceTemplate {
    /// Build the registration for a spawned interface, applying the
    /// template's settings to `info`.
    pub fn registration(
        &self,
        mut info: InterfaceInfo,
    ) -> crate::event::DynamicInterfaceRegistration {
        info.mode = self.mode;
        info.gravity = self.gravity;
        info.hop_limiter = self.hop_limiter;
        info.recursive_prs = self.recursive_prs;
        info.announces_from_internal = self.announces_from_internal;
        info.announces_to_internal = self.announces_to_internal;
        info.stamp_costs = self.stamp_costs;
        self.announce_limits.apply(&mut info);
        crate::event::DynamicInterfaceRegistration {
            info,
            interface_type: self.interface_type.clone(),
            parent_id: self.parent_id,
            telemetry: crate::event::InterfaceTelemetry::default(),
            ifac: self.ifac.clone(),
            display_name: None,
            short_name: None,
            reconnecting: false,
        }
    }
}

impl<T: Send + 'static> InterfaceConfigData for T {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn into_any(self: Box<Self>) -> Box<dyn Any> {
        self
    }
}

/// Why an interface section could not be turned into an interface config.
/// Its `Display` is the message logged for the section.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InterfaceConfigError {
    /// A required key is absent. Displays as `<section> requires 'a'`, or
    /// `'a' or 'b'` when any of several keys would do.
    MissingKey {
        /// What requires the key, e.g. `PipeInterface` or `subinterface 'A'`.
        section: String,
        /// The keys, any one of which is required.
        keys: &'static [&'static str],
    },
    /// A key has a value the interface cannot use.
    InvalidValue {
        /// The key.
        key: &'static str,
        /// What is wrong with it, naming the key and usually the value.
        message: String,
    },
    /// The section as a whole cannot be used.
    Invalid(String),
}

impl InterfaceConfigError {
    /// A missing-key error for the interface type or section `section`.
    pub fn missing(section: impl Into<String>, keys: &'static [&'static str]) -> Self {
        Self::MissingKey {
            section: section.into(),
            keys,
        }
    }

    /// An invalid-value error for `key`.
    pub fn invalid_value(key: &'static str, message: impl Into<String>) -> Self {
        Self::InvalidValue {
            key,
            message: message.into(),
        }
    }
}

impl std::fmt::Display for InterfaceConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingKey { section, keys } => {
                write!(f, "{section} requires ")?;
                for (index, key) in keys.iter().enumerate() {
                    if index > 0 {
                        f.write_str(" or ")?;
                    }
                    write!(f, "'{key}'")?;
                }
                Ok(())
            }
            Self::InvalidValue { message, .. } | Self::Invalid(message) => f.write_str(message),
        }
    }
}

impl std::error::Error for InterfaceConfigError {}

/// Factory that can parse config and start an interface type.
pub trait InterfaceFactory: Send + Sync {
    /// Config-file type name, e.g. "TCPClientInterface".
    fn type_name(&self) -> &str;

    /// Default IFAC size (bytes). 8 for serial/kiss/rnode, 16 for others.
    fn default_ifac_size(&self) -> usize {
        16
    }

    /// Parse from key-value params (config file or external).
    fn parse_config(
        &self,
        name: &str,
        id: InterfaceId,
        params: &HashMap<String, String>,
    ) -> Result<Box<dyn InterfaceConfigData>, InterfaceConfigError>;

    /// Parse a complete ConfigObj interface section. Flat factories inherit
    /// the compatibility default; multi-interface factories can inspect children.
    fn parse_config_section(
        &self,
        name: &str,
        id: InterfaceId,
        section: ConfigSection<'_>,
    ) -> Result<Box<dyn InterfaceConfigData>, InterfaceConfigError> {
        self.parse_config(name, id, section.params)
    }

    /// Start the interface from parsed config.
    fn start(
        &self,
        config: Box<dyn InterfaceConfigData>,
        ctx: StartContext,
    ) -> io::Result<StartResult>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use rns_core::constants;

    #[test]
    fn dynamic_registration_inherits_announces_to_internal() {
        let template = DynamicInterfaceTemplate {
            parent_id: InterfaceId(7),
            interface_type: "dynamic-test".into(),
            ifac: None,
            mode: constants::MODE_GATEWAY,
            gravity: -3,
            hop_limiter: Some(9),
            recursive_prs: true,
            announces_from_internal: false,
            announces_to_internal: Some(true),
            stamp_costs: rns_core::transport::types::InterfaceStampCosts {
                destination_cost: Some(rns_core::stamp::StampCost::from_whole(30)),
                pr_cost: None,
            },
            announce_limits: crate::node::InterfaceAnnounceLimits {
                rate_target: Some(600.0),
                rate_penalty: Some(60.0),
                cap: Some(0.05),
                ..Default::default()
            },
        };
        let info = InterfaceInfo {
            stamp_costs: Default::default(),
            id: InterfaceId(8),
            name: "child".into(),
            mode: constants::MODE_FULL,
            gravity: 0,
            recursive_prs: false,
            announces_from_internal: true,
            announces_to_internal: None,
            out_capable: true,
            in_capable: true,
            bitrate: None,
            airtime_profile: None,
            announce_rate_target: None,
            announce_rate_grace: 0,
            announce_rate_penalty: 0.0,
            announce_cap: constants::ANNOUNCE_CAP,
            is_local_client: false,
            wants_tunnel: false,
            shared_medium: false,
            hop_limiter: None,
            tunnel_id: None,
            mtu: constants::MTU as u32,
            mtu_upgradable: false,
            ingress_control: rns_core::transport::types::IngressControlConfig::disabled(),
            ia_freq: 0.0,
            ia_samples: 0,
            ip_freq: 0.0,
            op_freq: 0.0,
            op_samples: 0,
            started: 0.0,
        };

        let registration = template.registration(info);

        assert_eq!(registration.info.mode, constants::MODE_GATEWAY);
        assert_eq!(registration.info.gravity, -3);
        // Upstream bb63dd44: spawned peers take the parent's hop limiter.
        assert_eq!(registration.info.hop_limiter, Some(9));
        assert!(registration.info.recursive_prs);
        assert!(!registration.info.announces_from_internal);
        assert_eq!(registration.info.announces_to_internal, Some(true));
        assert_eq!(
            registration.info.stamp_costs.destination_cost,
            Some(rns_core::stamp::StampCost::from_whole(30))
        );
        // A listener's own announce options reach the clients it spawns.
        assert_eq!(registration.info.announce_rate_target, Some(600.0));
        assert_eq!(registration.info.announce_rate_grace, 0);
        assert_eq!(registration.info.announce_rate_penalty, 60.0);
        assert_eq!(registration.info.announce_cap, 0.05);
    }
}
