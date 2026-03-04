//! Interface factory registry.
//!
//! Holds a set of [`InterfaceFactory`] implementations keyed by their
//! config-file type name (e.g. "TCPClientInterface").

use std::collections::HashMap;

use super::InterfaceFactory;

/// Registry of interface factories keyed by type name.
pub struct InterfaceRegistry {
    factories: HashMap<String, Box<dyn InterfaceFactory>>,
}

impl InterfaceRegistry {
    /// Create an empty registry.
    pub fn new() -> Self {
        InterfaceRegistry {
            factories: HashMap::new(),
        }
    }

    /// Register a factory. The factory's `type_name()` is used as the key.
    pub fn register(&mut self, factory: Box<dyn InterfaceFactory>) {
        let name = factory.type_name().to_string();
        self.factories.insert(name, factory);
    }

    /// Look up a factory by config-file type name.
    pub fn get(&self, type_name: &str) -> Option<&dyn InterfaceFactory> {
        self.factories.get(type_name).map(|f| f.as_ref())
    }

    /// Create a registry pre-populated with all built-in interface types.
    pub fn with_builtins() -> Self {
        let mut reg = Self::new();
        #[cfg(feature = "iface-tcp")]
        {
            reg.register(Box::new(super::tcp::TcpClientFactory));
            reg.register(Box::new(super::tcp_server::TcpServerFactory));
        }
        #[cfg(feature = "iface-udp")]
        reg.register(Box::new(super::udp::UdpFactory));
        #[cfg(feature = "iface-serial")]
        reg.register(Box::new(super::serial_iface::SerialFactory));
        #[cfg(feature = "iface-kiss")]
        reg.register(Box::new(super::kiss_iface::KissFactory));
        #[cfg(feature = "iface-pipe")]
        reg.register(Box::new(super::pipe::PipeFactory));
        #[cfg(feature = "iface-local")]
        {
            reg.register(Box::new(super::local::LocalServerFactory));
            reg.register(Box::new(super::local::LocalClientFactory));
        }
        #[cfg(feature = "iface-backbone")]
        reg.register(Box::new(super::backbone::BackboneInterfaceFactory));
        #[cfg(feature = "iface-auto")]
        reg.register(Box::new(super::auto::AutoFactory));
        #[cfg(feature = "iface-i2p")]
        reg.register(Box::new(super::i2p::I2pFactory));
        #[cfg(feature = "iface-rnode")]
        reg.register(Box::new(super::rnode::RNodeFactory));
        reg
    }
}

impl Default for InterfaceRegistry {
    fn default() -> Self {
        Self::new()
    }
}
