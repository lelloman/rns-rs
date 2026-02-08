//! RnsNode: high-level lifecycle management.
//!
//! Wires together the driver, interfaces, and timer thread.

use std::io;
use std::thread::{self, JoinHandle};
use std::time::Duration;

use rns_core::transport::types::{InterfaceInfo, TransportConfig};
use rns_crypto::identity::Identity;
use rns_crypto::OsRng;

use crate::driver::{Callbacks, Driver};
use crate::event::{self, Event, EventSender};
use crate::interface::tcp::TcpClientConfig;
use crate::interface::InterfaceEntry;

/// Top-level node configuration.
pub struct NodeConfig {
    pub transport_enabled: bool,
    pub identity: Option<Identity>,
    pub interfaces: Vec<InterfaceConfig>,
}

/// Interface configuration variants.
pub enum InterfaceConfig {
    TcpClient(TcpClientConfig),
}

/// A running RNS node.
pub struct RnsNode {
    tx: EventSender,
    driver_handle: Option<JoinHandle<()>>,
}

impl RnsNode {
    /// Start the node. Connects all interfaces, starts driver and timer threads.
    pub fn start(config: NodeConfig, callbacks: Box<dyn Callbacks>) -> io::Result<Self> {
        let identity = config
            .identity
            .unwrap_or_else(|| Identity::new(&mut OsRng));

        let transport_config = TransportConfig {
            transport_enabled: config.transport_enabled,
            identity_hash: Some(*identity.hash()),
        };

        let (tx, rx) = event::channel();
        let mut driver = Driver::new(transport_config, rx, callbacks);

        // Start each interface
        for iface_config in config.interfaces {
            match iface_config {
                InterfaceConfig::TcpClient(tcp_config) => {
                    let id = tcp_config.interface_id;
                    let info = InterfaceInfo {
                        id,
                        mode: rns_core::constants::MODE_FULL,
                        out_capable: true,
                        in_capable: true,
                        bitrate: None,
                        announce_rate_target: None,
                        announce_rate_grace: 0,
                        announce_rate_penalty: 0.0,
                    };

                    let writer =
                        crate::interface::tcp::start(tcp_config, tx.clone())?;

                    driver.engine.register_interface(info.clone());
                    driver.interfaces.insert(
                        id,
                        InterfaceEntry {
                            id,
                            info,
                            writer,
                            online: false, // InterfaceUp event will set this
                        },
                    );
                }
            }
        }

        // Spawn timer thread
        let timer_tx = tx.clone();
        thread::Builder::new()
            .name("rns-timer".into())
            .spawn(move || {
                loop {
                    thread::sleep(Duration::from_secs(1));
                    if timer_tx.send(Event::Tick).is_err() {
                        break; // receiver dropped
                    }
                }
            })?;

        // Spawn driver thread
        let driver_handle = thread::Builder::new()
            .name("rns-driver".into())
            .spawn(move || {
                driver.run();
            })?;

        Ok(RnsNode {
            tx,
            driver_handle: Some(driver_handle),
        })
    }

    /// Shut down the node. Blocks until the driver thread exits.
    pub fn shutdown(mut self) {
        let _ = self.tx.send(Event::Shutdown);
        if let Some(handle) = self.driver_handle.take() {
            let _ = handle.join();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct NoopCallbacks;

    impl Callbacks for NoopCallbacks {
        fn on_announce(&mut self, _: [u8; 16], _: [u8; 16], _: [u8; 64], _: Option<Vec<u8>>, _: u8) {}
        fn on_path_updated(&mut self, _: [u8; 16], _: u8) {}
        fn on_local_delivery(&mut self, _: [u8; 16], _: Vec<u8>, _: [u8; 32]) {}
    }

    #[test]
    fn start_and_shutdown() {
        let node = RnsNode::start(
            NodeConfig {
                transport_enabled: false,
                identity: None,
                interfaces: vec![],
            },
            Box::new(NoopCallbacks),
        )
        .unwrap();
        node.shutdown();
    }

    #[test]
    fn start_with_identity() {
        let identity = Identity::new(&mut OsRng);
        let hash = *identity.hash();
        let node = RnsNode::start(
            NodeConfig {
                transport_enabled: true,
                identity: Some(identity),
                interfaces: vec![],
            },
            Box::new(NoopCallbacks),
        )
        .unwrap();
        // The identity hash should have been used
        let _ = hash;
        node.shutdown();
    }

    #[test]
    fn start_generates_identity() {
        let node = RnsNode::start(
            NodeConfig {
                transport_enabled: false,
                identity: None,
                interfaces: vec![],
            },
            Box::new(NoopCallbacks),
        )
        .unwrap();
        // Should not panic - identity was auto-generated
        node.shutdown();
    }
}
