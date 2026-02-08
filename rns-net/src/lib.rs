//! rns-net: Network node for Reticulum.
//!
//! Drives `rns-core::TransportEngine` with real TCP sockets and threads.
//! Connects to Python RNS TCP servers, receives HDLC-framed packets,
//! processes announces, and discovers paths.

pub mod hdlc;
pub mod event;
pub mod time;
pub mod interface;
pub mod driver;
pub mod node;

pub use driver::Callbacks;
pub use event::Event;
pub use node::{InterfaceConfig, NodeConfig, RnsNode};
pub use interface::tcp::TcpClientConfig;

// Re-export commonly used types from rns-core
pub use rns_core::transport::types::InterfaceId;
