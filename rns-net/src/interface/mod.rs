//! Network interface abstractions.

#[cfg(feature = "iface-auto")]
pub mod auto;
#[cfg(feature = "iface-kiss")]
pub mod ax25_kiss;
#[cfg(feature = "iface-backbone")]
pub mod backbone;
#[cfg(any(feature = "iface-rnode", feature = "iface-weave"))]
pub(crate) mod device_writer;
pub(crate) mod display;
#[cfg(feature = "iface-i2p")]
pub mod i2p;
#[cfg(feature = "iface-kiss")]
pub mod kiss_iface;
#[cfg(feature = "iface-local")]
pub mod local;
pub(crate) mod loop_writer;
#[cfg(feature = "iface-pipe")]
pub mod pipe;
pub mod registry;
#[cfg(feature = "iface-rnode")]
pub mod rnode;
#[cfg(feature = "iface-serial")]
pub mod serial_iface;
pub(crate) mod stream_read;
#[cfg(feature = "iface-tcp")]
pub mod tcp;
#[cfg(feature = "iface-tcp")]
pub mod tcp_server;
pub(crate) mod transmit_buffer;
#[cfg(feature = "iface-udp")]
pub mod udp;
#[cfg(all(feature = "iface-weave", target_os = "linux"))]
pub mod weave;

mod async_writer;
mod egress;
mod entry;
mod factory;
mod interface_map;
mod listener_control;
#[cfg(any(feature = "iface-tcp", feature = "iface-backbone"))]
mod tcp_params;
mod type_hints;
mod underlay;
mod writer;

pub use async_writer::{
    wrap_async_writer, AsyncWriterMetrics, ASYNC_WRITER_BACKPRESSURE_WAIT,
    DEFAULT_ASYNC_WRITER_QUEUE_CAPACITY,
};
pub use egress::EgressControl;
pub use entry::InterfaceEntry;
#[cfg(all(test, any(feature = "iface-tcp", feature = "iface-backbone")))]
pub(crate) use factory::test_start_context;
#[cfg(any(runtime_config_ifaces, feature = "iface-local"))]
pub(crate) use factory::KnownConfig;
pub use factory::{
    ConfigSection, DynamicInterfaceTemplate, InterfaceConfigData, InterfaceConfigError,
    InterfaceFactory, StartContext, StartResult, SubInterface,
};
pub use interface_map::{InterfaceIdHasher, InterfaceMap};
#[cfg(any(feature = "iface-serial", feature = "iface-kiss"))]
pub(crate) use listener_control::poll_readable;
#[cfg(any(
    feature = "iface-tcp",
    feature = "iface-serial",
    feature = "iface-kiss",
    feature = "iface-backbone"
))]
pub(crate) use listener_control::wait_while_active;
pub use listener_control::ListenerControl;
#[cfg(feature = "iface-backbone")]
pub(crate) use tcp_params::auto_mtu_for_bitrate;
#[cfg(feature = "iface-tcp")]
pub(crate) use tcp_params::{
    parse_flush_after, parse_tcp_rate_params, tcp_bitrate, tcp_hardware_mtu, DEFAULT_FLUSH_AFTER,
};
pub use type_hints::{shared_medium_hint, tunnels_allowed};
pub use underlay::{
    apply_underlay_mark, install_socket_protector, validate_underlay_mark, SocketProtector,
    SocketProtectorGuard,
};
#[cfg(target_os = "linux")]
pub use underlay::{bind_to_device, connect_tcp_with_options};
#[cfg(any(
    feature = "iface-tcp",
    feature = "iface-serial",
    feature = "iface-kiss",
    feature = "iface-backbone",
    feature = "iface-i2p"
))]
pub(crate) use writer::UnavailableWriter;
pub use writer::{FrameBytes, Writer};

pub(crate) use crate::sync::lock_or_recover;

pub use crate::common::interface_stats::{InterfaceStats, TrafficRates, ANNOUNCE_SAMPLE_MAX};
