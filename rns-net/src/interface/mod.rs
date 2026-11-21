//! Network interface abstractions.

#[cfg(feature = "iface-auto")]
pub(crate) mod auto;
#[cfg(feature = "iface-kiss")]
pub(crate) mod ax25_kiss;
#[cfg(feature = "iface-backbone")]
pub(crate) mod backbone;
#[cfg(any(feature = "iface-rnode", feature = "iface-weave"))]
pub(crate) mod device_writer;
pub(crate) mod display;
#[cfg(feature = "iface-i2p")]
pub(crate) mod i2p;
#[cfg(feature = "iface-kiss")]
pub(crate) mod kiss_iface;
#[cfg(feature = "iface-local")]
pub(crate) mod local;
pub(crate) mod loop_writer;
#[cfg(feature = "iface-pipe")]
pub(crate) mod pipe;
pub(crate) mod registry;
#[cfg(feature = "iface-rnode")]
pub(crate) mod rnode;
#[cfg(feature = "iface-serial")]
pub(crate) mod serial_iface;
pub(crate) mod stream_read;
#[cfg(feature = "iface-tcp")]
pub(crate) mod tcp;
#[cfg(feature = "iface-tcp")]
pub(crate) mod tcp_server;
pub(crate) mod transmit_buffer;
#[cfg(feature = "iface-udp")]
pub(crate) mod udp;
#[cfg(all(feature = "iface-weave", target_os = "linux"))]
pub(crate) mod weave;

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
pub(crate) use entry::InterfaceEntry;
#[cfg(all(test, any(feature = "iface-tcp", feature = "iface-backbone")))]
pub(crate) use factory::test_start_context;
#[cfg(any(runtime_config_ifaces, feature = "iface-local"))]
pub(crate) use factory::KnownConfig;
pub use factory::{
    ConfigSection, DynamicInterfaceTemplate, InterfaceConfigData, InterfaceConfigError,
    InterfaceFactory, StartContext, StartResult, SubInterface,
};
pub(crate) use interface_map::InterfaceMap;
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
pub use type_hints::InterfaceKind;
pub(crate) use type_hints::{shared_medium_hint, tunnels_allowed};
#[cfg(target_os = "linux")]
pub(crate) use underlay::bind_to_device;
#[cfg(all(target_os = "linux", feature = "iface-tcp"))]
pub(crate) use underlay::connect_tcp_with_options;
pub(crate) use underlay::{apply_underlay_mark, validate_underlay_mark};
pub use underlay::{install_socket_protector, SocketProtector, SocketProtectorGuard};
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

pub use crate::common::interface_stats::{
    FrequencySample, InterfaceStats, RadioStats, TrafficRates, ANNOUNCE_SAMPLE_MAX,
};

// The built-in interfaces: their factories and configs.
#[cfg(feature = "iface-auto")]
pub use auto::{AutoConfig, AutoFactory};
#[cfg(feature = "iface-ax25-kiss")]
pub use ax25_kiss::{
    decode_ui_frame as decode_ax25_ui_frame, encode_ui_frame as encode_ax25_ui_frame,
    validate_address as validate_ax25_address, Ax25AddressError, Ax25KissFactory,
};
#[cfg(feature = "iface-backbone")]
pub use backbone::{
    BackboneClientConfig, BackboneClientInterfaceFactory, BackboneConfig, BackboneInterfaceFactory,
};
#[cfg(feature = "iface-i2p")]
pub use i2p::{I2pConfig, I2pFactory};
#[cfg(feature = "iface-ax25-kiss")]
pub use kiss_iface::Ax25Address;
#[cfg(feature = "iface-kiss")]
pub use kiss_iface::{KissFactory, KissIfaceConfig};
#[cfg(feature = "iface-local")]
pub use local::{LocalClientConfig, LocalClientFactory, LocalServerConfig, LocalServerFactory};
#[cfg(feature = "iface-pipe")]
pub use pipe::{PipeConfig, PipeFactory};
pub use registry::InterfaceRegistry;
#[cfg(feature = "iface-rnode")]
pub use rnode::{RNodeConfig, RNodeFactory, RNodeMultiFactory, RNodeSubConfig};
#[cfg(feature = "iface-serial")]
pub use serial_iface::{SerialFactory, SerialIfaceConfig};
#[cfg(feature = "iface-tcp")]
pub use tcp::{TcpClientConfig, TcpClientFactory};
#[cfg(feature = "iface-tcp")]
pub use tcp_server::{TcpServerConfig, TcpServerFactory};
#[cfg(feature = "iface-udp")]
pub use udp::{UdpConfig, UdpFactory};
#[cfg(all(feature = "iface-weave", target_os = "linux"))]
pub use weave::{
    parse_device_frame as parse_weave_device_frame, WdclFrame, WeaveConfig, WeaveFactory,
    WeaveInput, WeaveLogFrame, WeavePeerState, WeaveState,
};
