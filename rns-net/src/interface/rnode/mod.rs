//! RNode LoRa radio interface.
//!
//! Manages serial connection to RNode device, detects firmware,
//! configures radio parameters per subinterface. Supports single-radio
//! (RNodeInterface) and multi-radio (RNodeMultiInterface) devices.
//!
//! Matches Python `RNodeInterface.py` and `RNodeMultiInterface.py`.

mod configure;
mod connection;
mod factory;
mod radio;
mod reader;
mod receive;
mod runtime;
mod telemetry;
#[cfg(test)]
mod tests;
mod writers;

pub(crate) use configure::*;
use connection::*;
pub use factory::{RNodeFactory, RNodeMultiFactory};
pub(crate) use radio::*;
use reader::*;
use receive::RNodeReceiver;
pub use runtime::RNodeRuntime;
pub(crate) use runtime::*;
use telemetry::*;
use writers::*;

mod ble;
mod folded;
mod setup;
mod transport;

pub(crate) use ble::LinkState as BleLinkState;

use std::io::{self, Read, Write};
use std::os::fd::AsRawFd;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;
use transport::Transport;

/// The shared write side of an RNode connection.
pub(crate) type DeviceWriter = crate::interface::device_writer::DeviceWriter<Transport>;

use rns_core::transport::types::{AirtimeProfile, InterfaceId};

use crate::common::interface_stats::RadioStats;
use crate::event::{Event, EventSender, InterfaceTelemetry};
use crate::interface::{lock_or_recover, Writer};
use crate::rnode_kiss;
use crate::serial::{Parity, SerialConfig};

// Validation limits matching Python RNodeInterface.

/// Lowest accepted radio frequency, in Hz.
pub(crate) const FREQ_MIN: u32 = 137_000_000;
/// Highest accepted radio frequency, in Hz.
pub(crate) const FREQ_MAX: u32 = 3_000_000_000;
/// Narrowest accepted LoRa bandwidth, in Hz.
pub(crate) const BW_MIN: u32 = 7_800;
/// Widest accepted LoRa bandwidth, in Hz.
pub(crate) const BW_MAX: u32 = 1_625_000;
/// Lowest accepted LoRa spreading factor.
pub(crate) const SF_MIN: u8 = 5;
/// Highest accepted LoRa spreading factor.
pub(crate) const SF_MAX: u8 = 12;
/// Lowest accepted LoRa coding rate (the `5` of 4/5).
pub(crate) const CR_MIN: u8 = 5;
/// Highest accepted LoRa coding rate (the `8` of 4/8).
pub(crate) const CR_MAX: u8 = 8;
/// Lowest accepted transmit power, in dBm.
pub(crate) const TXPOWER_MIN: i8 = 0;
/// Highest accepted transmit power, in dBm.
pub(crate) const TXPOWER_MAX: i8 = 37;
/// Hardware MTU of an RNode interface, in bytes (upstream `HW_MTU`).
pub(crate) const HW_MTU: u32 = 508;
/// LoRa preamble length, in symbols, used for airtime estimates.
pub(crate) const LORA_PREAMBLE_SYMBOLS: u16 = 8;
/// Whether airtime estimates assume an explicit LoRa header.
pub(crate) const LORA_EXPLICIT_HEADER: bool = true;
/// Whether airtime estimates assume a LoRa payload CRC.
pub(crate) const LORA_CRC: bool = true;

/// Configuration for one RNode subinterface (radio).
#[derive(Debug, Clone)]
pub struct RNodeSubConfig {
    /// Subinterface name; for a single RNode, the interface name.
    pub name: String,
    /// Virtual port (radio index) on a multi-radio device, 0 to 10; 0 for a single RNode.
    pub vport: u8,
    /// Whether the subinterface may transmit (`outgoing`, default true).
    pub outgoing: bool,
    /// Radio frequency, in Hz (`frequency`, default 868 MHz).
    pub frequency: u32,
    /// LoRa bandwidth, in Hz (`bandwidth`, default 125 kHz).
    pub bandwidth: u32,
    /// Transmit power, in dBm (`txpower`, default 7).
    pub txpower: i8,
    /// LoRa spreading factor (`spreadingfactor`, default 8).
    pub spreading_factor: u8,
    /// LoRa coding rate, 5 to 8 for 4/5 to 4/8 (`codingrate`, default 5).
    pub coding_rate: u8,
    /// Wait for the device to report ready after each frame before writing the next (`flow_control`).
    pub flow_control: bool,
    /// Short-term airtime limit, in percent (`airtime_limit_short`); sent to the device when set.
    pub st_alock: Option<f32>,
    /// Long-term airtime limit, in percent (`airtime_limit_long`); sent to the device when set.
    pub lt_alock: Option<f32>,
}

/// Configuration for the RNode device.
#[derive(Debug, Clone)]
pub struct RNodeConfig {
    /// Interface name.
    pub name: String,
    /// Device to open: a serial port path, `tcp:host[:port]` or `ble://...`.
    pub port: String,
    /// Serial baud rate (`speed`, default 115200).
    pub speed: u32,
    /// The radios to configure; one for a single RNode.
    pub subinterfaces: Vec<RNodeSubConfig>,
    /// Whether this is an `RNodeMultiInterface`, addressing radios by virtual port.
    pub multi: bool,
    /// Station identification interval (`id_interval`), in seconds: the
    /// callsign is sent this long after the first frame since the last one.
    pub id_interval: Option<u32>,
    /// Station identification callsign (`id_callsign`), at most 32 bytes;
    /// identification needs both it and `id_interval`.
    pub id_callsign: Option<Vec<u8>>,
    /// The interface's own id. An `RNodeMultiInterface` is listed under it
    /// while its subinterfaces take the ids after it, from
    /// `base_interface_id` on, in the order upstream adds them; a single
    /// RNode's only subinterface is the interface itself.
    pub interface_id: InterfaceId,
    /// The id of the first subinterface; the others follow it.
    pub base_interface_id: InterfaceId,
    /// Pre-opened file descriptor (e.g. from a USB bridge socketpair on Android).
    /// When set, `start()` uses this fd directly instead of opening `port`.
    pub pre_opened_fd: Option<i32>,
    /// Socket mark applied to the TCP connection of a `tcp:` port.
    pub underlay_mark: Option<u32>,
    /// Radio settings that can be changed while running, shared with the driver.
    pub runtime: Arc<Mutex<RNodeRuntime>>,
    /// What a BLE connection (`port = ble://...`) remembers between
    /// connections.
    pub ble: Arc<Mutex<BleLinkState>>,
    /// The radio timing a single RNode last reported, kept across
    /// connections: upstream logs it only when it changes.
    pub reported_phy: Arc<Mutex<Option<[u16; 6]>>>,
}

impl Default for RNodeConfig {
    fn default() -> Self {
        let mut config = RNodeConfig {
            name: String::new(),
            port: String::new(),
            speed: 115200,
            subinterfaces: Vec::new(),
            multi: false,
            id_interval: None,
            id_callsign: None,
            interface_id: InterfaceId(0),
            base_interface_id: InterfaceId(0),
            pre_opened_fd: None,
            underlay_mark: None,
            runtime: Arc::new(Mutex::new(RNodeRuntime {
                sub: RNodeSubConfig {
                    name: String::new(),
                    vport: 0,
                    outgoing: true,
                    frequency: 868_000_000,
                    bandwidth: 125_000,
                    txpower: 7,
                    spreading_factor: 8,
                    coding_rate: 5,
                    flow_control: false,
                    st_alock: None,
                    lt_alock: None,
                },
                writer: None,
            })),
            ble: Default::default(),
            reported_phy: Default::default(),
        };
        let startup = RNodeRuntime::from_config(&config);
        config.runtime = Arc::new(Mutex::new(startup));
        config
    }
}

use super::{
    ConfigSection, InterfaceConfigData, InterfaceFactory, StartContext, StartResult, SubInterface,
};
use rns_core::transport::types::InterfaceInfo;
use std::collections::HashMap;
