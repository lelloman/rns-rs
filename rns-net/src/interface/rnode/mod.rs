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
pub use connection::*;
pub use factory::*;
pub use radio::*;
use reader::*;
use receive::RNodeReceiver;
pub use runtime::*;
use telemetry::*;
use writers::*;

mod ble;
mod folded;
mod setup;
mod transport;

pub use ble::LinkState as BleLinkState;

use std::io::{self, Read, Write};
use std::os::fd::AsRawFd;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;
use transport::Transport;

/// The shared write side of an RNode connection.
pub type DeviceWriter = crate::interface::device_writer::DeviceWriter<Transport>;

use rns_core::transport::types::{AirtimeProfile, InterfaceId};

use crate::common::interface_stats::RadioStats;
use crate::event::{Event, EventSender, InterfaceTelemetry};
use crate::interface::{lock_or_recover, Writer};
use crate::rnode_kiss;
use crate::serial::{Parity, SerialConfig};

/// Validation limits matching Python RNodeInterface.
pub const FREQ_MIN: u32 = 137_000_000;
pub const FREQ_MAX: u32 = 3_000_000_000;
pub const BW_MIN: u32 = 7_800;
pub const BW_MAX: u32 = 1_625_000;
pub const SF_MIN: u8 = 5;
pub const SF_MAX: u8 = 12;
pub const CR_MIN: u8 = 5;
pub const CR_MAX: u8 = 8;
pub const TXPOWER_MIN: i8 = 0;
pub const TXPOWER_MAX: i8 = 37;
pub const HW_MTU: u32 = 508;
pub const LORA_PREAMBLE_SYMBOLS: u16 = 8;
pub const LORA_EXPLICIT_HEADER: bool = true;
pub const LORA_CRC: bool = true;

/// Configuration for one RNode subinterface (radio).
#[derive(Debug, Clone)]
pub struct RNodeSubConfig {
    pub name: String,
    pub vport: u8,
    pub outgoing: bool,
    pub frequency: u32,
    pub bandwidth: u32,
    pub txpower: i8,
    pub spreading_factor: u8,
    pub coding_rate: u8,
    pub flow_control: bool,
    pub st_alock: Option<f32>,
    pub lt_alock: Option<f32>,
}

/// Configuration for the RNode device.
#[derive(Debug, Clone)]
pub struct RNodeConfig {
    pub name: String,
    pub port: String,
    pub speed: u32,
    pub subinterfaces: Vec<RNodeSubConfig>,
    pub multi: bool,
    pub id_interval: Option<u32>,
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
    pub underlay_mark: Option<u32>,
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
