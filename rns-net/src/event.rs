//! Event types for the driver loop — concrete sync instantiation.

pub use crate::common::event::{
    BackboneInterfaceEntry, BackbonePeerHookEvent, BackbonePeerStateEntry, BlackholeInfo,
    DrainStatus, HolePunchPolicy, HookInfo, InterfaceStatsResponse, LifecycleState, LinkInfoEntry,
    LocalDestinationEntry, NextHopResponse, PathTableEntry, ProviderBridgeConsumerStats,
    ProviderBridgeStats, QueryRequest, QueryResponse, RateTableEntry, ResourceInfoEntry,
    RuntimeConfigApplyMode, RuntimeConfigEntry, RuntimeConfigError, RuntimeConfigErrorCode,
    RuntimeConfigSource, RuntimeConfigValue, SingleInterfaceStat,
};

/// Concrete Event type using boxed sync Writer.
pub type Event = crate::common::event::Event<Box<dyn crate::interface::Writer>>;

pub const DEFAULT_EVENT_QUEUE_CAPACITY: usize = 8192;

pub type EventSender = std::sync::mpsc::SyncSender<Event>;
pub type EventReceiver = std::sync::mpsc::Receiver<Event>;

pub fn channel() -> (EventSender, EventReceiver) {
    channel_with_capacity(DEFAULT_EVENT_QUEUE_CAPACITY)
}

pub fn channel_with_capacity(capacity: usize) -> (EventSender, EventReceiver) {
    std::sync::mpsc::sync_channel(capacity.max(1))
}
