//! Event types for the driver loop — concrete sync instantiation.

pub use crate::common::event::{
    HolePunchPolicy,
    HookInfo,
    QueryRequest, QueryResponse,
    InterfaceStatsResponse, SingleInterfaceStat,
    LocalDestinationEntry, LinkInfoEntry, ResourceInfoEntry,
    PathTableEntry, RateTableEntry,
    BlackholeInfo, NextHopResponse,
};

/// Concrete Event type using boxed sync Writer.
pub type Event = crate::common::event::Event<Box<dyn crate::interface::Writer>>;

pub type EventSender = std::sync::mpsc::Sender<Event>;
pub type EventReceiver = std::sync::mpsc::Receiver<Event>;

pub fn channel() -> (EventSender, EventReceiver) {
    std::sync::mpsc::channel()
}
