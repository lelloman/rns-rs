//! Event types for the driver loop — concrete sync instantiation.

pub use crate::common::event::{
    BackboneInterfaceEntry, BackbonePeerHookEvent, BackbonePeerPoolMemberStatus,
    BackbonePeerPoolStatus, BackbonePeerStateEntry, BlackholeInfo, DrainStatus, HolePunchPolicy,
    HookInfo, InterfaceStatsResponse, KnownDestinationEntry, LifecycleState, LinkInfoEntry,
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc::TrySendError;
    use std::time::Duration;

    #[test]
    fn bounded_event_queue_backpressures_when_full() {
        let (tx, rx) = channel_with_capacity(1);

        tx.try_send(Event::Tick).unwrap();
        match tx.try_send(Event::Shutdown) {
            Err(TrySendError::Full(Event::Shutdown)) => {}
            other => panic!("expected full queue for second event, got {other:?}"),
        }

        assert!(matches!(
            rx.recv_timeout(Duration::from_secs(1)).unwrap(),
            Event::Tick
        ));
        tx.try_send(Event::Shutdown).unwrap();
        assert!(matches!(
            rx.recv_timeout(Duration::from_secs(1)).unwrap(),
            Event::Shutdown
        ));
    }
}
