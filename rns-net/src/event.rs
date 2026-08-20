//! Event types for the driver loop — concrete sync instantiation.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use rns_core::packet::RawPacket;
use rns_core::transport::types::InterfaceId;

pub use crate::common::event::{
    BackboneInterfaceEntry, BackbonePeerHookEvent, BackbonePeerPoolMemberStatus,
    BackbonePeerPoolStatus, BackbonePeerStateEntry, BlackholeInfo, DrainStatus,
    DynamicInterfaceRegistration, HolePunchPolicy, HookInfo, InterfaceStatsResponse,
    InterfaceTelemetry, KnownDestinationEntry, LifecycleState, LinkInfoEntry,
    LocalDestinationEntry, NextHopResponse, PathTableEntry, ProviderBridgeConsumerStats,
    ProviderBridgeStats, QueryRequest, QueryResponse, RateTableEntry, ResourceInfoEntry,
    RuntimeConfigApplyMode, RuntimeConfigEntry, RuntimeConfigError, RuntimeConfigErrorCode,
    RuntimeConfigSource, RuntimeConfigValue, SingleInterfaceStat,
};

/// Concrete Event type using boxed sync Writer.
pub type Event = crate::common::event::Event<Box<dyn crate::interface::Writer>>;

pub const DEFAULT_EVENT_QUEUE_CAPACITY: usize = 8192;
const DEFAULT_ANNOUNCE_QUEUE_CAPACITY: usize = 1024;
const DEFAULT_PATH_REQUEST_QUEUE_CAPACITY: usize = 1024;
const DEFAULT_INGRESS_LIMITED_QUEUE_CAPACITY: usize = 256;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum QueueClass {
    Data = 0,
    Announce = 1,
    PathRequest = 2,
    IngressLimited = 3,
}

const INBOUND_QUEUE_COUNT: usize = 4;

struct QueuedEvent {
    sequence: u64,
    event: Event,
}

struct QueueState {
    control: VecDeque<QueuedEvent>,
    inbound: [VecDeque<QueuedEvent>; INBOUND_QUEUE_COUNT],
    next_sequence: u64,
    receiver_alive: bool,
    announce_burst_active: HashSet<InterfaceId>,
    pr_ingress_limited: HashSet<InterfaceId>,
    dynamic_interface_parents: HashMap<InterfaceId, InterfaceId>,
}

impl QueueState {
    fn new() -> Self {
        Self {
            control: VecDeque::new(),
            inbound: std::array::from_fn(|_| VecDeque::new()),
            next_sequence: 0,
            receiver_alive: true,
            announce_burst_active: HashSet::new(),
            pr_ingress_limited: HashSet::new(),
            dynamic_interface_parents: HashMap::new(),
        }
    }

    fn has_events(&self) -> bool {
        !self.control.is_empty() || self.inbound.iter().any(|queue| !queue.is_empty())
    }

    fn pop_next(&mut self) -> Option<Event> {
        let control_barrier = self.control.front().map(|queued| queued.sequence);
        for queue in &mut self.inbound {
            if queue.front().is_some_and(|queued| {
                control_barrier.is_none_or(|barrier| queued.sequence < barrier)
            }) {
                return queue.pop_front().map(|queued| queued.event);
            }
        }
        self.control.pop_front().map(|queued| queued.event)
    }
}

struct QueueShared {
    state: Mutex<QueueState>,
    changed: Condvar,
    sender_count: AtomicUsize,
    control_capacity: usize,
    inbound_capacities: [usize; INBOUND_QUEUE_COUNT],
    path_request_dest: [u8; 16],
}

/// Sender for the prioritized driver event queue.
pub struct EventSender {
    shared: Arc<QueueShared>,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub(crate) struct InboundQueueSnapshot {
    pub heights: [usize; INBOUND_QUEUE_COUNT],
    pub capacities: [usize; INBOUND_QUEUE_COUNT],
}

impl InboundQueueSnapshot {
    pub fn total_height(self) -> usize {
        self.heights.iter().sum()
    }

    pub fn total_capacity(self) -> usize {
        self.capacities.iter().sum()
    }
}

impl Clone for EventSender {
    fn clone(&self) -> Self {
        self.shared.sender_count.fetch_add(1, Ordering::Relaxed);
        Self {
            shared: Arc::clone(&self.shared),
        }
    }
}

impl Drop for EventSender {
    fn drop(&mut self) {
        if self.shared.sender_count.fetch_sub(1, Ordering::AcqRel) == 1 {
            self.shared.changed.notify_all();
        }
    }
}

impl EventSender {
    fn classify(&self, event: &Event, state: &QueueState) -> Option<QueueClass> {
        let Event::Frame {
            interface_id, data, ..
        } = event
        else {
            return None;
        };
        let packet = RawPacket::unpack(data).ok();
        if packet.as_ref().is_some_and(|packet| {
            packet.flags.packet_type == rns_core::constants::PACKET_TYPE_ANNOUNCE
        }) {
            return Some(QueueClass::Announce);
        }
        if packet
            .as_ref()
            .is_some_and(|packet| packet.destination_hash == self.shared.path_request_dest)
        {
            return Some(if state.pr_ingress_limited.contains(interface_id) {
                QueueClass::IngressLimited
            } else {
                QueueClass::PathRequest
            });
        }
        Some(QueueClass::Data)
    }

    // Preserve the former SyncSender-compatible error contract at this public boundary.
    #[allow(clippy::result_large_err)]
    fn enqueue(
        &self,
        event: Event,
        block_control: bool,
        drop_full_inbound: bool,
    ) -> Result<(), std::sync::mpsc::TrySendError<Event>> {
        let mut state = self.shared.state.lock().unwrap_or_else(|p| p.into_inner());
        if !state.receiver_alive {
            return Err(std::sync::mpsc::TrySendError::Disconnected(event));
        }
        let class = self.classify(&event, &state);
        if let Some(class) = class {
            let index = class as usize;
            if state.inbound[index].len() >= self.shared.inbound_capacities[index] {
                return if drop_full_inbound {
                    Ok(())
                } else {
                    Err(std::sync::mpsc::TrySendError::Full(event))
                };
            }
            let sequence = state.next_sequence;
            state.next_sequence = state.next_sequence.wrapping_add(1);
            state.inbound[index].push_back(QueuedEvent { sequence, event });
            drop(state);
            self.shared.changed.notify_one();
            return Ok(());
        }

        while state.control.len() >= self.shared.control_capacity {
            if !block_control {
                return Err(std::sync::mpsc::TrySendError::Full(event));
            }
            state = self
                .shared
                .changed
                .wait(state)
                .unwrap_or_else(|p| p.into_inner());
            if !state.receiver_alive {
                return Err(std::sync::mpsc::TrySendError::Disconnected(event));
            }
        }
        let sequence = state.next_sequence;
        state.next_sequence = state.next_sequence.wrapping_add(1);
        state.control.push_back(QueuedEvent { sequence, event });
        drop(state);
        self.shared.changed.notify_one();
        Ok(())
    }

    #[allow(clippy::result_large_err)]
    pub fn send(&self, event: Event) -> Result<(), std::sync::mpsc::SendError<Event>> {
        self.enqueue(event, true, true)
            .map_err(|error| match error {
                std::sync::mpsc::TrySendError::Full(event)
                | std::sync::mpsc::TrySendError::Disconnected(event) => {
                    std::sync::mpsc::SendError(event)
                }
            })
    }

    #[allow(clippy::result_large_err)]
    pub fn try_send(&self, event: Event) -> Result<(), std::sync::mpsc::TrySendError<Event>> {
        self.enqueue(event, false, false)
    }

    pub(crate) fn set_ingress_bursts(
        &self,
        interface_id: InterfaceId,
        announce_limited: bool,
        path_request_limited: bool,
    ) {
        let mut state = self.shared.state.lock().unwrap_or_else(|p| p.into_inner());
        if announce_limited {
            state.announce_burst_active.insert(interface_id);
        } else {
            state.announce_burst_active.remove(&interface_id);
        }
        if path_request_limited {
            state.pr_ingress_limited.insert(interface_id);
        } else {
            state.pr_ingress_limited.remove(&interface_id);
        }
    }

    pub(crate) fn register_dynamic_parent(
        &self,
        interface_id: InterfaceId,
        parent_id: InterfaceId,
    ) {
        self.shared
            .state
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .dynamic_interface_parents
            .insert(interface_id, parent_id);
    }

    pub(crate) fn remove_interface(&self, interface_id: InterfaceId) {
        let mut state = self.shared.state.lock().unwrap_or_else(|p| p.into_inner());
        state.announce_burst_active.remove(&interface_id);
        state.pr_ingress_limited.remove(&interface_id);
        state.dynamic_interface_parents.remove(&interface_id);
    }

    pub(crate) fn inbound_queue_snapshot(&self) -> InboundQueueSnapshot {
        let state = self.shared.state.lock().unwrap_or_else(|p| p.into_inner());
        InboundQueueSnapshot {
            heights: std::array::from_fn(|index| state.inbound[index].len()),
            capacities: self.shared.inbound_capacities,
        }
    }

    pub(crate) fn dynamic_burst_counts(&self, parent_id: InterfaceId) -> Option<(usize, usize)> {
        let state = self.shared.state.lock().unwrap_or_else(|p| p.into_inner());
        let children = state
            .dynamic_interface_parents
            .iter()
            .filter(|(_, candidate_parent)| **candidate_parent == parent_id);
        let mut found = false;
        let mut counts = (0, 0);
        for (child, _) in children {
            found = true;
            counts.0 += usize::from(state.announce_burst_active.contains(child));
            counts.1 += usize::from(state.pr_ingress_limited.contains(child));
        }
        found.then_some(counts)
    }
}

/// Receiver for the prioritized driver event queue.
pub struct EventReceiver {
    shared: Arc<QueueShared>,
}

impl Drop for EventReceiver {
    fn drop(&mut self) {
        let mut state = self.shared.state.lock().unwrap_or_else(|p| p.into_inner());
        state.receiver_alive = false;
        drop(state);
        self.shared.changed.notify_all();
    }
}

impl EventReceiver {
    fn pop_locked(&self, state: &mut QueueState) -> Option<Event> {
        let event = state.pop_next();
        if event.is_some() {
            self.shared.changed.notify_all();
        }
        event
    }

    pub fn recv(&self) -> Result<Event, std::sync::mpsc::RecvError> {
        let mut state = self.shared.state.lock().unwrap_or_else(|p| p.into_inner());
        loop {
            if let Some(event) = self.pop_locked(&mut state) {
                return Ok(event);
            }
            if self.shared.sender_count.load(Ordering::Acquire) == 0 {
                return Err(std::sync::mpsc::RecvError);
            }
            state = self
                .shared
                .changed
                .wait(state)
                .unwrap_or_else(|p| p.into_inner());
        }
    }

    pub fn try_recv(&self) -> Result<Event, std::sync::mpsc::TryRecvError> {
        let mut state = self.shared.state.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(event) = self.pop_locked(&mut state) {
            return Ok(event);
        }
        if self.shared.sender_count.load(Ordering::Acquire) == 0 {
            Err(std::sync::mpsc::TryRecvError::Disconnected)
        } else {
            Err(std::sync::mpsc::TryRecvError::Empty)
        }
    }

    pub fn recv_timeout(
        &self,
        timeout: Duration,
    ) -> Result<Event, std::sync::mpsc::RecvTimeoutError> {
        let deadline = Instant::now() + timeout;
        let mut state = self.shared.state.lock().unwrap_or_else(|p| p.into_inner());
        loop {
            if let Some(event) = self.pop_locked(&mut state) {
                return Ok(event);
            }
            if self.shared.sender_count.load(Ordering::Acquire) == 0 {
                return Err(std::sync::mpsc::RecvTimeoutError::Disconnected);
            }
            let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
                return Err(std::sync::mpsc::RecvTimeoutError::Timeout);
            };
            let (next_state, result) = self
                .shared
                .changed
                .wait_timeout(state, remaining)
                .unwrap_or_else(|p| p.into_inner());
            state = next_state;
            if result.timed_out() && !state.has_events() {
                return Err(std::sync::mpsc::RecvTimeoutError::Timeout);
            }
        }
    }
}

pub fn channel() -> (EventSender, EventReceiver) {
    channel_with_capacity(DEFAULT_EVENT_QUEUE_CAPACITY)
}

pub fn channel_with_capacity(capacity: usize) -> (EventSender, EventReceiver) {
    let capacity = capacity.max(1);
    let shared = Arc::new(QueueShared {
        state: Mutex::new(QueueState::new()),
        changed: Condvar::new(),
        sender_count: AtomicUsize::new(1),
        control_capacity: capacity,
        inbound_capacities: [
            capacity,
            capacity.min(DEFAULT_ANNOUNCE_QUEUE_CAPACITY),
            capacity.min(DEFAULT_PATH_REQUEST_QUEUE_CAPACITY),
            capacity.min(DEFAULT_INGRESS_LIMITED_QUEUE_CAPACITY),
        ],
        path_request_dest: rns_core::destination::destination_hash(
            "rnstransport",
            &["path", "request"],
            None,
        ),
    });
    (
        EventSender {
            shared: Arc::clone(&shared),
        },
        EventReceiver { shared },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use rns_core::packet::{PacketFlags, RawPacket};
    use std::sync::mpsc::TrySendError;
    use std::time::Duration;

    fn frame(interface_id: u64, destination: [u8; 16], packet_type: u8) -> Event {
        let raw = RawPacket::pack(
            PacketFlags {
                header_type: rns_core::constants::HEADER_1,
                context_flag: rns_core::constants::FLAG_UNSET,
                transport_type: rns_core::constants::TRANSPORT_BROADCAST,
                destination_type: rns_core::constants::DESTINATION_PLAIN,
                packet_type,
            },
            0,
            &destination,
            None,
            rns_core::constants::CONTEXT_NONE,
            b"queue-test",
        )
        .unwrap()
        .raw;
        Event::Frame {
            interface_id: InterfaceId(interface_id),
            data: raw,
            rssi: None,
            snr: None,
        }
    }

    fn frame_interface(event: Event) -> u64 {
        match event {
            Event::Frame { interface_id, .. } => interface_id.0,
            other => panic!("expected frame, got {other:?}"),
        }
    }

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

    #[test]
    fn inbound_frames_are_drained_in_traffic_class_priority_order() {
        let (tx, rx) = channel_with_capacity(8);
        let path_dest =
            rns_core::destination::destination_hash("rnstransport", &["path", "request"], None);
        tx.set_ingress_bursts(InterfaceId(4), false, true);

        tx.send(frame(4, path_dest, rns_core::constants::PACKET_TYPE_DATA))
            .unwrap();
        tx.send(frame(3, path_dest, rns_core::constants::PACKET_TYPE_DATA))
            .unwrap();
        tx.send(frame(
            2,
            [0xA2; 16],
            rns_core::constants::PACKET_TYPE_ANNOUNCE,
        ))
        .unwrap();
        tx.send(frame(1, [0xD1; 16], rns_core::constants::PACKET_TYPE_DATA))
            .unwrap();
        tx.send(Event::Shutdown).unwrap();

        assert_eq!(tx.inbound_queue_snapshot().heights, [1, 1, 1, 1]);

        assert_eq!(frame_interface(rx.recv().unwrap()), 1);
        assert_eq!(frame_interface(rx.recv().unwrap()), 2);
        assert_eq!(frame_interface(rx.recv().unwrap()), 3);
        assert_eq!(frame_interface(rx.recv().unwrap()), 4);
        assert!(matches!(rx.recv().unwrap(), Event::Shutdown));
    }

    #[test]
    fn dynamic_parent_burst_counts_track_independent_states_and_cleanup() {
        let (tx, _rx) = channel();
        tx.register_dynamic_parent(InterfaceId(11), InterfaceId(10));
        tx.register_dynamic_parent(InterfaceId(12), InterfaceId(10));
        tx.register_dynamic_parent(InterfaceId(21), InterfaceId(20));
        tx.set_ingress_bursts(InterfaceId(11), true, false);
        tx.set_ingress_bursts(InterfaceId(12), false, true);
        tx.set_ingress_bursts(InterfaceId(21), true, true);

        assert_eq!(tx.dynamic_burst_counts(InterfaceId(10)), Some((1, 1)));
        assert_eq!(tx.dynamic_burst_counts(InterfaceId(20)), Some((1, 1)));
        assert_eq!(tx.dynamic_burst_counts(InterfaceId(30)), None);

        tx.remove_interface(InterfaceId(12));
        assert_eq!(tx.dynamic_burst_counts(InterfaceId(10)), Some((1, 0)));
    }

    #[test]
    fn saturated_data_queue_does_not_consume_path_request_capacity() {
        let (tx, rx) = channel_with_capacity(1);
        let path_dest =
            rns_core::destination::destination_hash("rnstransport", &["path", "request"], None);
        tx.try_send(frame(1, [0xD1; 16], rns_core::constants::PACKET_TYPE_DATA))
            .unwrap();
        assert!(matches!(
            tx.try_send(frame(2, [0xD2; 16], rns_core::constants::PACKET_TYPE_DATA)),
            Err(TrySendError::Full(_))
        ));
        tx.try_send(frame(3, path_dest, rns_core::constants::PACKET_TYPE_DATA))
            .unwrap();
        tx.try_send(Event::Shutdown).unwrap();

        assert_eq!(frame_interface(rx.recv().unwrap()), 1);
        assert_eq!(frame_interface(rx.recv().unwrap()), 3);
        assert!(matches!(rx.recv().unwrap(), Event::Shutdown));
    }

    #[test]
    fn blocking_send_drops_only_the_full_inbound_class() {
        let (tx, rx) = channel_with_capacity(1);
        tx.send(frame(1, [0xD1; 16], rns_core::constants::PACKET_TYPE_DATA))
            .unwrap();
        tx.send(frame(2, [0xD2; 16], rns_core::constants::PACKET_TYPE_DATA))
            .expect("a full inbound class must drop instead of blocking its reader");
        tx.send(Event::Shutdown).unwrap();

        assert_eq!(frame_interface(rx.recv().unwrap()), 1);
        assert!(matches!(rx.recv().unwrap(), Event::Shutdown));
    }
}
