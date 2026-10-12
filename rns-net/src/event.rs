//! Event types for the driver loop — concrete sync instantiation.

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use crate::packet_header::PacketHeader;
use rns_core::transport::types::InterfaceId;

pub use crate::common::event::{
    BackboneInterfaceEntry, BackbonePeerHookEvent, BackbonePeerPoolMemberStatus,
    BackbonePeerPoolStatus, BackbonePeerStateEntry, BlackholeInfo, DrainStatus,
    DynamicInterfaceRegistration, HolePunchPolicy, HookInfo, InterfaceManagementOperation,
    InterfaceStatsResponse, InterfaceTelemetry, KnownDestinationEntry, LifecycleState,
    LinkDatagramError, LinkInfoEntry, LocalDestinationEntry, NextHopResponse, PathTableEntry,
    ProviderBridgeConsumerStats, ProviderBridgeStats, QueryRequest, QueryResponse, RateTableEntry,
    ResourceInfoEntry, RuntimeConfigApplyMode, RuntimeConfigEntry, RuntimeConfigError,
    RuntimeConfigErrorCode, RuntimeConfigSource, RuntimeConfigValue, SingleInterfaceStat,
    TrafficDetail,
};

/// Concrete Event type using boxed sync Writer.
pub type Event = crate::common::event::Event<Box<dyn crate::interface::Writer>>;

pub const DEFAULT_EVENT_QUEUE_CAPACITY: usize = 1024;
pub const DEFAULT_ANNOUNCE_QUEUE_CAPACITY: usize = 128;
pub const DEFAULT_PATH_REQUEST_QUEUE_CAPACITY: usize = 128;
pub const DEFAULT_INGRESS_LIMITED_QUEUE_CAPACITY: usize = 8;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InboundQueueCapacities {
    pub data: usize,
    pub announce: usize,
    pub path_request: usize,
    pub ingress_limited: usize,
}

impl Default for InboundQueueCapacities {
    fn default() -> Self {
        Self {
            data: DEFAULT_EVENT_QUEUE_CAPACITY,
            announce: DEFAULT_ANNOUNCE_QUEUE_CAPACITY,
            path_request: DEFAULT_PATH_REQUEST_QUEUE_CAPACITY,
            ingress_limited: DEFAULT_INGRESS_LIMITED_QUEUE_CAPACITY,
        }
    }
}

impl InboundQueueCapacities {
    pub(crate) fn from_shared_capacity(capacity: usize) -> Self {
        let capacity = capacity.max(1);
        Self {
            data: capacity,
            announce: capacity.min(DEFAULT_ANNOUNCE_QUEUE_CAPACITY),
            path_request: capacity.min(DEFAULT_PATH_REQUEST_QUEUE_CAPACITY),
            ingress_limited: capacity.min(DEFAULT_INGRESS_LIMITED_QUEUE_CAPACITY),
        }
    }

    fn as_array(self) -> [usize; INBOUND_QUEUE_COUNT] {
        [
            self.data,
            self.announce,
            self.path_request,
            self.ingress_limited,
        ]
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum QueueClass {
    Data = 0,
    Announce = 1,
    PathRequest = 2,
    IngressLimited = 3,
}

const INBOUND_QUEUE_COUNT: usize = 4;

/// A socket served on the receiving thread instead of by its own thread.
///
/// Sources are registered on the queue's poller with a key, and whichever
/// thread receives from the queue calls [`LoopSource::on_ready`] when the
/// socket is readable. Sources enqueue what they produce with
/// [`EventSender::push_from_loop`], which never blocks that thread.
pub(crate) trait LoopSource: Send {
    fn fd(&self) -> std::os::fd::RawFd;
    /// Serve a readable socket.
    fn on_ready(&mut self, cx: &mut LoopContext<'_>) -> SourceStatus;
    /// Whether the source should be closed at the next sweep (e.g. its
    /// interface was detached).
    fn stopped(&self) -> bool {
        false
    }
    /// Called once when the source is removed, before it is dropped.
    fn on_removed(&mut self) {}
    /// Called instead of [`LoopSource::on_removed`] when a source handed to
    /// [`LoopContext::add_source`] could not be registered at all.
    fn on_abandoned(&mut self) {
        self.on_removed();
    }
}

/// What to do with a source after [`LoopSource::on_ready`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SourceStatus {
    /// Keep watching for readability.
    Rearm,
    /// Stop reading until the receiver has drained the queue (inbound data
    /// is full); transport flow control then slows the sender.
    Suspend,
    /// Stop reading until the next tick-time
    /// [`EventReceiver::resume_paused_sources`], e.g. after an error that
    /// readiness alone would report again at once.
    Pause,
    /// Deregister and drop the source.
    Remove,
}

pub(crate) struct LoopContext<'a> {
    /// Scratch buffer shared by all sources for socket reads.
    pub(crate) buf: &'a mut [u8],
    added: Vec<(usize, Box<dyn LoopSource>)>,
}

impl LoopContext<'_> {
    /// Register another source once the current one returns.
    pub(crate) fn add_source(&mut self, key: usize, source: Box<dyn LoopSource>) {
        self.added.push((key, source));
    }
}

/// Bytes of scratch space shared by sources for one read.
const LOOP_READ_BUFFER: usize = 64 * 1024;

#[derive(Default)]
struct SourceRegistry {
    sources: HashMap<usize, Box<dyn LoopSource>>,
    suspended: Vec<usize>,
    /// Sources waiting for the next tick-time resume.
    paused: Vec<usize>,
    buf: Vec<u8>,
}

struct QueuedEvent {
    sequence: u64,
    event: Event,
}

struct QueueState {
    control: VecDeque<QueuedEvent>,
    inbound: [VecDeque<QueuedEvent>; INBOUND_QUEUE_COUNT],
    inbound_dropped: [usize; INBOUND_QUEUE_COUNT],
    next_sequence: u64,
    receiver_alive: bool,
    announce_bursts: HashMap<InterfaceId, f64>,
    path_request_bursts: HashMap<InterfaceId, f64>,
    dynamic_interface_parents: HashMap<InterfaceId, InterfaceId>,
    /// Threads currently blocked on `QueueShared::changed`. Producers and the
    /// receiver only notify when someone waits: a thread can start waiting
    /// only after taking the state lock, so it observes every change made
    /// before the notification check and no wakeup is lost.
    waiters: usize,
    /// The receiver is blocked in `QueueShared::poller` rather than on
    /// `changed`. Set and cleared under the state lock, like `waiters`.
    receiver_parked: bool,
}

pub(crate) struct ReceivedEvent {
    pub event: Event,
    pub ingress_limited: bool,
}

impl QueueState {
    fn new() -> Self {
        Self {
            control: VecDeque::new(),
            inbound: std::array::from_fn(|_| VecDeque::new()),
            inbound_dropped: [0; INBOUND_QUEUE_COUNT],
            next_sequence: 0,
            receiver_alive: true,
            announce_bursts: HashMap::new(),
            path_request_bursts: HashMap::new(),
            dynamic_interface_parents: HashMap::new(),
            waiters: 0,
            receiver_parked: false,
        }
    }

    fn has_events(&self) -> bool {
        !self.control.is_empty() || self.inbound.iter().any(|queue| !queue.is_empty())
    }

    fn pop_next(&mut self) -> Option<ReceivedEvent> {
        let control_barrier = self.control.front().map(|queued| queued.sequence);
        for (index, queue) in self.inbound.iter_mut().enumerate() {
            if queue.front().is_some_and(|queued| {
                control_barrier.is_none_or(|barrier| queued.sequence < barrier)
            }) {
                return queue.pop_front().map(|queued| ReceivedEvent {
                    event: queued.event,
                    ingress_limited: index == QueueClass::IngressLimited as usize,
                });
            }
        }
        self.control.pop_front().map(|queued| ReceivedEvent {
            event: queued.event,
            ingress_limited: false,
        })
    }
}

struct QueueShared {
    local_ratchets: crate::local_ratchet::Registry,
    link_sends: Arc<crate::link_send::SendPool>,
    async_waiters: Mutex<Vec<std::sync::Weak<crate::link_send::Waiter>>>,
    /// Length of `async_waiters` as of its last update, read without the lock
    /// on every receive. Registration stores it before the sender's queue
    /// attempt, which is ordered by the state lock relative to the receive.
    async_waiter_count: AtomicUsize,
    state: Mutex<QueueState>,
    changed: Condvar,
    /// The receiver can wait here instead of on `changed`, together with any
    /// sources registered on it. Producers wake it with `Poller::notify`.
    poller: Arc<polling::Poller>,
    sources: Mutex<SourceRegistry>,
    sender_count: AtomicUsize,
    control_capacity: usize,
    inbound_capacities: [usize; INBOUND_QUEUE_COUNT],
    path_request_dest: [u8; 16],
}

impl QueueShared {
    /// Wake whoever waits for this change: threads on `changed`, and the
    /// receiver if it is parked in the poller.
    fn notify_change(&self, state: &QueueState, all: bool) {
        if state.waiters > 0 {
            if all {
                self.changed.notify_all();
            } else {
                self.changed.notify_one();
            }
        }
        if state.receiver_parked {
            self.wake_poller();
        }
    }

    /// Add `source` to the registry and watch it for readability. The
    /// registry lock is held across both, so a receiver serving the key
    /// always finds the source.
    fn add_source(
        &self,
        registry: &mut SourceRegistry,
        key: usize,
        source: Box<dyn LoopSource>,
    ) -> std::io::Result<()> {
        self.try_add_source(registry, key, source)
            .map_err(|(error, _)| error)
    }

    /// Like `add_source`, handing the source back if it was not registered.
    #[allow(clippy::type_complexity)]
    fn try_add_source(
        &self,
        registry: &mut SourceRegistry,
        key: usize,
        source: Box<dyn LoopSource>,
    ) -> Result<(), (std::io::Error, Box<dyn LoopSource>)> {
        // SAFETY: the source owns the descriptor and is deleted from the
        // poller before it is dropped (see `remove_source`).
        if let Err(error) = unsafe { self.poller.add(source.fd(), polling::Event::readable(key)) } {
            return Err((error, source));
        }
        registry.sources.insert(key, source);
        Ok(())
    }

    fn data_has_room(&self, state: &QueueState) -> bool {
        let data = QueueClass::Data as usize;
        state.inbound[data].len() < self.inbound_capacities[data]
    }

    fn remove_source(&self, mut source: Box<dyn LoopSource>) {
        // SAFETY: the source still owns its descriptor here.
        let fd = unsafe { std::os::fd::BorrowedFd::borrow_raw(source.fd()) };
        if let Err(error) = self.poller.delete(fd) {
            log::warn!("failed to deregister a loop source: {error}");
        }
        source.on_removed();
    }

    fn arm_source(&self, key: usize, source: &dyn LoopSource) {
        // SAFETY: the source owns its descriptor while registered.
        let fd = unsafe { std::os::fd::BorrowedFd::borrow_raw(source.fd()) };
        if let Err(error) = self.poller.modify(fd, polling::Event::readable(key)) {
            log::warn!("failed to re-arm a loop source: {error}");
        }
    }

    fn wake_poller(&self) {
        if let Err(error) = self.poller.notify() {
            log::warn!("failed to wake the driver poller: {error}");
        }
    }

    /// Wait on `changed`, keeping the waiter count used to skip notifications.
    fn wait_changed<'a>(
        &self,
        mut state: std::sync::MutexGuard<'a, QueueState>,
    ) -> std::sync::MutexGuard<'a, QueueState> {
        state.waiters += 1;
        let mut state = self.changed.wait(state).unwrap_or_else(|p| p.into_inner());
        state.waiters -= 1;
        state
    }

    fn wake_async_senders(&self) {
        if self.async_waiter_count.load(Ordering::SeqCst) == 0 {
            return;
        }
        let waiters: Vec<_> = self
            .async_waiters
            .lock()
            .unwrap()
            .iter()
            .filter_map(|w| w.upgrade())
            .collect();
        for waiter in waiters {
            waiter.wake();
        }
    }
}

/// Sender for the prioritized driver event queue.
pub struct EventSender {
    shared: Arc<QueueShared>,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub(crate) struct InboundQueueSnapshot {
    pub heights: [usize; INBOUND_QUEUE_COUNT],
    pub capacities: [usize; INBOUND_QUEUE_COUNT],
    pub dropped: [usize; INBOUND_QUEUE_COUNT],
}

impl InboundQueueSnapshot {
    pub fn total_height(self) -> usize {
        self.heights.iter().sum()
    }

    pub fn total_capacity(self) -> usize {
        self.capacities.iter().sum()
    }

    pub fn total_dropped(self) -> usize {
        self.dropped.iter().sum()
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub(crate) struct BurstClassStats {
    pub(crate) count: usize,
    pub(crate) activated: Option<f64>,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub(crate) struct DynamicBurstStats {
    pub(crate) announce: BurstClassStats,
    pub(crate) path_request: BurstClassStats,
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
            // The notification is retained until the next wait, so a
            // receiver about to park still observes the disconnect.
            self.shared.wake_poller();
        }
    }
}

impl EventSender {
    /// The poller the receiver waits in; sources registered on it wake the
    /// receiver like a queued event does.
    pub(crate) fn poller(&self) -> &Arc<polling::Poller> {
        &self.shared.poller
    }

    /// Serve `source` on the receiving thread from now on.
    pub(crate) fn register_source(
        &self,
        key: usize,
        source: Box<dyn LoopSource>,
    ) -> std::io::Result<()> {
        let mut registry = self
            .shared
            .sources
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        self.shared.add_source(&mut registry, key, source)
    }

    /// Enqueue events produced on the receiving thread itself, by a loop
    /// source. Never blocks, since the caller is the queue's consumer: data
    /// frames are always queued, past capacity if need be, so none is lost;
    /// announce, path-request and ingress-limited frames keep their
    /// drop-on-full policy; control events are always queued. Returns
    /// whether inbound data still has room, so a source stops reading once
    /// it does not.
    pub(crate) fn push_from_loop(
        &self,
        events: impl IntoIterator<Item = Event>,
    ) -> Result<bool, std::sync::mpsc::RecvError> {
        let mut state = self.shared.state.lock().unwrap_or_else(|p| p.into_inner());
        if !state.receiver_alive {
            return Err(std::sync::mpsc::RecvError);
        }
        for event in events {
            let sequence = state.next_sequence;
            match self.classify(&event, &state) {
                Some(class) => {
                    let index = class as usize;
                    if class != QueueClass::Data
                        && state.inbound[index].len() >= self.shared.inbound_capacities[index]
                    {
                        state.inbound_dropped[index] =
                            state.inbound_dropped[index].saturating_add(1);
                        continue;
                    }
                    state.inbound[index].push_back(QueuedEvent { sequence, event });
                }
                None => {
                    if let Event::SendLinkTracked { completion, .. } = &event {
                        completion.admit();
                    }
                    state.control.push_back(QueuedEvent { sequence, event });
                }
            }
            state.next_sequence = state.next_sequence.wrapping_add(1);
        }
        let room = self.shared.data_has_room(&state);
        self.shared.notify_change(&state, false);
        Ok(room)
    }

    /// Whether inbound data has room; loop sources check before reading.
    pub(crate) fn inbound_data_has_room(&self) -> bool {
        let state = self.shared.state.lock().unwrap_or_else(|p| p.into_inner());
        self.shared.data_has_room(&state)
    }

    pub(crate) fn local_ratchets(&self) -> &crate::local_ratchet::Registry {
        &self.shared.local_ratchets
    }

    pub(crate) fn link_send_pool(&self) -> &Arc<crate::link_send::SendPool> {
        &self.shared.link_sends
    }

    pub(crate) async fn send_async(
        &self,
        event: Event,
    ) -> Result<(), crate::link_send::LinkSendError> {
        use crate::link_send::{LinkSendError, Waiter};
        let waiter = Arc::new(Waiter::default());
        {
            let mut waiters = self.shared.async_waiters.lock().unwrap();
            waiters.retain(|w| w.strong_count() > 0);
            waiters.push(Arc::downgrade(&waiter));
            self.shared
                .async_waiter_count
                .store(waiters.len(), Ordering::SeqCst);
        }
        let mut pending = Some(event);
        futures::future::poll_fn(|cx| {
            waiter.register(cx);
            match self.try_send(pending.take().unwrap()) {
                Ok(()) => std::task::Poll::Ready(Ok(())),
                Err(std::sync::mpsc::TrySendError::Full(event)) => {
                    pending = Some(event);
                    std::task::Poll::Pending
                }
                Err(std::sync::mpsc::TrySendError::Disconnected(_)) => {
                    std::task::Poll::Ready(Err(LinkSendError::DriverStopped))
                }
            }
        })
        .await
    }
    fn classify(&self, event: &Event, state: &QueueState) -> Option<QueueClass> {
        let Event::Frame {
            interface_id, data, ..
        } = event
        else {
            return None;
        };
        let packet = PacketHeader::unpack(data);
        if packet.as_ref().is_some_and(|packet| {
            packet.flags.packet_type == rns_core::constants::PACKET_TYPE_ANNOUNCE
        }) {
            return Some(if state.announce_bursts.contains_key(interface_id) {
                QueueClass::IngressLimited
            } else {
                QueueClass::Announce
            });
        }
        if packet
            .as_ref()
            .is_some_and(|packet| packet.destination_hash == self.shared.path_request_dest)
        {
            return Some(if state.path_request_bursts.contains_key(interface_id) {
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
        let state = self.shared.state.lock().unwrap_or_else(|p| p.into_inner());
        let (state, result) = self.enqueue_locked(state, event, block_control, drop_full_inbound);
        self.shared.notify_change(&state, false);
        drop(state);
        result
    }

    /// Enqueue one event while holding the state lock. Waits for space (when
    /// permitted) release and reacquire the lock; before waiting, any thread
    /// already waiting is woken so events pushed earlier in a batch are seen.
    #[allow(clippy::result_large_err)]
    fn enqueue_locked<'a>(
        &'a self,
        mut state: std::sync::MutexGuard<'a, QueueState>,
        event: Event,
        block_control: bool,
        drop_full_inbound: bool,
    ) -> (
        std::sync::MutexGuard<'a, QueueState>,
        Result<(), std::sync::mpsc::TrySendError<Event>>,
    ) {
        if !state.receiver_alive {
            return (
                state,
                Err(std::sync::mpsc::TrySendError::Disconnected(event)),
            );
        }
        let class = self.classify(&event, &state);
        if let Some(class) = class {
            let index = class as usize;
            // Interface readers deliver ordinary data with backpressure: when
            // the driver is behind, the reader thread pauses here, its socket
            // stops being read, and the transport (e.g. TCP flow control)
            // slows the sender instead of the relay silently losing frames.
            // Announce, path-request and ingress-limited classes keep their
            // protective drop-on-full policy.
            if block_control && class == QueueClass::Data {
                while state.inbound[index].len() >= self.shared.inbound_capacities[index] {
                    self.shared.notify_change(&state, true);
                    state = self.shared.wait_changed(state);
                    if !state.receiver_alive {
                        return (
                            state,
                            Err(std::sync::mpsc::TrySendError::Disconnected(event)),
                        );
                    }
                }
            }
            if state.inbound[index].len() >= self.shared.inbound_capacities[index] {
                state.inbound_dropped[index] = state.inbound_dropped[index].saturating_add(1);
                let result = if drop_full_inbound {
                    Ok(())
                } else {
                    Err(std::sync::mpsc::TrySendError::Full(event))
                };
                return (state, result);
            }
            let sequence = state.next_sequence;
            state.next_sequence = state.next_sequence.wrapping_add(1);
            state.inbound[index].push_back(QueuedEvent { sequence, event });
            return (state, Ok(()));
        }

        while state.control.len() >= self.shared.control_capacity {
            if !block_control {
                return (state, Err(std::sync::mpsc::TrySendError::Full(event)));
            }
            self.shared.notify_change(&state, true);
            state = self.shared.wait_changed(state);
            if !state.receiver_alive {
                return (
                    state,
                    Err(std::sync::mpsc::TrySendError::Disconnected(event)),
                );
            }
        }
        let sequence = state.next_sequence;
        state.next_sequence = state.next_sequence.wrapping_add(1);
        if let Event::SendLinkTracked { completion, .. } = &event {
            completion.admit();
        }
        state.control.push_back(QueuedEvent { sequence, event });
        (state, Ok(()))
    }

    /// Send several events in order under one lock acquisition, with the
    /// same per-event semantics as [`EventSender::send`]. Interface readers
    /// use this for all frames decoded from one socket read. Stops at the
    /// first event that cannot be delivered because the receiver is gone.
    #[allow(clippy::result_large_err)]
    pub fn send_batch(
        &self,
        events: impl IntoIterator<Item = Event>,
    ) -> Result<(), std::sync::mpsc::SendError<Event>> {
        let mut state = self.shared.state.lock().unwrap_or_else(|p| p.into_inner());
        let mut result = Ok(());
        for event in events {
            let (next, sent) = self.enqueue_locked(state, event, true, true);
            state = next;
            if let Err(
                std::sync::mpsc::TrySendError::Full(event)
                | std::sync::mpsc::TrySendError::Disconnected(event),
            ) = sent
            {
                result = Err(std::sync::mpsc::SendError(event));
                break;
            }
        }
        self.shared.notify_change(&state, false);
        drop(state);
        result
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
        announce_activated: Option<f64>,
        path_request_activated: Option<f64>,
    ) {
        let mut state = self.shared.state.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(activated) = announce_activated {
            state.announce_bursts.insert(interface_id, activated);
        } else {
            state.announce_bursts.remove(&interface_id);
        }
        if let Some(activated) = path_request_activated {
            state.path_request_bursts.insert(interface_id, activated);
        } else {
            state.path_request_bursts.remove(&interface_id);
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
        state.announce_bursts.remove(&interface_id);
        state.path_request_bursts.remove(&interface_id);
        state.dynamic_interface_parents.remove(&interface_id);
    }

    pub(crate) fn inbound_queue_snapshot(&self) -> InboundQueueSnapshot {
        let state = self.shared.state.lock().unwrap_or_else(|p| p.into_inner());
        InboundQueueSnapshot {
            heights: std::array::from_fn(|index| state.inbound[index].len()),
            capacities: self.shared.inbound_capacities,
            dropped: state.inbound_dropped,
        }
    }

    pub(crate) fn dynamic_burst_stats(&self, parent_id: InterfaceId) -> Option<DynamicBurstStats> {
        let state = self.shared.state.lock().unwrap_or_else(|p| p.into_inner());
        let children = state
            .dynamic_interface_parents
            .iter()
            .filter(|(_, candidate_parent)| **candidate_parent == parent_id);
        let mut found = false;
        let mut announce = (0, None::<f64>);
        let mut path_request = (0, None::<f64>);
        for (child, _) in children {
            found = true;
            if let Some(activated) = state.announce_bursts.get(child) {
                announce.0 += 1;
                announce.1 = Some(
                    announce
                        .1
                        .map_or(*activated, |current| current.min(*activated)),
                );
            }
            if let Some(activated) = state.path_request_bursts.get(child) {
                path_request.0 += 1;
                path_request.1 = Some(
                    path_request
                        .1
                        .map_or(*activated, |current| current.min(*activated)),
                );
            }
        }
        found.then_some(DynamicBurstStats {
            announce: BurstClassStats {
                count: announce.0,
                activated: announce.1,
            },
            path_request: BurstClassStats {
                count: path_request.0,
                activated: path_request.1,
            },
        })
    }
}

/// Receiver for the prioritized driver event queue.
pub struct EventReceiver {
    shared: Arc<QueueShared>,
    /// Events already taken from the shared queue, in delivery order. The
    /// driver drains up to [`RECEIVE_BATCH`] events per lock acquisition so
    /// interface readers contend for the queue lock less often.
    prefetched: std::cell::RefCell<VecDeque<ReceivedEvent>>,
}

/// Events moved from the shared queue per lock acquisition. Bounds how long
/// a higher-priority event arriving meanwhile waits behind earlier events.
const RECEIVE_BATCH: usize = 16;

impl Drop for EventReceiver {
    fn drop(&mut self) {
        let mut state = self.shared.state.lock().unwrap_or_else(|p| p.into_inner());
        state.receiver_alive = false;
        drop(state);
        self.shared.changed.notify_all();
        self.shared.link_sends.close();
        self.shared.wake_async_senders();
        // Nothing serves the sources any more. Close their sockets, and drop
        // the senders they hold, which would otherwise keep this queue (and
        // them) alive forever through the registry.
        let sources: Vec<_> = {
            let mut registry = self
                .shared
                .sources
                .lock()
                .unwrap_or_else(|p| p.into_inner());
            registry.suspended.clear();
            registry.paused.clear();
            registry.sources.drain().map(|(_, source)| source).collect()
        };
        for source in sources {
            self.shared.remove_source(source);
        }
    }
}

impl EventReceiver {
    fn pop_locked(&self, state: &mut QueueState) -> Option<ReceivedEvent> {
        let event = state.pop_next();
        if event.is_some() && state.waiters > 0 {
            self.shared.changed.notify_all();
        }
        event
    }

    /// Whether events already taken from the queue are waiting locally, so
    /// the next receive cannot block.
    pub(crate) fn has_prefetched(&self) -> bool {
        !self.prefetched.borrow().is_empty()
    }

    /// Take the next event without blocking: `Ok(None)` when the queue is
    /// empty, `Err` once it is empty and every sender is gone.
    pub(crate) fn try_recv_classified(
        &self,
    ) -> Result<Option<ReceivedEvent>, std::sync::mpsc::RecvError> {
        if let Some(event) = self.prefetched.borrow_mut().pop_front() {
            return Ok(Some(event));
        }
        let mut state = self.shared.state.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(event) = self.pop_locked(&mut state) {
            let mut prefetched = self.prefetched.borrow_mut();
            while prefetched.len() + 1 < RECEIVE_BATCH {
                match self.pop_locked(&mut state) {
                    Some(next) => prefetched.push_back(next),
                    None => break,
                }
            }
            drop(prefetched);
            drop(state);
            self.shared.wake_async_senders();
            return Ok(Some(event));
        }
        if self.shared.sender_count.load(Ordering::Acquire) == 0 {
            return Err(std::sync::mpsc::RecvError);
        }
        Ok(None)
    }

    /// Block in the poller until an event is queued, every sender is gone, a
    /// source registered on the poller is ready, or `timeout` elapses.
    /// Ready sources are reported in `ready`; returns at once if events are
    /// already waiting.
    pub(crate) fn wait(
        &self,
        ready: &mut polling::Events,
        timeout: Option<Duration>,
    ) -> std::io::Result<()> {
        if self.has_prefetched() {
            return Ok(());
        }
        self.resume_suspended();
        let mut state = self.shared.state.lock().unwrap_or_else(|p| p.into_inner());
        if state.has_events() || self.shared.sender_count.load(Ordering::Acquire) == 0 {
            return Ok(());
        }
        // Producers read this under the lock: one that enqueues after the
        // check above sees the flag and notifies, and the poller keeps that
        // notification until the wait below consumes it.
        state.receiver_parked = true;
        drop(state);
        let result = self.shared.poller.wait(ready, timeout).map(|_| ());
        self.shared
            .state
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .receiver_parked = false;
        result
    }

    /// Collect ready sources without blocking or parking, for a receiver
    /// that still has queued events: sources must not starve while other
    /// threads keep the queue busy. Suspended sources resume only once
    /// inbound data has room again.
    pub(crate) fn poll_ready(&self, ready: &mut polling::Events) -> std::io::Result<()> {
        let room = {
            let state = self.shared.state.lock().unwrap_or_else(|p| p.into_inner());
            self.shared.data_has_room(&state)
        };
        if room {
            self.resume_suspended();
        }
        self.shared
            .poller
            .wait(ready, Some(Duration::ZERO))
            .map(|_| ())
    }

    /// Sources suspended because inbound data was full read again once the
    /// receiver is about to wait, i.e. has drained the queue.
    fn resume_suspended(&self) {
        let mut registry = self
            .shared
            .sources
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        let registry = &mut *registry;
        for key in registry.suspended.drain(..) {
            if let Some(source) = registry.sources.get(&key) {
                self.shared.arm_source(key, source.as_ref());
            }
        }
    }

    /// Serve the loop sources `ready` reports readable. Keys of other kinds
    /// (the driver's writers) are left to the caller.
    pub(crate) fn serve_sources(&self, ready: &polling::Events) {
        let mut registry = self
            .shared
            .sources
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        let registry = &mut *registry;
        if registry.buf.is_empty() {
            registry.buf = vec![0; LOOP_READ_BUFFER];
        }
        let mut cx = LoopContext {
            buf: &mut registry.buf,
            added: Vec::new(),
        };
        for event in ready.iter() {
            if !event.readable {
                continue;
            }
            let Some(mut source) = registry.sources.remove(&event.key) else {
                continue;
            };
            match source.on_ready(&mut cx) {
                SourceStatus::Rearm => {
                    self.shared.arm_source(event.key, source.as_ref());
                    registry.sources.insert(event.key, source);
                }
                SourceStatus::Suspend => {
                    registry.suspended.push(event.key);
                    registry.sources.insert(event.key, source);
                }
                SourceStatus::Pause => {
                    registry.paused.push(event.key);
                    registry.sources.insert(event.key, source);
                }
                SourceStatus::Remove => self.shared.remove_source(source),
            }
        }
        for (key, source) in std::mem::take(&mut cx.added) {
            if let Err((error, mut source)) = self.shared.try_add_source(registry, key, source) {
                log::warn!("failed to register a loop source: {error}");
                source.on_abandoned();
            }
        }
    }

    /// Close sources that report themselves stopped.
    pub(crate) fn sweep_stopped_sources(&self) {
        let mut registry = self
            .shared
            .sources
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        let stopped: Vec<usize> = registry
            .sources
            .iter()
            .filter(|(_, source)| source.stopped())
            .map(|(key, _)| *key)
            .collect();
        for key in stopped {
            registry.suspended.retain(|suspended| *suspended != key);
            registry.paused.retain(|paused| *paused != key);
            if let Some(source) = registry.sources.remove(&key) {
                self.shared.remove_source(source);
            }
        }
    }

    /// Watch sources paused by [`SourceStatus::Pause`] again. Called once
    /// per tick, so a paused source stays idle for about a second.
    pub(crate) fn resume_paused_sources(&self) {
        let mut registry = self
            .shared
            .sources
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        let registry = &mut *registry;
        for key in registry.paused.drain(..) {
            if let Some(source) = registry.sources.get(&key) {
                self.shared.arm_source(key, source.as_ref());
            }
        }
    }

    pub fn recv(&self) -> Result<Event, std::sync::mpsc::RecvError> {
        self.recv_classified().map(|received| received.event)
    }

    /// Blocking receive. While waiting it serves loop sources, so any
    /// receiver drives the sockets registered on the queue.
    pub(crate) fn recv_classified(&self) -> Result<ReceivedEvent, std::sync::mpsc::RecvError> {
        let mut ready = polling::Events::new();
        loop {
            if let Some(event) = self.try_recv_classified()? {
                return Ok(event);
            }
            ready.clear();
            if let Err(error) = self.wait(&mut ready, None) {
                log::warn!("event receiver wait failed: {error}");
            }
            self.serve_sources(&ready);
        }
    }

    pub fn try_recv(&self) -> Result<Event, std::sync::mpsc::TryRecvError> {
        if let Some(event) = self.prefetched.borrow_mut().pop_front() {
            return Ok(event.event);
        }
        let mut state = self.shared.state.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(event) = self.pop_locked(&mut state) {
            drop(state);
            self.shared.wake_async_senders();
            return Ok(event.event);
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
        if let Some(event) = self.prefetched.borrow_mut().pop_front() {
            return Ok(event.event);
        }
        let deadline = Instant::now() + timeout;
        let mut ready = polling::Events::new();
        loop {
            match self.try_recv_classified() {
                Ok(Some(event)) => return Ok(event.event),
                Ok(None) => {}
                Err(_) => return Err(std::sync::mpsc::RecvTimeoutError::Disconnected),
            }
            let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
                return Err(std::sync::mpsc::RecvTimeoutError::Timeout);
            };
            ready.clear();
            if let Err(error) = self.wait(&mut ready, Some(remaining)) {
                log::warn!("event receiver wait failed: {error}");
            }
            self.serve_sources(&ready);
        }
    }
}

pub fn channel() -> (EventSender, EventReceiver) {
    channel_with_queue_capacities(
        DEFAULT_EVENT_QUEUE_CAPACITY,
        InboundQueueCapacities::default(),
    )
}

pub fn channel_with_capacity(capacity: usize) -> (EventSender, EventReceiver) {
    let capacity = capacity.max(1);
    channel_with_queue_capacities(
        capacity,
        InboundQueueCapacities::from_shared_capacity(capacity),
    )
}

pub(crate) fn channel_with_queue_capacities(
    control_capacity: usize,
    inbound_capacities: InboundQueueCapacities,
) -> (EventSender, EventReceiver) {
    let shared = Arc::new(QueueShared {
        local_ratchets: Default::default(),
        link_sends: crate::link_send::SendPool::new(control_capacity),
        async_waiters: Mutex::new(Vec::new()),
        async_waiter_count: AtomicUsize::new(0),
        state: Mutex::new(QueueState::new()),
        changed: Condvar::new(),
        poller: Arc::new(polling::Poller::new().expect("create the driver event poller")),
        sources: Mutex::default(),
        sender_count: AtomicUsize::new(1),
        control_capacity: control_capacity.max(1),
        inbound_capacities: inbound_capacities
            .as_array()
            .map(|capacity| capacity.max(1)),
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
        EventReceiver {
            shared,
            prefetched: Default::default(),
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use rns_core::packet::{PacketFlags, RawPacket};
    use std::sync::mpsc::TrySendError;
    use std::time::Duration;

    #[test]
    fn inbound_classification_matches_full_unpack_with_burst_limits() {
        let (tx, _rx) = channel_with_capacity(2);
        let interface_id = InterfaceId(4);
        for flags in 0..=u8::MAX {
            for hops in [
                0,
                rns_core::constants::PATHFINDER_M - 1,
                rns_core::constants::PATHFINDER_M,
                255,
            ] {
                for matching in [false, true] {
                    let mut raw = [0x31; 80];
                    raw[0] = flags;
                    raw[1] = hops;
                    let start = if flags & 0x40 == 0 { 2 } else { 18 };
                    if matching {
                        raw[start..start + 16].copy_from_slice(&tx.shared.path_request_dest);
                    }
                    for len in (0..=40).chain([80]) {
                        let packet = RawPacket::unpack(&raw[..len]).ok();
                        let event = Event::Frame {
                            interface_id,
                            data: raw[..len].to_vec(),
                            rssi: None,
                            snr: None,
                        };
                        for announce_limited in [false, true] {
                            for path_limited in [false, true] {
                                let mut state = QueueState::new();
                                if announce_limited {
                                    state.announce_bursts.insert(interface_id, 1.0);
                                }
                                if path_limited {
                                    state.path_request_bursts.insert(interface_id, 1.0);
                                }
                                let expected = match packet.as_ref() {
                                    Some(p)
                                        if p.flags.packet_type
                                            == rns_core::constants::PACKET_TYPE_ANNOUNCE =>
                                    {
                                        if announce_limited {
                                            QueueClass::IngressLimited
                                        } else {
                                            QueueClass::Announce
                                        }
                                    }
                                    Some(p)
                                        if p.destination_hash == tx.shared.path_request_dest =>
                                    {
                                        if path_limited {
                                            QueueClass::IngressLimited
                                        } else {
                                            QueueClass::PathRequest
                                        }
                                    }
                                    _ => QueueClass::Data,
                                };
                                assert_eq!(tx.classify(&event, &state), Some(expected),
                                    "flags={flags} hops={hops} len={len} matching={matching} announce_limited={announce_limited} path_limited={path_limited}");
                            }
                        }
                    }
                }
            }
        }
        assert_eq!(tx.classify(&Event::Tick, &QueueState::new()), None);
    }

    #[test]
    fn async_control_send_waits_for_space_and_handles_receiver_shutdown() {
        use futures::{executor::block_on, FutureExt};
        let (tx, rx) = channel_with_capacity(1);
        tx.try_send(Event::Tick).unwrap();
        let mut pending = Box::pin(tx.send_async(Event::Shutdown));
        assert!(pending.as_mut().now_or_never().is_none());
        assert!(matches!(rx.try_recv(), Ok(Event::Tick)));
        block_on(pending).unwrap();
        assert!(matches!(rx.try_recv(), Ok(Event::Shutdown)));
        tx.try_send(Event::Tick).unwrap();
        let mut pending = Box::pin(tx.send_async(Event::Shutdown));
        assert!(pending.as_mut().now_or_never().is_none());
        drop(rx);
        assert_eq!(
            block_on(pending),
            Err(crate::link_send::LinkSendError::DriverStopped)
        );
    }
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
    fn inbound_queue_defaults_match_upstream() {
        assert_eq!(
            InboundQueueCapacities::default(),
            InboundQueueCapacities {
                data: 1024,
                announce: 128,
                path_request: 128,
                ingress_limited: 8,
            }
        );
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
        tx.set_ingress_bursts(InterfaceId(4), None, Some(4.0));

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
        tx.register_dynamic_parent(InterfaceId(13), InterfaceId(10));
        tx.register_dynamic_parent(InterfaceId(21), InterfaceId(20));
        tx.set_ingress_bursts(InterfaceId(11), Some(11.0), None);
        tx.set_ingress_bursts(InterfaceId(12), None, Some(12.0));
        tx.set_ingress_bursts(InterfaceId(13), Some(9.0), None);
        tx.set_ingress_bursts(InterfaceId(21), Some(21.0), Some(22.0));

        assert_eq!(
            tx.dynamic_burst_stats(InterfaceId(10)),
            Some(DynamicBurstStats {
                announce: BurstClassStats {
                    count: 2,
                    activated: Some(9.0),
                },
                path_request: BurstClassStats {
                    count: 1,
                    activated: Some(12.0),
                },
            })
        );
        assert_eq!(
            tx.dynamic_burst_stats(InterfaceId(20)),
            Some(DynamicBurstStats {
                announce: BurstClassStats {
                    count: 1,
                    activated: Some(21.0),
                },
                path_request: BurstClassStats {
                    count: 1,
                    activated: Some(22.0),
                },
            })
        );
        assert_eq!(tx.dynamic_burst_stats(InterfaceId(30)), None);

        tx.remove_interface(InterfaceId(12));
        assert_eq!(
            tx.dynamic_burst_stats(InterfaceId(10)),
            Some(DynamicBurstStats {
                announce: BurstClassStats {
                    count: 2,
                    activated: Some(9.0),
                },
                path_request: BurstClassStats {
                    count: 0,
                    activated: None,
                },
            })
        );
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
    fn custom_traffic_class_capacities_are_enforced_independently() {
        let capacities = InboundQueueCapacities {
            data: 1,
            announce: 2,
            path_request: 3,
            ingress_limited: 4,
        };
        let (tx, _rx) = channel_with_queue_capacities(9, capacities);
        let path_dest =
            rns_core::destination::destination_hash("rnstransport", &["path", "request"], None);
        tx.set_ingress_bursts(InterfaceId(4), None, Some(1.0));

        let classes = [
            (1, [0xD1; 16], rns_core::constants::PACKET_TYPE_DATA, 1),
            (2, [0xA2; 16], rns_core::constants::PACKET_TYPE_ANNOUNCE, 2),
            (3, path_dest, rns_core::constants::PACKET_TYPE_DATA, 3),
            (4, path_dest, rns_core::constants::PACKET_TYPE_DATA, 4),
        ];
        for (interface_id, destination, packet_type, capacity) in classes {
            for _ in 0..capacity {
                tx.try_send(frame(interface_id, destination, packet_type))
                    .unwrap();
            }
            assert!(matches!(
                tx.try_send(frame(interface_id, destination, packet_type)),
                Err(TrySendError::Full(_))
            ));
        }

        assert_eq!(
            tx.inbound_queue_snapshot().capacities,
            capacities.as_array()
        );
        assert_eq!(tx.inbound_queue_snapshot().heights, [1, 2, 3, 4]);
        assert_eq!(tx.inbound_queue_snapshot().dropped, [1, 1, 1, 1]);
        assert_eq!(tx.inbound_queue_snapshot().total_dropped(), 4);
    }

    #[test]
    fn ingress_limited_classification_survives_limiter_state_change() {
        let (tx, rx) = channel_with_capacity(2);
        let path_dest =
            rns_core::destination::destination_hash("rnstransport", &["path", "request"], None);
        tx.set_ingress_bursts(InterfaceId(4), None, Some(1.0));
        tx.send(frame(4, path_dest, rns_core::constants::PACKET_TYPE_DATA))
            .unwrap();

        tx.set_ingress_bursts(InterfaceId(4), None, None);
        let received = rx.recv_classified().unwrap();
        assert!(received.ingress_limited);
        assert_eq!(frame_interface(received.event), 4);
    }

    #[test]
    fn ingress_limited_announce_keeps_higher_traffic_class() {
        let (tx, rx) = channel_with_capacity(2);
        tx.set_ingress_bursts(InterfaceId(4), Some(1.0), None);
        tx.send(frame(
            4,
            [0xA4; 16],
            rns_core::constants::PACKET_TYPE_ANNOUNCE,
        ))
        .unwrap();

        tx.set_ingress_bursts(InterfaceId(4), None, None);
        let received = rx.recv_classified().unwrap();
        assert!(received.ingress_limited);
        assert_eq!(frame_interface(received.event), 4);
    }

    #[test]
    fn blocking_send_waits_for_space_in_the_data_class() {
        let (tx, rx) = channel_with_capacity(1);
        tx.send(frame(1, [0xD1; 16], rns_core::constants::PACKET_TYPE_DATA))
            .unwrap();

        // A reader delivering data into a full queue pauses (applying
        // backpressure to its own transport) instead of dropping the frame.
        let reader = {
            let tx = tx.clone();
            std::thread::spawn(move || {
                tx.send(frame(2, [0xD2; 16], rns_core::constants::PACKET_TYPE_DATA))
                    .map_err(|_| ())
            })
        };
        std::thread::sleep(std::time::Duration::from_millis(50));
        assert!(
            !reader.is_finished(),
            "a full data queue must pause its reader"
        );
        assert_eq!(tx.inbound_queue_snapshot().dropped, [0, 0, 0, 0]);

        assert_eq!(frame_interface(rx.recv().unwrap()), 1);
        reader.join().unwrap().unwrap();
        assert_eq!(frame_interface(rx.recv().unwrap()), 2);
        assert_eq!(tx.inbound_queue_snapshot().dropped, [0, 0, 0, 0]);
    }

    #[test]
    fn batch_larger_than_the_queue_wakes_a_waiting_receiver_and_keeps_order() {
        let (tx, rx) = channel_with_capacity(2);
        // The receiver is already waiting on an empty queue when the batch
        // starts; the batch must wake it before blocking on a full queue.
        let receiver = std::thread::spawn(move || {
            (0..6)
                .map(|_| frame_interface(rx.recv().unwrap()))
                .collect::<Vec<_>>()
        });
        std::thread::sleep(std::time::Duration::from_millis(20));
        tx.send_batch((1..=6).map(|id| {
            frame(
                id,
                [0xD0 + id as u8; 16],
                rns_core::constants::PACKET_TYPE_DATA,
            )
        }))
        .unwrap();
        assert_eq!(receiver.join().unwrap(), vec![1, 2, 3, 4, 5, 6]);
        assert_eq!(tx.inbound_queue_snapshot().dropped, [0, 0, 0, 0]);
    }

    #[test]
    fn blocked_data_sender_is_released_when_the_receiver_closes() {
        let (tx, rx) = channel_with_capacity(1);
        tx.send(frame(1, [0xD1; 16], rns_core::constants::PACKET_TYPE_DATA))
            .unwrap();
        let reader = {
            let tx = tx.clone();
            std::thread::spawn(move || {
                tx.send(frame(2, [0xD2; 16], rns_core::constants::PACKET_TYPE_DATA))
                    .map_err(|_| ())
            })
        };
        std::thread::sleep(std::time::Duration::from_millis(20));
        drop(rx);
        assert!(reader.join().unwrap().is_err());
    }

    #[test]
    fn try_send_still_refuses_a_full_data_class() {
        let (tx, _rx) = channel_with_capacity(1);
        tx.try_send(frame(1, [0xD1; 16], rns_core::constants::PACKET_TYPE_DATA))
            .unwrap();
        assert!(matches!(
            tx.try_send(frame(2, [0xD2; 16], rns_core::constants::PACKET_TYPE_DATA)),
            Err(std::sync::mpsc::TrySendError::Full(_))
        ));
        assert_eq!(tx.inbound_queue_snapshot().dropped, [1, 0, 0, 0]);
    }

    /// Run `wait` on another thread and report when it returns.
    fn parked_wait(
        rx: EventReceiver,
        timeout: Option<Duration>,
    ) -> std::sync::mpsc::Receiver<(EventReceiver, std::io::Result<()>)> {
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let mut ready = polling::Events::new();
            let result = rx.wait(&mut ready, timeout);
            let _ = done_tx.send((rx, result));
        });
        done_rx
    }

    fn assert_parked(done: &std::sync::mpsc::Receiver<(EventReceiver, std::io::Result<()>)>) {
        assert!(matches!(
            done.recv_timeout(Duration::from_millis(50)),
            Err(std::sync::mpsc::RecvTimeoutError::Timeout)
        ));
    }

    /// A loop source over one end of a socket pair: every readable byte
    /// becomes a Tick; `spawn` makes it add an unregistrable child.
    struct PairSource {
        stream: std::os::unix::net::UnixStream,
        tx: EventSender,
        spawn: bool,
        events: Arc<Mutex<Vec<&'static str>>>,
    }

    struct BadFdSource(Arc<Mutex<Vec<&'static str>>>);

    impl LoopSource for BadFdSource {
        fn fd(&self) -> std::os::fd::RawFd {
            // Not an open descriptor: registration fails with EBADF.
            999_999
        }
        fn on_ready(&mut self, _cx: &mut LoopContext<'_>) -> SourceStatus {
            unreachable!("never registered")
        }
        fn on_abandoned(&mut self) {
            self.0.lock().unwrap().push("abandoned");
        }
    }

    impl LoopSource for PairSource {
        fn fd(&self) -> std::os::fd::RawFd {
            std::os::fd::AsRawFd::as_raw_fd(&self.stream)
        }
        fn on_ready(&mut self, cx: &mut LoopContext<'_>) -> SourceStatus {
            use std::io::Read;
            self.stream.set_nonblocking(true).unwrap();
            match self.stream.read(cx.buf) {
                Ok(0) => SourceStatus::Remove,
                Ok(n) => {
                    self.events.lock().unwrap().push("read");
                    self.tx.push_from_loop((0..n).map(|_| Event::Tick)).unwrap();
                    if std::mem::take(&mut self.spawn) {
                        cx.add_source(99, Box::new(BadFdSource(Arc::clone(&self.events))));
                    }
                    SourceStatus::Rearm
                }
                Err(_) => SourceStatus::Rearm,
            }
        }
        fn on_removed(&mut self) {
            self.events.lock().unwrap().push("removed");
        }
    }

    fn pair_source(
        tx: &EventSender,
        spawn: bool,
    ) -> (
        std::os::unix::net::UnixStream,
        Arc<Mutex<Vec<&'static str>>>,
    ) {
        let (ours, theirs) = std::os::unix::net::UnixStream::pair().unwrap();
        let events = Arc::new(Mutex::new(Vec::new()));
        tx.register_source(
            2,
            Box::new(PairSource {
                stream: ours,
                tx: tx.clone(),
                spawn,
                events: Arc::clone(&events),
            }),
        )
        .unwrap();
        (theirs, events)
    }

    #[test]
    fn sources_are_polled_while_the_queue_is_still_busy() {
        use std::io::Write;
        let (tx, rx) = channel();
        let (mut peer, events) = pair_source(&tx, false);
        tx.send(Event::Tick).unwrap();
        peer.write_all(&[1, 2, 3]).unwrap();
        // The queue is not empty, so `wait` would return without polling.
        let mut ready = polling::Events::new();
        rx.poll_ready(&mut ready).unwrap();
        rx.serve_sources(&ready);
        assert_eq!(*events.lock().unwrap(), ["read"]);
        let mut ticks = 0;
        while rx.try_recv_classified().unwrap().is_some() {
            ticks += 1;
        }
        assert_eq!(ticks, 1 + 3);
    }

    /// A loop source that never reads its socket and pauses on every pass,
    /// so the socket stays readable; counts how often it is served.
    struct PausingSource {
        stream: std::os::unix::net::UnixStream,
        served: Arc<Mutex<usize>>,
        stop: Arc<std::sync::atomic::AtomicBool>,
        events: Arc<Mutex<Vec<&'static str>>>,
    }

    impl LoopSource for PausingSource {
        fn fd(&self) -> std::os::fd::RawFd {
            std::os::fd::AsRawFd::as_raw_fd(&self.stream)
        }
        fn stopped(&self) -> bool {
            self.stop.load(Ordering::Relaxed)
        }
        fn on_ready(&mut self, _cx: &mut LoopContext<'_>) -> SourceStatus {
            *self.served.lock().unwrap() += 1;
            SourceStatus::Pause
        }
        fn on_removed(&mut self) {
            self.events.lock().unwrap().push("removed");
        }
    }

    struct PausingPair {
        peer: std::os::unix::net::UnixStream,
        served: Arc<Mutex<usize>>,
        stop: Arc<std::sync::atomic::AtomicBool>,
        events: Arc<Mutex<Vec<&'static str>>>,
    }

    fn pausing_source(tx: &EventSender) -> PausingPair {
        use std::io::Write;
        let (ours, mut peer) = std::os::unix::net::UnixStream::pair().unwrap();
        let served = Arc::new(Mutex::new(0));
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let events = Arc::new(Mutex::new(Vec::new()));
        tx.register_source(
            7,
            Box::new(PausingSource {
                stream: ours,
                served: Arc::clone(&served),
                stop: Arc::clone(&stop),
                events: Arc::clone(&events),
            }),
        )
        .unwrap();
        peer.write_all(&[1]).unwrap();
        PausingPair {
            peer,
            served,
            stop,
            events,
        }
    }

    fn serve_once(rx: &EventReceiver) {
        let mut ready = polling::Events::new();
        rx.wait(&mut ready, Some(Duration::from_millis(20)))
            .unwrap();
        rx.serve_sources(&ready);
    }

    #[test]
    fn a_paused_source_is_served_again_only_after_the_tick_resume() {
        let (tx, rx) = channel();
        let pair = pausing_source(&tx);
        serve_once(&rx);
        assert_eq!(*pair.served.lock().unwrap(), 1);
        // Still readable, but neither waiting (which resumes suspended
        // sources) nor polling serves it while paused.
        serve_once(&rx);
        let mut ready = polling::Events::new();
        rx.poll_ready(&mut ready).unwrap();
        rx.serve_sources(&ready);
        rx.sweep_stopped_sources();
        serve_once(&rx);
        assert_eq!(*pair.served.lock().unwrap(), 1);

        rx.resume_paused_sources();
        serve_once(&rx);
        assert_eq!(*pair.served.lock().unwrap(), 2);
        drop(pair.peer);
    }

    #[test]
    fn a_paused_source_that_stops_is_closed_at_the_next_sweep() {
        let (tx, rx) = channel();
        let pair = pausing_source(&tx);
        serve_once(&rx);
        assert_eq!(*pair.served.lock().unwrap(), 1);
        pair.stop.store(true, Ordering::Relaxed);
        rx.sweep_stopped_sources();
        assert_eq!(*pair.events.lock().unwrap(), ["removed"]);
        // Resuming afterwards finds nothing to re-arm.
        rx.resume_paused_sources();
        serve_once(&rx);
        assert_eq!(*pair.served.lock().unwrap(), 1);
    }

    #[test]
    fn a_source_that_cannot_be_registered_is_abandoned() {
        use std::io::Write;
        let (tx, rx) = channel();
        let (mut peer, events) = pair_source(&tx, true);
        peer.write_all(&[1]).unwrap();
        assert!(matches!(
            rx.recv_timeout(Duration::from_secs(5)),
            Ok(Event::Tick)
        ));
        assert_eq!(*events.lock().unwrap(), ["read", "abandoned"]);
    }

    #[test]
    fn dropping_the_receiver_closes_sources_and_releases_their_senders() {
        let (tx, rx) = channel();
        let (peer, events) = pair_source(&tx, false);
        let shared = std::sync::Arc::downgrade(&tx.shared);
        drop(tx);
        drop(rx);
        assert_eq!(*events.lock().unwrap(), ["removed"]);
        // The source's end was closed.
        peer.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        let mut byte = [0u8; 1];
        assert_eq!(std::io::Read::read(&mut &peer, &mut byte).unwrap(), 0);
        assert!(
            shared.upgrade().is_none(),
            "the queue leaked through its sources"
        );
    }

    #[test]
    fn loop_pushes_never_drop_data_but_keep_the_burst_class_limits() {
        let (tx, rx) = channel_with_capacity(2);
        let data = (0..5).map(|id| frame(id, [0xC1; 16], rns_core::constants::PACKET_TYPE_DATA));
        assert_eq!(tx.push_from_loop(data), Ok(false));
        let announces =
            (10..15).map(|id| frame(id, [0xC2; 16], rns_core::constants::PACKET_TYPE_ANNOUNCE));
        tx.push_from_loop(announces).unwrap();
        tx.push_from_loop((0..3).map(|_| Event::Tick)).unwrap();
        let snapshot = tx.inbound_queue_snapshot();
        assert_eq!(snapshot.heights[..2], [5, 2]);
        assert_eq!(snapshot.dropped, [0, 3, 0, 0]);
        let mut received = 0;
        while rx.try_recv_classified().unwrap().is_some() {
            received += 1;
        }
        assert_eq!(received, 5 + 2 + 3);
        drop(rx);
        assert!(tx.push_from_loop([Event::Tick]).is_err());
    }

    #[test]
    fn wait_returns_at_once_when_events_are_queued() {
        let (tx, rx) = channel();
        tx.send(Event::Tick).unwrap();
        let mut ready = polling::Events::new();
        rx.wait(&mut ready, None).unwrap();
        assert!(matches!(
            rx.try_recv_classified().unwrap().map(|r| r.event),
            Some(Event::Tick)
        ));
        assert!(rx.try_recv_classified().unwrap().is_none());
    }

    #[test]
    fn parked_receiver_is_woken_by_send() {
        let (tx, rx) = channel();
        let done = parked_wait(rx, None);
        assert_parked(&done);
        tx.send(frame(1, [0xA1; 16], rns_core::constants::PACKET_TYPE_DATA))
            .unwrap();
        let (rx, result) = done.recv_timeout(Duration::from_secs(5)).unwrap();
        result.unwrap();
        assert_eq!(
            frame_interface(rx.try_recv_classified().unwrap().unwrap().event),
            1
        );
    }

    #[test]
    fn parked_receiver_is_woken_by_send_batch_and_try_send() {
        let (tx, rx) = channel();
        let done = parked_wait(rx, None);
        assert_parked(&done);
        tx.send_batch([
            frame(1, [0xA1; 16], rns_core::constants::PACKET_TYPE_DATA),
            frame(2, [0xA2; 16], rns_core::constants::PACKET_TYPE_DATA),
        ])
        .unwrap();
        let (rx, result) = done.recv_timeout(Duration::from_secs(5)).unwrap();
        result.unwrap();
        while rx.try_recv_classified().unwrap().is_some() {}

        let done = parked_wait(rx, None);
        assert_parked(&done);
        tx.try_send(Event::Tick).unwrap();
        let (rx, result) = done.recv_timeout(Duration::from_secs(5)).unwrap();
        result.unwrap();
        assert!(matches!(
            rx.try_recv_classified().unwrap().map(|r| r.event),
            Some(Event::Tick)
        ));
    }

    #[test]
    fn parked_receiver_observes_the_last_sender_leaving() {
        let (tx, rx) = channel();
        let extra = tx.clone();
        let done = parked_wait(rx, None);
        assert_parked(&done);
        drop(extra);
        assert_parked(&done);
        drop(tx);
        let (rx, result) = done.recv_timeout(Duration::from_secs(5)).unwrap();
        result.unwrap();
        assert!(rx.try_recv_classified().is_err());
        // Waiting again once disconnected returns immediately.
        rx.wait(&mut polling::Events::new(), None).unwrap();
    }

    #[test]
    fn wait_times_out_without_events() {
        let (_tx, rx) = channel();
        let started = std::time::Instant::now();
        rx.wait(&mut polling::Events::new(), Some(Duration::from_millis(30)))
            .unwrap();
        assert!(started.elapsed() >= Duration::from_millis(25));
        assert!(rx.try_recv_classified().unwrap().is_none());
    }

    #[test]
    fn many_producers_never_leave_a_parked_receiver_asleep() {
        let (tx, rx) = channel();
        let producers: Vec<_> = (0..4u64)
            .map(|id| {
                let tx = tx.clone();
                std::thread::spawn(move || {
                    for _ in 0..2_000 {
                        tx.send(frame(id, [0xB0; 16], rns_core::constants::PACKET_TYPE_DATA))
                            .unwrap();
                    }
                })
            })
            .collect();
        drop(tx);
        let mut ready = polling::Events::new();
        let mut received = 0;
        loop {
            match rx.try_recv_classified() {
                Ok(Some(_)) => received += 1,
                Ok(None) => {
                    ready.clear();
                    let started = std::time::Instant::now();
                    rx.wait(&mut ready, Some(Duration::from_secs(5))).unwrap();
                    // A lost wakeup would only end at the timeout.
                    assert!(started.elapsed() < Duration::from_secs(4));
                }
                Err(_) => break,
            }
        }
        for producer in producers {
            producer.join().unwrap();
        }
        assert_eq!(received, 8_000);
    }
}
