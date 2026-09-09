//! Runtime-independent transmission completion and bounded admission.
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex, Weak};
use std::task::{Context, Poll, Waker};

use futures::channel::oneshot;

/// A local send failure. Success never implies acknowledgement by the peer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LinkSendError {
    QueueFull,
    DriverStopped,
    Interrupted,
    Draining,
    InvalidPacket(crate::event::LinkDatagramError),
    PacketBuildFailed,
    NoRoute,
    Rejected,
    InterfaceUnavailable,
    WriteFailed(String),
}

impl std::fmt::Display for LinkSendError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::QueueFull => f.write_str("outbound queue is full"),
            Self::DriverStopped => f.write_str("driver stopped before transmission completed"),
            Self::Interrupted => f.write_str("transmission interrupted before completion"),
            Self::Draining => f.write_str("node is draining"),
            Self::InvalidPacket(error) => write!(f, "{error}"),
            Self::PacketBuildFailed => f.write_str("failed to build or encrypt outbound packet"),
            Self::NoRoute => f.write_str("no outgoing interface route"),
            Self::Rejected => f.write_str("outbound packet rejected by routing or policy"),
            Self::InterfaceUnavailable => f.write_str("outbound interface is unavailable"),
            Self::WriteFailed(error) => write!(f, "interface write failed: {error}"),
        }
    }
}
impl std::error::Error for LinkSendError {}

/// Await this receipt to learn whether all selected interfaces finished writing.
/// Obtaining a receipt means admission only; it is not a transmission result.
/// Dropping a receipt does not cancel an admitted send.
#[must_use = "await the receipt (or call wait) to observe transmission completion"]
pub struct LinkSendReceipt(oneshot::Receiver<Result<(), LinkSendError>>);

impl Future for LinkSendReceipt {
    type Output = Result<(), LinkSendError>;
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        Pin::new(&mut self.0)
            .poll(cx)
            .map(|result| result.unwrap_or(Err(LinkSendError::Interrupted)))
    }
}

impl LinkSendReceipt {
    /// Blocking counterpart for synchronous callers. Do not call from a driver callback.
    pub fn wait(self) -> Result<(), LinkSendError> {
        futures::executor::block_on(self)
    }
}

/// A packet's hash is available immediately for proof tracking, but successful
/// transmission is reported only when this receipt resolves. Failure may follow
/// partial transmission; neither the hash nor success promises remote delivery.
#[must_use = "await the receipt (or call wait) to observe transmission completion"]
pub struct PacketSendReceipt {
    pub(crate) completion: LinkSendReceipt,
    pub(crate) hash: rns_core::types::PacketHash,
}
impl PacketSendReceipt {
    pub fn packet_hash(&self) -> rns_core::types::PacketHash {
        self.hash
    }
    /// Blocking completion wait. Do not call from a driver callback.
    pub fn wait(self) -> Result<rns_core::types::PacketHash, LinkSendError> {
        futures::executor::block_on(self)
    }
}
impl Future for PacketSendReceipt {
    type Output = Result<rns_core::types::PacketHash, LinkSendError>;
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let hash = self.hash;
        Pin::new(&mut self.completion)
            .poll(cx)
            .map(|r| r.map(|()| hash))
    }
}

#[derive(Default)]
pub(crate) struct Waiter(Mutex<Option<Waker>>);

impl Waiter {
    pub(crate) fn register(&self, cx: &Context<'_>) {
        *self.0.lock().unwrap() = Some(cx.waker().clone());
    }
    pub(crate) fn wake(&self) {
        let waker = self.0.lock().unwrap().take();
        if let Some(waker) = waker {
            waker.wake();
        }
    }
}

struct PoolState {
    used: usize,
    closed: bool,
    waiters: Vec<Weak<Waiter>>,
    completions: Vec<Weak<CompletionState>>,
    links: std::collections::HashMap<[u8; 16], SendCounts>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct SendCounts {
    pub pending: usize,
    pub waiting: usize,
}

enum SendPhase {
    Unadmitted,
    Waiting,
    Pending,
}

pub(crate) struct SendTracking {
    pool: Arc<SendPool>,
    link_id: [u8; 16],
    phase: SendPhase,
}

impl SendTracking {
    fn admit(&mut self) {
        let mut state = self.pool.state.lock().unwrap();
        if state.closed {
            return;
        }
        let counts = state.links.entry(self.link_id).or_default();
        match self.phase {
            SendPhase::Waiting => counts.waiting -= 1,
            SendPhase::Pending => return,
            SendPhase::Unadmitted => {}
        }
        counts.pending += 1;
        self.phase = SendPhase::Pending;
    }
}

impl Drop for SendTracking {
    fn drop(&mut self) {
        let mut state = self.pool.state.lock().unwrap();
        if let Some(counts) = state.links.get_mut(&self.link_id) {
            match self.phase {
                SendPhase::Waiting => counts.waiting -= 1,
                SendPhase::Pending => counts.pending -= 1,
                SendPhase::Unadmitted => {}
            }
            if counts.pending == 0 && counts.waiting == 0 {
                state.links.remove(&self.link_id);
            }
        }
    }
}

pub(crate) struct SendPool {
    capacity: usize,
    state: Mutex<PoolState>,
}

impl SendPool {
    pub(crate) fn new(capacity: usize) -> Arc<Self> {
        Arc::new(Self {
            capacity: capacity.max(1),
            state: Mutex::new(PoolState {
                used: 0,
                closed: false,
                waiters: Vec::new(),
                completions: Vec::new(),
                links: std::collections::HashMap::new(),
            }),
        })
    }

    pub(crate) fn try_acquire(self: &Arc<Self>) -> Result<Permit, LinkSendError> {
        let mut state = self.state.lock().unwrap();
        if state.closed {
            return Err(LinkSendError::DriverStopped);
        }
        if state.used == self.capacity {
            return Err(LinkSendError::QueueFull);
        }
        state.used += 1;
        Ok(Permit(self.clone()))
    }

    pub(crate) fn track(self: &Arc<Self>, link_id: [u8; 16], waiting: bool) -> SendTracking {
        let mut state = self.state.lock().unwrap();
        let phase = if waiting && !state.closed {
            state.links.entry(link_id).or_default().waiting += 1;
            SendPhase::Waiting
        } else {
            SendPhase::Unadmitted
        };
        SendTracking {
            pool: self.clone(),
            link_id,
            phase,
        }
    }

    pub(crate) fn snapshot(&self) -> std::collections::HashMap<[u8; 16], SendCounts> {
        self.state.lock().unwrap().links.clone()
    }

    pub(crate) async fn acquire(self: &Arc<Self>) -> Result<Permit, LinkSendError> {
        let waiter = Arc::new(Waiter::default());
        {
            let mut state = self.state.lock().unwrap();
            state.waiters.retain(|waiter| waiter.strong_count() > 0);
            state.waiters.push(Arc::downgrade(&waiter));
        }
        futures::future::poll_fn(|cx| {
            waiter.register(cx);
            match self.try_acquire() {
                Err(LinkSendError::QueueFull) => Poll::Pending,
                result => Poll::Ready(result),
            }
        })
        .await
    }

    pub(crate) fn close(&self) {
        let (waiters, completions) = {
            let mut state = self.state.lock().unwrap();
            state.closed = true;
            state.links.clear();
            (
                std::mem::take(&mut state.waiters),
                std::mem::take(&mut state.completions),
            )
        };
        for waiter in waiters.into_iter().filter_map(|w| w.upgrade()) {
            waiter.wake();
        }
        for completion in completions.into_iter().filter_map(|w| w.upgrade()) {
            completion.finish(Err(LinkSendError::DriverStopped));
        }
    }

    pub(crate) fn in_flight(&self) -> usize {
        self.state.lock().unwrap().used
    }
}

pub(crate) struct Permit(Arc<SendPool>);
impl Drop for Permit {
    fn drop(&mut self) {
        let waiters = {
            let mut state = self.0.state.lock().unwrap();
            state.used -= 1;
            state.waiters.retain(|waiter| waiter.strong_count() > 0);
            state.waiters.clone()
        };
        for waiter in waiters.into_iter().filter_map(|w| w.upgrade()) {
            waiter.wake();
        }
    }
}

/// Internal writer completion token. Dropping it reports an interrupted send.
#[doc(hidden)]
pub struct Completion {
    state: Arc<CompletionState>,
    settled: bool,
}

struct CompletionData {
    tx: oneshot::Sender<Result<(), LinkSendError>>,
    tracking: Option<SendTracking>,
    permit: Permit,
    remaining: usize,
    error: Option<LinkSendError>,
}
struct CompletionState(Mutex<Option<CompletionData>>);
impl Drop for CompletionState {
    fn drop(&mut self) {
        // Clear counters before waking a receipt whose writer/event vanished.
        self.finish(Err(LinkSendError::Interrupted));
    }
}
impl CompletionState {
    fn finish(&self, result: Result<(), LinkSendError>) {
        let data = self.0.lock().unwrap().take();
        if let Some(data) = data {
            drop(data.tracking);
            drop(data.permit);
            let _ = data.tx.send(result);
        }
    }
}

impl Completion {
    pub(crate) fn new(permit: Permit) -> (Self, LinkSendReceipt) {
        Self::new_inner(permit, None)
    }

    pub(crate) fn new_tracked(permit: Permit, tracking: SendTracking) -> (Self, LinkSendReceipt) {
        Self::new_inner(permit, Some(tracking))
    }

    fn new_inner(permit: Permit, tracking: Option<SendTracking>) -> (Self, LinkSendReceipt) {
        let (tx, rx) = oneshot::channel();
        let pool = permit.0.clone();
        let completion = Arc::new(CompletionState(Mutex::new(Some(CompletionData {
            tx,
            tracking,
            permit,
            remaining: 1,
            error: None,
        }))));
        {
            let mut pool = pool.state.lock().unwrap();
            pool.completions.retain(|w| w.strong_count() > 0);
            if pool.closed {
                drop(pool);
                completion.finish(Err(LinkSendError::DriverStopped));
            } else {
                pool.completions.push(Arc::downgrade(&completion));
            }
        }
        (
            Self {
                state: completion,
                settled: false,
            },
            LinkSendReceipt(rx),
        )
    }
    pub(crate) fn finish(mut self, result: Result<(), LinkSendError>) {
        self.settle(result);
    }

    /// Each selected interface gets a branch. The permit and receipt remain
    /// live until every branch settles, even if one branch fails early.
    pub(crate) fn branch(&self) -> Self {
        if let Some(data) = self.state.0.lock().unwrap().as_mut() {
            data.remaining += 1;
        }
        Self {
            state: self.state.clone(),
            settled: false,
        }
    }

    fn settle(&mut self, result: Result<(), LinkSendError>) {
        self.settled = true;
        let final_data = {
            let mut guard = self.state.0.lock().unwrap();
            let Some(data) = guard.as_mut() else { return };
            if data.error.is_none() {
                data.error = result.err();
            }
            data.remaining -= 1;
            if data.remaining == 0 {
                guard.take()
            } else {
                None
            }
        };
        if let Some(data) = final_data {
            drop(data.tracking);
            drop(data.permit);
            let _ = data.tx.send(data.error.map_or(Ok(()), Err));
        }
    }
    pub(crate) fn is_finished(&self) -> bool {
        self.state.0.lock().unwrap().is_none()
    }

    pub(crate) fn admit(&self) {
        if let Some(data) = self.state.0.lock().unwrap().as_mut() {
            if let Some(tracking) = data.tracking.as_mut() {
                tracking.admit();
            }
        }
    }
}

impl Drop for Completion {
    fn drop(&mut self) {
        if !self.settled {
            self.settle(Err(LinkSendError::Interrupted));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::{executor::block_on, FutureExt};

    #[test]
    fn fanout_keeps_capacity_until_all_writes_settle() {
        let pool = SendPool::new(1);
        let (completion, mut receipt) = Completion::new(pool.try_acquire().unwrap());
        let first = completion.branch();
        let last = completion.branch();
        completion.finish(Ok(()));
        first.finish(Err(LinkSendError::WriteFailed("first failed".into())));
        assert!((&mut receipt).now_or_never().is_none());
        assert!(matches!(pool.try_acquire(), Err(LinkSendError::QueueFull)));
        last.finish(Ok(()));
        assert_eq!(
            receipt.wait(),
            Err(LinkSendError::WriteFailed("first failed".into()))
        );
        assert_eq!(pool.in_flight(), 0);

        let (completion, receipt) = Completion::new(pool.try_acquire().unwrap());
        let child = completion.branch();
        completion.finish(Ok(()));
        drop(child);
        assert_eq!(receipt.wait(), Err(LinkSendError::Interrupted));
        assert_eq!(pool.in_flight(), 0);

        let (completion, receipt) = Completion::new(pool.try_acquire().unwrap());
        let child = completion.branch();
        pool.close();
        assert_eq!(receipt.wait(), Err(LinkSendError::DriverStopped));
        assert_eq!(pool.in_flight(), 0);
        drop((completion, child));
    }

    #[test]
    fn packet_and_announce_admission_is_bounded_and_runtime_independent() {
        use crate::event::Event;
        let (tx, rx) = crate::event::channel_with_capacity(1);
        let node = crate::RnsNode::from_parts(
            tx.clone(),
            std::thread::spawn(|| {}),
            None,
            Arc::new(std::sync::atomic::AtomicU64::new(1000)),
        );
        let dest = crate::Destination::plain("confirmed", &["packet"]);
        let identity = rns_crypto::identity::Identity::new(&mut rns_crypto::OsRng);
        let announce_dest = crate::Destination::single_in(
            "confirmed",
            &["announce"],
            crate::IdentityHash(*identity.hash()),
        );
        drop(node.announce(&announce_dest, &identity, None));
        assert!(
            rx.try_recv().is_err(),
            "unpolled sends must have no side effects"
        );
        tx.send(Event::Tick).unwrap();
        assert!(matches!(
            node.try_announce(&announce_dest, &identity, None),
            Err(LinkSendError::QueueFull)
        ));
        let mut cancelled = Box::pin(node.announce(&announce_dest, &identity, None));
        assert!(cancelled.as_mut().now_or_never().is_none());
        drop(cancelled);
        assert_eq!(tx.link_send_pool().in_flight(), 0);
        assert!(matches!(rx.try_recv(), Ok(Event::Tick)));
        assert!(
            rx.try_recv().is_err(),
            "cancelled admission must not update replay state"
        );
        let receipt = node.try_send_packet(&dest, b"first").unwrap();
        let hash = receipt.packet_hash();
        let Event::SendOutboundTracked {
            completion: first, ..
        } = rx.try_recv().unwrap()
        else {
            panic!("expected tracked packet")
        };
        assert!(matches!(
            node.try_announce(&announce_dest, &identity, None),
            Err(LinkSendError::QueueFull)
        ));
        let mut announce = Box::pin(node.announce(&announce_dest, &identity, None));
        assert!(announce.as_mut().now_or_never().is_none());
        assert!(rx.try_recv().is_err());
        first.finish(Ok(()));
        assert_eq!(receipt.wait().unwrap(), hash);
        assert!(announce.as_mut().now_or_never().is_none());
        let Event::SendOutboundTracked {
            completion, replay, ..
        } = rx.try_recv().unwrap()
        else {
            panic!("expected tracked announce")
        };
        assert_eq!(replay.unwrap().dest_hash, announce_dest.hash.0);
        assert!(matches!(
            node.try_send_packet(&dest, b"full"),
            Err(LinkSendError::QueueFull)
        ));
        completion.finish(Ok(()));
        block_on(announce).unwrap();
        let receipt = node.try_announce(&announce_dest, &identity, None).unwrap();
        let Event::SendOutboundTracked { completion, .. } = rx.try_recv().unwrap() else {
            panic!("expected tracked announce")
        };
        completion.finish(Ok(()));
        receipt.wait().unwrap();
        let mut packet = Box::pin(node.send_packet(&dest, b"async"));
        assert!(packet.as_mut().now_or_never().is_none());
        let Event::SendOutboundTracked {
            completion, raw, ..
        } = rx.try_recv().unwrap()
        else {
            panic!("expected tracked packet")
        };
        let hash = rns_core::types::PacketHash(
            rns_core::packet::RawPacket::unpack(&raw)
                .unwrap()
                .packet_hash,
        );
        completion.finish(Ok(()));
        assert_eq!(block_on(packet).unwrap(), hash);
        assert!(
            tx.link_send_pool().snapshot().is_empty(),
            "non-Link sends must not affect per-Link counts"
        );
        drop(rx);
        assert!(matches!(
            node.try_send_packet(&dest, b"stopped"),
            Err(LinkSendError::DriverStopped)
        ));
        assert_eq!(
            block_on(node.announce(&announce_dest, &identity, None)),
            Err(LinkSendError::DriverStopped)
        );
    }

    #[test]
    fn per_link_counts_cover_failure_shutdown_and_receipt_cancellation() {
        let pool = SendPool::new(3);
        let waiting = pool.track([1; 16], true);
        let tracking = pool.track([2; 16], true);
        let (completion, receipt) = Completion::new_tracked(pool.try_acquire().unwrap(), tracking);
        completion.admit();
        assert_eq!(
            pool.snapshot().get(&[1; 16]),
            Some(&SendCounts {
                pending: 0,
                waiting: 1
            })
        );
        assert_eq!(
            pool.snapshot().get(&[2; 16]),
            Some(&SendCounts {
                pending: 1,
                waiting: 0
            })
        );
        drop(receipt);
        assert_eq!(
            pool.snapshot()[&[2; 16]].pending,
            1,
            "dropping a receipt does not cancel transmission"
        );
        completion.finish(Err(LinkSendError::WriteFailed("broken pipe".into())));
        assert!(!pool.snapshot().contains_key(&[2; 16]));
        drop(waiting);
        assert!(pool.snapshot().is_empty());

        let tracking = pool.track([4; 16], false);
        let (completion, receipt) = Completion::new_tracked(pool.try_acquire().unwrap(), tracking);
        completion.admit();
        drop(completion);
        assert_eq!(receipt.wait(), Err(LinkSendError::Interrupted));
        assert!(pool.snapshot().is_empty());

        let tracking = pool.track([3; 16], false);
        let (completion, receipt) = Completion::new_tracked(pool.try_acquire().unwrap(), tracking);
        completion.admit();
        let waiting = pool.track([3; 16], true);
        pool.close();
        assert_eq!(receipt.wait(), Err(LinkSendError::DriverStopped));
        assert!(pool.snapshot().is_empty());
        drop(waiting);
        drop(completion);
        assert!(pool.snapshot().is_empty());
    }

    #[test]
    fn node_try_rejects_full_capacity_and_async_send_wakes_without_blocking() {
        use crate::event::Event;
        use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
        struct WakeCount(AtomicUsize);
        impl futures::task::ArcWake for WakeCount {
            fn wake_by_ref(this: &Arc<Self>) {
                this.0.fetch_add(1, Ordering::SeqCst);
            }
        }
        let (tx, rx) = crate::event::channel_with_capacity(1);
        let node = crate::RnsNode::from_parts(
            tx.clone(),
            std::thread::spawn(|| {}),
            None,
            Arc::new(AtomicU64::new(1000)),
        );
        let receipt = node.try_send_on_link([1; 16], vec![1], 0).unwrap();
        assert_eq!(
            tx.link_send_pool().snapshot()[&[1; 16]],
            SendCounts {
                pending: 1,
                waiting: 0
            }
        );
        let first = match rx.try_recv().unwrap() {
            Event::SendLinkTracked { completion, .. } => completion,
            _ => panic!("expected a tracked send"),
        };
        assert!(matches!(
            node.try_send_on_link([1; 16], vec![2], 0),
            Err(LinkSendError::QueueFull)
        ));
        let mut pending = Box::pin(node.send_on_link([1; 16], vec![2], 0));
        let wakes = Arc::new(WakeCount(AtomicUsize::new(0)));
        let waker = futures::task::waker(wakes.clone());
        let mut cx = Context::from_waker(&waker);
        assert!(pending.as_mut().poll(&mut cx).is_pending());
        assert_eq!(
            tx.link_send_pool().snapshot()[&[1; 16]],
            SendCounts {
                pending: 1,
                waiting: 1
            }
        );
        assert!(
            rx.try_recv().is_err(),
            "capacity wait must not enqueue prematurely"
        );
        first.finish(Ok(()));
        receipt.wait().unwrap();
        assert_eq!(
            tx.link_send_pool().snapshot()[&[1; 16]],
            SendCounts {
                pending: 0,
                waiting: 1
            }
        );
        assert!(
            wakes.0.load(Ordering::SeqCst) > 0,
            "capacity release must wake the task"
        );
        assert!(pending.as_mut().poll(&mut cx).is_pending());
        let second = match rx.try_recv().unwrap() {
            Event::SendLinkTracked { completion, .. } => completion,
            _ => panic!("expected a tracked send"),
        };
        assert_eq!(
            tx.link_send_pool().snapshot()[&[1; 16]],
            SendCounts {
                pending: 1,
                waiting: 0
            }
        );
        second.finish(Ok(()));
        assert!(tx.link_send_pool().snapshot().is_empty());
        assert_eq!(pending.as_mut().poll(&mut cx), Poll::Ready(Ok(())));
        drop(pending);

        // A full *driver* event queue also makes try return immediately.
        tx.try_send(Event::Tick).unwrap();
        assert!(matches!(
            node.try_send_on_link([1; 16], vec![3], 0),
            Err(LinkSendError::QueueFull)
        ));
        let mut cancelled = Box::pin(node.send_on_link([1; 16], vec![3], 0));
        assert!(cancelled.as_mut().poll(&mut cx).is_pending());
        assert_eq!(
            tx.link_send_pool().snapshot()[&[1; 16]],
            SendCounts {
                pending: 0,
                waiting: 1
            }
        );
        drop(cancelled);
        assert!(tx.link_send_pool().snapshot().is_empty());
        assert_eq!(tx.link_send_pool().in_flight(), 0);
        assert!(matches!(rx.try_recv(), Ok(Event::Tick)));
        assert!(
            rx.try_recv().is_err(),
            "cancelled admission must not send later"
        );
        drop(rx);
        node.shutdown();
    }

    #[test]
    fn capacity_waits_for_transmission_not_receipt_creation() {
        let pool = SendPool::new(1);
        let (completion, mut receipt) = Completion::new(pool.try_acquire().unwrap());
        assert!(matches!(pool.try_acquire(), Err(LinkSendError::QueueFull)));
        assert!((&mut receipt).now_or_never().is_none());
        let mut waiting = Box::pin(pool.acquire());
        assert!(waiting.as_mut().now_or_never().is_none());
        completion.finish(Ok(()));
        receipt.wait().unwrap();
        let permit = block_on(waiting).unwrap();
        assert!(matches!(pool.try_acquire(), Err(LinkSendError::QueueFull)));
        drop(permit);
        assert!(pool.try_acquire().is_ok());
    }

    #[test]
    fn shutdown_resolves_in_flight_receipts_and_capacity_waiters() {
        let pool = SendPool::new(1);
        let (completion, receipt) = Completion::new(pool.try_acquire().unwrap());
        let mut waiting = Box::pin(pool.acquire());
        assert!(waiting.as_mut().now_or_never().is_none());
        pool.close();
        assert_eq!(receipt.wait(), Err(LinkSendError::DriverStopped));
        assert!(matches!(
            block_on(waiting),
            Err(LinkSendError::DriverStopped)
        ));
        // A delayed worker cannot overwrite the shutdown result.
        completion.finish(Ok(()));
    }

    #[test]
    fn dropping_receipt_does_not_release_an_in_flight_slot() {
        let pool = SendPool::new(1);
        let (completion, receipt) = Completion::new(pool.try_acquire().unwrap());
        drop(receipt);
        assert!(matches!(pool.try_acquire(), Err(LinkSendError::QueueFull)));
        drop(completion);
        assert!(pool.try_acquire().is_ok());
    }

    #[test]
    fn both_node_apis_report_the_same_invalid_link_error() {
        struct Callbacks;
        impl crate::Callbacks for Callbacks {
            fn on_announce(&mut self, _: crate::AnnouncedIdentity) {}
            fn on_path_updated(&mut self, _: crate::DestHash, _: u8) {}
            fn on_local_delivery(&mut self, _: crate::DestHash, _: Vec<u8>, _: crate::PacketHash) {}
        }
        let node =
            crate::RnsNode::start(crate::NodeConfig::default(), Box::new(Callbacks)).unwrap();
        let expected = Err(LinkSendError::InvalidPacket(
            crate::event::LinkDatagramError::LinkNotFound,
        ));
        assert_eq!(
            block_on(node.send_on_link([0x42; 16], vec![1], 0)),
            expected
        );
        assert_eq!(
            node.try_send_on_link([0x42; 16], vec![1], 0)
                .unwrap()
                .wait(),
            expected
        );
        let dest = crate::Destination::plain("confirmed", &["no_route"]);
        assert_eq!(
            block_on(node.send_packet(&dest, b"data")),
            Err(LinkSendError::NoRoute)
        );
        assert_eq!(
            node.try_send_packet(&dest, b"data").unwrap().wait(),
            Err(LinkSendError::NoRoute)
        );
        let identity = rns_crypto::identity::Identity::new(&mut rns_crypto::OsRng);
        let announce_dest = crate::Destination::single_in(
            "confirmed",
            &["announce"],
            crate::IdentityHash(*identity.hash()),
        );
        assert_eq!(
            block_on(node.announce(&announce_dest, &identity, None)),
            Err(LinkSendError::NoRoute)
        );
        assert_eq!(
            node.try_announce(&announce_dest, &identity, None)
                .unwrap()
                .wait(),
            Err(LinkSendError::NoRoute)
        );
        let oversized = vec![0; rns_core::constants::MTU * 2];
        assert_eq!(
            block_on(node.send_packet(&dest, &oversized)),
            Err(LinkSendError::PacketBuildFailed)
        );
        assert!(matches!(
            node.try_send_packet(&dest, &oversized),
            Err(LinkSendError::PacketBuildFailed)
        ));
        node.begin_drain(std::time::Duration::from_secs(30))
            .unwrap();
        node.drain_status().unwrap();
        assert_eq!(
            block_on(node.send_packet(&dest, b"data")),
            Err(LinkSendError::Draining)
        );
        assert_eq!(
            node.try_announce(&announce_dest, &identity, None)
                .unwrap()
                .wait(),
            Err(LinkSendError::Draining)
        );
        node.shutdown();
    }
}
