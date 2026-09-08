//! Runtime-independent Link transmission completion and bounded admission.
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
            Self::NoRoute => f.write_str("no interface route for Link"),
            Self::Rejected => f.write_str("outbound packet rejected by routing or policy"),
            Self::InterfaceUnavailable => f.write_str("outbound interface is unavailable"),
            Self::WriteFailed(error) => write!(f, "interface write failed: {error}"),
        }
    }
}
impl std::error::Error for LinkSendError {}

/// Await this receipt to learn whether the interface finished writing the packet.
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
    _permit: Permit,
}

struct CompletionState(Mutex<Option<oneshot::Sender<Result<(), LinkSendError>>>>);
impl CompletionState {
    fn finish(&self, result: Result<(), LinkSendError>) {
        let tx = self.0.lock().unwrap().take();
        if let Some(tx) = tx {
            let _ = tx.send(result);
        }
    }
}

impl Completion {
    pub(crate) fn new(permit: Permit) -> (Self, LinkSendReceipt) {
        let (tx, rx) = oneshot::channel();
        let completion = Arc::new(CompletionState(Mutex::new(Some(tx))));
        {
            let mut pool = permit.0.state.lock().unwrap();
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
                _permit: permit,
            },
            LinkSendReceipt(rx),
        )
    }
    pub(crate) fn finish(self, result: Result<(), LinkSendError>) {
        let Self { state, _permit } = self;
        drop(_permit);
        state.finish(result);
    }
    pub(crate) fn is_finished(&self) -> bool {
        self.state.0.lock().unwrap().is_none()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::{executor::block_on, FutureExt};

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
        assert!(
            rx.try_recv().is_err(),
            "capacity wait must not enqueue prematurely"
        );
        first.finish(Ok(()));
        receipt.wait().unwrap();
        assert!(
            wakes.0.load(Ordering::SeqCst) > 0,
            "capacity release must wake the task"
        );
        assert!(pending.as_mut().poll(&mut cx).is_pending());
        let second = match rx.try_recv().unwrap() {
            Event::SendLinkTracked { completion, .. } => completion,
            _ => panic!("expected a tracked send"),
        };
        second.finish(Ok(()));
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
        drop(cancelled);
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
        node.shutdown();
    }
}
