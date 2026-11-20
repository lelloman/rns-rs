//! Async writer: a queue and worker thread between the driver and a writer.

use std::io;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc::TrySendError;
use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use super::{lock_or_recover, loop_writer, EgressControl, FrameBytes, Writer};
use crate::event::EventSender;
use rns_core::transport::types::InterfaceId;

/// Default number of frames an async writer queue holds.
pub const DEFAULT_ASYNC_WRITER_QUEUE_CAPACITY: usize = 256;

/// Longest time a producer waits for a busy async writer to free queue space
/// or byte budget before treating the frame as undeliverable.
///
/// A healthy writer drains its queue in well under a millisecond, so this
/// bound converts momentary bursts into backpressure (the producer pauses and
/// the inbound queue fills) instead of silent loss. A writer that stays full
/// for the whole bound is treated as stalled: the frame is refused and the
/// driver's per-interface send deferral protects other interfaces.
pub const ASYNC_WRITER_BACKPRESSURE_WAIT: Duration = Duration::from_millis(20);

/// Shared counters of an interface writer wrapped by [`wrap_async_writer`].
#[derive(Clone, Default)]
pub struct AsyncWriterMetrics {
    pub(super) queued_frames: Arc<AtomicUsize>,
    pub(super) worker_alive: Arc<AtomicBool>,
    pub(super) egress_control: Option<EgressControl>,
    /// Signalled by the worker whenever it frees queue slots or byte budget.
    pub(super) space: Arc<(Mutex<()>, Condvar)>,
    /// Producers inside a backpressure wait. Incremented under the `space`
    /// lock before the producer's queue attempt, so a worker that frees space
    /// after a failed attempt always observes it and notifies.
    pub(super) space_waiters: Arc<AtomicUsize>,
}

impl AsyncWriterMetrics {
    fn notify_space(&self) {
        if self.space_waiters.load(Ordering::SeqCst) == 0 {
            return;
        }
        let (lock, condvar) = &*self.space;
        let _guard = lock_or_recover(lock, "async writer space");
        condvar.notify_all();
    }

    /// Frames waiting in the async queue.
    pub fn queued_frames(&self) -> usize {
        self.queued_frames.load(Ordering::Relaxed)
    }

    /// False once the writer worker has stopped or failed to start.
    pub fn worker_alive(&self) -> bool {
        self.worker_alive.load(Ordering::Relaxed)
    }

    /// Exact encoded bytes waiting in the async queue or concrete writer.
    pub fn tx_buffered(&self) -> usize {
        self.egress_control
            .as_ref()
            .map(|control| control.reserved_bytes.load(Ordering::Relaxed))
            .unwrap_or(0)
    }

    /// Frames dropped by egress control: over the byte limit, out of byte
    /// budget, or sent while the peer was stalled.
    pub fn tx_drops(&self) -> u64 {
        self.egress_control
            .as_ref()
            .map(|control| control.dropped_frames.load(Ordering::Relaxed))
            .unwrap_or(0)
    }

    /// Encoded bytes of the frames counted by [`Self::tx_drops`].
    pub fn tx_dropped_bytes(&self) -> u64 {
        self.egress_control
            .as_ref()
            .map(|control| control.dropped_bytes.load(Ordering::Relaxed))
            .unwrap_or(0)
    }

    /// Whether egress control currently marks the peer as stalled.
    pub fn tx_stalled(&self) -> bool {
        self.egress_control
            .as_ref()
            .is_some_and(EgressControl::stalled)
    }
}

/// Bounded frame queue between the driver and one interface writer thread.
///
/// The worker drains every queued frame in one lock acquisition. This
/// replaces a std sync channel whose receiver spins while it observes a send
/// in progress, which on a single CPU burned the rest of the time slice.
struct WriterQueue {
    state: Mutex<WriterQueueState>,
    ready: Condvar,
    capacity: usize,
}

struct WriterQueueState {
    frames: std::collections::VecDeque<QueuedFrame>,
    sender_closed: bool,
    receiver_closed: bool,
    receiver_waiting: bool,
    /// The driver asked to close the connection ([`Writer::shutdown`]).
    shutdown_requested: bool,
}

impl WriterQueue {
    fn new(capacity: usize) -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(WriterQueueState {
                frames: std::collections::VecDeque::new(),
                sender_closed: false,
                receiver_closed: false,
                receiver_waiting: false,
                shutdown_requested: false,
            }),
            ready: Condvar::new(),
            capacity: capacity.max(1),
        })
    }

    /// Wait until frames are queued, then move all of them into `out`.
    /// Returns false once the sender is gone and nothing remains.
    fn recv_all(&self, out: &mut Vec<QueuedFrame>) -> bool {
        let mut state = lock_or_recover(&self.state, "async writer queue");
        if state.shutdown_requested {
            return false;
        }
        while state.frames.is_empty() {
            if state.sender_closed || state.shutdown_requested {
                return false;
            }
            state.receiver_waiting = true;
            // Sleep until woken. A postponed wakeup (see send_frame_deferred)
            // comes from the driver before it waits for more input, and its
            // tick wakes any writer still owed one.
            state = match self.ready.wait(state) {
                Ok(state) => state,
                Err(poisoned) => poisoned.into_inner(),
            };
            state.receiver_waiting = false;
        }
        out.extend(state.frames.drain(..));
        true
    }

    /// Ask the worker to close its writer's connection and exit.
    fn request_shutdown(&self) {
        lock_or_recover(&self.state, "async writer queue").shutdown_requested = true;
        self.ready.notify_one();
    }

    fn shutdown_requested(&self) -> bool {
        lock_or_recover(&self.state, "async writer queue").shutdown_requested
    }

    /// Wake the worker if it sleeps while frames are queued.
    fn kick(&self) {
        let state = lock_or_recover(&self.state, "async writer queue");
        let wake = state.receiver_waiting && !state.frames.is_empty();
        drop(state);
        if wake {
            self.ready.notify_one();
        }
    }

    fn close_receiver(&self) {
        lock_or_recover(&self.state, "async writer queue").receiver_closed = true;
    }
}

/// Producer handle; dropping it lets the worker exit after draining.
struct WriterTx(Arc<WriterQueue>);

impl WriterTx {
    /// Queue a frame. Returns whether the worker still needs waking: false
    /// when it was woken here (`notify`) or was not waiting.
    fn try_send(
        &self,
        frame: QueuedFrame,
        notify: bool,
    ) -> Result<bool, TrySendError<QueuedFrame>> {
        let mut state = lock_or_recover(&self.0.state, "async writer queue");
        if state.receiver_closed {
            return Err(TrySendError::Disconnected(frame));
        }
        if state.frames.len() >= self.0.capacity {
            return Err(TrySendError::Full(frame));
        }
        state.frames.push_back(frame);
        let waiting = state.receiver_waiting;
        drop(state);
        if waiting && notify {
            self.0.ready.notify_one();
        }
        Ok(waiting && !notify)
    }
}

impl Drop for WriterTx {
    fn drop(&mut self) {
        lock_or_recover(&self.0.state, "async writer queue").sender_closed = true;
        self.0.ready.notify_one();
    }
}

struct AsyncWriter {
    tx: WriterTx,
    metrics: AsyncWriterMetrics,
    /// Set after a backpressure wait times out. Until a frame is admitted
    /// again, unconfirmed sends make a single attempt instead of waiting,
    /// so a stalled peer costs the producer at most one wait.
    skip_wait: bool,
    /// Set while a deferred send is in progress.
    defer_wake: bool,
    /// A deferred send left the worker asleep with frames queued.
    wake_pending: bool,
    /// Longest wait for queue space before an unconfirmed frame is refused.
    /// [`ASYNC_WRITER_BACKPRESSURE_WAIT`] outside tests.
    backpressure_wait: Duration,
}

enum Admission {
    Done,
    Refused(QueuedFrame),
}

struct QueuedFrame {
    data: FrameBytes,
    reserved_bytes: usize,
    completion: Option<crate::link_send::Completion>,
}

impl Writer for AsyncWriter {
    fn send_frame(&mut self, data: &[u8]) -> io::Result<()> {
        self.enqueue(data, &mut None)
    }

    fn send_frame_deferred(&mut self, data: &[u8]) -> io::Result<()> {
        self.defer_wake = true;
        let result = self.enqueue(data, &mut None);
        self.defer_wake = false;
        result
    }

    fn send_shared_deferred(
        &mut self,
        data: &rns_core::transport::types::PacketBytes,
    ) -> io::Result<()> {
        self.defer_wake = true;
        let result = self.enqueue_unconfirmed(FrameBytes::Shared(data.clone()));
        self.defer_wake = false;
        result
    }

    fn wake(&mut self) {
        if std::mem::take(&mut self.wake_pending) {
            self.tx.0.kick();
        }
    }

    fn tick(&mut self) {
        // A backstop: the worker no longer rechecks its queue on a timer.
        self.wake();
    }

    fn flush_pending(&mut self) {
        // The driver's pass is over: nothing it deferred may wait longer.
        self.wake();
    }

    fn shutdown(&mut self) {
        // The worker owns the inner writer; it closes the connection.
        self.tx.0.request_shutdown();
    }

    fn enqueue_confirmed(
        &mut self,
        data: &[u8],
        completion: &mut Option<crate::link_send::Completion>,
    ) -> io::Result<()> {
        self.enqueue(data, completion)
    }
}

impl AsyncWriter {
    /// Admit an unconfirmed frame, waiting up to the backpressure wait
    /// ([`ASYNC_WRITER_BACKPRESSURE_WAIT`]) while the worker is busy.
    ///
    /// A stalled peer (as reported by the byte-budget controller) is refused
    /// immediately so that one dead connection cannot repeatedly pause the
    /// driver. Over-budget frames that can never fit are dropped as before.
    fn enqueue_unconfirmed(&mut self, data: FrameBytes) -> io::Result<()> {
        let mut frame = QueuedFrame {
            data,
            reserved_bytes: 0,
            completion: None,
        };
        // Fast path without the space lock: almost every frame fits.
        match self.try_admit(frame)? {
            Admission::Done => return Ok(()),
            Admission::Refused(returned) => frame = returned,
        }
        if self.skip_wait {
            return self.refuse(frame);
        }
        // The worker must run to free space; wake it if a deferred send left
        // it asleep.
        self.wake();
        let space = Arc::clone(&self.metrics.space);
        let (lock, condvar) = &*space;
        let mut guard = lock_or_recover(lock, "async writer space");
        // Register before retrying: a worker that frees space after this
        // retry fails observes the waiter and must take the lock to notify,
        // which it can only do once this thread is waiting.
        self.metrics.space_waiters.fetch_add(1, Ordering::SeqCst);
        let deadline = Instant::now() + self.backpressure_wait;
        let result = loop {
            match self.try_admit(frame) {
                Err(error) => break Err(error),
                Ok(Admission::Done) => break Ok(()),
                Ok(Admission::Refused(returned)) => frame = returned,
            }
            let now = Instant::now();
            if now >= deadline {
                self.skip_wait = true;
                break self.refuse(frame);
            }
            guard = match condvar.wait_timeout(guard, deadline - now) {
                Ok((guard, _)) => guard,
                Err(poisoned) => poisoned.into_inner().0,
            };
        };
        self.metrics.space_waiters.fetch_sub(1, Ordering::SeqCst);
        drop(guard);
        result
    }

    /// One admission attempt. Frames that can never be admitted (over the
    /// byte limit, or a stalled peer) are dropped and counted, as before.
    fn try_admit(&mut self, mut frame: QueuedFrame) -> io::Result<Admission> {
        if !self.metrics.worker_alive() {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "interface writer worker is offline",
            ));
        }
        if let Some(control) = &self.metrics.egress_control {
            let bytes = crate::hdlc::framed_len(&frame.data);
            if bytes > control.byte_limit || control.stalled() {
                control.record_drop(bytes);
                return Ok(Admission::Done);
            }
            if !control.try_reserve(bytes) {
                return Ok(Admission::Refused(frame));
            }
            frame.reserved_bytes = bytes;
        }
        self.metrics.queued_frames.fetch_add(1, Ordering::Relaxed);
        match self.tx.try_send(frame, !self.defer_wake) {
            Ok(needs_wake) => {
                self.skip_wait = false;
                self.wake_pending |= needs_wake;
                Ok(Admission::Done)
            }
            Err(TrySendError::Full(mut returned)) => {
                self.metrics.queued_frames.fetch_sub(1, Ordering::Relaxed);
                if let Some(control) = &self.metrics.egress_control {
                    control.release(returned.reserved_bytes);
                }
                returned.reserved_bytes = 0;
                Ok(Admission::Refused(returned))
            }
            Err(TrySendError::Disconnected(returned)) => {
                self.metrics.queued_frames.fetch_sub(1, Ordering::Relaxed);
                if let Some(control) = &self.metrics.egress_control {
                    control.release(returned.reserved_bytes);
                }
                self.metrics.worker_alive.store(false, Ordering::Relaxed);
                Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "interface writer worker disconnected",
                ))
            }
        }
    }

    /// Give up on a frame that did not fit. A frame refused for byte budget
    /// is dropped and counted (the pre-existing egress-control policy); a
    /// frame refused for queue slots is reported as would-block.
    fn refuse(&self, frame: QueuedFrame) -> io::Result<()> {
        if let Some(control) = &self.metrics.egress_control {
            let bytes = crate::hdlc::framed_len(&frame.data);
            if self.metrics.queued_frames() < self.tx.0.capacity {
                control.record_drop(bytes);
                return Ok(());
            }
        }
        Err(io::Error::new(
            io::ErrorKind::WouldBlock,
            "interface writer queue is full",
        ))
    }

    fn enqueue(
        &mut self,
        data: &[u8],
        completion: &mut Option<crate::link_send::Completion>,
    ) -> io::Result<()> {
        if !self.metrics.worker_alive() {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "interface writer worker is offline",
            ));
        }

        // Unconfirmed frames (transit forwarding, announces) wait briefly for a
        // busy worker instead of being refused at the first full queue.
        // Confirmed sends keep their immediate WouldBlock contract: their
        // callers already retry through the completion machinery.
        if completion.is_none() {
            return self.enqueue_unconfirmed(FrameBytes::Owned(data.to_vec()));
        }

        let reserved_bytes = if let Some(control) = &self.metrics.egress_control {
            let framed_bytes = crate::hdlc::framed_len(data);
            if !control.try_reserve(framed_bytes) {
                if completion.is_some() {
                    if framed_bytes > control.byte_limit {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidInput,
                            "frame exceeds interface byte budget",
                        ));
                    }
                    return Err(io::Error::new(
                        io::ErrorKind::WouldBlock,
                        "interface egress budget is full",
                    ));
                }
                control.record_drop(framed_bytes);
                return Ok(());
            }
            framed_bytes
        } else {
            0
        };

        // Publish accounting before the frame becomes visible to the worker.
        self.metrics.queued_frames.fetch_add(1, Ordering::Relaxed);
        match self.tx.try_send(
            QueuedFrame {
                data: FrameBytes::Owned(data.to_vec()),
                reserved_bytes,
                completion: completion.take(),
            },
            true,
        ) {
            Ok(_) => Ok(()),
            Err(TrySendError::Full(frame)) => {
                *completion = frame.completion;
                self.metrics.queued_frames.fetch_sub(1, Ordering::Relaxed);
                if let Some(control) = &self.metrics.egress_control {
                    control.release(frame.reserved_bytes);
                }
                Err(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "interface writer queue is full",
                ))
            }
            Err(TrySendError::Disconnected(frame)) => {
                *completion = frame.completion;
                self.metrics.queued_frames.fetch_sub(1, Ordering::Relaxed);
                if let Some(control) = &self.metrics.egress_control {
                    control.release(frame.reserved_bytes);
                }
                self.metrics.worker_alive.store(false, Ordering::Relaxed);
                Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "interface writer worker disconnected",
                ))
            }
        }
    }
}

/// Wrap `writer` so frames are written off the driver thread.
///
/// Writers that send inline are returned unchanged, and writers that expose a
/// loop socket are run by the driver's loop writer; any other writer gets a
/// worker thread fed by a queue of `queue_capacity` frames.
pub fn wrap_async_writer(
    writer: Box<dyn Writer>,
    interface_id: InterfaceId,
    interface_name: &str,
    event_tx: EventSender,
    queue_capacity: usize,
) -> (Box<dyn Writer>, AsyncWriterMetrics) {
    wrap_async_writer_with_wait(
        writer,
        interface_id,
        interface_name,
        event_tx,
        queue_capacity,
        ASYNC_WRITER_BACKPRESSURE_WAIT,
    )
}

/// [`wrap_async_writer`] with an explicit backpressure wait, so tests can use
/// a wait long enough to stay deterministic on a loaded machine.
fn wrap_async_writer_with_wait(
    writer: Box<dyn Writer>,
    interface_id: InterfaceId,
    interface_name: &str,
    event_tx: EventSender,
    queue_capacity: usize,
    backpressure_wait: Duration,
) -> (Box<dyn Writer>, AsyncWriterMetrics) {
    if let Some(fd) = writer.loop_socket() {
        return loop_writer::wrap(writer, fd, interface_id, interface_name, event_tx);
    }
    if writer.sends_inline() {
        let metrics = AsyncWriterMetrics {
            queued_frames: Arc::default(),
            worker_alive: Arc::new(AtomicBool::new(true)),
            egress_control: None,
            space: Arc::default(),
            space_waiters: Arc::default(),
        };
        return (writer, metrics);
    }
    let egress_control = writer.egress_control();
    let queue = WriterQueue::new(queue_capacity);
    let (tx, rx) = (WriterTx(Arc::clone(&queue)), queue);
    let metrics = AsyncWriterMetrics {
        queued_frames: Arc::new(AtomicUsize::new(0)),
        worker_alive: Arc::new(AtomicBool::new(true)),
        egress_control,
        space: Arc::default(),
        space_waiters: Arc::default(),
    };
    let metrics_thread = metrics.clone();
    let name = interface_name.to_string();

    let spawn_result = thread::Builder::new()
        .name(format!("iface-writer-{}", interface_id.0))
        .spawn(move || async_writer_loop(writer, rx, interface_id, name, event_tx, metrics_thread));

    if let Err(err) = spawn_result {
        metrics.worker_alive.store(false, Ordering::Relaxed);
        log::error!(
            "[{}:{}] failed to spawn async writer thread: {}",
            interface_name,
            interface_id.0,
            err
        );
        return (Box::new(DirectWriterFallback), metrics);
    }

    (
        Box::new(AsyncWriter {
            tx,
            metrics: metrics.clone(),
            skip_wait: false,
            defer_wake: false,
            wake_pending: false,
            backpressure_wait,
        }),
        metrics,
    )
}

struct DirectWriterFallback;

impl Writer for DirectWriterFallback {
    fn send_frame(&mut self, _data: &[u8]) -> io::Result<()> {
        Err(io::Error::other("interface writer worker unavailable"))
    }
}

fn async_writer_loop(
    mut writer: Box<dyn Writer>,
    rx: Arc<WriterQueue>,
    interface_id: InterfaceId,
    interface_name: String,
    event_tx: EventSender,
    metrics: AsyncWriterMetrics,
) {
    let mut batch = Vec::new();
    while rx.recv_all(&mut batch) {
        let queued = std::mem::take(&mut batch);
        let reserved_bytes = queued.iter().map(|frame| frame.reserved_bytes).sum();
        metrics
            .queued_frames
            .fetch_sub(queued.len(), Ordering::Relaxed);
        metrics.notify_space();
        if event_tx.link_send_pool().in_flight() > 0 {
            let _ = event_tx.try_send(crate::event::Event::LinkWriterReady);
        }

        let mut result = Ok(());
        if queued.iter().any(|frame| frame.completion.is_some()) {
            for mut frame in queued {
                let confirmed = frame.completion.is_some();
                if frame.completion.as_ref().is_some_and(|c| c.is_finished()) {
                    result = Err(io::Error::new(
                        io::ErrorKind::Interrupted,
                        "transmission cancelled by shutdown",
                    ));
                }
                if result.is_ok() {
                    result = if frame.completion.is_some() {
                        writer.send_frame_confirmed(&frame.data)
                    } else {
                        writer.send_frame(&frame.data)
                    };
                    while result
                        .as_ref()
                        .is_err_and(|e| e.kind() == io::ErrorKind::WouldBlock)
                    {
                        if frame.completion.as_ref().is_some_and(|c| c.is_finished()) {
                            result = Err(io::Error::new(
                                io::ErrorKind::Interrupted,
                                "transmission cancelled by shutdown",
                            ));
                            break;
                        }
                        thread::sleep(Duration::from_millis(1));
                        result = writer.flush();
                    }
                }
                if let Some(completion) = frame.completion.take() {
                    completion.finish(
                        result.as_ref().map(|_| ()).map_err(|e| {
                            crate::link_send::LinkSendError::WriteFailed(e.to_string())
                        }),
                    );
                }
                // Packet-level policy/validation errors do not imply a broken
                // connection (e.g. a Local client that temporarily holds TX).
                if confirmed
                    && result.as_ref().is_err_and(|error| {
                        matches!(
                            error.kind(),
                            io::ErrorKind::PermissionDenied
                                | io::ErrorKind::InvalidInput
                                | io::ErrorKind::Unsupported
                        )
                    })
                {
                    result = Ok(());
                }
            }
        } else {
            let frames: Vec<_> = queued.into_iter().map(|frame| frame.data).collect();
            result = writer.send_frames(&frames);
        }
        while result
            .as_ref()
            .is_err_and(|error| error.kind() == io::ErrorKind::WouldBlock)
        {
            thread::sleep(Duration::from_millis(1));
            result = writer.flush();
        }

        if let Some(control) = &metrics.egress_control {
            control.release(reserved_bytes);
        }
        metrics.notify_space();
        if event_tx.link_send_pool().in_flight() > 0 {
            let _ = event_tx.try_send(crate::event::Event::LinkWriterReady);
        }

        if let Err(err) = result {
            metrics.worker_alive.store(false, Ordering::Relaxed);
            log::warn!(
                "[{}:{}] async writer exiting after send failure: {}",
                interface_name,
                interface_id.0,
                err
            );
            writer.shutdown();
            rx.close_receiver();
            metrics.notify_space();
            let _ = event_tx.send(crate::event::Event::InterfaceDown(interface_id));
            return;
        }
    }

    if rx.shutdown_requested() {
        writer.shutdown();
    }
    rx.close_receiver();
    metrics.worker_alive.store(false, Ordering::Relaxed);
    metrics.notify_space();
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::Event;
    use std::sync::mpsc;

    struct BlockingWriter {
        entered_tx: mpsc::Sender<()>,
        release_rx: mpsc::Receiver<()>,
    }

    #[test]
    fn confirmed_writer_waits_for_flush_and_reports_write_failures() {
        use crate::link_send::{Completion, LinkSendError, SendPool};
        use futures::FutureExt;
        struct FlushWriter {
            entered: mpsc::Sender<()>,
            release: mpsc::Receiver<()>,
            writes: Arc<AtomicUsize>,
        }
        impl Writer for FlushWriter {
            fn send_frame(&mut self, _: &[u8]) -> io::Result<()> {
                self.writes.fetch_add(1, Ordering::SeqCst);
                Err(io::ErrorKind::WouldBlock.into())
            }
            fn flush(&mut self) -> io::Result<()> {
                self.entered.send(()).unwrap();
                self.release.recv().unwrap();
                Ok(())
            }
        }
        let (event_tx, _rx) = crate::event::channel();
        let (entered, entered_rx) = mpsc::channel();
        let (release_tx, release) = mpsc::channel();
        let writes = Arc::new(AtomicUsize::new(0));
        let pool = SendPool::new(1);
        let (completion, mut receipt) = Completion::new(pool.try_acquire().unwrap());
        let (mut writer, _) = wrap_async_writer(
            Box::new(FlushWriter {
                entered,
                release,
                writes: writes.clone(),
            }),
            InterfaceId(999),
            "flush test",
            event_tx.clone(),
            1,
        );
        writer
            .enqueue_confirmed(b"once", &mut Some(completion))
            .unwrap();
        entered_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        assert!((&mut receipt).now_or_never().is_none());
        release_tx.send(()).unwrap();
        receipt.wait().unwrap();
        assert_eq!(
            writes.load(Ordering::SeqCst),
            1,
            "flush must not resubmit the frame"
        );

        let (completion, receipt) = Completion::new(pool.try_acquire().unwrap());
        let (mut writer, _) = wrap_async_writer(
            Box::new(FailingWriter {
                shutdown_called: Arc::new(AtomicBool::new(false)),
            }),
            InterfaceId(998),
            "failure test",
            event_tx,
            1,
        );
        writer
            .enqueue_confirmed(b"fail", &mut Some(completion))
            .unwrap();
        assert_eq!(
            receipt.wait(),
            Err(LinkSendError::WriteFailed("boom".into()))
        );
    }

    impl Writer for BlockingWriter {
        fn send_frame(&mut self, _data: &[u8]) -> io::Result<()> {
            let _ = self.entered_tx.send(());
            let _ = self.release_rx.recv();
            Ok(())
        }
    }

    #[cfg(feature = "iface-backbone")]
    struct EgressControlledBlockingWriter {
        inner: BlockingWriter,
        control: EgressControl,
    }

    #[cfg(feature = "iface-backbone")]
    impl Writer for EgressControlledBlockingWriter {
        fn send_frame(&mut self, data: &[u8]) -> io::Result<()> {
            self.inner.send_frame(data)
        }

        fn egress_control(&self) -> Option<EgressControl> {
            Some(self.control.clone())
        }
    }

    struct FailingWriter {
        shutdown_called: Arc<AtomicBool>,
    }

    struct RecordingWriter {
        sent_tx: mpsc::Sender<Vec<u8>>,
    }

    impl Writer for RecordingWriter {
        fn send_frame(&mut self, data: &[u8]) -> io::Result<()> {
            self.sent_tx
                .send(data.to_vec())
                .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "test receiver closed"))
        }
    }

    struct BatchRecordingWriter {
        batch_tx: mpsc::Sender<usize>,
        first_release: Option<mpsc::Receiver<()>>,
    }

    impl Writer for BatchRecordingWriter {
        fn send_frame(&mut self, _data: &[u8]) -> io::Result<()> {
            unreachable!("the async worker must use batch delivery")
        }

        fn send_frames(&mut self, frames: &[crate::interface::FrameBytes]) -> io::Result<()> {
            self.batch_tx.send(frames.len()).unwrap();
            if let Some(release) = self.first_release.take() {
                release.recv().unwrap();
            }
            Ok(())
        }
    }

    impl Writer for FailingWriter {
        fn send_frame(&mut self, _data: &[u8]) -> io::Result<()> {
            Err(io::Error::new(io::ErrorKind::BrokenPipe, "boom"))
        }

        fn shutdown(&mut self) {
            self.shutdown_called.store(true, Ordering::Relaxed);
        }
    }

    #[test]
    fn async_writer_returns_wouldblock_when_queue_is_full() {
        let (event_tx, _event_rx) = crate::event::channel();
        let (entered_tx, entered_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let (mut writer, metrics) = wrap_async_writer(
            Box::new(BlockingWriter {
                entered_tx,
                release_rx,
            }),
            InterfaceId(7),
            "test",
            event_tx,
            1,
        );

        writer.send_frame(&[1]).unwrap();
        entered_rx.recv_timeout(Duration::from_secs(1)).unwrap();
        writer.send_frame(&[2]).unwrap();
        assert_eq!(metrics.queued_frames(), 1);
        let err = writer.send_frame(&[3]).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::WouldBlock);

        release_tx.send(()).unwrap();
        entered_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("the queued frame must wake the writer without another send trigger");
        assert_eq!(metrics.queued_frames(), 0);
        release_tx.send(()).unwrap();
    }

    #[test]
    fn deferred_sends_are_delivered_on_wake_or_by_the_tick_backstop() {
        struct Recorder(mpsc::Sender<Vec<u8>>);
        impl Writer for Recorder {
            fn send_frame(&mut self, data: &[u8]) -> io::Result<()> {
                self.0.send(data.to_vec()).unwrap();
                Ok(())
            }
        }
        let (event_tx, _event_rx) = crate::event::channel();
        let (sent_tx, sent_rx) = mpsc::channel();
        let (mut writer, _metrics) = wrap_async_writer(
            Box::new(Recorder(sent_tx)),
            InterfaceId(9),
            "test",
            event_tx,
            8,
        );
        // Let the worker go to sleep on the empty queue.
        std::thread::sleep(Duration::from_millis(20));
        writer.send_frame_deferred(&[1]).unwrap();
        writer.send_frame_deferred(&[2]).unwrap();
        writer.wake();
        assert_eq!(
            sent_rx.recv_timeout(Duration::from_secs(1)).unwrap(),
            vec![1]
        );
        assert_eq!(
            sent_rx.recv_timeout(Duration::from_secs(1)).unwrap(),
            vec![2]
        );

        std::thread::sleep(Duration::from_millis(20));
        writer.send_frame_deferred(&[3]).unwrap();
        // No wake: the worker sleeps rather than polling...
        assert!(sent_rx.recv_timeout(Duration::from_millis(100)).is_err());
        // ...until the driver's tick, the backstop, or its end-of-pass flush.
        writer.tick();
        assert_eq!(
            sent_rx.recv_timeout(Duration::from_secs(1)).unwrap(),
            vec![3]
        );
        writer.send_frame_deferred(&[4]).unwrap();
        writer.flush_pending();
        assert_eq!(
            sent_rx.recv_timeout(Duration::from_secs(1)).unwrap(),
            vec![4]
        );
    }

    #[test]
    fn async_writer_waits_briefly_for_space_then_fails_fast_while_stalled() {
        let (event_tx, _event_rx) = crate::event::channel();
        let (entered_tx, entered_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        // Far longer than the production wait: the release below must reach
        // the worker, and a non-waiting send must return, within this bound
        // even when the machine is busy.
        let wait = Duration::from_millis(500);
        let (mut writer, metrics) = wrap_async_writer_with_wait(
            Box::new(BlockingWriter {
                entered_tx,
                release_rx,
            }),
            InterfaceId(8),
            "test",
            event_tx,
            1,
            wait,
        );
        writer.send_frame(&[1]).unwrap();
        entered_rx.recv_timeout(Duration::from_secs(1)).unwrap();
        writer.send_frame(&[2]).unwrap();

        // The worker frees the slot while the producer is waiting: the frame
        // is admitted instead of being refused.
        let release = release_tx.clone();
        let releaser = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(5));
            release.send(()).unwrap();
        });
        writer.send_frame(&[3]).unwrap();
        releaser.join().unwrap();
        entered_rx.recv_timeout(Duration::from_secs(1)).unwrap();
        assert_eq!(metrics.queued_frames(), 1);

        // A writer that stays full costs one bounded wait; later sends do not
        // wait again until a frame is admitted.
        let started = Instant::now();
        let err = writer.send_frame(&[4]).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::WouldBlock);
        assert!(started.elapsed() >= wait);
        let started = Instant::now();
        let err = writer.send_frame(&[5]).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::WouldBlock);
        assert!(started.elapsed() < wait);

        for _ in 0..3 {
            let _ = release_tx.send(());
        }
    }

    #[test]
    #[cfg(feature = "iface-backbone")]
    fn async_writer_shares_exact_egress_byte_valve_and_stall_gate() {
        let (event_tx, _event_rx) = crate::event::channel();
        let (entered_tx, entered_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let control = EgressControl::new(4);
        let (mut writer, metrics) = wrap_async_writer(
            Box::new(EgressControlledBlockingWriter {
                inner: BlockingWriter {
                    entered_tx,
                    release_rx,
                },
                control: control.clone(),
            }),
            InterfaceId(8),
            "egress-test",
            event_tx,
            8,
        );

        // Two ordinary bytes occupy exactly four HDLC bytes on wire.
        writer.send_frame(&[1, 2]).unwrap();
        entered_rx.recv_timeout(Duration::from_secs(1)).unwrap();
        assert_eq!(control.reserved_bytes.load(Ordering::Relaxed), 4);
        assert_eq!(metrics.tx_buffered(), 4);

        // The hard valve drops instead of retaining another four-byte frame.
        writer.send_frame(&[3, 4]).unwrap();
        assert_eq!(control.reserved_bytes.load(Ordering::Relaxed), 4);
        assert_eq!(control.dropped_frames.load(Ordering::Relaxed), 1);
        assert_eq!(control.dropped_bytes.load(Ordering::Relaxed), 4);
        assert_eq!(metrics.tx_drops(), 1);
        assert_eq!(metrics.tx_dropped_bytes(), 4);

        release_tx.send(()).unwrap();
        let deadline = Instant::now() + Duration::from_secs(1);
        while control.reserved_bytes.load(Ordering::Relaxed) != 0 {
            assert!(
                Instant::now() < deadline,
                "egress reservation did not drain"
            );
            thread::yield_now();
        }

        control.set_stalled(true);
        assert!(metrics.tx_stalled());
        writer.send_frame(&[5]).unwrap();
        assert_eq!(control.dropped_frames.load(Ordering::Relaxed), 2);
        assert_eq!(control.dropped_bytes.load(Ordering::Relaxed), 7);
        assert_eq!(metrics.queued_frames(), 0);
    }

    #[test]
    fn async_writer_reports_interface_down_after_worker_failure() {
        let (event_tx, event_rx) = crate::event::channel();
        let shutdown_called = Arc::new(AtomicBool::new(false));
        let (mut writer, metrics) = wrap_async_writer(
            Box::new(FailingWriter {
                shutdown_called: Arc::clone(&shutdown_called),
            }),
            InterfaceId(9),
            "fail",
            event_tx,
            2,
        );

        writer.send_frame(&[1]).unwrap();
        let event = event_rx.recv_timeout(Duration::from_secs(1)).unwrap();
        assert!(matches!(event, Event::InterfaceDown(InterfaceId(9))));
        assert!(!metrics.worker_alive());
        assert!(shutdown_called.load(Ordering::Relaxed));
    }

    #[test]
    fn async_writer_preserves_order_through_fifty_thousand_frame_burst() {
        const FRAME_COUNT: usize = 50_000;
        let (event_tx, _event_rx) = crate::event::channel();
        let (sent_tx, sent_rx) = mpsc::channel();
        let (mut writer, metrics) = wrap_async_writer(
            Box::new(RecordingWriter { sent_tx }),
            InterfaceId(11),
            "burst",
            event_tx,
            FRAME_COUNT,
        );

        for index in 0..FRAME_COUNT {
            let payload = (index as u64).to_be_bytes();
            writer.send_frame(&payload).unwrap();
        }

        for index in 0..FRAME_COUNT {
            let received = sent_rx.recv_timeout(Duration::from_secs(2)).unwrap();
            assert_eq!(received, (index as u64).to_be_bytes());
        }
        assert!(metrics.worker_alive());
    }

    #[test]
    fn async_writer_coalesces_frames_waiting_behind_an_active_batch() {
        let (event_tx, _event_rx) = crate::event::channel();
        let (batch_tx, batch_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let (mut writer, _) = wrap_async_writer(
            Box::new(BatchRecordingWriter {
                batch_tx,
                first_release: Some(release_rx),
            }),
            InterfaceId(12),
            "batch",
            event_tx,
            16,
        );

        writer.send_frame(&[0]).unwrap();
        assert_eq!(batch_rx.recv_timeout(Duration::from_secs(1)).unwrap(), 1);
        for index in 1..=10 {
            writer.send_frame(&[index]).unwrap();
        }
        release_tx.send(()).unwrap();

        assert_eq!(batch_rx.recv_timeout(Duration::from_secs(1)).unwrap(), 10);
    }
}
