//! Socket writer driven by the driver thread.
//!
//! Replaces the async writer thread for stream sockets. Frames are encoded
//! straight into one byte buffer; the driver writes it to the socket with
//! nonblocking sends: immediately for ordinary sends, and once per event
//! pass for deferred (forwarded) frames, so a burst leaves in few large
//! writes. Bytes the socket cannot take yet stay buffered; the writer then
//! registers writable interest on the driver's poller and finishes when the
//! driver reports the socket writable.

use std::collections::VecDeque;
use std::io;
use std::os::fd::{BorrowedFd, RawFd};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Instant;

use rns_core::transport::types::InterfaceId;

use super::{AsyncWriterMetrics, Writer, ASYNC_WRITER_BACKPRESSURE_WAIT};
use crate::event::EventSender;
use crate::link_send::{Completion, LinkSendError};

/// Bytes buffered per writer before new frames must wait for the socket.
/// A frame is always admitted into an empty buffer, whatever its size.
pub(crate) const LOOP_WRITER_BUFFER_LIMIT: usize = 1024 * 1024;

/// Poller key for a writer's writable interest. Keys of even value are left
/// for read interest on the same interface.
pub(crate) fn write_key(id: InterfaceId) -> usize {
    ((id.0 as usize) << 1) | 1
}

/// Poller key for read interest on an interface's socket (or, for a
/// listening interface, its listener).
pub(crate) fn read_key(id: InterfaceId) -> usize {
    (id.0 as usize) << 1
}

/// The interface a poller key belongs to, and whether it is a write key.
pub(crate) fn key_target(key: usize) -> (InterfaceId, bool) {
    (InterfaceId((key >> 1) as u64), key & 1 == 1)
}

pub(crate) struct LoopWriter {
    /// Owns the socket (and anything else the concrete writer holds).
    inner: Box<dyn Writer>,
    fd: RawFd,
    out: Vec<u8>,
    /// Bytes of `out` already written to the socket.
    head: usize,
    /// Total bytes ever appended and written; offsets below are in this space.
    appended: u64,
    sent: u64,
    /// End offset of each frame still (partly) buffered.
    frame_ends: VecDeque<u64>,
    /// Confirmed sends, completed once their last byte is written.
    completions: VecDeque<(u64, Completion)>,
    metrics: AsyncWriterMetrics,
    poller: Arc<polling::Poller>,
    key: usize,
    registered: bool,
    want_writable: bool,
    /// Set after a backpressure wait times out; cleared on the next
    /// admission. Mirrors the async writer's stalled-peer behaviour.
    skip_wait: bool,
    failed: bool,
    interface_id: InterfaceId,
    interface_name: String,
    event_tx: EventSender,
}

pub(crate) fn wrap(
    inner: Box<dyn Writer>,
    fd: RawFd,
    interface_id: InterfaceId,
    interface_name: &str,
    event_tx: EventSender,
) -> (Box<dyn Writer>, AsyncWriterMetrics) {
    let metrics = AsyncWriterMetrics {
        queued_frames: Arc::default(),
        worker_alive: Arc::new(std::sync::atomic::AtomicBool::new(true)),
        egress_control: None,
        space: Arc::default(),
        space_waiters: Arc::default(),
    };
    let poller = Arc::clone(event_tx.poller());
    let key = write_key(interface_id);
    // SAFETY: `fd` is owned by `inner`, which outlives the registration:
    // `Drop` deletes it before the fields (and the socket) are dropped.
    let registered = match unsafe { poller.add(fd, polling::Event::none(key)) } {
        Ok(()) => true,
        Err(error) => {
            log::warn!(
                "[{}:{}] cannot register writer with the driver poller: {}",
                interface_name,
                interface_id.0,
                error
            );
            false
        }
    };
    let writer = LoopWriter {
        inner,
        fd,
        out: Vec::new(),
        head: 0,
        appended: 0,
        sent: 0,
        frame_ends: VecDeque::new(),
        completions: VecDeque::new(),
        metrics: metrics.clone(),
        poller,
        key,
        registered,
        want_writable: false,
        skip_wait: false,
        failed: false,
        interface_id,
        interface_name: interface_name.to_string(),
        event_tx,
    };
    (Box::new(writer), metrics)
}

impl LoopWriter {
    fn buffered(&self) -> usize {
        (self.appended - self.sent) as usize
    }

    fn offline() -> io::Error {
        io::Error::new(io::ErrorKind::BrokenPipe, "interface writer is offline")
    }

    /// Whether a frame of `bytes` encoded bytes fits now.
    fn fits(&self, bytes: usize) -> bool {
        self.buffered() == 0 || self.buffered() + bytes <= LOOP_WRITER_BUFFER_LIMIT
    }

    fn append(&mut self, data: &[u8]) {
        if self.head == self.out.len() {
            self.out.clear();
            self.head = 0;
        }
        let before = self.out.len();
        crate::hdlc::append_frame(data, &mut self.out);
        self.appended += (self.out.len() - before) as u64;
        self.frame_ends.push_back(self.appended);
        self.metrics.queued_frames.fetch_add(1, Ordering::Relaxed);
    }

    /// Admit an unconfirmed frame. Like the async writer, a full buffer
    /// makes the caller wait up to [`ASYNC_WRITER_BACKPRESSURE_WAIT`] for
    /// the socket to drain, and a peer that stayed full for a whole wait is
    /// refused at once until a frame fits again.
    fn admit_unconfirmed(&mut self, data: &[u8]) -> io::Result<()> {
        if self.failed {
            return Err(Self::offline());
        }
        let bytes = crate::hdlc::framed_len(data);
        if !self.fits(bytes) {
            self.drain();
            if self.failed {
                return Err(Self::offline());
            }
        }
        if !self.fits(bytes) && (self.skip_wait || !self.wait_for_space(bytes)) {
            self.skip_wait = true;
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "interface writer buffer is full",
            ));
        }
        self.skip_wait = false;
        self.append(data);
        Ok(())
    }

    fn wait_for_space(&mut self, bytes: usize) -> bool {
        let deadline = Instant::now() + ASYNC_WRITER_BACKPRESSURE_WAIT;
        while !self.fits(bytes) {
            let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
                return false;
            };
            let mut pfd = libc::pollfd {
                fd: self.fd,
                events: libc::POLLOUT,
                revents: 0,
            };
            let timeout = i32::try_from(remaining.as_millis().max(1)).unwrap_or(i32::MAX);
            // SAFETY: one valid pollfd for the duration of the call.
            let ready = unsafe { libc::poll(&mut pfd, 1, timeout) };
            if ready < 0 {
                let error = io::Error::last_os_error();
                if error.kind() != io::ErrorKind::Interrupted {
                    self.fail(error);
                    return false;
                }
            }
            self.drain();
            if self.failed {
                return false;
            }
        }
        true
    }

    /// Write as much as the socket takes without blocking, complete what was
    /// written, and keep writable interest exactly while bytes remain.
    fn drain(&mut self) {
        while !self.failed && self.head < self.out.len() {
            let pending = &self.out[self.head..];
            // SAFETY: `pending` is a valid initialized slice; MSG_DONTWAIT
            // makes this call nonblocking without changing the socket's mode,
            // which a reader on a duplicate of the descriptor may rely on.
            let written = unsafe {
                libc::send(
                    self.fd,
                    pending.as_ptr().cast(),
                    pending.len(),
                    libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL,
                )
            };
            if written < 0 {
                let error = io::Error::last_os_error();
                match error.kind() {
                    io::ErrorKind::Interrupted => continue,
                    io::ErrorKind::WouldBlock => break,
                    _ => {
                        self.fail(error);
                        return;
                    }
                }
            }
            if written == 0 {
                break;
            }
            self.head += written as usize;
            self.sent += written as u64;
        }
        self.complete_written();
        if self.head == self.out.len() {
            self.out.clear();
            self.head = 0;
            if self.out.capacity() > 2 * LOOP_WRITER_BUFFER_LIMIT {
                self.out.shrink_to(LOOP_WRITER_BUFFER_LIMIT);
            }
        } else if self.head >= self.out.len() / 2 {
            self.out.drain(..self.head);
            self.head = 0;
        }
        self.set_writable_interest(self.buffered() > 0);
    }

    fn complete_written(&mut self) {
        let mut done = 0;
        while self.frame_ends.front().is_some_and(|end| *end <= self.sent) {
            self.frame_ends.pop_front();
            done += 1;
        }
        if done > 0 {
            self.metrics
                .queued_frames
                .fetch_sub(done, Ordering::Relaxed);
        }
        while self
            .completions
            .front()
            .is_some_and(|(end, _)| *end <= self.sent)
        {
            if let Some((_, completion)) = self.completions.pop_front() {
                completion.finish(Ok(()));
            }
        }
    }

    /// Interest is one-shot: a delivered writable event disarms it, so
    /// wanting it re-arms on every call, and only disarming is skipped when
    /// already disarmed.
    fn set_writable_interest(&mut self, want: bool) {
        if !self.registered || (!want && !self.want_writable) {
            return;
        }
        let interest = if want {
            polling::Event::writable(self.key)
        } else {
            polling::Event::none(self.key)
        };
        // SAFETY: the descriptor stays open while registered (see `wrap`).
        let source = unsafe { BorrowedFd::borrow_raw(self.fd) };
        match self.poller.modify(source, interest) {
            Ok(()) => self.want_writable = want,
            Err(error) => log::warn!(
                "[{}:{}] cannot update writer poll interest: {}",
                self.interface_name,
                self.interface_id.0,
                error
            ),
        }
    }

    /// The socket failed: report the interface down once, as the async
    /// writer does, and fail every pending confirmed send.
    fn fail(&mut self, error: io::Error) {
        if self.failed {
            return;
        }
        self.failed = true;
        self.metrics.worker_alive.store(false, Ordering::Relaxed);
        log::warn!(
            "[{}:{}] interface writer stopping after send failure: {}",
            self.interface_name,
            self.interface_id.0,
            error
        );
        for (_, completion) in self.completions.drain(..) {
            completion.finish(Err(LinkSendError::WriteFailed(error.to_string())));
        }
        self.metrics.queued_frames.store(0, Ordering::Relaxed);
        self.frame_ends.clear();
        self.out.clear();
        self.head = 0;
        self.sent = self.appended;
        self.set_writable_interest(false);
        self.inner.shutdown();
        // The driver is the queue's consumer, so it must never block on it.
        if let Err(error) = self
            .event_tx
            .try_send(crate::event::Event::InterfaceDown(self.interface_id))
        {
            log::warn!(
                "[{}:{}] could not queue interface down: {:?}",
                self.interface_name,
                self.interface_id.0,
                error.to_string()
            );
        }
    }
}

impl Writer for LoopWriter {
    fn send_frame(&mut self, data: &[u8]) -> io::Result<()> {
        self.admit_unconfirmed(data)?;
        self.drain();
        Ok(())
    }

    fn send_frame_deferred(&mut self, data: &[u8]) -> io::Result<()> {
        self.admit_unconfirmed(data)
    }

    fn wake(&mut self) {
        self.drain();
    }

    fn send_frames(&mut self, frames: &[crate::interface::FrameBytes]) -> io::Result<()> {
        for frame in frames {
            self.admit_unconfirmed(frame)?;
        }
        self.drain();
        Ok(())
    }

    fn enqueue_confirmed(
        &mut self,
        data: &[u8],
        completion: &mut Option<Completion>,
    ) -> io::Result<()> {
        if self.failed {
            return Err(Self::offline());
        }
        let bytes = crate::hdlc::framed_len(data);
        if !self.fits(bytes) {
            self.drain();
            if self.failed {
                return Err(Self::offline());
            }
            if !self.fits(bytes) {
                // Confirmed senders retry through the completion machinery.
                return Err(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "interface writer buffer is full",
                ));
            }
        }
        self.append(data);
        if let Some(completion) = completion.take() {
            self.completions.push_back((self.appended, completion));
        }
        self.drain();
        Ok(())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.drain();
        if self.failed {
            Err(Self::offline())
        } else if self.buffered() > 0 {
            Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "interface writer still has buffered bytes",
            ))
        } else {
            Ok(())
        }
    }

    fn shutdown(&mut self) {
        self.inner.shutdown();
    }
}

impl Drop for LoopWriter {
    fn drop(&mut self) {
        if self.registered {
            // SAFETY: `inner` still owns the open descriptor here.
            let source = unsafe { BorrowedFd::borrow_raw(self.fd) };
            let _ = self.poller.delete(source);
        }
        for (_, completion) in self.completions.drain(..) {
            completion.finish(Err(LinkSendError::WriteFailed(
                "interface writer dropped".into(),
            )));
        }
        self.metrics.worker_alive.store(false, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::link_send::SendPool;
    use futures::FutureExt;
    use std::io::Read;
    use std::net::{TcpListener, TcpStream};
    use std::os::fd::AsRawFd;
    use std::time::Duration;

    struct Socket(TcpStream);

    impl Writer for Socket {
        fn send_frame(&mut self, _data: &[u8]) -> io::Result<()> {
            unreachable!("the loop writer writes the descriptor itself")
        }

        fn shutdown(&mut self) {
            let _ = self.0.shutdown(std::net::Shutdown::Both);
        }
    }

    struct Fixture {
        writer: Box<dyn Writer>,
        metrics: AsyncWriterMetrics,
        peer: TcpStream,
        rx: crate::event::EventReceiver,
        poller: Arc<polling::Poller>,
    }

    fn fixture(send_buffer: Option<usize>) -> Fixture {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let stream = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (peer, _) = listener.accept().unwrap();
        // A small send buffer makes the writer keep bytes itself; a tiny
        // receive window would only slow TCP down to delayed-ACK pace.
        if let Some(size) = send_buffer {
            socket2::SockRef::from(&stream)
                .set_send_buffer_size(size)
                .unwrap();
            socket2::SockRef::from(&peer)
                .set_recv_buffer_size(64 * 1024)
                .unwrap();
        }
        let fd = stream.as_raw_fd();
        let (tx, rx) = crate::event::channel();
        let poller = Arc::clone(tx.poller());
        let (writer, metrics) = wrap(Box::new(Socket(stream)), fd, InterfaceId(7), "test", tx);
        Fixture {
            writer,
            metrics,
            peer,
            rx,
            poller,
        }
    }

    fn read_exact(peer: &mut TcpStream, len: usize) -> Vec<u8> {
        peer.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let mut out = vec![0; len];
        peer.read_exact(&mut out).unwrap();
        out
    }

    fn nothing_readable(peer: &mut TcpStream) -> bool {
        peer.set_read_timeout(Some(Duration::from_millis(30)))
            .unwrap();
        let mut byte = [0u8; 1];
        matches!(peer.read(&mut byte), Err(error) if error.kind() == io::ErrorKind::WouldBlock)
    }

    #[test]
    fn keys_round_trip_and_separate_directions() {
        let id = InterfaceId(41);
        assert_eq!(key_target(write_key(id)), (id, true));
        assert_eq!(key_target(read_key(id)), (id, false));
        assert_eq!(read_key(id) + 1, write_key(id));
    }

    #[test]
    fn ordinary_sends_are_written_immediately_as_hdlc() {
        let mut f = fixture(None);
        f.writer.send_frame(&[1, 0x7E, 2]).unwrap();
        f.writer
            .send_frames(&[
                crate::interface::FrameBytes::Owned(vec![3]),
                crate::interface::FrameBytes::Owned(vec![0x7D]),
            ])
            .unwrap();
        let mut expected = crate::hdlc::frame(&[1, 0x7E, 2]);
        expected.extend(crate::hdlc::frame(&[3]));
        expected.extend(crate::hdlc::frame(&[0x7D]));
        assert_eq!(read_exact(&mut f.peer, expected.len()), expected);
        assert_eq!(f.metrics.queued_frames(), 0);
    }

    #[test]
    fn deferred_sends_wait_for_wake_and_leave_together() {
        let mut f = fixture(None);
        for byte in 0..50u8 {
            f.writer.send_frame_deferred(&[byte; 40]).unwrap();
        }
        assert!(nothing_readable(&mut f.peer));
        assert_eq!(f.metrics.queued_frames(), 50);
        f.writer.wake();
        let expected: Vec<u8> = (0..50u8)
            .flat_map(|b| crate::hdlc::frame(&[b; 40]))
            .collect();
        assert_eq!(read_exact(&mut f.peer, expected.len()), expected);
        assert_eq!(f.metrics.queued_frames(), 0);
    }

    #[test]
    fn leftover_bytes_arm_writable_interest_and_finish_later() {
        let mut f = fixture(Some(4096));
        let payload = vec![0x55u8; 200_000];
        let pool = SendPool::new(1);
        let (completion, mut receipt) = Completion::new(pool.try_acquire().unwrap());
        let mut completion = Some(completion);
        f.writer
            .enqueue_confirmed(&payload, &mut completion)
            .unwrap();
        assert!(completion.is_none());
        assert_eq!(f.metrics.queued_frames(), 1);
        assert!(
            (&mut receipt).now_or_never().is_none(),
            "completed before its bytes were written"
        );

        let expected = crate::hdlc::frame(&payload);
        let mut received = Vec::new();
        let mut events = polling::Events::new();
        f.peer
            .set_read_timeout(Some(Duration::from_millis(20)))
            .unwrap();
        while received.len() < expected.len() {
            let mut buf = [0u8; 65536];
            match f.peer.read(&mut buf) {
                Ok(n) => received.extend_from_slice(&buf[..n]),
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                Err(e) => panic!("{e}"),
            }
            events.clear();
            f.poller
                .wait(&mut events, Some(Duration::from_millis(20)))
                .unwrap();
            for event in events.iter() {
                assert_eq!(key_target(event.key), (InterfaceId(7), true));
                f.writer.wake();
            }
        }
        assert_eq!(received, expected);
        receipt.wait().unwrap();
        assert_eq!(f.metrics.queued_frames(), 0);
    }

    #[test]
    fn a_full_buffer_waits_briefly_then_refuses_until_space_returns() {
        let mut f = fixture(Some(4096));
        let frame = vec![0x11u8; 64 * 1024];
        let mut admitted = 0;
        let started = Instant::now();
        let refused = loop {
            match f.writer.send_frame_deferred(&frame) {
                Ok(()) => admitted += 1,
                Err(error) => break error,
            }
            assert!(admitted < 1000, "buffer never filled");
        };
        assert_eq!(refused.kind(), io::ErrorKind::WouldBlock);
        assert!(started.elapsed() >= ASYNC_WRITER_BACKPRESSURE_WAIT);
        // Stalled: the next refusal is immediate.
        let again = Instant::now();
        assert!(f.writer.send_frame_deferred(&frame).is_err());
        assert!(again.elapsed() < ASYNC_WRITER_BACKPRESSURE_WAIT);
        // Once the peer reads everything, frames are admitted again.
        let expected_len = admitted * crate::hdlc::frame(&frame).len();
        let reader = std::thread::spawn(move || read_exact(&mut f.peer, expected_len).len());
        let deadline = Instant::now() + Duration::from_secs(10);
        let mut events = polling::Events::new();
        while f.metrics.queued_frames() > 0 {
            assert!(Instant::now() < deadline, "buffer never drained");
            events.clear();
            f.poller
                .wait(&mut events, Some(Duration::from_millis(50)))
                .unwrap();
            f.writer.wake();
        }
        assert_eq!(reader.join().unwrap(), expected_len);
        f.writer.send_frame(&frame).unwrap();
    }

    #[test]
    fn a_dead_peer_fails_pending_sends_and_reports_the_interface_down() {
        let mut f = fixture(Some(4096));
        let pool = SendPool::new(1);
        let (completion, receipt) = Completion::new(pool.try_acquire().unwrap());
        f.writer
            .enqueue_confirmed(&vec![0x22u8; 300_000], &mut Some(completion))
            .unwrap();
        drop(f.peer);
        let deadline = Instant::now() + Duration::from_secs(5);
        while f.metrics.worker_alive() {
            assert!(Instant::now() < deadline, "send failure never observed");
            f.writer.wake();
            std::thread::sleep(Duration::from_millis(5));
        }
        assert!(matches!(receipt.wait(), Err(LinkSendError::WriteFailed(_))));
        assert_eq!(
            f.writer.send_frame(&[1]).unwrap_err().kind(),
            io::ErrorKind::BrokenPipe
        );
        let mut seen_down = false;
        while let Ok(Some(event)) = f.rx.try_recv_classified() {
            seen_down |= matches!(
                event.event,
                crate::event::Event::InterfaceDown(InterfaceId(7))
            );
        }
        assert!(seen_down);
    }
}
