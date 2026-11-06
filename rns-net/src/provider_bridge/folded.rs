//! The provider bridge on the compact engine's driver loop.
//!
//! With services folded (see [`crate::engine::FOLD_SERVICES`]) the bridge's
//! socket and its consumers' connections are registered on the driver's
//! poller, and the driver writes each consumer's queue as far as the socket
//! takes it: right after it queues an event, and again when the socket can
//! take more. Queues, limits and overflow are the threaded bridge's.
//!
//! A consumer that stops reading keeps its connection; its queue fills and
//! the overflow policy applies. The threaded bridge instead drops it after a
//! write blocks for a second.

use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::os::fd::{AsFd, AsRawFd};
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::Arc;

use super::{
    add_consumer, admit_consumer, lock_bridge_state, mark_disconnected, next_consumer_frame,
    prune_disconnected_consumers, BridgeShared, ConsumerShared,
};
use crate::poll::{Event as Interest, Poller};

/// Poller keys for the bridge: just above the RPC service's keys, which
/// start at `1 << (usize::BITS - 2)` and span `1 << 30`.
const KEY_BASE: usize = (1 << (usize::BITS - 2)) + (1 << 30);
const KEY_SPAN: usize = 1 << 20;
const LISTENER_KEY: usize = KEY_BASE;

/// Whether the bridge owns a poller key.
pub(super) fn owns(key: usize) -> bool {
    (KEY_BASE..KEY_BASE + KEY_SPAN).contains(&key)
}

fn interest(key: usize, writable: bool) -> Interest {
    let mut interest = Interest::readable(key);
    interest.writable = writable;
    interest
}

struct Consumer {
    shared: Arc<ConsumerShared>,
    stream: UnixStream,
    /// The frame being written, and how much of it is out.
    out: Vec<u8>,
    sent: usize,
    /// What the poller is armed for: `Some(writable)`, or `None` once the
    /// registration fired and has not been armed again.
    armed: Option<bool>,
}

pub(crate) struct FoldedIo {
    poller: Arc<Poller>,
    listener: UnixListener,
    consumers: HashMap<usize, Consumer>,
    next_key: usize,
}

impl FoldedIo {
    /// `listener` must already be non-blocking.
    pub(super) fn new(listener: UnixListener, poller: Arc<Poller>) -> io::Result<Self> {
        // SAFETY: the listener is kept, open, until `Drop` removes the
        // registration.
        unsafe {
            poller.add(
                listener.as_fd().as_raw_fd(),
                Interest::readable(LISTENER_KEY),
            )?
        };
        Ok(Self {
            poller,
            listener,
            consumers: HashMap::new(),
            next_key: LISTENER_KEY + 1,
        })
    }

    fn allocate_key(&mut self) -> usize {
        loop {
            let key = self.next_key;
            self.next_key = if key + 1 >= KEY_BASE + KEY_SPAN {
                LISTENER_KEY + 1
            } else {
                key + 1
            };
            if !self.consumers.contains_key(&key) {
                return key;
            }
        }
    }

    /// Serve a bridge key the poller reported ready.
    pub(super) fn ready(&mut self, shared: &Arc<BridgeShared>, event: crate::poll::Event) {
        if event.key == LISTENER_KEY {
            self.accept(shared);
            return;
        }
        let Some(mut consumer) = self.consumers.remove(&event.key) else {
            return;
        };
        consumer.armed = None;
        let result = if event.readable {
            drain(&mut consumer.stream)
        } else {
            Ok(())
        };
        match result.and_then(|()| drive(&self.poller, shared, event.key, &mut consumer)) {
            Ok(()) => {
                self.consumers.insert(event.key, consumer);
            }
            Err(err) => close(&self.poller, shared, consumer, &err),
        }
    }

    /// Write every consumer's queue as far as its socket takes it.
    pub(super) fn flush_all(&mut self, shared: &Arc<BridgeShared>) {
        let mut gone = Vec::new();
        for (key, consumer) in &mut self.consumers {
            if let Err(err) = drive(&self.poller, shared, *key, consumer) {
                gone.push((*key, err));
            }
        }
        for (key, err) in gone {
            if let Some(consumer) = self.consumers.remove(&key) {
                close(&self.poller, shared, consumer, &err);
            }
        }
    }

    fn accept(&mut self, shared: &Arc<BridgeShared>) {
        if !lock_bridge_state(shared).accepting {
            // Leave the listener unarmed: no consumer is accepted from now on.
            return;
        }
        loop {
            let stream = match self.listener.accept() {
                Ok((stream, _)) => stream,
                Err(err) if err.kind() == io::ErrorKind::WouldBlock => break,
                Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
                Err(err) => {
                    log::warn!("provider bridge accept error: {}", err);
                    break;
                }
            };
            if let Err(err) = stream.set_nonblocking(true) {
                log::debug!("provider bridge consumer setup failed: {}", err);
                continue;
            }
            let key = self.allocate_key();
            // SAFETY: the stream is kept, open, until `close` or `Drop`
            // removes the registration.
            if let Err(err) = unsafe {
                self.poller
                    .add(stream.as_fd().as_raw_fd(), Interest::none(key))
            } {
                log::warn!("provider bridge cannot watch a consumer: {}", err);
                continue;
            }
            let consumer_shared = admit_consumer(shared);
            add_consumer(shared, consumer_shared.clone(), None);
            let mut consumer = Consumer {
                shared: consumer_shared,
                stream,
                out: Vec::new(),
                sent: 0,
                armed: None,
            };
            match drive(&self.poller, shared, key, &mut consumer) {
                Ok(()) => {
                    self.consumers.insert(key, consumer);
                }
                Err(err) => close(&self.poller, shared, consumer, &err),
            }
        }
        if let Err(err) = self
            .poller
            .modify(self.listener.as_fd(), Interest::readable(LISTENER_KEY))
        {
            log::warn!("provider bridge cannot watch its socket again: {}", err);
        }
    }
}

impl Drop for FoldedIo {
    fn drop(&mut self) {
        for consumer in self.consumers.values() {
            let _ = self.poller.delete(consumer.stream.as_fd());
        }
        let _ = self.poller.delete(self.listener.as_fd());
    }
}

/// Read and discard what a consumer sent; consumers only listen, so this is
/// how a hang-up is noticed while there is nothing to write.
fn drain(stream: &mut UnixStream) -> io::Result<()> {
    let mut buf = [0u8; 512];
    loop {
        match stream.read(&mut buf) {
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "consumer closed the connection",
                ))
            }
            Ok(_) => {}
            Err(err) if err.kind() == io::ErrorKind::WouldBlock => return Ok(()),
            Err(err) if err.kind() == io::ErrorKind::Interrupted => {}
            Err(err) => return Err(err),
        }
    }
}

/// Write a consumer's queue until it is empty or the socket is full, then
/// arm the poller for what comes next.
fn drive(
    poller: &Poller,
    bridge: &Arc<BridgeShared>,
    key: usize,
    consumer: &mut Consumer,
) -> io::Result<()> {
    loop {
        if consumer.sent == consumer.out.len() {
            consumer.out.clear();
            consumer.sent = 0;
            let Some(frame) = next_consumer_frame(bridge, &consumer.shared) else {
                break;
            };
            let len = u32::try_from(frame.len()).map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidData, "provider frame too large")
            })?;
            consumer.out.extend_from_slice(&len.to_be_bytes());
            consumer.out.extend_from_slice(&frame);
        }
        match consumer.stream.write(&consumer.out[consumer.sent..]) {
            Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
            Ok(written) => consumer.sent += written,
            Err(err) if err.kind() == io::ErrorKind::WouldBlock => break,
            Err(err) if err.kind() == io::ErrorKind::Interrupted => {}
            Err(err) => return Err(err),
        }
    }
    let writable = consumer.sent < consumer.out.len();
    if consumer.armed != Some(writable) {
        poller.modify(consumer.stream.as_fd(), interest(key, writable))?;
        consumer.armed = Some(writable);
    }
    Ok(())
}

fn close(poller: &Poller, bridge: &Arc<BridgeShared>, consumer: Consumer, err: &io::Error) {
    let _ = poller.delete(consumer.stream.as_fd());
    mark_disconnected(bridge, &consumer.shared, err);
    prune_disconnected_consumers(bridge);
}
