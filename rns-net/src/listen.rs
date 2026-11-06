//! Waiting for connections on a listening socket without polling it.
//!
//! A listener thread blocks in its poller until a connection is pending or
//! it is woken to stop, instead of retrying a non-blocking `accept` on a
//! timer, which on an idle node woke each listener up to a hundred times a
//! second.

use std::io;
use std::os::fd::{AsFd, AsRawFd};
use std::sync::Arc;

use crate::poll::{Event, Events, Poller};

const LISTENER_KEY: usize = 0;

/// A non-blocking listener and the poller its thread waits in.
pub(crate) struct Listener<L: AsFd> {
    // Dropped after the registration is removed, in `Drop`.
    listener: L,
    poller: Arc<Poller>,
    events: Events,
}

/// Wakes a [`Listener`]'s current or next wait, for its thread to see a stop
/// request.
#[derive(Clone)]
pub(crate) struct ListenerWake {
    poller: Arc<Poller>,
}

impl ListenerWake {
    pub(crate) fn wake(&self) {
        let _ = self.poller.notify();
    }
}

impl<L: AsFd> Listener<L> {
    /// `listener` must already be non-blocking.
    pub(crate) fn new(listener: L) -> io::Result<(Self, ListenerWake)> {
        let poller = Arc::new(Poller::new()?);
        // SAFETY: the descriptor is owned by `listener`, which this value
        // keeps open until `Drop` has removed the registration.
        unsafe { poller.add(listener.as_fd().as_raw_fd(), Event::readable(LISTENER_KEY))? };
        let wake = ListenerWake {
            poller: Arc::clone(&poller),
        };
        Ok((
            Self {
                listener,
                poller,
                events: Events::new(),
            },
            wake,
        ))
    }

    pub(crate) fn get(&self) -> &L {
        &self.listener
    }

    /// Block until a connection may be pending or [`ListenerWake::wake`] is
    /// called. Call it after `accept` reports `WouldBlock`; a connection that
    /// arrived in between ends the wait at once.
    pub(crate) fn wait(&mut self) -> io::Result<()> {
        self.poller
            .modify(self.listener.as_fd(), Event::readable(LISTENER_KEY))?;
        self.events.clear();
        self.poller.wait(&mut self.events, None)?;
        Ok(())
    }
}

impl<L: AsFd> Drop for Listener<L> {
    fn drop(&mut self) {
        let _ = self.poller.delete(self.listener.as_fd());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{TcpListener, TcpStream};
    use std::time::{Duration, Instant};

    fn listener() -> (Listener<TcpListener>, ListenerWake, std::net::SocketAddr) {
        let socket = TcpListener::bind("127.0.0.1:0").unwrap();
        socket.set_nonblocking(true).unwrap();
        let addr = socket.local_addr().unwrap();
        let (listener, wake) = Listener::new(socket).unwrap();
        (listener, wake, addr)
    }

    #[test]
    fn wait_ends_when_a_connection_arrives() {
        let (mut listener, _wake, addr) = listener();
        assert_eq!(
            listener.get().accept().unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
        let client = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(50));
            TcpStream::connect(addr).unwrap()
        });
        listener.wait().unwrap();
        assert!(listener.get().accept().is_ok());
        drop(client.join());
    }

    #[test]
    fn wait_ends_at_once_for_a_connection_already_pending() {
        let (mut listener, _wake, addr) = listener();
        let _client = TcpStream::connect(addr).unwrap();
        let started = Instant::now();
        listener.wait().unwrap();
        assert!(started.elapsed() < Duration::from_secs(1));
        assert!(listener.get().accept().is_ok());
    }

    #[test]
    fn wake_ends_the_wait_without_a_connection() {
        let (mut listener, wake, _addr) = listener();
        let waker = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(50));
            wake.wake();
        });
        listener.wait().unwrap();
        assert_eq!(
            listener.get().accept().unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
        waker.join().unwrap();
    }
}
