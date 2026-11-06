//! The compact engine's RPC servers, served on the driver loop.
//!
//! With services folded (see [`crate::engine::FOLD_SERVICES`]) the RPC
//! listeners and their connections are registered on the driver's poller
//! under keys of their own, like interface writers. The exchange on each
//! connection is the one the server threads have ([`crate::rpc::ServerSession`]);
//! the request is then answered by the driver itself, with no event queue
//! and no thread in between.

use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::fd::{AsFd, AsRawFd, BorrowedFd};
#[cfg(target_os = "linux")]
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::Arc;
use std::time::{Duration, Instant};

use super::*;
use crate::poll::{Event as Interest, Poller};
use crate::rpc::{RpcDriver, ServerSession};

const RPC_KEYS: std::ops::Range<usize> = crate::engine::service_keys::RPC;

/// Connections served at once, as the server threads allow.
const MAX_CONNECTIONS: usize = 32;

/// A connection that makes no progress for this long is closed, as the
/// server threads' socket timeouts close it.
const IDLE_TIMEOUT: Duration = Duration::from_secs(10);

/// Bytes read from a connection at a time.
const READ_CHUNK: usize = 16 * 1024;

/// A listening RPC socket.
pub(crate) enum RpcListener {
    Tcp(TcpListener),
    #[cfg(target_os = "linux")]
    Unix(UnixListener),
}

impl RpcListener {
    fn fd(&self) -> BorrowedFd<'_> {
        match self {
            RpcListener::Tcp(listener) => listener.as_fd(),
            #[cfg(target_os = "linux")]
            RpcListener::Unix(listener) => listener.as_fd(),
        }
    }

    fn set_nonblocking(&self) -> io::Result<()> {
        match self {
            RpcListener::Tcp(listener) => listener.set_nonblocking(true),
            #[cfg(target_os = "linux")]
            RpcListener::Unix(listener) => listener.set_nonblocking(true),
        }
    }

    fn accept(&self) -> io::Result<RpcStream> {
        match self {
            RpcListener::Tcp(listener) => listener.accept().map(|(s, _)| RpcStream::Tcp(s)),
            #[cfg(target_os = "linux")]
            RpcListener::Unix(listener) => listener.accept().map(|(s, _)| RpcStream::Unix(s)),
        }
    }
}

enum RpcStream {
    Tcp(TcpStream),
    #[cfg(target_os = "linux")]
    Unix(UnixStream),
}

impl RpcStream {
    fn fd(&self) -> BorrowedFd<'_> {
        match self {
            RpcStream::Tcp(stream) => stream.as_fd(),
            #[cfg(target_os = "linux")]
            RpcStream::Unix(stream) => stream.as_fd(),
        }
    }

    fn set_nonblocking(&self) -> io::Result<()> {
        match self {
            RpcStream::Tcp(stream) => stream.set_nonblocking(true),
            #[cfg(target_os = "linux")]
            RpcStream::Unix(stream) => stream.set_nonblocking(true),
        }
    }

    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            RpcStream::Tcp(stream) => stream.read(buf),
            #[cfg(target_os = "linux")]
            RpcStream::Unix(stream) => stream.read(buf),
        }
    }

    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            RpcStream::Tcp(stream) => stream.write(buf),
            #[cfg(target_os = "linux")]
            RpcStream::Unix(stream) => stream.write(buf),
        }
    }
}

struct Connection {
    stream: RpcStream,
    session: ServerSession,
    last_progress: Instant,
}

/// The RPC listeners and connections the driver serves.
pub(crate) struct RpcService {
    auth_key: [u8; 32],
    poller: Arc<Poller>,
    listeners: Vec<(usize, RpcListener)>,
    connections: HashMap<usize, Connection>,
    next_key: usize,
}

fn interest(key: usize, readable: bool, writable: bool) -> Interest {
    let mut interest = Interest::none(key);
    interest.readable = readable;
    interest.writable = writable;
    interest
}

impl RpcService {
    pub(crate) fn new(auth_key: [u8; 32], poller: Arc<Poller>) -> Self {
        Self {
            auth_key,
            poller,
            listeners: Vec::new(),
            connections: HashMap::new(),
            next_key: RPC_KEYS.start,
        }
    }

    /// Whether `key` is one of this service's poller keys.
    pub(crate) fn owns(key: usize) -> bool {
        RPC_KEYS.contains(&key)
    }

    fn allocate_key(&mut self) -> usize {
        loop {
            let key = self.next_key;
            self.next_key = if key + 1 >= RPC_KEYS.end {
                RPC_KEYS.start
            } else {
                key + 1
            };
            let in_use = self.connections.contains_key(&key)
                || self.listeners.iter().any(|(used, _)| *used == key);
            if !in_use {
                return key;
            }
        }
    }

    /// Accept connections on `listener` from now on.
    pub(crate) fn add_listener(&mut self, listener: RpcListener) -> io::Result<()> {
        listener.set_nonblocking()?;
        let key = self.allocate_key();
        // SAFETY: the listener is kept, open, until `Drop` removes the
        // registration.
        unsafe {
            self.poller
                .add(listener.fd().as_raw_fd(), Interest::readable(key))?
        };
        self.listeners.push((key, listener));
        Ok(())
    }

    /// Serve a key the poller reported ready.
    pub(crate) fn ready(&mut self, key: usize, driver: &mut dyn RpcDriver) {
        if let Some(index) = self.listeners.iter().position(|(used, _)| *used == key) {
            self.accept(index, driver);
            return;
        }
        let Some(mut connection) = self.connections.remove(&key) else {
            return;
        };
        if self.drive(key, &mut connection, driver) {
            self.connections.insert(key, connection);
        } else {
            self.close(connection);
        }
    }

    fn accept(&mut self, index: usize, driver: &mut dyn RpcDriver) {
        loop {
            let accepted = self.listeners[index].1.accept();
            let stream = match accepted {
                Ok(stream) => stream,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => {
                    log::error!("RPC accept error: {error}");
                    break;
                }
            };
            if self.connections.len() >= MAX_CONNECTIONS {
                log::warn!(
                    "rejecting RPC connection: {MAX_CONNECTIONS} connections already active"
                );
                continue;
            }
            if let Err(error) = stream.set_nonblocking() {
                log::debug!("RPC connection setup failed: {error}");
                continue;
            }
            let key = self.allocate_key();
            // SAFETY: the stream is kept, open, until `close` removes the
            // registration.
            if let Err(error) = unsafe {
                self.poller
                    .add(stream.fd().as_raw_fd(), interest(key, false, false))
            } {
                log::error!("cannot watch an RPC connection: {error}");
                continue;
            }
            let mut connection = Connection {
                stream,
                session: ServerSession::new(self.auth_key, crate::rpc::challenge_random()),
                last_progress: Instant::now(),
            };
            if self.drive(key, &mut connection, driver) {
                self.connections.insert(key, connection);
            } else {
                self.close(connection);
            }
        }
        let (key, listener) = &self.listeners[index];
        if let Err(error) = self.poller.modify(listener.fd(), Interest::readable(*key)) {
            log::error!("cannot watch an RPC listener again: {error}");
        }
    }

    /// Move a connection along as far as its socket allows. Returns false
    /// once it is over.
    fn drive(&self, key: usize, connection: &mut Connection, driver: &mut dyn RpcDriver) -> bool {
        let mut buf = [0u8; READ_CHUNK];
        loop {
            while !connection.session.pending().is_empty() {
                match connection.stream.write(connection.session.pending()) {
                    Ok(0) => return false,
                    Ok(written) => {
                        connection.session.sent(written);
                        connection.last_progress = Instant::now();
                    }
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                    Err(error) => {
                        log::debug!("RPC connection error: {error}");
                        return false;
                    }
                }
            }
            if connection.session.finished() {
                return false;
            }
            if !connection.session.wants_input() {
                break;
            }
            let read = match connection.stream.read(&mut buf) {
                // The client hung up before the exchange was over.
                Ok(0) => return false,
                Ok(read) => read,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => {
                    log::debug!("RPC connection error: {error}");
                    return false;
                }
            };
            connection.last_progress = Instant::now();
            match connection.session.receive(&buf[..read]) {
                Ok(Some(request)) => match crate::rpc::answer_request(&request, driver) {
                    Ok(response) => connection.session.answer(&response),
                    Err(error) => {
                        log::debug!("RPC connection error: {error}");
                        connection.session.fail();
                    }
                },
                Ok(None) => {}
                // The session queued its refusal, if it has one, and ends
                // once that is sent.
                Err(error) => log::debug!("RPC connection error: {error}"),
            }
        }
        let wants = interest(
            key,
            connection.session.wants_input(),
            !connection.session.pending().is_empty(),
        );
        if let Err(error) = self.poller.modify(connection.stream.fd(), wants) {
            log::debug!("cannot watch an RPC connection again: {error}");
            return false;
        }
        true
    }

    fn close(&self, connection: Connection) {
        let _ = self.poller.delete(connection.stream.fd());
    }

    /// Close connections that made no progress for [`IDLE_TIMEOUT`].
    pub(crate) fn expire(&mut self, now: Instant) {
        let idle: Vec<usize> = self
            .connections
            .iter()
            .filter(|(_, c)| now.saturating_duration_since(c.last_progress) >= IDLE_TIMEOUT)
            .map(|(key, _)| *key)
            .collect();
        for key in idle {
            if let Some(connection) = self.connections.remove(&key) {
                log::debug!("RPC connection timed out");
                self.close(connection);
            }
        }
    }
}

impl Drop for RpcService {
    fn drop(&mut self) {
        for (_, connection) in self.connections.drain() {
            let _ = self.poller.delete(connection.stream.fd());
        }
        for (_, listener) in &self.listeners {
            let _ = self.poller.delete(listener.fd());
        }
    }
}

impl Driver {
    /// Serve the RPC keys among `ready`.
    pub(crate) fn serve_rpc(&mut self, ready: &crate::poll::Events) {
        let Some(mut service) = self.rpc_service.take() else {
            return;
        };
        for event in ready.iter() {
            if RpcService::owns(event.key) {
                service.ready(event.key, self);
            }
        }
        self.rpc_service = Some(service);
    }

    /// Close RPC connections that stalled.
    pub(crate) fn expire_rpc_connections(&mut self) {
        if let Some(service) = &mut self.rpc_service {
            service.expire(Instant::now());
        }
    }
}

impl RpcDriver for Driver {
    fn query(&mut self, request: QueryRequest) -> io::Result<QueryResponse> {
        Ok(self.handle_query_mut(request))
    }

    fn send(&mut self, event: Event) -> io::Result<()> {
        match event {
            Event::Query(request, response_tx) => {
                let _ = response_tx.send(self.handle_query_mut(*request));
                Ok(())
            }
            // Answered through their response channels, which the request
            // handler reads as soon as this returns.
            event @ (Event::LoadHook { .. }
            | Event::LoadHookFile { .. }
            | Event::LoadBuiltinHook { .. }
            | Event::UnloadHook { .. }
            | Event::ReloadHook { .. }
            | Event::ReloadHookFile { .. }
            | Event::ReloadBuiltinHook { .. }
            | Event::SetHookEnabled { .. }
            | Event::SetHookPriority { .. }
            | Event::ListHooks { .. }) => {
                self.handle_hook_event(event);
                Ok(())
            }
            // Nothing waits on the rest: they join the queue the loop drains.
            event => crate::rpc::send_to_driver(&self.event_tx, event),
        }
    }

    fn inbound_queue_snapshot(&self) -> crate::event::InboundQueueSnapshot {
        self.event_tx.inbound_queue_snapshot()
    }

    fn dynamic_burst_stats(&self, parent: InterfaceId) -> Option<crate::event::DynamicBurstStats> {
        self.event_tx.dynamic_burst_stats(parent)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pickle::PickleValue;
    use crate::rpc::{RpcAddr, RpcClient};

    const KEY: [u8; 32] = [7; 32];

    /// A test driver serving RPC on a loopback port.
    fn serving_driver() -> (Driver, u16) {
        let mut driver = crate::driver::tests::new_test_driver();
        let mut service = RpcService::new(KEY, Arc::clone(driver.event_tx.poller()));
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        service.add_listener(RpcListener::Tcp(listener)).unwrap();
        driver.rpc_service = Some(service);
        (driver, port)
    }

    /// Run the driver's poller until `client` is done, and return its result.
    fn serve_until<T: Send + 'static>(
        driver: &mut Driver,
        client: std::thread::JoinHandle<T>,
    ) -> T {
        let mut ready = crate::poll::Events::new();
        let deadline = Instant::now() + Duration::from_secs(10);
        while !client.is_finished() {
            assert!(Instant::now() < deadline, "client did not finish");
            while let Ok(Some(_)) = driver.rx.try_recv_classified() {}
            ready.clear();
            driver
                .rx
                .wait(&mut ready, Some(Duration::from_millis(10)))
                .unwrap();
            driver.handle_ready_sources(&ready);
        }
        client.join().unwrap()
    }

    fn connections(driver: &Driver) -> usize {
        driver.rpc_service.as_ref().unwrap().connections.len()
    }

    fn get(what: &str) -> PickleValue {
        PickleValue::Dict(vec![(
            PickleValue::String("get".into()),
            PickleValue::String(what.into()),
        )])
    }

    #[test]
    fn driver_answers_rpc_requests_on_its_own_loop() {
        let (mut driver, port) = serving_driver();
        let client = std::thread::spawn(move || {
            let addr = RpcAddr::Tcp("127.0.0.1".into(), port);
            let link_count = RpcClient::connect(&addr, &KEY)
                .unwrap()
                .call(&get("link_count"))
                .unwrap();
            // Hook requests are answered through a response channel the
            // driver fills inline.
            let hooks = RpcClient::connect(&addr, &KEY)
                .unwrap()
                .list_hooks()
                .unwrap();
            (link_count, hooks)
        });
        let (link_count, hooks) = serve_until(&mut driver, client);
        assert_eq!(link_count.as_int(), Some(0));
        assert!(hooks.is_empty());
        // One request per connection: both are closed once answered.
        assert_eq!(connections(&driver), 0);
    }

    #[test]
    fn rpc_client_with_the_wrong_key_is_refused() {
        let (mut driver, port) = serving_driver();
        let client = std::thread::spawn(move || {
            let addr = RpcAddr::Tcp("127.0.0.1".into(), port);
            RpcClient::connect(&addr, &[8; 32]).map(|_| ())
        });
        let refused = serve_until(&mut driver, client);
        assert!(refused.is_err());
        assert_eq!(connections(&driver), 0);
        // The service keeps serving others.
        let client = std::thread::spawn(move || {
            let addr = RpcAddr::Tcp("127.0.0.1".into(), port);
            RpcClient::connect(&addr, &KEY)?.call(&get("link_count"))
        });
        assert_eq!(serve_until(&mut driver, client).unwrap().as_int(), Some(0));
    }

    #[test]
    fn stalled_rpc_connection_is_closed_without_holding_others() {
        let (mut driver, port) = serving_driver();
        // Connects and never answers the challenge.
        let mut stalled = TcpStream::connect(("127.0.0.1", port)).unwrap();
        let client = std::thread::spawn(move || {
            let addr = RpcAddr::Tcp("127.0.0.1".into(), port);
            RpcClient::connect(&addr, &KEY)?.call(&get("link_count"))
        });
        assert_eq!(serve_until(&mut driver, client).unwrap().as_int(), Some(0));
        assert_eq!(connections(&driver), 1);
        driver
            .rpc_service
            .as_mut()
            .unwrap()
            .expire(Instant::now() + IDLE_TIMEOUT);
        assert_eq!(connections(&driver), 0);
        // The stalled client sees its challenge, then the connection close.
        stalled
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut received = Vec::new();
        stalled.read_to_end(&mut received).unwrap();
        assert!(received.windows(11).any(|w| w == b"#CHALLENGE#"));
    }
}
