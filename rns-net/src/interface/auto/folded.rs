//! An AutoInterface on the compact engine's driver loop.
//!
//! With interface I/O folded (see [`crate::engine::FOLD_IO`]) every socket
//! an AutoInterface receives on is a loop source read on the driver thread,
//! and a controller source runs what the supervisor, peer-jobs and
//! discovery-sender threads did, from timers: rescanning network
//! interfaces, culling silent peers, and multicasting the discovery token.
//! Peers' writers are called by the driver directly (see `UdpWriter`).

use std::collections::HashMap;
use std::io;
use std::net::{SocketAddrV6, UdpSocket};
use std::os::fd::AsFd;
use std::os::unix::net::UnixDatagram;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use rns_core::transport::types::InterfaceId;

use super::{
    compute_discovery_token, cull_timed_out_peers, handle_data, log_worker_online,
    open_worker_sockets, rescan_workers, take_peers_for_worker, AutoWorkerContext, AutoWorkerEntry,
    AutoWorkerKey, DiscoveryHandler, RunningAutoWorker, SharedState, AUTO_RESCAN_INTERVAL, HW_MTU,
};
use crate::event::{Event, LoopContext, LoopSource, SourceStatus};
use crate::interface::lock_or_recover;
use crate::interface::loop_writer::read_key;

/// Datagrams read from one socket per readiness before other sources get
/// a turn.
const READ_BUDGET: usize = 64;

/// Serve an AutoInterface on the driver loop from now on.
pub(super) fn start(
    parent_id: InterfaceId,
    context: AutoWorkerContext,
    allowed: Vec<String>,
    ignored: Vec<String>,
    running: Arc<AtomicBool>,
) -> io::Result<()> {
    // The controller runs on timers only; it watches one end of a socket
    // pair that is never written, since every source has a descriptor.
    let (anchor, anchor_peer) = UnixDatagram::pair()?;
    let tx = context.tx.clone();
    // Like the peer-jobs thread, cull one interval after starting.
    let peer_job_interval = lock_or_recover(&context.runtime, "auto runtime")
        .peer_job_interval_secs
        .max(0.1);
    tx.register_source(
        read_key(parent_id),
        Box::new(Controller {
            anchor,
            _anchor_peer: anchor_peer,
            context,
            allowed,
            ignored,
            running,
            workers: HashMap::new(),
            senders: HashMap::new(),
            next_rescan: Instant::now(),
            next_jobs: Instant::now() + Duration::from_secs_f64(peer_job_interval),
        }),
    )
}

/// Multicasts one worker's discovery token.
struct DiscoverySender {
    socket: Option<UdpSocket>,
    token: [u8; 32],
    target: SocketAddrV6,
    next: Instant,
}

impl DiscoverySender {
    fn new(key: &AutoWorkerKey, context: &AutoWorkerContext) -> Self {
        Self {
            socket: None,
            token: compute_discovery_token(&context.group_id, &key.link_local_addr),
            target: SocketAddrV6::new(context.mcast_ip, context.discovery_port, 0, 0),
            next: Instant::now(),
        }
    }

    fn socket(&mut self, if_index: u32, underlay_mark: Option<u32>) -> io::Result<&UdpSocket> {
        let socket = match self.socket.take() {
            Some(socket) => socket,
            None => {
                let socket = UdpSocket::bind("[::]:0")?;
                crate::interface::apply_underlay_mark(socket.as_fd(), underlay_mark)?;
                socket.set_multicast_if_v6_compat(if_index)?;
                socket.set_nonblocking(true)?;
                socket
            }
        };
        Ok(self.socket.insert(socket))
    }

    fn send(&mut self, key: &AutoWorkerKey, context: &AutoWorkerContext) {
        let token = self.token;
        let target = self.target;
        let result = self
            .socket(key.if_index, context.underlay_mark)
            .and_then(|socket| socket.send_to(&token, target));
        if let Err(e) = result {
            log::debug!("[{}] multicast send error: {}", context.name, e);
            // Start over with a fresh socket next time, as the reader
            // threads' sender does every time.
            self.socket = None;
        }
    }
}

/// Setting the outgoing multicast interface, which `std` does not offer.
trait MulticastIf {
    fn set_multicast_if_v6_compat(&self, if_index: u32) -> io::Result<()>;
}

impl MulticastIf for UdpSocket {
    fn set_multicast_if_v6_compat(&self, if_index: u32) -> io::Result<()> {
        socket2::SockRef::from(self).set_multicast_if_v6(if_index)
    }
}

/// Runs the AutoInterface's periodic work on the driver thread.
struct Controller {
    anchor: UnixDatagram,
    _anchor_peer: UnixDatagram,
    context: AutoWorkerContext,
    allowed: Vec<String>,
    ignored: Vec<String>,
    running: Arc<AtomicBool>,
    workers: HashMap<AutoWorkerKey, AutoWorkerEntry>,
    senders: HashMap<AutoWorkerKey, DiscoverySender>,
    next_rescan: Instant,
    next_jobs: Instant,
}

impl Controller {
    /// What the supervisor thread does on each pass: adopt new network
    /// interfaces and drop vanished ones.
    fn rescan(&mut self, cx: &mut LoopContext<'_>) {
        let context = &self.context;
        rescan_workers(
            context,
            &self.allowed,
            &self.ignored,
            &mut self.workers,
            |down| {
                if !down.is_empty() {
                    let _ = context
                        .tx
                        .push_from_loop(down.into_iter().map(Event::InterfaceDown));
                }
            },
            |key| start_worker(key, context, &self.running, cx),
        );
        let workers = &self.workers;
        self.senders
            .retain(|key, _| matches!(workers.get(key), Some(AutoWorkerEntry::Running(_))));
        for (key, worker) in &self.workers {
            if matches!(worker, AutoWorkerEntry::Running(_)) && !self.senders.contains_key(key) {
                self.senders
                    .insert(key.clone(), DiscoverySender::new(key, context));
            }
        }
    }

    /// What the peer-jobs thread does: report peers gone silent as down.
    fn cull_peers(&self) {
        let context = &self.context;
        let timed_out = cull_timed_out_peers(&context.shared, &context.runtime, &context.name);
        if timed_out.is_empty() {
            return;
        }
        let _ = context
            .tx
            .push_from_loop(timed_out.into_iter().map(Event::InterfaceDown));
    }
}

impl LoopSource for Controller {
    fn fd(&self) -> std::os::fd::BorrowedFd<'_> {
        self.anchor.as_fd()
    }

    fn on_ready(&mut self, _cx: &mut LoopContext<'_>) -> SourceStatus {
        // Nothing writes to the anchor; never expected.
        SourceStatus::Rearm
    }

    fn stopped(&self) -> bool {
        !self.running.load(Ordering::Relaxed)
    }

    fn on_removed(&mut self) {
        let mut down = Vec::new();
        for (key, worker) in self.workers.drain() {
            down.extend(take_peers_for_worker(&self.context.shared, &key));
            worker.stop();
        }
        let _ = self
            .context
            .tx
            .push_from_loop(down.into_iter().map(Event::InterfaceDown));
    }

    fn deadline(&self) -> Option<Instant> {
        self.senders
            .values()
            .map(|sender| sender.next)
            .chain([self.next_rescan, self.next_jobs])
            .min()
    }

    fn on_timer(&mut self, cx: &mut LoopContext<'_>) -> SourceStatus {
        if !self.running.load(Ordering::Relaxed) {
            return SourceStatus::Remove;
        }
        let now = Instant::now();
        if now >= self.next_rescan {
            self.rescan(cx);
            self.next_rescan = now + Duration::from_secs_f64(AUTO_RESCAN_INTERVAL);
        }
        let (announce_interval, peer_job_interval) = {
            let runtime = lock_or_recover(&self.context.runtime, "auto runtime");
            (
                runtime.announce_interval_secs.max(0.1),
                runtime.peer_job_interval_secs.max(0.1),
            )
        };
        if now >= self.next_jobs {
            self.cull_peers();
            self.next_jobs = now + Duration::from_secs_f64(peer_job_interval);
        }
        for (key, sender) in &mut self.senders {
            if now >= sender.next {
                sender.send(key, &self.context);
                sender.next = now + Duration::from_secs_f64(announce_interval);
            }
        }
        SourceStatus::Rearm
    }
}

/// Open a worker's receiving sockets and serve them on the driver loop.
fn start_worker(
    key: &AutoWorkerKey,
    context: &AutoWorkerContext,
    running: &Arc<AtomicBool>,
    cx: &mut LoopContext<'_>,
) -> io::Result<RunningAutoWorker> {
    let sockets = open_worker_sockets(key, context)?;
    for socket in &sockets {
        socket.set_nonblocking(true)?;
    }
    let worker_running = Arc::new(AtomicBool::new(true));
    let handler = context.discovery_handler(key);
    let [mcast, unicast, data] = sockets;
    let kinds = [
        (mcast, Kind::Discovery(Box::new(handler.clone()))),
        (unicast, Kind::Discovery(Box::new(handler))),
        (
            data,
            Kind::Data {
                if_index: key.if_index,
            },
        ),
    ];
    for (socket, kind) in kinds {
        // Each socket takes a poller key of its own, from an interface id
        // no interface uses.
        let id = lock_or_recover(&context.shared, "auto shared state")
            .next_id
            .fetch_add(1, Ordering::Relaxed);
        cx.add_source(
            read_key(InterfaceId(id)),
            Box::new(AutoSocket {
                socket,
                kind,
                shared: Arc::clone(&context.shared),
                tx: context.tx.clone(),
                name: context.name.clone(),
                worker_running: Arc::clone(&worker_running),
                running: Arc::clone(running),
            }),
        );
    }
    log_worker_online(key, context);
    Ok(RunningAutoWorker {
        running: worker_running,
    })
}

enum Kind {
    Discovery(Box<DiscoveryHandler>),
    Data { if_index: u32 },
}

/// A worker's receiving socket, read on the driver thread.
struct AutoSocket {
    socket: UdpSocket,
    kind: Kind,
    shared: Arc<std::sync::Mutex<SharedState>>,
    tx: crate::event::EventSender,
    name: String,
    worker_running: Arc<AtomicBool>,
    running: Arc<AtomicBool>,
}

impl LoopSource for AutoSocket {
    fn fd(&self) -> std::os::fd::BorrowedFd<'_> {
        self.socket.as_fd()
    }

    fn stopped(&self) -> bool {
        !self.worker_running.load(Ordering::Relaxed) || !self.running.load(Ordering::Relaxed)
    }

    fn on_ready(&mut self, cx: &mut LoopContext<'_>) -> SourceStatus {
        if self.stopped() {
            return SourceStatus::Remove;
        }
        let data = matches!(self.kind, Kind::Data { .. });
        if data && !self.tx.inbound_data_has_room() {
            return SourceStatus::Suspend;
        }
        let len = cx.buf.len().min(HW_MTU + 64);
        let buf = cx.buf.get_mut(..len).unwrap_or_default();
        let mut events = Vec::new();
        for _ in 0..READ_BUDGET {
            let (n, src) = match self.socket.recv_from(buf) {
                Ok(received) => received,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => {
                    log::warn!("[{}] receive error: {}", self.name, e);
                    let _ = self.tx.push_from_loop(events);
                    // Readiness would report the error again at once; back
                    // off until the next tick.
                    return SourceStatus::Pause;
                }
            };
            let event = match &self.kind {
                Kind::Discovery(handler) => handler.handle(buf.get(..n).unwrap_or_default(), src),
                Kind::Data { if_index } => handle_data(
                    &self.shared,
                    *if_index,
                    buf.get(..n).unwrap_or_default(),
                    src,
                ),
            };
            events.extend(event);
        }
        match self.tx.push_from_loop(events) {
            Ok(true) => SourceStatus::Rearm,
            Ok(false) if data => SourceStatus::Suspend,
            Ok(false) => SourceStatus::Rearm,
            Err(_) => SourceStatus::Remove,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::PeerKey;
    use super::*;
    use std::net::Ipv6Addr;

    #[test]
    fn data_from_a_known_peer_is_read_on_the_driver_loop() {
        let (tx, rx) = crate::event::channel();
        let shared = Arc::new(std::sync::Mutex::new(SharedState::new(Arc::new(
            std::sync::atomic::AtomicU64::new(500),
        ))));
        let socket = UdpSocket::bind((Ipv6Addr::LOCALHOST, 0)).unwrap();
        socket.set_nonblocking(true).unwrap();
        let addr = socket.local_addr().unwrap();
        let sender = UdpSocket::bind((Ipv6Addr::LOCALHOST, 0)).unwrap();
        {
            let mut state = shared.lock().unwrap();
            state.online = true;
            state.peers.insert(
                PeerKey {
                    link_local_addr: "::1".into(),
                    if_index: 7,
                },
                super::super::AutoPeer {
                    interface_id: InterfaceId(321),
                    ifname: "test0".into(),
                    if_index: 7,
                    last_heard: 0.0,
                },
            );
        }
        let worker_running = Arc::new(AtomicBool::new(true));
        tx.register_source(
            read_key(InterfaceId(500)),
            Box::new(AutoSocket {
                socket,
                kind: Kind::Data { if_index: 7 },
                shared: Arc::clone(&shared),
                tx: tx.clone(),
                name: "auto-test".into(),
                worker_running: Arc::clone(&worker_running),
                running: Arc::new(AtomicBool::new(true)),
            }),
        )
        .unwrap();

        sender.send_to(b"from the peer", addr).unwrap();
        // The same datagram again is a duplicate (a peer reachable over
        // two network interfaces), and is dropped.
        sender.send_to(b"from the peer", addr).unwrap();
        match rx.recv_timeout(Duration::from_secs(2)).unwrap() {
            Event::Frame {
                interface_id, data, ..
            } => {
                assert_eq!(interface_id, InterfaceId(321));
                assert_eq!(&*data, b"from the peer");
            }
            other => panic!("expected Frame, got {other:?}"),
        }
        assert!(rx.recv_timeout(Duration::from_millis(200)).is_err());

        // A stopped worker reads no more.
        worker_running.store(false, Ordering::Relaxed);
        sender.send_to(b"after stopping", addr).unwrap();
        assert!(rx.recv_timeout(Duration::from_millis(200)).is_err());
    }
}
