//! Endpoint discovery on the compact engine's driver loop.
//!
//! With services folded (see [`crate::engine::FOLD_SERVICES`]) a session's
//! probe is a loop source instead of a probe-worker thread: it sends the
//! request to one probe server at a time and waits for the reply on the
//! driver's poller, moving to the next server when one times out or fails.

use std::io;
use std::net::{SocketAddr, UdpSocket};
use std::os::fd::{AsRawFd, RawFd};
use std::time::{Duration, Instant};

use rns_core::holepunch::ProbeProtocol;

use super::probe::{open_probe_socket, ProbeRequest};
use crate::event::{Event, EventSender, LoopContext, LoopSource, SourceStatus};

/// How long each probe server has to answer, as for the probe workers.
pub(crate) const PROBE_TIMEOUT: Duration = Duration::from_secs(3);

/// What a session's probe needs across servers.
pub(crate) struct ProbeJob {
    pub(crate) servers: Vec<SocketAddr>,
    pub(crate) protocol: ProbeProtocol,
    pub(crate) session_id: [u8; 16],
    pub(crate) link_id: [u8; 16],
    pub(crate) tx: EventSender,
    pub(crate) device: Option<String>,
    pub(crate) underlay_mark: Option<u32>,
    pub(crate) timeout: Duration,
}

impl ProbeJob {
    /// Probe the servers from `next` on, serving the first that can be
    /// asked on the driver loop, or report the probe failed.
    fn ask_from(self, next: usize, mut serve: impl FnMut(Box<ProbeSource>)) {
        for index in next..self.servers.len() {
            let server = self.servers[index];
            match ask(server, &self) {
                Ok((socket, request)) => {
                    serve(Box::new(ProbeSource {
                        fd: socket.as_raw_fd(),
                        socket: Some(socket),
                        request,
                        index,
                        deadline: Instant::now() + self.timeout,
                        job: Some(self),
                    }));
                    return;
                }
                Err(e) => log::debug!("Probe server {} failed: {}", server, e),
            }
        }
        log::warn!(
            "Probe failed for session {:02x?} (tried {} servers)",
            &self.session_id[..4],
            self.servers.len()
        );
        let _ = self.tx.push_from_loop([Event::HolePunchProbeFailed {
            link_id: self.link_id,
            session_id: self.session_id,
        }]);
    }
}

fn ask(server: SocketAddr, job: &ProbeJob) -> io::Result<(UdpSocket, ProbeRequest)> {
    let socket = open_probe_socket(server, job.device.as_deref(), job.underlay_mark)?;
    socket.set_nonblocking(true)?;
    let port = socket.local_addr().map(|a| a.port()).unwrap_or(0);
    let request = ProbeRequest::new(job.protocol, port);
    socket.send_to(request.bytes(), server)?;
    Ok((socket, request))
}

/// Start probing on the driver loop. Called on the driver thread.
pub(crate) fn start(job: ProbeJob) {
    let tx = job.tx.clone();
    job.ask_from(0, |source| {
        if let Err(e) = tx.register_source(super::next_loop_key(), source) {
            log::warn!("Cannot wait for a probe reply: {}", e);
        }
    });
}

/// Waiting for one probe server's reply.
struct ProbeSource {
    /// The socket's descriptor, kept for deregistering after the socket
    /// was handed over with the result.
    fd: RawFd,
    socket: Option<UdpSocket>,
    request: ProbeRequest,
    /// The server asked, in the job's list.
    index: usize,
    deadline: Instant,
    /// Taken when the probe ends here, or moves to the next server.
    job: Option<ProbeJob>,
}

impl ProbeSource {
    /// Move on to the next server, if any.
    fn fail_over(&mut self, cx: &mut LoopContext<'_>, reason: &str) -> SourceStatus {
        if let Some(job) = self.job.take() {
            log::debug!(
                "Probe server {} failed: {}",
                job.servers[self.index],
                reason
            );
            job.ask_from(self.index + 1, |source| {
                cx.add_source(super::next_loop_key(), source)
            });
        }
        SourceStatus::Remove
    }
}

impl LoopSource for ProbeSource {
    fn fd(&self) -> RawFd {
        self.fd
    }

    fn on_ready(&mut self, cx: &mut LoopContext<'_>) -> SourceStatus {
        let Some(socket) = self.socket.as_ref() else {
            return SourceStatus::Remove;
        };
        loop {
            let (len, _) = match socket.recv_from(cx.buf) {
                Ok(received) => received,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => return SourceStatus::Rearm,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                // The server is unreachable (an ICMP error), or the socket
                // failed: the next server, at once.
                Err(e) => return self.fail_over(cx, &e.to_string()),
            };
            // Anything but the reply is ignored until the deadline.
            let Some(observed) = self.request.reply(&cx.buf[..len]) else {
                continue;
            };
            let (Some(job), Some(socket)) = (self.job.take(), self.socket.take()) else {
                return SourceStatus::Remove;
            };
            let probe_server = job.servers[self.index];
            log::info!(
                "Probe discovered endpoint: {} via server {} for session {:02x?}",
                observed,
                probe_server,
                &job.session_id[..4]
            );
            let _ = job.tx.push_from_loop([Event::HolePunchProbeResult {
                link_id: job.link_id,
                session_id: job.session_id,
                observed_addr: observed,
                socket,
                probe_server,
            }]);
            return SourceStatus::Remove;
        }
    }

    fn deadline(&self) -> Option<Instant> {
        Some(self.deadline)
    }

    fn on_timer(&mut self, cx: &mut LoopContext<'_>) -> SourceStatus {
        self.fail_over(cx, "timed out")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn job(servers: Vec<SocketAddr>, tx: EventSender) -> ProbeJob {
        ProbeJob {
            servers,
            protocol: ProbeProtocol::Rnsp,
            session_id: [5; 16],
            link_id: [6; 16],
            tx,
            device: None,
            underlay_mark: None,
            timeout: Duration::from_millis(300),
        }
    }

    #[test]
    fn probe_fails_over_to_a_server_that_answers() {
        let mut server = super::super::probe::start_probe_server("127.0.0.1:0".parse().unwrap())
            .unwrap_or_else(|e| panic!("probe server: {e}"));
        let live = server.local_addr();
        // Nothing listens here: the probe moves on when it is refused or
        // times out.
        let dead = UdpSocket::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap();
        let silent = UdpSocket::bind("127.0.0.1:0").unwrap();
        let (tx, rx) = crate::event::channel();
        start(job(vec![dead, silent.local_addr().unwrap(), live], tx));
        let deadline = Instant::now() + Duration::from_secs(3);
        let result = loop {
            assert!(Instant::now() < deadline, "no probe result");
            match rx.recv_timeout(Duration::from_millis(50)) {
                Ok(event) => break event,
                Err(_) => continue,
            }
        };
        match result {
            Event::HolePunchProbeResult {
                link_id,
                session_id,
                observed_addr,
                socket,
                probe_server,
            } => {
                assert_eq!((link_id, session_id), ([6; 16], [5; 16]));
                assert_eq!(probe_server, live);
                assert_eq!(observed_addr.port(), socket.local_addr().unwrap().port());
            }
            other => panic!("expected a probe result, got {other:?}"),
        }
        server.stop();
    }

    #[test]
    fn probe_reports_failure_when_no_server_answers() {
        let silent = UdpSocket::bind("127.0.0.1:0").unwrap();
        let (tx, rx) = crate::event::channel();
        start(job(vec![silent.local_addr().unwrap()], tx));
        match rx.recv_timeout(Duration::from_secs(2)).unwrap() {
            Event::HolePunchProbeFailed {
                link_id,
                session_id,
            } => assert_eq!((link_id, session_id), ([6; 16], [5; 16])),
            other => panic!("expected a probe failure, got {other:?}"),
        }
    }
}
