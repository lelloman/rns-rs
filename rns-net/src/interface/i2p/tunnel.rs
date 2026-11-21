//! The tunnel state of an I2P peer, kept as upstream's `I2PInterfacePeer`
//! keeps it.
//!
//! Upstream's peer starts in `TUNNEL_STATE_INIT`, which an outbound peer
//! reports from when its interface starts, until it first connects. Once it is connected, a
//! watchdog checks it every second: the tunnel is `STALE` when nothing was
//! read for twice `I2P_PROBE_AFTER`, else `ACTIVE`; a keepalive (an empty
//! HDLC frame) goes out on every check while nothing was written for
//! `I2P_PROBE_AFTER`; and the stream is shut down, so the peer reconnects
//! or is torn down, when nothing was read for `I2P_READ_TIMEOUT`.
//!
//! Here the peer's reader records each read, and the driver runs the
//! watchdog on its tick (see [`PeerTunnel::watch`]), sending the keepalive
//! through the peer's writer so it never lands inside another frame.

use std::net::{Shutdown, TcpStream};
use std::sync::atomic::{AtomicU64, AtomicU8, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::interface::lock_or_recover;

/// Upstream `I2PInterfacePeer.I2P_PROBE_AFTER`, in seconds.
const I2P_PROBE_AFTER: u64 = 10;
/// Upstream `I2PInterfacePeer.I2P_PROBE_INTERVAL`, in seconds.
const I2P_PROBE_INTERVAL: u64 = 9;
/// Upstream `I2PInterfacePeer.I2P_PROBES`.
const I2P_PROBES: u64 = 5;
/// Upstream `I2PInterfacePeer.I2P_READ_TIMEOUT`: 110 seconds.
const I2P_READ_TIMEOUT: Duration =
    Duration::from_secs((I2P_PROBE_INTERVAL * I2P_PROBES + I2P_PROBE_AFTER) * 2);
/// How long without reads makes a tunnel unresponsive.
const STALE_AFTER: Duration = Duration::from_secs(I2P_PROBE_AFTER * 2);
/// How long without writes before keepalives go out.
const KEEPALIVE_AFTER: Duration = Duration::from_secs(I2P_PROBE_AFTER);
/// The watchdog's period.
const WATCH_INTERVAL: Duration = Duration::from_secs(1);

/// Upstream's `TUNNEL_STATE_*`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum TunnelState {
    /// Not connected yet (`TUNNEL_STATE_INIT`).
    Init = 0x00,
    /// Something was read within the last 20 seconds (`TUNNEL_STATE_ACTIVE`).
    Active = 0x01,
    /// Nothing was read for over 20 seconds (`TUNNEL_STATE_STALE`).
    Stale = 0x02,
}

impl TunnelState {
    fn from_u8(value: u8) -> Self {
        match value {
            0x01 => TunnelState::Active,
            0x02 => TunnelState::Stale,
            _ => TunnelState::Init,
        }
    }

    /// How upstream's interface statistics report the state
    /// (`tunnelstate`).
    pub fn description(self) -> &'static str {
        match self {
            TunnelState::Init => "Creating Tunnel",
            TunnelState::Active => "Tunnel Active",
            TunnelState::Stale => "Tunnel Unresponsive",
        }
    }
}

/// What one watchdog check found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WatchCheck {
    /// The tunnel's state.
    pub state: TunnelState,
    /// Send a keepalive.
    pub keepalive: bool,
    /// Shut the stream down: the tunnel stopped answering.
    pub restart: bool,
}

/// One watchdog check, given how long ago the peer last read and wrote.
pub(crate) fn check(since_read: Duration, since_write: Duration) -> WatchCheck {
    WatchCheck {
        state: if since_read > STALE_AFTER {
            TunnelState::Stale
        } else {
            TunnelState::Active
        },
        keepalive: since_write > KEEPALIVE_AFTER,
        restart: since_read > I2P_READ_TIMEOUT,
    }
}

/// The driver's side of the watchdog.
#[derive(Debug)]
struct Watch {
    last_check: Instant,
    last_write: Instant,
    /// The peer's transmitted bytes when last checked.
    last_txb: u64,
}

/// A connected peer's tunnel.
#[derive(Debug)]
pub struct PeerTunnel {
    created: Instant,
    /// Milliseconds after `created` of the last read.
    last_read: AtomicU64,
    state: AtomicU8,
    watch: Mutex<Watch>,
    /// The peer's stream, shut down when the tunnel stops answering.
    stream: Option<TcpStream>,
}

impl PeerTunnel {
    /// A tunnel connected now over `stream`.
    pub fn new(stream: Option<TcpStream>) -> Self {
        Self::at(Instant::now(), stream)
    }

    /// A tunnel connected at `now` over `stream`.
    pub(crate) fn at(now: Instant, stream: Option<TcpStream>) -> Self {
        PeerTunnel {
            created: now,
            last_read: AtomicU64::new(0),
            state: AtomicU8::new(TunnelState::Init as u8),
            watch: Mutex::new(Watch {
                last_check: now,
                last_write: now,
                last_txb: 0,
            }),
            stream,
        }
    }

    /// The tunnel's current state.
    pub fn state(&self) -> TunnelState {
        TunnelState::from_u8(self.state.load(Ordering::Relaxed))
    }

    /// Continue in `state`: an outbound peer that reconnects keeps the
    /// state its tunnel was in, as upstream's peer does until its watchdog
    /// checks the new connection.
    pub fn resume(&self, state: TunnelState) {
        self.state.store(state as u8, Ordering::Relaxed);
    }

    /// Record that the peer's stream delivered bytes.
    pub fn note_read(&self) {
        self.note_read_at(Instant::now());
    }

    fn note_read_at(&self, now: Instant) {
        let ms = now.saturating_duration_since(self.created).as_millis() as u64;
        self.last_read.fetch_max(ms, Ordering::Relaxed);
    }

    fn last_read(&self) -> Instant {
        self.created + Duration::from_millis(self.last_read.load(Ordering::Relaxed))
    }

    /// Run the watchdog, at most once a second, given the bytes the peer
    /// has transmitted so far. Returns `None` between checks. On a check
    /// that finds the tunnel unresponsive for too long, the stream is shut
    /// down.
    pub fn watch(&self, txb: u64) -> Option<WatchCheck> {
        self.watch_at(Instant::now(), txb)
    }

    fn watch_at(&self, now: Instant, txb: u64) -> Option<WatchCheck> {
        let mut watch = lock_or_recover(&self.watch, "i2p tunnel watch");
        if now.saturating_duration_since(watch.last_check) < WATCH_INTERVAL {
            return None;
        }
        watch.last_check = now;
        if txb != watch.last_txb {
            watch.last_txb = txb;
            watch.last_write = now;
        }
        let since_read = now.saturating_duration_since(self.last_read());
        let found = check(since_read, now.saturating_duration_since(watch.last_write));
        if found.state == TunnelState::Stale && self.state() != TunnelState::Stale {
            log::debug!("I2P tunnel became unresponsive");
        }
        self.state.store(found.state as u8, Ordering::Relaxed);
        if found.restart {
            log::warn!("I2P socket is unresponsive, restarting...");
            self.shutdown();
        }
        Some(found)
    }

    /// Shut the stream down, so its reader sees it closed.
    pub fn shutdown(&self) {
        if let Some(stream) = &self.stream {
            let _ = stream.shutdown(Shutdown::Both);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn secs(s: u64) -> Duration {
        Duration::from_secs(s)
    }

    #[test]
    fn states_are_described_as_upstream() {
        assert_eq!(TunnelState::Init.description(), "Creating Tunnel");
        assert_eq!(TunnelState::Active.description(), "Tunnel Active");
        assert_eq!(TunnelState::Stale.description(), "Tunnel Unresponsive");
    }

    #[test]
    fn check_follows_upstream_watchdog_thresholds() {
        // Stale past twice I2P_PROBE_AFTER without reads.
        assert_eq!(check(secs(20), secs(0)).state, TunnelState::Active);
        assert_eq!(
            check(secs(20) + Duration::from_millis(1), secs(0)).state,
            TunnelState::Stale
        );
        // Keepalives past I2P_PROBE_AFTER without writes.
        assert!(!check(secs(0), secs(10)).keepalive);
        assert!(check(secs(0), secs(11)).keepalive);
        // Restarted past I2P_READ_TIMEOUT, 110 seconds, without reads.
        assert!(!check(secs(110), secs(0)).restart);
        assert!(check(secs(111), secs(0)).restart);
    }

    #[test]
    fn tunnel_starts_creating_and_becomes_active_on_first_check() {
        let t0 = Instant::now();
        let tunnel = PeerTunnel::at(t0, None);
        assert_eq!(tunnel.state(), TunnelState::Init);
        // Checked once a second, as upstream's watchdog sleeps first.
        assert_eq!(tunnel.watch_at(t0 + Duration::from_millis(500), 0), None);
        assert_eq!(tunnel.state(), TunnelState::Init);
        let found = tunnel.watch_at(t0 + secs(1), 0).unwrap();
        assert_eq!(found.state, TunnelState::Active);
        assert!(!found.keepalive);
        assert_eq!(tunnel.state(), TunnelState::Active);
    }

    #[test]
    fn tunnel_goes_stale_without_reads_and_recovers_on_read() {
        let t0 = Instant::now();
        let tunnel = PeerTunnel::at(t0, None);
        tunnel.watch_at(t0 + secs(20), 0).unwrap();
        assert_eq!(tunnel.state(), TunnelState::Active);
        tunnel.watch_at(t0 + secs(21), 0).unwrap();
        assert_eq!(tunnel.state(), TunnelState::Stale);
        tunnel.note_read_at(t0 + secs(22));
        tunnel.watch_at(t0 + secs(23), 0).unwrap();
        assert_eq!(tunnel.state(), TunnelState::Active);
    }

    #[test]
    fn keepalives_go_out_on_every_check_while_nothing_is_written() {
        let t0 = Instant::now();
        let tunnel = PeerTunnel::at(t0, None);
        assert!(!tunnel.watch_at(t0 + secs(10), 0).unwrap().keepalive);
        assert!(tunnel.watch_at(t0 + secs(11), 0).unwrap().keepalive);
        // Keepalives themselves do not count as writes.
        assert!(tunnel.watch_at(t0 + secs(12), 0).unwrap().keepalive);
        // Transmitted bytes do.
        assert!(!tunnel.watch_at(t0 + secs(13), 100).unwrap().keepalive);
        assert!(!tunnel.watch_at(t0 + secs(23), 100).unwrap().keepalive);
        assert!(tunnel.watch_at(t0 + secs(24), 100).unwrap().keepalive);
    }

    #[test]
    fn unresponsive_tunnel_shuts_its_stream_down() {
        use std::io::Read;
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (mut server, _) = listener.accept().unwrap();
        let mut reader = client.try_clone().unwrap();
        let t0 = Instant::now();
        let tunnel = PeerTunnel::at(t0, Some(client));
        assert!(!tunnel.watch_at(t0 + secs(110), 0).unwrap().restart);
        assert!(tunnel.watch_at(t0 + secs(111), 0).unwrap().restart);
        // The peer's reader sees its stream closed, and so does the remote.
        let mut buf = [0u8; 1];
        assert_eq!(reader.read(&mut buf).unwrap(), 0);
        assert_eq!(server.read(&mut buf).unwrap(), 0);
    }
}
