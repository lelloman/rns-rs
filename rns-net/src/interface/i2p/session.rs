//! The interface's SAM session and the steps of bringing its peers up and
//! down, shared by both ways of running it: reader threads, or the driver
//! loop (see [`crate::engine::FOLD_IO`]). Each mode reads the streams in its
//! own way and sends the events these steps produce.

use std::net::{SocketAddr, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use rns_core::transport::types::InterfaceId;

use super::sam::{self, SamError};
use super::tunnel::PeerTunnel;
use super::{
    control_reply, open_session_retrying, peer_info, peer_up, I2pConfig, I2pEndpoint, I2pRuntime,
    I2pWriter, OutboundPeer,
};
use crate::event::{Event, EventSender};
use crate::interface::lock_or_recover;

/// How long to wait before asking the bridge again after an accept failed.
pub(super) const ACCEPT_RETRY_WAIT: Duration = Duration::from_secs(1);

/// Longest line kept from the bridge, on the session's control socket or
/// ahead of an accepted stream's data: a destination in I2P base64 is well
/// under this.
pub(super) const MAX_SAM_LINE: usize = 4096;

/// What the interface's streams share.
pub(super) struct Session {
    pub(super) sam_addr: SocketAddr,
    pub(super) session_id: String,
    pub(super) name: String,
    pub(super) tx: EventSender,
    pub(super) next_id: Arc<AtomicU64>,
    pub(super) runtime: Arc<Mutex<I2pRuntime>>,
    pub(super) ingress_control: rns_core::transport::types::IngressControlConfig,
    pub(super) dynamic_template: Option<crate::interface::DynamicInterfaceTemplate>,
    pub(super) underlay_mark: Option<u32>,
    pub(super) endpoint: Arc<Mutex<I2pEndpoint>>,
    /// The interface's configuration, to open the session again with.
    pub(super) config: I2pConfig,
    /// How long to wait before opening the session again.
    pub(super) sam_retry_wait: Duration,
}

/// A peer's stream, connected and its interface ready to come up.
pub(super) struct PeerUp {
    /// The event bringing the peer's interface up.
    pub(super) event: Event,
    /// The peer's tunnel, now watched.
    pub(super) tunnel: Arc<PeerTunnel>,
    /// Set when the driver detaches the peer.
    pub(super) detached: Arc<AtomicBool>,
}

impl Session {
    /// Open the interface's session, retrying until the bridge takes it
    /// (one session carries every stream, outbound and inbound). Returns it
    /// with its control socket, which keeps it open.
    pub(super) fn open(
        config: I2pConfig,
        tx: EventSender,
        next_id: Arc<AtomicU64>,
        dynamic_template: Option<crate::interface::DynamicInterfaceTemplate>,
    ) -> Result<(Arc<Self>, TcpStream), SamError> {
        let sam_addr: SocketAddr = format!("{}:{}", config.sam_host, config.sam_port)
            .parse()
            .map_err(|e| SamError::Io(std::io::Error::new(std::io::ErrorKind::InvalidInput, e)))?;
        let (control, session_id) =
            open_session_retrying(&config, &sam_addr, config.sam_retry_wait());
        let session = Arc::new(Session {
            sam_addr,
            session_id,
            name: config.name.clone(),
            tx,
            next_id,
            runtime: Arc::clone(&config.runtime),
            ingress_control: config.ingress_control,
            dynamic_template,
            underlay_mark: config.underlay_mark,
            endpoint: Arc::clone(&config.endpoint),
            sam_retry_wait: config.sam_retry_wait(),
            config,
        });
        Ok((session, control))
    }

    /// How long an outbound peer waits before connecting again.
    pub(super) fn reconnect_wait(&self) -> Duration {
        lock_or_recover(&self.runtime, "i2p runtime").reconnect_wait
    }

    pub(super) fn allocate_id(&self) -> InterfaceId {
        InterfaceId(self.next_id.fetch_add(1, Ordering::Relaxed))
    }

    /// Bring up a peer whose writer writes `stream`, connected to `remote`.
    pub(super) fn peer_up(
        &self,
        stream: &TcpStream,
        id: InterfaceId,
        remote: &str,
        outbound: bool,
    ) -> std::io::Result<PeerUp> {
        let (writer, detached) = I2pWriter::new(stream.try_clone()?);
        let writer = Box::new(writer);
        let tunnel = I2pEndpoint::add_tunnel(&self.endpoint, id, Some(stream));
        let event = peer_up(
            id,
            writer,
            peer_info(id, remote, self.ingress_control, outbound),
            self.dynamic_template.as_ref(),
            crate::interface::display::i2p_peer_name(&self.name, remote, outbound),
        );
        Ok(PeerUp {
            event,
            tunnel,
            detached,
        })
    }

    /// Try once to connect to an outbound peer: resolve its address,
    /// connect a stream to it and ready its interface. Says why it failed,
    /// if it did.
    pub(super) fn connect_once(&self, peer: &OutboundPeer) -> Option<(TcpStream, PeerUp)> {
        let OutboundPeer { address, id } = peer;
        log::info!("[{}] connecting to I2P peer {}", self.name, address);
        let destination = if address.ends_with(".i2p") {
            match sam::naming_lookup_with_mark(&self.sam_addr, address, self.underlay_mark) {
                Ok(dest) => dest.to_i2p_base64(),
                Err(e) => {
                    log::warn!("[{}] failed to resolve {}: {}", self.name, address, e);
                    return None;
                }
            }
        } else {
            // Assume it's already a full base64 destination
            address.clone()
        };
        let stream = match sam::stream_connect_with_mark(
            &self.sam_addr,
            &self.session_id,
            &destination,
            self.underlay_mark,
        ) {
            Ok(stream) => stream,
            Err(e) => {
                log::warn!(
                    "[{}] failed to connect to I2P peer {}: {}",
                    self.name,
                    address,
                    e
                );
                return None;
            }
        };
        log::info!(
            "[{}] connected to I2P peer {} → id {}",
            self.name,
            address,
            id.0
        );
        match self.peer_up(&stream, *id, address, true) {
            Ok(up) => Some((stream, up)),
            Err(e) => {
                log::warn!("[{}] failed to clone stream: {}", self.name, e);
                None
            }
        }
    }

    /// Ready the interface of a peer the bridge accepted from `remote`.
    /// Says why it failed, if it did.
    pub(super) fn accepted(
        &self,
        stream: &TcpStream,
        id: InterfaceId,
        remote: &str,
    ) -> Option<PeerUp> {
        log::info!(
            "[{}] accepted I2P connection from {} → id {}",
            self.name,
            remote,
            id.0
        );
        match self.peer_up(stream, id, remote, false) {
            Ok(up) => Some(up),
            Err(e) => {
                log::warn!("[{}] failed to clone accepted stream: {}", self.name, e);
                None
            }
        }
    }

    /// An outbound peer's stream ended (and its interface was reported
    /// down): whether to connect it again, which it is unless the driver
    /// detached it, as upstream's detached `I2PInterfacePeer` stays down.
    pub(super) fn outbound_lost(&self, peer: &OutboundPeer, detached: &AtomicBool) -> bool {
        if detached.load(Ordering::Relaxed) {
            log::info!(
                "[{}] I2P peer {} was detached, not reconnecting",
                self.name,
                peer.address
            );
            I2pEndpoint::remove_tunnel(&self.endpoint, peer.id);
            return false;
        }
        log::warn!(
            "[{}] I2P peer {} disconnected, reconnecting in {}s",
            self.name,
            peer.address,
            self.reconnect_wait().as_secs()
        );
        true
    }
}

/// The lines the bridge sends on the session's control socket.
#[derive(Default)]
pub(super) struct ControlLines {
    line: Vec<u8>,
}

impl ControlLines {
    /// Take bytes read from the control socket, calling `reply` with what
    /// to answer each complete line: a `PING` keeps the session alive.
    pub(super) fn feed(&mut self, bytes: &[u8], mut reply: impl FnMut(&str)) {
        for &byte in bytes {
            if byte != b'\n' {
                if self.line.len() < MAX_SAM_LINE {
                    self.line.push(byte);
                }
                continue;
            }
            let line = String::from_utf8_lossy(&self.line).into_owned();
            self.line.clear();
            if let Some(answer) = control_reply(&line) {
                reply(&answer);
            }
        }
    }
}
