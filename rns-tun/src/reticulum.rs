//! The private Reticulum node rntun runs, and the events it reports.

use std::io;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, SyncSender, TrySendError};
use std::sync::Arc;
use std::time::{Duration, Instant};

use rns_core::types::{DestHash, IdentityHash, LinkId};
use rns_crypto::identity::Identity;
use rns_net::{Callbacks, Destination, RnsNode};

use crate::identity::{load_or_create, signature_keys};

/// Events the node queues for [`PrivateNode::events`] before further ones
/// are dropped and counted (see [`PrivateNode::dropped_callbacks`]).
pub const CALLBACK_QUEUE_CAPACITY: usize = 256;
/// Application name of the gateway destination.
pub const APP_NAME: &str = "rntun";
/// Aspect of the gateway destination (`rntun.gateway`).
pub const GATEWAY_ASPECT: &str = "gateway";

/// A node callback, queued for the rntun worker. Link ids, destination
/// hashes and identity hashes are raw 16-byte values.
#[derive(Debug)]
pub enum NodeEvent {
    /// An announce was received.
    Announce(rns_net::AnnouncedIdentity),
    /// The path to this destination hash changed.
    PathUpdated([u8; 16]),
    /// A Link came up; `initiator` is true for Links this node opened.
    LinkEstablished {
        /// The Link.
        link_id: [u8; 16],
        /// Whether this node opened the Link.
        initiator: bool,
    },
    /// A Link went down.
    LinkClosed {
        /// The Link.
        link_id: [u8; 16],
        /// Why, when known.
        reason: Option<rns_core::link::TeardownReason>,
    },
    /// The peer on a Link proved its identity.
    RemoteIdentified {
        /// The Link.
        link_id: [u8; 16],
        /// The peer's identity hash.
        identity: [u8; 16],
    },
    /// An rntun control frame arrived on a Link's Channel.
    Control {
        /// The Link.
        link_id: [u8; 16],
        /// The encoded [`ControlMessage`](crate::ControlMessage).
        payload: Vec<u8>,
    },
    /// An rntun packet fragment arrived on a Link.
    PacketData {
        /// The Link.
        link_id: [u8; 16],
        /// The encoded [`PacketFragment`](crate::PacketFragment).
        payload: Vec<u8>,
    },
}

struct NodeCallbacks {
    tx: SyncSender<NodeEvent>,
    dropped: Arc<AtomicU64>,
}

impl NodeCallbacks {
    fn emit(&self, event: NodeEvent) {
        if matches!(self.tx.try_send(event), Err(TrySendError::Full(_))) {
            self.dropped.fetch_add(1, Ordering::Relaxed);
        }
    }
}

impl Callbacks for NodeCallbacks {
    fn on_announce(&mut self, value: rns_net::AnnouncedIdentity) {
        self.emit(NodeEvent::Announce(value));
    }
    fn on_path_updated(&mut self, dest_hash: DestHash, _hops: u8) {
        self.emit(NodeEvent::PathUpdated(dest_hash.0));
    }
    fn on_link_established(&mut self, link_id: LinkId, _: DestHash, _: f64, initiator: bool) {
        self.emit(NodeEvent::LinkEstablished {
            link_id: link_id.0,
            initiator,
        });
    }
    fn on_link_closed(&mut self, link_id: LinkId, reason: Option<rns_core::link::TeardownReason>) {
        self.emit(NodeEvent::LinkClosed {
            link_id: link_id.0,
            reason,
        });
    }
    fn on_remote_identified(&mut self, link_id: LinkId, identity: IdentityHash, _: [u8; 64]) {
        self.emit(NodeEvent::RemoteIdentified {
            link_id: link_id.0,
            identity: identity.0,
        });
    }
    fn on_channel_message(&mut self, link_id: LinkId, msgtype: u16, payload: Vec<u8>) {
        if msgtype == crate::RNTUN_CHANNEL_MSGTYPE {
            self.emit(NodeEvent::Control {
                link_id: link_id.0,
                payload,
            });
        }
    }
    fn on_link_data(&mut self, link_id: LinkId, context: u8, payload: Vec<u8>) {
        if context == crate::RNTUN_LINK_CONTEXT {
            self.emit(NodeEvent::PacketData {
                link_id: link_id.0,
                payload,
            });
        }
    }
}

/// An application-private Reticulum node with the rntun identity and a
/// bounded event queue.
pub struct PrivateNode {
    /// The running node.
    pub node: RnsNode,
    /// This host's rntun identity (not the node's transport identity).
    pub identity: Identity,
    /// Node events, oldest first.
    pub events: Receiver<NodeEvent>,
    dropped_callbacks: Arc<AtomicU64>,
}

impl PrivateNode {
    /// Load or create the identity at `identity_file` and start a private
    /// node from the Reticulum config in `node_config_dir`, keeping its state
    /// under `state_dir/reticulum`. `underlay_mark`, when set, overrides the
    /// configured socket mark. Fails when the identity or the node cannot be
    /// set up.
    pub fn start(
        node_config_dir: &Path,
        state_dir: &Path,
        identity_file: &Path,
        underlay_mark: Option<u32>,
    ) -> io::Result<Self> {
        let identity = load_or_create(identity_file)?;
        let (tx, events) = mpsc::sync_channel(CALLBACK_QUEUE_CAPACITY);
        let dropped_callbacks = Arc::new(AtomicU64::new(0));
        let callbacks = NodeCallbacks {
            tx,
            dropped: Arc::clone(&dropped_callbacks),
        };
        let node = RnsNode::from_private_config(
            node_config_dir,
            &state_dir.join("reticulum"),
            underlay_mark,
            Box::new(callbacks),
        )?;
        Ok(Self {
            node,
            identity,
            events,
            dropped_callbacks,
        })
    }

    /// Events dropped so far because the queue was full.
    pub fn dropped_callbacks(&self) -> u64 {
        self.dropped_callbacks.load(Ordering::Relaxed)
    }

    /// Register the inbound `rntun.gateway` destination for this identity
    /// and accept Links to it.
    pub fn register_gateway(&self) -> io::Result<Destination> {
        let destination = Destination::single_in(
            APP_NAME,
            &[GATEWAY_ASPECT],
            IdentityHash(*self.identity.hash()),
        );
        let (private, public) = signature_keys(&self.identity)?;
        self.node
            .register_destination_with_proof(&destination, self.identity.get_private_key())
            .map_err(node_error)?;
        self.node
            .register_link_destination(destination.hash.0, private, public, 0)
            .map_err(node_error)?;
        Ok(destination)
    }

    /// Queue an announce of the gateway destination with app data
    /// `RNTU\x01`.
    pub fn announce_gateway(&self, destination: &Destination) -> io::Result<()> {
        self.node
            .announce_queued(destination, &self.identity, Some(b"RNTU\x01"))
            .map(|_| ())
            .map_err(node_error)
    }

    /// Open a Link to the gateway `destination` and identify on it, blocking
    /// for up to `timeout`. Requests a path first when none is known. Returns
    /// the Link id. Other events that arrive meanwhile are consumed and lost.
    pub fn connect(&self, destination: [u8; 16], timeout: Duration) -> io::Result<[u8; 16]> {
        self.connect_with_cancel(destination, timeout, || false)
    }

    /// Establish and identify a Link while periodically checking cancellation.
    /// This is used by embedded hosts whose service lifecycle must not wait for
    /// the complete path or Link timeout before shutting down. Fails with
    /// [`io::ErrorKind::Interrupted`] once `cancelled` is set.
    pub fn connect_cancellable(
        &self,
        destination: [u8; 16],
        timeout: Duration,
        cancelled: &std::sync::atomic::AtomicBool,
    ) -> io::Result<[u8; 16]> {
        self.connect_with_cancel(destination, timeout, || cancelled.load(Ordering::Relaxed))
    }

    fn connect_with_cancel(
        &self,
        destination: [u8; 16],
        timeout: Duration,
        is_cancelled: impl Fn() -> bool,
    ) -> io::Result<[u8; 16]> {
        let deadline = Instant::now() + timeout;
        let hash = DestHash(destination);
        if !self.node.has_path(&hash).map_err(node_error)? {
            self.node.request_path(&hash).map_err(node_error)?;
        }
        while !self.node.has_path(&hash).map_err(node_error)? {
            if is_cancelled() {
                return Err(io::Error::new(
                    io::ErrorKind::Interrupted,
                    "Link setup cancelled",
                ));
            }
            if Instant::now() >= deadline {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "path request timed out",
                ));
            }
            let _ = self.events.recv_timeout(Duration::from_millis(50));
        }
        let announced = self
            .node
            .recall_identity(&hash)
            .map_err(node_error)?
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::NotFound, "destination identity unknown")
            })?;
        let mut signature_public = [0; 32];
        signature_public.copy_from_slice(&announced.public_key[32..]);
        let link_id = self
            .node
            .create_link(destination, signature_public)
            .map_err(node_error)?;
        loop {
            if is_cancelled() {
                let _ = self.node.teardown_link(link_id);
                return Err(io::Error::new(
                    io::ErrorKind::Interrupted,
                    "Link setup cancelled",
                ));
            }
            let remaining = deadline
                .saturating_duration_since(Instant::now())
                .min(Duration::from_millis(100));
            match self.events.recv_timeout(remaining) {
                Ok(NodeEvent::LinkEstablished {
                    link_id: id,
                    initiator: true,
                }) if id == link_id => break,
                Ok(NodeEvent::LinkClosed { link_id: id, .. }) if id == link_id => {
                    return Err(io::Error::new(
                        io::ErrorKind::ConnectionAborted,
                        "link closed during setup",
                    ));
                }
                Ok(_) => {}
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) if Instant::now() < deadline => {}
                Err(_) => {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "link setup timed out",
                    ))
                }
            }
        }
        self.node
            .identify_on_link(
                link_id,
                self.identity.get_private_key().ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidData, "identity has no private key")
                })?,
            )
            .map_err(node_error)?;
        Ok(link_id)
    }
}

fn node_error(error: rns_net::SendError) -> io::Error {
    io::Error::new(io::ErrorKind::BrokenPipe, error)
}
