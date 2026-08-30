use std::io;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, SyncSender, TrySendError};
use std::sync::Arc;
use std::time::{Duration, Instant};

use rns_core::types::{DestHash, IdentityHash, LinkId, PacketHash};
use rns_crypto::identity::Identity;
use rns_net::{Callbacks, Destination, RnsNode};

use crate::identity::{load_or_create, signature_keys};

pub const CALLBACK_QUEUE_CAPACITY: usize = 256;
pub const APP_NAME: &str = "rntun";
pub const GATEWAY_ASPECT: &str = "gateway";

#[derive(Debug)]
pub enum NodeEvent {
    Announce(rns_net::AnnouncedIdentity),
    PathUpdated([u8; 16]),
    LinkEstablished {
        link_id: [u8; 16],
        initiator: bool,
    },
    LinkClosed([u8; 16]),
    RemoteIdentified {
        link_id: [u8; 16],
        identity: [u8; 16],
    },
    Control {
        link_id: [u8; 16],
        payload: Vec<u8>,
    },
    PacketData {
        link_id: [u8; 16],
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
    fn on_local_delivery(&mut self, _: DestHash, _: Vec<u8>, _: PacketHash) {}
    fn on_link_established(&mut self, link_id: LinkId, _: DestHash, _: f64, initiator: bool) {
        self.emit(NodeEvent::LinkEstablished {
            link_id: link_id.0,
            initiator,
        });
    }
    fn on_link_closed(&mut self, link_id: LinkId, _: Option<rns_core::link::TeardownReason>) {
        self.emit(NodeEvent::LinkClosed(link_id.0));
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

pub struct PrivateNode {
    pub node: RnsNode,
    pub identity: Identity,
    pub events: Receiver<NodeEvent>,
    dropped_callbacks: Arc<AtomicU64>,
}

impl PrivateNode {
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

    pub fn dropped_callbacks(&self) -> u64 {
        self.dropped_callbacks.load(Ordering::Relaxed)
    }

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

    pub fn announce_gateway(&self, destination: &Destination) -> io::Result<()> {
        self.node
            .announce(destination, &self.identity, Some(b"RNTU\x01"))
            .map(|_| ())
            .map_err(node_error)
    }

    pub fn connect(&self, destination: [u8; 16], timeout: Duration) -> io::Result<[u8; 16]> {
        let deadline = Instant::now() + timeout;
        let hash = DestHash(destination);
        if !self.node.has_path(&hash).map_err(node_error)? {
            self.node.request_path(&hash).map_err(node_error)?;
        }
        while !self.node.has_path(&hash).map_err(node_error)? {
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
            let remaining = deadline.saturating_duration_since(Instant::now());
            match self.events.recv_timeout(remaining) {
                Ok(NodeEvent::LinkEstablished {
                    link_id: id,
                    initiator: true,
                }) if id == link_id => break,
                Ok(NodeEvent::LinkClosed(id)) if id == link_id => {
                    return Err(io::Error::new(
                        io::ErrorKind::ConnectionAborted,
                        "link closed during setup",
                    ));
                }
                Ok(_) => {}
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

fn node_error(error: rns_net::node::SendError) -> io::Error {
    io::Error::new(io::ErrorKind::BrokenPipe, error)
}
