//! Discovery: announcing ourselves and hearing peers.

use super::*;
use std::os::fd::AsFd;

/// Discovery sender: periodically sends discovery token via multicast.
pub(super) struct DiscoverySenderContext {
    pub(super) group_id: Vec<u8>,
    pub(super) link_local_addr: String,
    pub(super) mcast_ip: Ipv6Addr,
    pub(super) discovery_port: u16,
    pub(super) if_index: u32,
    pub(super) runtime: Arc<Mutex<AutoRuntime>>,
    pub(super) running: Arc<AtomicBool>,
    pub(super) name: String,
    pub(super) underlay_mark: Option<u32>,
}

pub(super) fn discovery_sender_loop(context: DiscoverySenderContext) {
    let DiscoverySenderContext {
        group_id,
        link_local_addr,
        mcast_ip,
        discovery_port,
        if_index,
        runtime,
        running,
        name,
        underlay_mark,
    } = context;
    let token = compute_discovery_token(&group_id, &link_local_addr);

    while running.load(Ordering::Relaxed) {
        // Create a fresh socket for each send (matches Python)
        if let Ok(socket) = UdpSocket::bind("[::]:0") {
            if let Err(error) = crate::interface::apply_underlay_mark(socket.as_fd(), underlay_mark)
            {
                log::error!("[{}] failed to mark discovery socket: {}", name, error);
                return;
            }
            // Set multicast interface
            let _ = socket2::SockRef::from(&socket).set_multicast_if_v6(if_index);

            let target = SocketAddrV6::new(mcast_ip, discovery_port, 0, 0);
            if let Err(e) = socket.send_to(&token, target) {
                log::debug!("[{}] multicast send error: {}", name, e);
            }
        }

        let sleep_dur = Duration::from_secs_f64(
            lock_or_recover(&runtime, "auto runtime")
                .announce_interval_secs
                .max(0.1),
        );
        thread::sleep(sleep_dur);
    }
}

/// What handling a discovery token needs: validating it and admitting the
/// peer that sent it.
#[derive(Clone)]
pub(super) struct DiscoveryHandler {
    pub(super) group_id: Vec<u8>,
    pub(super) shared: Arc<Mutex<SharedState>>,
    pub(super) name: String,
    pub(super) ifname: String,
    pub(super) if_index: u32,
    pub(super) data_port: u16,
    pub(super) configured_bitrate: u64,
    pub(super) ingress_control: rns_core::transport::types::IngressControlConfig,
    pub(super) runtime: Arc<Mutex<AutoRuntime>>,
    pub(super) dynamic_template: Option<crate::interface::DynamicInterfaceTemplate>,
    pub(super) underlay_mark: Option<u32>,
    /// Whether new peers' writers are called by the driver directly.
    pub(super) inline: bool,
}

impl DiscoveryHandler {
    /// Handle one discovery datagram, returning the event that brings up
    /// a newly admitted peer.
    pub(super) fn handle(&self, datagram: &[u8], src: std::net::SocketAddr) -> Option<Event> {
        if datagram.len() < 32 {
            return None;
        }
        // Extract source IPv6 address
        let std::net::SocketAddr::V6(src_addr) = src else {
            return None;
        };
        let peer_key = peer_key_from_src(&src_addr, self.if_index);
        let peering_hash = &datagram[..32];
        let expected = compute_discovery_token(&self.group_id, &peer_key.link_local_addr);
        if peering_hash != expected {
            log::debug!(
                "[{}] invalid peering hash from {}",
                self.name,
                peer_key.link_local_addr
            );
            return None;
        }

        {
            // Peers are accepted before the interface is fully online, for
            // initial peering (Python processes after final_init_done).
            let mut state = lock_or_recover(&self.shared, "auto shared state");
            // Multicast echo from ourselves.
            if state.link_local_addresses.contains(&peer_key) {
                return None;
            }
            // Already known.
            if state.peers.contains_key(&peer_key) {
                state.refresh_peer(&peer_key, crate::time::now());
                return None;
            }
        }

        // New peer! Create a data writer to send to them.
        add_peer(AddPeerContext {
            shared: &self.shared,
            peer_key: &peer_key,
            data_port: self.data_port,
            name: &self.name,
            ifname: &self.ifname,
            configured_bitrate: self.configured_bitrate,
            ingress_control: self.ingress_control,
            runtime: &self.runtime,
            dynamic_template: self.dynamic_template.as_ref(),
            underlay_mark: self.underlay_mark,
            inline: self.inline,
        })
    }
}

/// Discovery receiver: listens for discovery tokens and adds peers.
pub(super) fn discovery_receiver_loop(
    socket: UdpSocket,
    handler: DiscoveryHandler,
    tx: EventSender,
    running: Arc<AtomicBool>,
) {
    let mut buf = [0u8; 1024];

    while running.load(Ordering::Relaxed) {
        match socket.recv_from(&mut buf) {
            Ok((n, src)) => {
                if let Some(event) = handler.handle(&buf[..n], src) {
                    let _ = tx.send(event);
                }
            }
            Err(ref e)
                if e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::TimedOut =>
            {
                // Timeout, loop again
                continue;
            }
            Err(e) => {
                log::warn!("[{}] discovery recv error: {}", handler.name, e);
                if !running.load(Ordering::Relaxed) {
                    return;
                }
                thread::sleep(Duration::from_millis(100));
            }
        }
    }
}
