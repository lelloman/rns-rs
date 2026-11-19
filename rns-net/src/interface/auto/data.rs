//! Data packets to and from peers.

use super::*;

/// Writer that sends UDP unicast data to a peer.
pub(super) struct UdpWriter {
    pub(super) socket: UdpSocket,
    pub(super) target: SocketAddrV6,
    /// Called by the driver directly on a non-blocking socket (see
    /// [`Writer::sends_inline`]), with interface I/O folded.
    pub(super) inline: bool,
}

impl Writer for UdpWriter {
    fn send_frame(&mut self, data: &[u8]) -> io::Result<()> {
        match self.socket.send_to(data, self.target) {
            // A datagram the socket buffer cannot take is dropped, as the
            // network may drop it.
            Err(e) if self.inline && e.kind() == io::ErrorKind::WouldBlock => Ok(()),
            result => result.map(|_| ()),
        }
    }

    fn send_frame_confirmed(&mut self, data: &[u8]) -> io::Result<()> {
        self.socket.send_to(data, self.target).map(|_| ())
    }

    fn enqueue_confirmed(
        &mut self,
        data: &[u8],
        completion: &mut Option<crate::link_send::Completion>,
    ) -> io::Result<()> {
        // A full buffer returns WouldBlock with the completion untouched,
        // and the driver retries the frame.
        self.socket.send_to(data, self.target)?;
        if let Some(completion) = completion.take() {
            completion.finish(Ok(()));
        }
        Ok(())
    }

    fn sends_inline(&self) -> bool {
        self.inline
    }
}

/// Handle one datagram on a data socket, returning the frame it carries
/// for its peer's interface, or `None` if it is dropped.
pub(super) fn handle_data(
    shared: &Mutex<SharedState>,
    if_index: u32,
    data: &[u8],
    src: std::net::SocketAddr,
) -> Option<Event> {
    if data.is_empty() {
        return None;
    }
    let std::net::SocketAddr::V6(src_addr) = src else {
        return None;
    };
    let peer_key = peer_key_from_src(&src_addr, if_index);

    // Only data from known peers is considered (as in Python, which looks
    // up the spawned peer before deduplicating).
    let mut state = lock_or_recover(shared, "auto shared state");
    if !state.online || !state.peers.contains_key(&peer_key) {
        return None;
    }
    let now = crate::time::now();
    let data_hash = rns_crypto::sha256::sha256(data);
    // Deduplication
    if state.is_duplicate(&data_hash, now) {
        return None;
    }
    state.add_dedup(data_hash, now);
    state.refresh_peer(&peer_key, now);
    let iface_id = state.peers.get(&peer_key)?.interface_id;
    Some(Event::Frame {
        interface_id: iface_id,
        data: data.into(),
        rssi: None,
        snr: None,
    })
}

/// Data receiver: receives unicast UDP data from peers and dispatches as frames.
pub(super) fn data_receiver_loop(
    socket: UdpSocket,
    shared: Arc<Mutex<SharedState>>,
    tx: EventSender,
    running: &AtomicBool,
    name: &str,
    if_index: u32,
) {
    let mut buf = [0u8; HW_MTU + 64]; // a bit extra

    while running.load(Ordering::Relaxed) {
        match socket.recv_from(&mut buf) {
            Ok((n, src)) => {
                if let Some(frame) = handle_data(&shared, if_index, &buf[..n], src) {
                    if tx.send(frame).is_err() {
                        return;
                    }
                }
            }
            Err(ref e)
                if e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::TimedOut =>
            {
                continue;
            }
            Err(e) => {
                log::warn!("[{}] data recv error: {}", name, e);
                if !running.load(Ordering::Relaxed) {
                    return;
                }
                thread::sleep(Duration::from_millis(100));
            }
        }
    }
}
