pub mod crypto;
pub mod handshake;
pub mod identify;
pub mod keepalive;
pub mod types;

use alloc::vec::Vec;

use rns_crypto::ed25519::{Ed25519PrivateKey, Ed25519PublicKey};
use rns_crypto::token::Token;
use rns_crypto::x25519::X25519PrivateKey;
use rns_crypto::Rng;

use crate::constants::{
    LINK_ECPUBSIZE, LINK_ESTABLISHMENT_TIMEOUT_PER_HOP, LINK_KEEPALIVE_MAX, LINK_MTU_MAX,
    LINK_MTU_MIN, MTU, PATHFINDER_M,
};

pub use types::{LinkAction, LinkError, LinkId, LinkMode, LinkState, TeardownReason};

use crypto::{create_session_token, link_decrypt, link_decrypt_chunks, link_encrypt};
use handshake::{
    build_linkrequest_data, compute_link_id, pack_rtt, parse_linkrequest_data,
    perform_key_exchange, unpack_rtt, validate_lrproof,
};
use keepalive::{
    compute_establishment_timeout, compute_keepalive, compute_stale_time, is_establishment_timeout,
    should_go_stale, should_send_keepalive, stale_close_timeout,
};

/// The Link Engine manages a single link's lifecycle.
///
/// It follows the action-queue model: methods return `Vec<LinkAction>` instead
/// of performing I/O directly. The caller dispatches actions.
pub struct LinkEngine {
    link_id: LinkId,
    state: LinkState,
    is_initiator: bool,
    mode: LinkMode,

    // Ephemeral keys
    prv: X25519PrivateKey,
    sig_prv: Ed25519PrivateKey,

    // Peer keys
    peer_pub_bytes: Option<[u8; 32]>,
    peer_sig_pub_bytes: Option<[u8; 32]>,

    // Session crypto
    derived_key: Option<Vec<u8>>,
    token: Option<Token>,

    // Timing
    request_time: f64,
    activated_at: Option<f64>,
    last_inbound: f64,
    last_outbound: f64,
    last_keepalive: f64,
    last_proof: f64,
    rtt: Option<f64>,
    keepalive_interval: f64,
    stale_time: f64,
    /// When the link went stale; it closes `stale_close_timeout` later
    /// unless inbound traffic recovers it first.
    stale_since: Option<f64>,
    establishment_timeout: f64,
    expected_hops: u8,
    /// Time of the first authenticated terminus hop rebalance.
    rebalanced_at: Option<f64>,

    // Counts packed packet data/ciphertext, matching Python Link accounting.
    tx_packets: u64,
    rx_packets: u64,
    tx_bytes: u64,
    rx_bytes: u64,

    // Identity
    remote_identity: Option<([u8; 16], [u8; 64])>,
    destination_hash: [u8; 16],

    // MDU
    mtu: u32,
    mdu: usize,
}

impl LinkEngine {
    /// Create a new initiator-side link engine.
    ///
    /// Returns `(engine, linkrequest_data)` — the caller must pack linkrequest_data
    /// into a LINKREQUEST packet and send it.
    pub fn new_initiator(
        dest_hash: &[u8; 16],
        hops: u8,
        mode: LinkMode,
        mtu: Option<u32>,
        now: f64,
        rng: &mut dyn Rng,
    ) -> (Self, Vec<u8>) {
        let prv = X25519PrivateKey::generate(rng);
        let sig_prv = Ed25519PrivateKey::generate(rng);
        Self::new_initiator_with_keys(dest_hash, hops, mode, mtu, now, prv, sig_prv)
    }

    /// Create an initiator link whose X25519 public key carries a stamp of at
    /// least `stamp_cost` over `destination_hash || ed25519_public_key`.
    pub fn new_initiator_stamped(
        dest_hash: &[u8; 16],
        hops: u8,
        mode: LinkMode,
        mtu: Option<u32>,
        now: f64,
        rng: &mut dyn Rng,
        stamp_cost: u8,
    ) -> (Self, Vec<u8>) {
        let sig_prv = Ed25519PrivateKey::generate(rng);
        let sig_pub_bytes = sig_prv.public_key().public_bytes();
        let mut material = [0u8; 48];
        material[..16].copy_from_slice(dest_hash);
        material[16..].copy_from_slice(&sig_pub_bytes);
        let (prv, _public, _value) =
            rns_crypto::identity::generate_stamped_key(rng, &material, stamp_cost);
        Self::new_initiator_with_keys(dest_hash, hops, mode, mtu, now, prv, sig_prv)
    }

    /// Create an initiator link from pre-generated keys.
    ///
    /// Used when the X25519 key was stamped ahead of time, off the caller's
    /// latency-sensitive thread; see `rns-net`'s link request stamping.
    #[allow(clippy::too_many_arguments)]
    pub fn new_initiator_with_keys(
        dest_hash: &[u8; 16],
        hops: u8,
        mode: LinkMode,
        mtu: Option<u32>,
        now: f64,
        prv: X25519PrivateKey,
        sig_prv: Ed25519PrivateKey,
    ) -> (Self, Vec<u8>) {
        let pub_bytes = prv.public_key().public_bytes();
        let sig_pub_bytes = sig_prv.public_key().public_bytes();

        let request_data = build_linkrequest_data(&pub_bytes, &sig_pub_bytes, mtu, mode);

        let link_mtu = effective_link_mtu(mtu);

        let engine = LinkEngine {
            link_id: [0u8; 16], // will be set after packet is built
            state: LinkState::Pending,
            is_initiator: true,
            mode,
            prv,
            sig_prv,
            peer_pub_bytes: None,
            peer_sig_pub_bytes: None,
            derived_key: None,
            token: None,
            request_time: now,
            activated_at: None,
            last_inbound: now,
            last_outbound: now,
            last_keepalive: now,
            last_proof: 0.0,
            rtt: None,
            keepalive_interval: LINK_KEEPALIVE_MAX,
            stale_time: LINK_KEEPALIVE_MAX * 2.0,
            stale_since: None,
            establishment_timeout: compute_establishment_timeout(
                LINK_ESTABLISHMENT_TIMEOUT_PER_HOP,
                hops,
            ),
            expected_hops: if hops < PATHFINDER_M {
                hops
            } else {
                PATHFINDER_M
            },
            rebalanced_at: None,
            tx_packets: 0,
            rx_packets: 0,
            tx_bytes: 0,
            rx_bytes: 0,
            remote_identity: None,
            destination_hash: *dest_hash,
            mtu: link_mtu,
            mdu: compute_mdu(link_mtu as usize),
        };

        (engine, request_data)
    }

    /// Set link_id from the hashable part of the packed LINKREQUEST packet.
    ///
    /// Must be called after packing the LINKREQUEST packet (since link_id depends
    /// on the packet's hashable part).
    pub fn set_link_id_from_hashable(&mut self, hashable_part: &[u8], data_len: usize) {
        let extra = data_len.saturating_sub(LINK_ECPUBSIZE);
        self.link_id = compute_link_id(hashable_part, extra);
    }

    /// Create a new responder-side link engine from an incoming LINKREQUEST.
    ///
    /// `owner_sig_prv` / `owner_sig_pub` are the destination's signing keys.
    /// Returns `(engine, actions)` where actions include the LRPROOF data to send.
    #[allow(clippy::too_many_arguments)]
    pub fn new_responder(
        owner_sig_prv: &Ed25519PrivateKey,
        owner_sig_pub_bytes: &[u8; 32],
        linkrequest_data: &[u8],
        hashable_part: &[u8],
        dest_hash: &[u8; 16],
        hops: u8,
        now: f64,
        rng: &mut dyn Rng,
    ) -> Result<(Self, Vec<u8>), LinkError> {
        let (peer_pub, peer_sig_pub, peer_mtu, mode) = parse_linkrequest_data(linkrequest_data)?;

        let extra = linkrequest_data.len().saturating_sub(LINK_ECPUBSIZE);
        let link_id = compute_link_id(hashable_part, extra);

        // Generate ephemeral keys for this end
        let prv = X25519PrivateKey::generate(rng);
        let pub_bytes = prv.public_key().public_bytes();
        let sig_pub_bytes = *owner_sig_pub_bytes;

        // Perform ECDH + HKDF
        let derived_key = perform_key_exchange(&prv, &peer_pub, &link_id, mode)?;
        let token = create_session_token(&derived_key)?;

        let link_mtu = effective_link_mtu(peer_mtu);

        // Build LRPROOF
        let lrproof_data = handshake::build_lrproof(
            &link_id,
            &pub_bytes,
            &sig_pub_bytes,
            owner_sig_prv,
            peer_mtu,
            mode,
        );

        let engine = LinkEngine {
            link_id,
            state: LinkState::Handshake,
            is_initiator: false,
            mode,
            prv,
            sig_prv: Ed25519PrivateKey::from_bytes(&owner_sig_prv.private_bytes()),
            peer_pub_bytes: Some(peer_pub),
            peer_sig_pub_bytes: Some(peer_sig_pub),
            derived_key: Some(derived_key),
            token: Some(token),
            request_time: now,
            activated_at: None,
            last_inbound: now,
            last_outbound: now,
            last_keepalive: now,
            last_proof: 0.0,
            rtt: None,
            keepalive_interval: LINK_KEEPALIVE_MAX,
            stale_time: LINK_KEEPALIVE_MAX * 2.0,
            stale_since: None,
            establishment_timeout: compute_establishment_timeout(
                LINK_ESTABLISHMENT_TIMEOUT_PER_HOP,
                hops,
            ),
            expected_hops: PATHFINDER_M,
            rebalanced_at: None,
            tx_packets: 0,
            rx_packets: 0,
            tx_bytes: 0,
            rx_bytes: 0,
            remote_identity: None,
            destination_hash: *dest_hash,
            mtu: link_mtu,
            mdu: compute_mdu(link_mtu as usize),
        };

        Ok((engine, lrproof_data))
    }

    /// Handle an incoming LRPROOF (initiator side).
    ///
    /// Validates the proof, performs ECDH, derives session key, returns LRRTT data
    /// to be encrypted and sent.
    pub fn handle_lrproof(
        &mut self,
        proof_data: &[u8],
        peer_sig_pub_bytes: &[u8; 32],
        now: f64,
        rng: &mut dyn Rng,
    ) -> Result<(Vec<u8>, Vec<LinkAction>), LinkError> {
        self.handle_lrproof_with_hops(proof_data, peer_sig_pub_bytes, None, now, rng)
    }

    /// Validate an LRPROOF while recording its authenticated hop metric.
    pub fn handle_lrproof_with_hops(
        &mut self,
        proof_data: &[u8],
        peer_sig_pub_bytes: &[u8; 32],
        packet_hops: Option<u8>,
        now: f64,
        rng: &mut dyn Rng,
    ) -> Result<(Vec<u8>, Vec<LinkAction>), LinkError> {
        if self.state != LinkState::Pending || !self.is_initiator {
            return Err(LinkError::InvalidState);
        }

        let peer_sig_pub = Ed25519PublicKey::from_bytes(peer_sig_pub_bytes)
            .map_err(|_| LinkError::InvalidSignature)?;

        let (peer_pub, confirmed_mtu, confirmed_mode) =
            validate_lrproof(proof_data, &self.link_id, &peer_sig_pub, peer_sig_pub_bytes)?;

        if confirmed_mode != self.mode {
            return Err(LinkError::UnsupportedMode);
        }

        if let Some(hops) = packet_hops {
            if hops != self.expected_hops && self.rebalanced_at.is_none() {
                self.rebalanced_at = Some(now);
                self.expected_hops = hops;
            }
        }

        self.peer_pub_bytes = Some(peer_pub);
        self.peer_sig_pub_bytes = Some(*peer_sig_pub_bytes);

        // ECDH + HKDF
        let derived_key = perform_key_exchange(&self.prv, &peer_pub, &self.link_id, self.mode)?;
        let token = create_session_token(&derived_key)?;

        self.derived_key = Some(derived_key);
        self.token = Some(token);

        // Update MTU if confirmed
        if confirmed_mtu.is_some() {
            let mtu = effective_link_mtu(confirmed_mtu);
            self.mtu = mtu;
            self.mdu = compute_mdu(mtu as usize);
        }

        // Compute RTT and activate
        let rtt = now - self.request_time;
        self.rtt = Some(rtt);
        self.state = LinkState::Active;
        self.activated_at = Some(now);
        self.last_inbound = now;
        self.update_keepalive();

        // Build encrypted LRRTT packet data
        let rtt_packed = pack_rtt(rtt);
        let rtt_encrypted = self.encrypt(&rtt_packed, rng)?;

        let actions = vec![
            LinkAction::StateChanged {
                link_id: self.link_id,
                new_state: LinkState::Active,
                reason: None,
            },
            LinkAction::LinkEstablished {
                link_id: self.link_id,
                rtt,
                is_initiator: true,
            },
        ];

        Ok((rtt_encrypted, actions))
    }

    /// Handle an incoming LRRTT (responder side).
    ///
    /// Decrypts the RTT packet, activates the link.
    pub fn handle_lrrtt(
        &mut self,
        encrypted_data: &[u8],
        now: f64,
    ) -> Result<Vec<LinkAction>, LinkError> {
        self.handle_lrrtt_with_hops(encrypted_data, None, now)
    }

    /// Handle LRRTT while recording the responder-side hop metric. The legacy
    /// timing-only method remains available for existing callers.
    pub fn handle_lrrtt_with_hops(
        &mut self,
        encrypted_data: &[u8],
        packet_hops: Option<u8>,
        now: f64,
    ) -> Result<Vec<LinkAction>, LinkError> {
        if self.state != LinkState::Handshake || self.is_initiator {
            return Err(LinkError::InvalidState);
        }

        let plaintext = self.decrypt(encrypted_data)?;
        let initiator_rtt = unpack_rtt(&plaintext).ok_or(LinkError::InvalidData)?;
        if let Some(hops) = packet_hops {
            self.expected_hops = hops;
        }

        let measured_rtt = now - self.request_time;
        // `f64::max` ignores a NaN operand, so a NaN can never be selected.
        let rtt = measured_rtt.max(initiator_rtt);

        self.rtt = Some(rtt);
        self.state = LinkState::Active;
        self.activated_at = Some(now);
        self.last_inbound = now;
        self.update_keepalive();

        let actions = vec![
            LinkAction::StateChanged {
                link_id: self.link_id,
                new_state: LinkState::Active,
                reason: None,
            },
            LinkAction::LinkEstablished {
                link_id: self.link_id,
                rtt,
                is_initiator: false,
            },
        ];

        Ok(actions)
    }

    /// Encrypt plaintext for transmission over this link.
    pub fn encrypt(&self, plaintext: &[u8], rng: &mut dyn Rng) -> Result<Vec<u8>, LinkError> {
        let token = self.token.as_ref().ok_or(LinkError::NoSessionKey)?;
        Ok(link_encrypt(token, plaintext, rng))
    }

    /// Decrypt ciphertext received on this link.
    pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, LinkError> {
        let token = self.token.as_ref().ok_or(LinkError::NoSessionKey)?;
        link_decrypt(token, ciphertext)
    }

    /// Decrypt ciphertext held in consecutive chunks without joining them,
    /// dropping the first `skip` plaintext bytes.
    pub fn decrypt_chunks(&self, chunks: &[&[u8]], skip: usize) -> Result<Vec<u8>, LinkError> {
        let token = self.token.as_ref().ok_or(LinkError::NoSessionKey)?;
        link_decrypt_chunks(token, chunks, skip)
    }

    /// Sign an explicit delivery proof for a packet sent over this Link.
    pub fn sign_packet_hash(&self, packet_hash: &[u8; 32]) -> [u8; 64] {
        self.sig_prv.sign(packet_hash)
    }

    /// Validate a delivery proof using the remote endpoint's Link signing key.
    pub fn validate_packet_proof(&self, packet_hash: &[u8; 32], signature: &[u8; 64]) -> bool {
        self.peer_sig_pub_bytes
            .and_then(|bytes| Ed25519PublicKey::from_bytes(&bytes).ok())
            .map(|key| key.verify(signature, packet_hash))
            .unwrap_or(false)
    }

    /// Build LINKIDENTIFY data (encrypted).
    pub fn build_identify(
        &self,
        identity: &rns_crypto::identity::Identity,
        rng: &mut dyn Rng,
    ) -> Result<Vec<u8>, LinkError> {
        if self.state != LinkState::Active {
            return Err(LinkError::InvalidState);
        }
        let plaintext = identify::build_identify_data(identity, &self.link_id)?;
        self.encrypt(&plaintext, rng)
    }

    /// Handle incoming LINKIDENTIFY (encrypted data).
    ///
    /// Only responders (non-initiators) can receive LINKIDENTIFY (Python: Link.py:1017).
    pub fn handle_identify(&mut self, encrypted_data: &[u8]) -> Result<Vec<LinkAction>, LinkError> {
        if self.state != LinkState::Active || self.is_initiator {
            return Err(LinkError::InvalidState);
        }

        let plaintext = self.decrypt(encrypted_data)?;
        let (identity_hash, public_key) =
            identify::validate_identify_data(&plaintext, &self.link_id)?;
        if self.remote_identity.is_some() {
            return Ok(Vec::new());
        }
        self.remote_identity = Some((identity_hash, public_key));

        Ok(alloc::vec![LinkAction::RemoteIdentified {
            link_id: self.link_id,
            identity_hash,
            public_key,
        }])
    }

    /// Record that an inbound packet was received (updates timing).
    ///
    /// If the link is STALE, recovers to ACTIVE (Python: Link.py:987-988).
    pub fn record_inbound(&mut self, now: f64) -> Vec<LinkAction> {
        self.last_inbound = now;
        if self.state == LinkState::Stale {
            self.state = LinkState::Active;
            self.stale_since = None;
            return alloc::vec![LinkAction::StateChanged {
                link_id: self.link_id,
                new_state: LinkState::Active,
                reason: None,
            }];
        }
        Vec::new()
    }

    /// Record that a proof signed by the peer was received.
    ///
    /// Python's `PacketReceipt.validate_link_proof` sets `link.last_proof`,
    /// and the watchdog's stale check takes the latest of `last_inbound` and
    /// `last_proof`: an initiator that only ever hears proofs back for its
    /// own confirmed traffic stays active. Proofs do not reactivate a link
    /// that already went stale, matching upstream.
    pub fn record_proof(&mut self, now: f64) {
        self.last_proof = now;
    }

    /// Record that an outbound packet was sent (updates timing).
    pub fn record_outbound(&mut self, now: f64, is_keepalive: bool) {
        self.last_outbound = now;
        if is_keepalive {
            self.last_keepalive = now;
        }
    }

    /// Record one accepted inbound packet using its packed data/ciphertext size.
    pub fn record_inbound_traffic(&mut self, data_len: usize) {
        if self.state != LinkState::Closed {
            self.rx_packets = self.rx_packets.saturating_add(1);
            self.rx_bytes = self.rx_bytes.saturating_add(data_len as u64);
        }
    }

    /// Record one successfully packed outbound packet.
    pub fn record_outbound_traffic(&mut self, data_len: usize) {
        self.tx_packets = self.tx_packets.saturating_add(1);
        self.tx_bytes = self.tx_bytes.saturating_add(data_len as u64);
    }

    /// Periodic tick: check keepalive, stale, timeouts.
    pub fn tick(&mut self, now: f64) -> Vec<LinkAction> {
        let mut actions = Vec::new();

        match self.state {
            LinkState::Pending | LinkState::Handshake => {
                if is_establishment_timeout(self.request_time, self.establishment_timeout, now) {
                    self.state = LinkState::Closed;
                    actions.push(LinkAction::StateChanged {
                        link_id: self.link_id,
                        new_state: LinkState::Closed,
                        reason: Some(TeardownReason::Timeout),
                    });
                }
            }
            LinkState::Active => {
                let activated = self.activated_at.unwrap_or(0.0);
                // Python: max(max(self.last_inbound, self.last_proof), activated_at)
                let last_inbound = self.last_inbound.max(self.last_proof).max(activated);

                if should_go_stale(last_inbound, self.stale_time, now) {
                    self.state = LinkState::Stale;
                    self.stale_since = Some(now);
                    actions.push(LinkAction::StateChanged {
                        link_id: self.link_id,
                        new_state: LinkState::Stale,
                        reason: None,
                    });
                }
            }
            LinkState::Stale => {
                // Python's watchdog sleeps `rtt * KEEPALIVE_TIMEOUT_FACTOR +
                // STALE_GRACE` after marking the link stale and only closes
                // it if no inbound packet reactivated it meanwhile.
                let rtt = self.rtt.filter(|rtt| rtt.is_finite()).unwrap_or(0.0);
                let stale_since = self.stale_since.unwrap_or(now);
                if now >= stale_since + stale_close_timeout(rtt) {
                    self.state = LinkState::Closed;
                    self.stale_since = None;
                    actions.push(LinkAction::StateChanged {
                        link_id: self.link_id,
                        new_state: LinkState::Closed,
                        reason: Some(TeardownReason::Timeout),
                    });
                }
            }
            LinkState::Closed => {}
        }

        actions
    }

    /// Check if a keepalive should be sent. Returns true if conditions are met.
    pub fn needs_keepalive(&self, now: f64) -> bool {
        if self.state != LinkState::Active || !self.is_initiator {
            return false;
        }
        let activated = self.activated_at.unwrap_or(0.0);
        let last_inbound = self.last_inbound.max(self.last_proof).max(activated);

        // Initiators probe whenever either direction has been quiet for a full
        // interval. In particular, continuous responder-to-initiator traffic
        // must not suppress the probe that keeps the responder's inbound timer
        // alive.
        let inbound_quiet = now >= last_inbound + self.keepalive_interval;
        let outbound_quiet = now >= self.last_outbound + self.keepalive_interval;
        if !inbound_quiet && !outbound_quiet {
            return false;
        }

        should_send_keepalive(self.last_keepalive, self.keepalive_interval, now)
    }

    /// Return whether a received keepalive probe needs a responder reply.
    ///
    /// `0xff` is the initiator probe and `0xfe` the responder acknowledgement,
    /// matching upstream Reticulum. A responder that sent any traffic within
    /// the current keepalive interval can omit the acknowledgement because that
    /// traffic already refreshed the initiator's inbound timer.
    pub fn should_reply_keepalive(&self, payload: &[u8], now: f64) -> bool {
        self.state == LinkState::Active
            && !self.is_initiator
            && payload == [0xff]
            && now >= self.last_outbound + self.keepalive_interval
    }

    /// Tear down the link (initiator-initiated close).
    pub fn teardown(&mut self) -> Vec<LinkAction> {
        if self.state == LinkState::Closed {
            return Vec::new();
        }
        self.state = LinkState::Closed;
        let reason = if self.is_initiator {
            TeardownReason::InitiatorClosed
        } else {
            TeardownReason::DestinationClosed
        };
        alloc::vec![LinkAction::StateChanged {
            link_id: self.link_id,
            new_state: LinkState::Closed,
            reason: Some(reason),
        }]
    }

    /// Handle incoming teardown (remote close).
    pub fn handle_teardown(&mut self) -> Vec<LinkAction> {
        if self.state == LinkState::Closed {
            return Vec::new();
        }
        self.state = LinkState::Closed;
        let reason = if self.is_initiator {
            TeardownReason::DestinationClosed
        } else {
            TeardownReason::InitiatorClosed
        };
        alloc::vec![LinkAction::StateChanged {
            link_id: self.link_id,
            new_state: LinkState::Closed,
            reason: Some(reason),
        }]
    }

    // --- Queries ---

    pub fn link_id(&self) -> &LinkId {
        &self.link_id
    }

    pub fn state(&self) -> LinkState {
        self.state
    }

    pub fn rtt(&self) -> Option<f64> {
        self.rtt
    }

    pub fn mdu(&self) -> usize {
        self.mdu
    }

    pub fn mtu(&self) -> u32 {
        self.mtu
    }

    pub fn is_initiator(&self) -> bool {
        self.is_initiator
    }

    pub fn mode(&self) -> LinkMode {
        self.mode
    }

    pub fn remote_identity(&self) -> Option<&([u8; 16], [u8; 64])> {
        self.remote_identity.as_ref()
    }

    pub fn destination_hash(&self) -> &[u8; 16] {
        &self.destination_hash
    }

    pub fn expected_hops(&self) -> u8 {
        self.expected_hops
    }

    pub fn rebalanced_at(&self) -> Option<f64> {
        self.rebalanced_at
    }

    pub fn tx_packets(&self) -> u64 {
        self.tx_packets
    }

    pub fn rx_packets(&self) -> u64 {
        self.rx_packets
    }

    pub fn tx_bytes(&self) -> u64 {
        self.tx_bytes
    }

    pub fn rx_bytes(&self) -> u64 {
        self.rx_bytes
    }

    /// Get the derived session key (needed for hole-punch token derivation).
    pub fn derived_key(&self) -> Option<&[u8]> {
        self.derived_key.as_deref()
    }

    pub fn keepalive_interval(&self) -> f64 {
        self.keepalive_interval
    }

    /// When the peer's latest valid packet proof arrived (0 before the first).
    pub fn last_proof(&self) -> f64 {
        self.last_proof
    }

    /// Update the measured RTT (e.g., after path redirect to a direct link).
    /// Also recalculates keepalive and stale timers.
    pub fn set_rtt(&mut self, rtt: f64) {
        self.rtt = Some(rtt);
        self.update_keepalive();
    }

    /// Update the link MTU (e.g., after path redirect to a different interface).
    pub fn set_mtu(&mut self, mtu: u32) {
        self.mtu = mtu;
        self.mdu = compute_mdu(mtu as usize);
    }

    #[doc(hidden)]
    pub fn clear_session_for_testing(&mut self) {
        self.derived_key = None;
        self.token = None;
    }

    // --- Internal ---

    fn update_keepalive(&mut self) {
        if let Some(rtt) = self.rtt {
            self.keepalive_interval = compute_keepalive(rtt);
            self.stale_time = compute_stale_time(self.keepalive_interval);
        }
    }
}

/// Compute link MDU from MTU.
///
/// MDU = floor((mtu - IFAC_MIN_SIZE - HEADER_MINSIZE - TOKEN_OVERHEAD) / AES128_BLOCKSIZE) * AES128_BLOCKSIZE - 1
///
/// Saturates at 0 for MTUs too small to carry one AES block.
fn compute_mdu(mtu: usize) -> usize {
    use crate::constants::{AES128_BLOCKSIZE, HEADER_MINSIZE, IFAC_MIN_SIZE, TOKEN_OVERHEAD};
    let numerator = mtu.saturating_sub(IFAC_MIN_SIZE + HEADER_MINSIZE + TOKEN_OVERHEAD);
    ((numerator / AES128_BLOCKSIZE) * AES128_BLOCKSIZE).saturating_sub(1)
}

/// Resolve the link MTU from the signalled value: absent or 0 means the
/// default Reticulum MTU; anything else is clamped to
/// `[LINK_MTU_MIN, LINK_MTU_MAX]`.
fn effective_link_mtu(signalled_mtu: Option<u32>) -> u32 {
    signalled_mtu
        .filter(|mtu| *mtu != 0)
        .map(|mtu| mtu.clamp(LINK_MTU_MIN, LINK_MTU_MAX))
        .unwrap_or(MTU as u32)
}
use alloc::vec;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::{LINK_MDU, LINK_STALE_GRACE};
    use rns_crypto::FixedRng;

    fn make_rng(seed: u8) -> FixedRng {
        FixedRng::new(&[seed; 128])
    }

    fn active_link_pair() -> (LinkEngine, LinkEngine, Vec<u8>) {
        let mut rng_id = make_rng(0x01);
        let dest_sig_prv = Ed25519PrivateKey::generate(&mut rng_id);
        let dest_sig_pub_bytes = dest_sig_prv.public_key().public_bytes();
        let dest_hash = [0xDD; 16];

        let mut rng_init = make_rng(0x10);
        let (mut initiator, request_data) = LinkEngine::new_initiator(
            &dest_hash,
            1,
            LinkMode::Aes256Cbc,
            Some(500),
            100.0,
            &mut rng_init,
        );
        let mut hashable = vec![0x00, 0x00];
        hashable.extend_from_slice(&dest_hash);
        hashable.push(0x00);
        hashable.extend_from_slice(&request_data);
        initiator.set_link_id_from_hashable(&hashable, request_data.len());

        let mut rng_resp = make_rng(0x20);
        let (mut responder, lrproof_data) = LinkEngine::new_responder(
            &dest_sig_prv,
            &dest_sig_pub_bytes,
            &request_data,
            &hashable,
            &dest_hash,
            1,
            100.5,
            &mut rng_resp,
        )
        .unwrap();
        let mut rng_lrrtt = make_rng(0x30);
        let (lrrtt_encrypted, _) = initiator
            .handle_lrproof(&lrproof_data, &dest_sig_pub_bytes, 100.8, &mut rng_lrrtt)
            .unwrap();
        responder.handle_lrrtt(&lrrtt_encrypted, 101.0).unwrap();

        (initiator, responder, lrrtt_encrypted)
    }

    #[test]
    fn test_compute_mdu_default() {
        assert_eq!(compute_mdu(500), LINK_MDU);
    }

    #[test]
    fn zero_mtu_signalling_falls_back_to_reticulum_mtu() {
        let mut rng_id = make_rng(0x01);
        let dest_sig_prv = Ed25519PrivateKey::generate(&mut rng_id);
        let dest_sig_pub_bytes = dest_sig_prv.public_key().public_bytes();
        let dest_hash = [0xDD; 16];

        let mut rng_init = make_rng(0x10);
        let (mut initiator, request_data) = LinkEngine::new_initiator(
            &dest_hash,
            1,
            LinkMode::Aes256Cbc,
            Some(0),
            100.0,
            &mut rng_init,
        );
        let mut hashable = vec![0x00, 0x00];
        hashable.extend_from_slice(&dest_hash);
        hashable.push(0x00);
        hashable.extend_from_slice(&request_data);
        initiator.set_link_id_from_hashable(&hashable, request_data.len());

        let mut rng_resp = make_rng(0x20);
        let (responder, lrproof_data) = LinkEngine::new_responder(
            &dest_sig_prv,
            &dest_sig_pub_bytes,
            &request_data,
            &hashable,
            &dest_hash,
            1,
            100.5,
            &mut rng_resp,
        )
        .unwrap();

        let mut rng_lrrtt = make_rng(0x30);
        initiator
            .handle_lrproof(&lrproof_data, &dest_sig_pub_bytes, 100.8, &mut rng_lrrtt)
            .unwrap();

        assert_eq!(initiator.mtu(), MTU as u32);
        assert_eq!(responder.mtu(), MTU as u32);
        assert_eq!(initiator.mdu(), LINK_MDU);
        assert_eq!(responder.mdu(), LINK_MDU);
    }

    #[test]
    fn test_full_handshake() {
        // Setup: destination identity (for responder)
        let mut rng_id = make_rng(0x01);
        let dest_sig_prv = Ed25519PrivateKey::generate(&mut rng_id);
        let dest_sig_pub_bytes = dest_sig_prv.public_key().public_bytes();

        let dest_hash = [0xDD; 16];
        let mode = LinkMode::Aes256Cbc;

        // Step 1: Initiator creates link request
        let mut rng_init = make_rng(0x10);
        let (mut initiator, request_data) =
            LinkEngine::new_initiator(&dest_hash, 1, mode, Some(500), 100.0, &mut rng_init);
        assert_eq!(initiator.state(), LinkState::Pending);

        // Simulate packet packing: build a fake hashable part
        // In real usage, the caller packs a LINKREQUEST packet and calls set_link_id_from_hashable
        let mut hashable = Vec::new();
        hashable.push(0x00); // flags byte (lower nibble)
        hashable.push(0x00); // hops
        hashable.extend_from_slice(&dest_hash);
        hashable.push(0x00); // context
        hashable.extend_from_slice(&request_data);

        initiator.set_link_id_from_hashable(&hashable, request_data.len());
        assert_ne!(initiator.link_id(), &[0u8; 16]);

        // Step 2: Responder receives link request
        let mut rng_resp = make_rng(0x20);
        let (mut responder, lrproof_data) = LinkEngine::new_responder(
            &dest_sig_prv,
            &dest_sig_pub_bytes,
            &request_data,
            &hashable,
            &dest_hash,
            1,
            100.5,
            &mut rng_resp,
        )
        .unwrap();
        assert_eq!(responder.state(), LinkState::Handshake);
        assert_eq!(responder.link_id(), initiator.link_id());

        // Step 3: Initiator validates LRPROOF
        let mut rng_lrrtt = make_rng(0x30);
        assert!(initiator
            .handle_lrproof_with_hops(
                &[0xAA; 3],
                &dest_sig_pub_bytes,
                Some(8),
                100.6,
                &mut rng_lrrtt,
            )
            .is_err());
        assert_eq!(initiator.expected_hops(), 1);
        let mismatched_mode_proof = handshake::build_lrproof(
            initiator.link_id(),
            lrproof_data[64..96].try_into().unwrap(),
            &dest_sig_pub_bytes,
            &dest_sig_prv,
            Some(500),
            LinkMode::Aes128Cbc,
        );
        assert_eq!(
            initiator
                .handle_lrproof_with_hops(
                    &mismatched_mode_proof,
                    &dest_sig_pub_bytes,
                    Some(9),
                    100.65,
                    &mut rng_lrrtt,
                )
                .unwrap_err(),
            LinkError::UnsupportedMode,
        );
        assert_eq!(initiator.expected_hops(), 1);
        let mut invalid_lrproof = lrproof_data.clone();
        invalid_lrproof[0] ^= 0x01;
        assert!(initiator
            .handle_lrproof_with_hops(
                &invalid_lrproof,
                &dest_sig_pub_bytes,
                Some(7),
                100.7,
                &mut rng_lrrtt,
            )
            .is_err());
        assert_eq!(initiator.expected_hops(), 1);
        let (lrrtt_encrypted, actions) = initiator
            .handle_lrproof_with_hops(
                &lrproof_data,
                &dest_sig_pub_bytes,
                Some(4),
                100.8,
                &mut rng_lrrtt,
            )
            .unwrap();
        assert_eq!(initiator.state(), LinkState::Active);
        assert!(initiator.rtt().is_some());
        assert_eq!(initiator.rebalanced_at(), Some(100.8));
        assert_eq!(actions.len(), 2); // StateChanged + LinkEstablished

        // Step 4: Responder handles LRRTT
        let actions = responder
            .handle_lrrtt_with_hops(&lrrtt_encrypted, Some(4), 101.0)
            .unwrap();
        assert_eq!(responder.state(), LinkState::Active);
        assert_eq!(initiator.expected_hops(), 4);
        assert_eq!(responder.expected_hops(), 4);
        assert_eq!(responder.rebalanced_at(), None);

        // A later valid proof cannot rewrite the first authenticated
        // rebalance, even if it reports another hop metric.
        initiator.state = LinkState::Pending;
        let mut repeated_rng = make_rng(0x31);
        initiator
            .handle_lrproof_with_hops(
                &lrproof_data,
                &dest_sig_pub_bytes,
                Some(6),
                101.1,
                &mut repeated_rng,
            )
            .unwrap();
        assert_eq!(initiator.expected_hops(), 4);
        assert_eq!(initiator.rebalanced_at(), Some(100.8));

        initiator.record_outbound_traffic(48);
        initiator.record_inbound_traffic(32);
        assert_eq!((initiator.tx_packets(), initiator.tx_bytes()), (1, 48));
        assert_eq!((initiator.rx_packets(), initiator.rx_bytes()), (1, 32));
        assert!(responder.rtt().is_some());
        assert_eq!(actions.len(), 2);
    }

    #[test]
    fn test_encrypt_decrypt_after_handshake() {
        let mut rng_id = make_rng(0x01);
        let dest_sig_prv = Ed25519PrivateKey::generate(&mut rng_id);
        let dest_sig_pub_bytes = dest_sig_prv.public_key().public_bytes();
        let dest_hash = [0xDD; 16];

        let mut rng_init = make_rng(0x10);
        let (mut initiator, request_data) = LinkEngine::new_initiator(
            &dest_hash,
            1,
            LinkMode::Aes256Cbc,
            Some(500),
            100.0,
            &mut rng_init,
        );
        let mut hashable = Vec::new();
        hashable.push(0x00);
        hashable.push(0x00);
        hashable.extend_from_slice(&dest_hash);
        hashable.push(0x00);
        hashable.extend_from_slice(&request_data);
        initiator.set_link_id_from_hashable(&hashable, request_data.len());

        let mut rng_resp = make_rng(0x20);
        let (mut responder, lrproof_data) = LinkEngine::new_responder(
            &dest_sig_prv,
            &dest_sig_pub_bytes,
            &request_data,
            &hashable,
            &dest_hash,
            1,
            100.5,
            &mut rng_resp,
        )
        .unwrap();

        let mut rng_lrrtt = make_rng(0x30);
        let (lrrtt_encrypted, _) = initiator
            .handle_lrproof(&lrproof_data, &dest_sig_pub_bytes, 100.8, &mut rng_lrrtt)
            .unwrap();
        responder.handle_lrrtt(&lrrtt_encrypted, 101.0).unwrap();

        // Now both sides are ACTIVE — test encrypt/decrypt
        let mut rng_enc = make_rng(0x40);
        let plaintext = b"Hello over encrypted link!";
        let ciphertext = initiator.encrypt(plaintext, &mut rng_enc).unwrap();
        let decrypted = responder.decrypt(&ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);

        // And in reverse
        let mut rng_enc2 = make_rng(0x50);
        let ciphertext2 = responder.encrypt(b"Reply!", &mut rng_enc2).unwrap();
        let decrypted2 = initiator.decrypt(&ciphertext2).unwrap();
        assert_eq!(decrypted2, b"Reply!");
    }

    #[test]
    fn test_tick_establishment_timeout() {
        let mut rng = make_rng(0x10);
        let dest_hash = [0xDD; 16];
        let (mut engine, _) =
            LinkEngine::new_initiator(&dest_hash, 1, LinkMode::Aes256Cbc, None, 100.0, &mut rng);
        // Timeout = 6.0 + 6.0 * 1 = 12.0s → expires at 112.0

        // Before timeout — no state change
        let actions = engine.tick(110.0);
        assert!(actions.is_empty());

        // After timeout
        let actions = engine.tick(113.0);
        assert_eq!(actions.len(), 1);
        assert_eq!(engine.state(), LinkState::Closed);
    }

    #[test]
    fn test_tick_stale_and_close() {
        let mut rng_id = make_rng(0x01);
        let dest_sig_prv = Ed25519PrivateKey::generate(&mut rng_id);
        let dest_sig_pub_bytes = dest_sig_prv.public_key().public_bytes();
        let dest_hash = [0xDD; 16];

        let mut rng_init = make_rng(0x10);
        let (mut initiator, request_data) = LinkEngine::new_initiator(
            &dest_hash,
            1,
            LinkMode::Aes256Cbc,
            Some(500),
            100.0,
            &mut rng_init,
        );
        let mut hashable = Vec::new();
        hashable.push(0x00);
        hashable.push(0x00);
        hashable.extend_from_slice(&dest_hash);
        hashable.push(0x00);
        hashable.extend_from_slice(&request_data);
        initiator.set_link_id_from_hashable(&hashable, request_data.len());

        let mut rng_resp = make_rng(0x20);
        let (_, lrproof_data) = LinkEngine::new_responder(
            &dest_sig_prv,
            &dest_sig_pub_bytes,
            &request_data,
            &hashable,
            &dest_hash,
            1,
            100.5,
            &mut rng_resp,
        )
        .unwrap();

        let mut rng_lrrtt = make_rng(0x30);
        initiator
            .handle_lrproof(&lrproof_data, &dest_sig_pub_bytes, 100.8, &mut rng_lrrtt)
            .unwrap();
        assert_eq!(initiator.state(), LinkState::Active);

        // Advance time past stale_time
        let stale_time = initiator.stale_time;
        let went_stale = 100.8 + stale_time + 1.0;
        let actions = initiator.tick(went_stale);
        assert_eq!(initiator.state(), LinkState::Stale);
        assert_eq!(actions.len(), 1);

        // STALE holds for `rtt * KEEPALIVE_TIMEOUT_FACTOR + STALE_GRACE`
        // before closing, like the Python watchdog's stale sleep.
        let grace = stale_close_timeout(initiator.rtt().unwrap());
        assert!(grace >= LINK_STALE_GRACE);
        let actions = initiator.tick(went_stale + grace - 0.1);
        assert_eq!(initiator.state(), LinkState::Stale);
        assert!(actions.is_empty());

        let actions = initiator.tick(went_stale + grace);
        assert_eq!(initiator.state(), LinkState::Closed);
        assert_eq!(actions.len(), 1);
        assert!(matches!(
            actions[0],
            LinkAction::StateChanged {
                new_state: LinkState::Closed,
                reason: Some(TeardownReason::Timeout),
                ..
            }
        ));
    }

    #[test]
    fn inbound_during_stale_grace_reactivates_the_link() {
        let (mut initiator, _, _) = active_link_pair();
        let stale_time = initiator.stale_time;
        let went_stale = 101.0 + stale_time + 1.0;
        initiator.tick(went_stale);
        assert_eq!(initiator.state(), LinkState::Stale);

        let actions = initiator.record_inbound(went_stale + 1.0);
        assert_eq!(initiator.state(), LinkState::Active);
        assert_eq!(actions.len(), 1);

        // The recovered link only goes stale again after a full quiet period.
        let grace = stale_close_timeout(initiator.rtt().unwrap());
        assert!(initiator.tick(went_stale + grace + 1.0).is_empty());
        assert_eq!(initiator.state(), LinkState::Active);
        initiator.tick(went_stale + 1.0 + stale_time);
        assert_eq!(initiator.state(), LinkState::Stale);
    }

    #[test]
    fn received_proofs_keep_an_initiator_from_going_stale() {
        let (mut initiator, _, _) = active_link_pair();
        let stale_time = initiator.stale_time;
        // Only proofs come back for a long stream of confirmed sends.
        initiator.record_proof(101.0 + stale_time - 1.0);
        assert!(initiator.tick(101.0 + stale_time + 1.0).is_empty());
        assert_eq!(initiator.state(), LinkState::Active);

        // A stale link is not reactivated by a proof alone.
        initiator.tick(101.0 + 2.0 * stale_time);
        assert_eq!(initiator.state(), LinkState::Stale);
        initiator.record_proof(101.0 + 2.0 * stale_time + 1.0);
        assert_eq!(initiator.state(), LinkState::Stale);
    }

    #[test]
    fn test_needs_keepalive() {
        let mut rng_id = make_rng(0x01);
        let dest_sig_prv = Ed25519PrivateKey::generate(&mut rng_id);
        let dest_sig_pub_bytes = dest_sig_prv.public_key().public_bytes();
        let dest_hash = [0xDD; 16];

        let mut rng_init = make_rng(0x10);
        let (mut initiator, request_data) = LinkEngine::new_initiator(
            &dest_hash,
            1,
            LinkMode::Aes256Cbc,
            Some(500),
            100.0,
            &mut rng_init,
        );
        let mut hashable = Vec::new();
        hashable.push(0x00);
        hashable.push(0x00);
        hashable.extend_from_slice(&dest_hash);
        hashable.push(0x00);
        hashable.extend_from_slice(&request_data);
        initiator.set_link_id_from_hashable(&hashable, request_data.len());

        let mut rng_resp = make_rng(0x20);
        let (_, lrproof_data) = LinkEngine::new_responder(
            &dest_sig_prv,
            &dest_sig_pub_bytes,
            &request_data,
            &hashable,
            &dest_hash,
            1,
            100.5,
            &mut rng_resp,
        )
        .unwrap();

        let mut rng_lrrtt = make_rng(0x30);
        initiator
            .handle_lrproof(&lrproof_data, &dest_sig_pub_bytes, 100.8, &mut rng_lrrtt)
            .unwrap();

        let ka = initiator.keepalive_interval();
        // Not yet
        assert!(!initiator.needs_keepalive(100.8 + ka - 1.0));
        // Past keepalive
        assert!(initiator.needs_keepalive(100.8 + ka + 1.0));
    }

    #[test]
    fn initiator_probes_when_outbound_is_quiet_despite_recent_inbound() {
        let (mut initiator, _, _) = active_link_pair();
        let keepalive = initiator.keepalive_interval();
        let now = 1_000.0;

        initiator.record_inbound(now - 0.1);
        initiator.record_outbound(now - keepalive - 0.1, false);

        assert!(initiator.needs_keepalive(now));
    }

    #[test]
    fn initiator_probes_when_inbound_is_quiet_despite_recent_outbound() {
        let (mut initiator, _, _) = active_link_pair();
        let keepalive = initiator.keepalive_interval();
        let now = 1_000.0;

        initiator.record_inbound(now - keepalive - 0.1);
        initiator.record_outbound(now - 0.1, false);

        assert!(initiator.needs_keepalive(now));
    }

    #[test]
    fn initiator_does_not_probe_when_both_directions_are_recent() {
        let (mut initiator, _, _) = active_link_pair();
        let now = 1_000.0;

        initiator.record_inbound(now - 0.1);
        initiator.record_outbound(now - 0.1, false);

        assert!(!initiator.needs_keepalive(now));
    }

    #[test]
    fn test_needs_keepalive_responder() {
        let mut rng_id = make_rng(0x01);
        let dest_sig_prv = Ed25519PrivateKey::generate(&mut rng_id);
        let dest_sig_pub_bytes = dest_sig_prv.public_key().public_bytes();
        let dest_hash = [0xDD; 16];

        let mut rng_init = make_rng(0x10);
        let (mut initiator, request_data) = LinkEngine::new_initiator(
            &dest_hash,
            1,
            LinkMode::Aes256Cbc,
            Some(500),
            100.0,
            &mut rng_init,
        );
        let mut hashable = Vec::new();
        hashable.push(0x00);
        hashable.push(0x00);
        hashable.extend_from_slice(&dest_hash);
        hashable.push(0x00);
        hashable.extend_from_slice(&request_data);
        initiator.set_link_id_from_hashable(&hashable, request_data.len());

        let mut rng_resp = make_rng(0x20);
        let (mut responder, lrproof_data) = LinkEngine::new_responder(
            &dest_sig_prv,
            &dest_sig_pub_bytes,
            &request_data,
            &hashable,
            &dest_hash,
            1,
            100.5,
            &mut rng_resp,
        )
        .unwrap();

        let mut rng_lrrtt = make_rng(0x30);
        let (lrrtt_encrypted, _) = initiator
            .handle_lrproof(&lrproof_data, &dest_sig_pub_bytes, 100.8, &mut rng_lrrtt)
            .unwrap();
        responder.handle_lrrtt(&lrrtt_encrypted, 101.0).unwrap();

        let ka = responder.keepalive_interval();
        // Only the initiator emits probes. The responder replies to probes.
        assert!(!responder.needs_keepalive(101.0 + ka - 1.0));
        assert!(!responder.needs_keepalive(101.0 + ka + 1.0));
    }

    #[test]
    fn responder_replies_only_to_probe_and_only_when_outbound_is_quiet() {
        let (_, mut responder, _) = active_link_pair();
        let keepalive = responder.keepalive_interval();
        let now = 1_000.0;

        responder.record_outbound(now - keepalive - 0.1, false);
        assert!(responder.should_reply_keepalive(&[0xff], now));
        assert!(!responder.should_reply_keepalive(&[0xfe], now));
        assert!(!responder.should_reply_keepalive(&[], now));

        responder.record_outbound(now - 0.1, false);
        assert!(!responder.should_reply_keepalive(&[0xff], now));
    }

    #[test]
    fn initiator_never_replies_to_keepalive_probe() {
        let (mut initiator, _, _) = active_link_pair();
        let keepalive = initiator.keepalive_interval();
        let now = 1_000.0;
        initiator.record_outbound(now - keepalive - 0.1, false);

        assert!(!initiator.should_reply_keepalive(&[0xff], now));
    }

    #[test]
    fn packet_delivery_proofs_are_bidirectional_and_peer_authenticated() {
        let (initiator, responder, _) = active_link_pair();
        let packet_hash = [0x42; 32];

        let initiator_proof = initiator.sign_packet_hash(&packet_hash);
        assert!(responder.validate_packet_proof(&packet_hash, &initiator_proof));
        assert!(!initiator.validate_packet_proof(&packet_hash, &initiator_proof));

        let responder_proof = responder.sign_packet_hash(&packet_hash);
        assert!(initiator.validate_packet_proof(&packet_hash, &responder_proof));
        assert!(!responder.validate_packet_proof(&packet_hash, &responder_proof));
        assert!(!initiator.validate_packet_proof(&[0x43; 32], &responder_proof));
    }

    #[test]
    fn test_teardown() {
        let mut rng = make_rng(0x10);
        let (mut engine, _) =
            LinkEngine::new_initiator(&[0xDD; 16], 1, LinkMode::Aes256Cbc, None, 100.0, &mut rng);
        let actions = engine.teardown();
        assert_eq!(engine.state(), LinkState::Closed);
        assert_eq!(actions.len(), 1);

        // Teardown again is no-op
        let actions = engine.teardown();
        assert!(actions.is_empty());
    }

    #[test]
    fn test_handle_teardown() {
        let mut rng = make_rng(0x10);
        let (mut engine, _) =
            LinkEngine::new_initiator(&[0xDD; 16], 1, LinkMode::Aes256Cbc, None, 100.0, &mut rng);
        let actions = engine.handle_teardown();
        assert_eq!(engine.state(), LinkState::Closed);
        assert_eq!(actions.len(), 1);
        match &actions[0] {
            LinkAction::StateChanged { reason, .. } => {
                assert_eq!(*reason, Some(TeardownReason::DestinationClosed));
            }
            _ => panic!("Expected StateChanged"),
        }
    }

    #[test]
    fn test_identify_over_link() {
        let mut rng_id = make_rng(0x01);
        let dest_sig_prv = Ed25519PrivateKey::generate(&mut rng_id);
        let dest_sig_pub_bytes = dest_sig_prv.public_key().public_bytes();
        let dest_hash = [0xDD; 16];

        let mut rng_init = make_rng(0x10);
        let (mut initiator, request_data) = LinkEngine::new_initiator(
            &dest_hash,
            1,
            LinkMode::Aes256Cbc,
            Some(500),
            100.0,
            &mut rng_init,
        );
        let mut hashable = Vec::new();
        hashable.push(0x00);
        hashable.push(0x00);
        hashable.extend_from_slice(&dest_hash);
        hashable.push(0x00);
        hashable.extend_from_slice(&request_data);
        initiator.set_link_id_from_hashable(&hashable, request_data.len());

        let mut rng_resp = make_rng(0x20);
        let (mut responder, lrproof_data) = LinkEngine::new_responder(
            &dest_sig_prv,
            &dest_sig_pub_bytes,
            &request_data,
            &hashable,
            &dest_hash,
            1,
            100.5,
            &mut rng_resp,
        )
        .unwrap();

        let mut rng_lrrtt = make_rng(0x30);
        let (lrrtt_encrypted, _) = initiator
            .handle_lrproof(&lrproof_data, &dest_sig_pub_bytes, 100.8, &mut rng_lrrtt)
            .unwrap();
        responder.handle_lrrtt(&lrrtt_encrypted, 101.0).unwrap();

        // Create identity to identify with
        let mut rng_ident = make_rng(0x40);
        let my_identity = rns_crypto::identity::Identity::new(&mut rng_ident);

        // Initiator identifies itself to responder
        let mut rng_enc = make_rng(0x50);
        let identify_encrypted = initiator
            .build_identify(&my_identity, &mut rng_enc)
            .unwrap();

        let actions = responder.handle_identify(&identify_encrypted).unwrap();
        assert_eq!(actions.len(), 1);
        match &actions[0] {
            LinkAction::RemoteIdentified {
                identity_hash,
                public_key,
                ..
            } => {
                assert_eq!(identity_hash, my_identity.hash());
                assert_eq!(public_key, &my_identity.get_public_key().unwrap());
            }
            _ => panic!("Expected RemoteIdentified"),
        }

        // Valid repeated identifies are authenticated, but identification is
        // one-shot and cannot replace the first identity or emit callbacks.
        let mut rng_repeat = make_rng(0x51);
        let repeated = initiator
            .build_identify(&my_identity, &mut rng_repeat)
            .unwrap();
        assert!(responder.handle_identify(&repeated).unwrap().is_empty());

        let mut rng_other = make_rng(0x60);
        let other_identity = rns_crypto::identity::Identity::new(&mut rng_other);
        let mut rng_other_enc = make_rng(0x61);
        let other = initiator
            .build_identify(&other_identity, &mut rng_other_enc)
            .unwrap();
        assert!(responder.handle_identify(&other).unwrap().is_empty());
        assert_eq!(
            responder.remote_identity().map(|(hash, _)| hash),
            Some(my_identity.hash())
        );

        // Malformed repeats are still rejected cryptographically.
        let mut rng_bad = make_rng(0x70);
        let malformed = initiator
            .encrypt(b"invalid identify", &mut rng_bad)
            .unwrap();
        assert!(responder.handle_identify(&malformed).is_err());
        assert_eq!(
            responder.remote_identity().map(|(hash, _)| hash),
            Some(my_identity.hash())
        );
    }

    #[test]
    fn test_aes128_mode_handshake() {
        let mut rng_id = make_rng(0x01);
        let dest_sig_prv = Ed25519PrivateKey::generate(&mut rng_id);
        let dest_sig_pub_bytes = dest_sig_prv.public_key().public_bytes();
        let dest_hash = [0xDD; 16];

        let mut rng_init = make_rng(0x10);
        let (mut initiator, request_data) = LinkEngine::new_initiator(
            &dest_hash,
            1,
            LinkMode::Aes128Cbc,
            Some(500),
            100.0,
            &mut rng_init,
        );
        let mut hashable = Vec::new();
        hashable.push(0x00);
        hashable.push(0x00);
        hashable.extend_from_slice(&dest_hash);
        hashable.push(0x00);
        hashable.extend_from_slice(&request_data);
        initiator.set_link_id_from_hashable(&hashable, request_data.len());

        let mut rng_resp = make_rng(0x20);
        let (mut responder, lrproof_data) = LinkEngine::new_responder(
            &dest_sig_prv,
            &dest_sig_pub_bytes,
            &request_data,
            &hashable,
            &dest_hash,
            1,
            100.5,
            &mut rng_resp,
        )
        .unwrap();

        let mut rng_lrrtt = make_rng(0x30);
        let (lrrtt_encrypted, _) = initiator
            .handle_lrproof(&lrproof_data, &dest_sig_pub_bytes, 100.8, &mut rng_lrrtt)
            .unwrap();
        responder.handle_lrrtt(&lrrtt_encrypted, 101.0).unwrap();

        assert_eq!(initiator.state(), LinkState::Active);
        assert_eq!(responder.state(), LinkState::Active);
        assert_eq!(initiator.mode(), LinkMode::Aes128Cbc);

        // Verify encrypt/decrypt works
        let mut rng_enc = make_rng(0x40);
        let ct = initiator.encrypt(b"AES128 test", &mut rng_enc).unwrap();
        let pt = responder.decrypt(&ct).unwrap();
        assert_eq!(pt, b"AES128 test");
    }

    /// Run LINKREQUEST + LRPROOF with the given signalled MTU. Returns the
    /// active initiator and the responder still waiting for its LRRTT.
    fn handshake_pair_with_mtu(mtu: Option<u32>) -> (LinkEngine, LinkEngine) {
        let mut rng_id = make_rng(0x01);
        let dest_sig_prv = Ed25519PrivateKey::generate(&mut rng_id);
        let dest_sig_pub_bytes = dest_sig_prv.public_key().public_bytes();
        let dest_hash = [0xDD; 16];

        let mut rng_init = make_rng(0x10);
        let (mut initiator, request_data) = LinkEngine::new_initiator(
            &dest_hash,
            1,
            LinkMode::Aes256Cbc,
            mtu,
            100.0,
            &mut rng_init,
        );
        let mut hashable = vec![0x00, 0x00];
        hashable.extend_from_slice(&dest_hash);
        hashable.push(0x00);
        hashable.extend_from_slice(&request_data);
        initiator.set_link_id_from_hashable(&hashable, request_data.len());

        let mut rng_resp = make_rng(0x20);
        let (responder, lrproof_data) = LinkEngine::new_responder(
            &dest_sig_prv,
            &dest_sig_pub_bytes,
            &request_data,
            &hashable,
            &dest_hash,
            1,
            100.5,
            &mut rng_resp,
        )
        .unwrap();

        let mut rng_lrrtt = make_rng(0x30);
        initiator
            .handle_lrproof(&lrproof_data, &dest_sig_pub_bytes, 100.8, &mut rng_lrrtt)
            .unwrap();
        (initiator, responder)
    }

    fn raw_rtt_payload(rtt: f64) -> Vec<u8> {
        let mut data = vec![0xcb];
        data.extend_from_slice(&rtt.to_be_bytes());
        data
    }

    #[test]
    fn compute_mdu_keeps_values_for_regular_mtus() {
        assert_eq!(compute_mdu(500), 431);
        assert_eq!(compute_mdu(508), 431);
        assert_eq!(compute_mdu(1064), 991);
        assert_eq!(compute_mdu(8192), 8111);
        assert_eq!(compute_mdu(262_144), 262_063);
        assert_eq!(compute_mdu(LINK_MTU_MAX as usize), 2_097_071);
    }

    #[test]
    fn compute_mdu_saturates_for_small_mtus() {
        for mtu in [0usize, 1, 50, 67, 68, 83] {
            assert_eq!(compute_mdu(mtu), 0, "mtu {mtu}");
        }
        assert_eq!(compute_mdu(LINK_MTU_MIN as usize), 15);
    }

    #[test]
    fn effective_link_mtu_is_clamped_and_mdu_monotone() {
        assert_eq!(effective_link_mtu(None), MTU as u32);
        assert_eq!(effective_link_mtu(Some(0)), MTU as u32);
        assert_eq!(effective_link_mtu(Some(1)), LINK_MTU_MIN);
        assert_eq!(effective_link_mtu(Some(50)), LINK_MTU_MIN);
        assert_eq!(effective_link_mtu(Some(83)), LINK_MTU_MIN);
        assert_eq!(effective_link_mtu(Some(84)), 84);
        assert_eq!(effective_link_mtu(Some(500)), 500);
        assert_eq!(effective_link_mtu(Some(LINK_MTU_MAX)), LINK_MTU_MAX);
        assert_eq!(effective_link_mtu(Some(u32::MAX)), LINK_MTU_MAX);

        let mut prev = 0usize;
        for mtu in [1u32, 50, 83, 84, 500, LINK_MTU_MAX] {
            let mdu = compute_mdu(effective_link_mtu(Some(mtu)) as usize);
            assert!(mdu >= 15, "mtu {mtu} gave mdu {mdu}");
            assert!(mdu >= prev, "mdu not monotone at mtu {mtu}");
            prev = mdu;
        }
    }

    #[test]
    fn small_signalled_mtu_is_raised_to_minimum_on_both_sides() {
        let (initiator, mut responder) = handshake_pair_with_mtu(Some(70));
        assert_eq!(responder.mtu(), LINK_MTU_MIN);
        assert_eq!(responder.mdu(), 15);
        assert_eq!(initiator.mtu(), LINK_MTU_MIN);
        assert_eq!(initiator.mdu(), 15);
        assert_eq!(initiator.state(), LinkState::Active);

        let mut rng = make_rng(0x40);
        let lrrtt = initiator.encrypt(&pack_rtt(0.3), &mut rng).unwrap();
        responder.handle_lrrtt(&lrrtt, 101.0).unwrap();
        assert_eq!(responder.state(), LinkState::Active);

        let ct = initiator.encrypt(b"hello", &mut rng).unwrap();
        assert_eq!(responder.decrypt(&ct).unwrap(), b"hello");
    }

    #[test]
    fn signalled_mtu_edge_values_do_not_panic() {
        for mtu in [0u32, 1, 50, 83, 84, 500, LINK_MTU_MAX] {
            let (initiator, responder) = handshake_pair_with_mtu(Some(mtu));
            assert!(responder.mtu() >= LINK_MTU_MIN);
            assert!(responder.mdu() >= 15);
            assert_eq!(initiator.mtu(), responder.mtu());
            assert_eq!(initiator.mdu(), responder.mdu());
        }
    }

    #[test]
    fn non_finite_or_negative_lrrtt_is_rejected() {
        for bad in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY, -1.0] {
            let (initiator, mut responder) = handshake_pair_with_mtu(Some(500));
            let mut rng = make_rng(0x40);
            let lrrtt = initiator.encrypt(&raw_rtt_payload(bad), &mut rng).unwrap();
            assert!(
                matches!(
                    responder.handle_lrrtt(&lrrtt, 101.0),
                    Err(LinkError::InvalidData)
                ),
                "rtt {bad}"
            );
            assert_eq!(responder.state(), LinkState::Handshake);
            assert_eq!(responder.rtt(), None);
            assert!(responder.keepalive_interval.is_finite());
            assert!(responder.stale_time.is_finite());

            // The peer goes silent: the pending link still times out.
            let deadline = responder.request_time + responder.establishment_timeout;
            let actions = responder.tick(deadline + 1.0);
            assert_eq!(responder.state(), LinkState::Closed);
            assert_eq!(actions.len(), 1);
        }
    }

    #[test]
    fn valid_lrrtt_updates_rtt_and_timers() {
        let (initiator, mut responder) = handshake_pair_with_mtu(Some(500));
        let mut rng = make_rng(0x40);
        // Larger than the responder's own measurement (0.5s), so it is selected.
        let lrrtt = initiator.encrypt(&pack_rtt(0.9), &mut rng).unwrap();
        responder.handle_lrrtt(&lrrtt, 101.0).unwrap();
        assert_eq!(responder.state(), LinkState::Active);
        assert_eq!(responder.rtt(), Some(0.9));
        assert_eq!(responder.keepalive_interval, compute_keepalive(0.9));
        assert_eq!(
            responder.stale_time,
            compute_stale_time(compute_keepalive(0.9))
        );
    }

    #[test]
    fn non_finite_rtt_keeps_timers_finite_and_link_goes_stale() {
        let (_, mut responder, _) = active_link_pair();
        for bad in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY] {
            responder.set_rtt(bad);
            assert!(responder.keepalive_interval.is_finite(), "rtt {bad}");
            assert!(responder.stale_time.is_finite(), "rtt {bad}");
            assert!(responder.stale_time <= LINK_KEEPALIVE_MAX * 2.0);
        }

        let stale_time = responder.stale_time;
        responder.tick(101.0 + stale_time + 1.0);
        assert_eq!(responder.state(), LinkState::Stale);
    }

    #[test]
    fn stamped_link_request_carries_required_value() {
        let mut rng = rns_crypto::OsRng;
        let dest_hash = [0xAB; 16];
        let (_engine, data) = LinkEngine::new_initiator_stamped(
            &dest_hash,
            1,
            LinkMode::Aes256Cbc,
            None,
            0.0,
            &mut rng,
            4,
        );
        let value = handshake::link_request_stamp_value(&dest_hash, &data).unwrap();
        assert!(value.meets(4));
    }

    #[test]
    fn initiator_with_keys_uses_the_supplied_keys() {
        let mut rng = rns_crypto::OsRng;
        let dest_hash = [0xAC; 16];
        let prv = X25519PrivateKey::generate(&mut rng);
        let sig_prv = Ed25519PrivateKey::generate(&mut rng);
        let expected_pub = prv.public_key().public_bytes();
        let expected_sig_pub = sig_prv.public_key().public_bytes();

        let (engine, data) = LinkEngine::new_initiator_with_keys(
            &dest_hash,
            1,
            LinkMode::Aes256Cbc,
            None,
            0.0,
            prv,
            sig_prv,
        );
        let (peer_pub, peer_sig_pub, mtu, mode) = handshake::parse_linkrequest_data(&data).unwrap();
        assert_eq!(peer_pub, expected_pub);
        assert_eq!(peer_sig_pub, expected_sig_pub);
        assert_eq!(mtu, None);
        assert_eq!(mode, LinkMode::Aes256Cbc);
        assert!(engine.is_initiator());
        assert_eq!(engine.state(), LinkState::Pending);
    }
}
