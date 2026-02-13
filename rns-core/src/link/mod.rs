pub mod types;
pub mod handshake;
pub mod crypto;
pub mod keepalive;
pub mod identify;

use alloc::vec::Vec;

use rns_crypto::ed25519::{Ed25519PrivateKey, Ed25519PublicKey};
use rns_crypto::token::Token;
use rns_crypto::x25519::X25519PrivateKey;
use rns_crypto::Rng;

use crate::constants::{
    LINK_ECPUBSIZE, LINK_KEEPALIVE_MAX, MTU,
    LINK_ESTABLISHMENT_TIMEOUT_PER_HOP,
};

pub use types::{LinkAction, LinkError, LinkId, LinkMode, LinkState, TeardownReason};

use handshake::{
    build_linkrequest_data, compute_link_id, pack_rtt, parse_linkrequest_data,
    perform_key_exchange, unpack_rtt, validate_lrproof,
};
use crypto::{create_session_token, link_decrypt, link_encrypt};
use keepalive::{
    compute_establishment_timeout, compute_keepalive, compute_stale_time,
    is_establishment_timeout, should_go_stale, should_send_keepalive,
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
    pub_bytes: [u8; 32],
    sig_prv: Ed25519PrivateKey,
    sig_pub_bytes: [u8; 32],

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
    establishment_timeout: f64,

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
        let pub_bytes = prv.public_key().public_bytes();
        let sig_prv = Ed25519PrivateKey::generate(rng);
        let sig_pub_bytes = sig_prv.public_key().public_bytes();

        let request_data = build_linkrequest_data(&pub_bytes, &sig_pub_bytes, mtu, mode);

        let link_mtu = mtu.unwrap_or(MTU as u32);

        let engine = LinkEngine {
            link_id: [0u8; 16], // will be set after packet is built
            state: LinkState::Pending,
            is_initiator: true,
            mode,
            prv,
            pub_bytes,
            sig_prv,
            sig_pub_bytes,
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
            establishment_timeout: compute_establishment_timeout(
                LINK_ESTABLISHMENT_TIMEOUT_PER_HOP,
                hops,
            ),
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
        let extra = if data_len > LINK_ECPUBSIZE {
            data_len - LINK_ECPUBSIZE
        } else {
            0
        };
        self.link_id = compute_link_id(hashable_part, extra);
    }

    /// Create a new responder-side link engine from an incoming LINKREQUEST.
    ///
    /// `owner_sig_prv` / `owner_sig_pub` are the destination's signing keys.
    /// Returns `(engine, actions)` where actions include the LRPROOF data to send.
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

        let extra = if linkrequest_data.len() > LINK_ECPUBSIZE {
            linkrequest_data.len() - LINK_ECPUBSIZE
        } else {
            0
        };
        let link_id = compute_link_id(hashable_part, extra);

        // Generate ephemeral keys for this end
        let prv = X25519PrivateKey::generate(rng);
        let pub_bytes = prv.public_key().public_bytes();
        let sig_prv_clone = Ed25519PrivateKey::from_bytes(&owner_sig_prv.private_bytes());
        let sig_pub_bytes = *owner_sig_pub_bytes;

        // Perform ECDH + HKDF
        let derived_key = perform_key_exchange(&prv, &peer_pub, &link_id, mode)?;
        let token = create_session_token(&derived_key)?;

        let link_mtu = peer_mtu.unwrap_or(MTU as u32);

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
            pub_bytes,
            sig_prv: sig_prv_clone,
            sig_pub_bytes,
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
            establishment_timeout: compute_establishment_timeout(
                LINK_ESTABLISHMENT_TIMEOUT_PER_HOP,
                hops,
            ),
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
        if self.state != LinkState::Pending || !self.is_initiator {
            return Err(LinkError::InvalidState);
        }

        let peer_sig_pub = Ed25519PublicKey::from_bytes(peer_sig_pub_bytes);

        let (peer_pub, confirmed_mtu, confirmed_mode) =
            validate_lrproof(proof_data, &self.link_id, &peer_sig_pub, peer_sig_pub_bytes)?;

        if confirmed_mode != self.mode {
            return Err(LinkError::UnsupportedMode);
        }

        self.peer_pub_bytes = Some(peer_pub);
        self.peer_sig_pub_bytes = Some(*peer_sig_pub_bytes);

        // ECDH + HKDF
        let derived_key = perform_key_exchange(&self.prv, &peer_pub, &self.link_id, self.mode)?;
        let token = create_session_token(&derived_key)?;

        self.derived_key = Some(derived_key);
        self.token = Some(token);

        // Update MTU if confirmed
        if let Some(mtu) = confirmed_mtu {
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

        let mut actions = Vec::new();
        actions.push(LinkAction::StateChanged {
            link_id: self.link_id,
            new_state: LinkState::Active,
            reason: None,
        });
        actions.push(LinkAction::LinkEstablished {
            link_id: self.link_id,
            rtt,
            is_initiator: true,
        });

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
        if self.state != LinkState::Handshake || self.is_initiator {
            return Err(LinkError::InvalidState);
        }

        let plaintext = self.decrypt(encrypted_data)?;
        let initiator_rtt = unpack_rtt(&plaintext).ok_or(LinkError::InvalidData)?;

        let measured_rtt = now - self.request_time;
        let rtt = if measured_rtt > initiator_rtt { measured_rtt } else { initiator_rtt };

        self.rtt = Some(rtt);
        self.state = LinkState::Active;
        self.activated_at = Some(now);
        self.last_inbound = now;
        self.update_keepalive();

        let mut actions = Vec::new();
        actions.push(LinkAction::StateChanged {
            link_id: self.link_id,
            new_state: LinkState::Active,
            reason: None,
        });
        actions.push(LinkAction::LinkEstablished {
            link_id: self.link_id,
            rtt,
            is_initiator: false,
        });

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
        let (identity_hash, public_key) = identify::validate_identify_data(&plaintext, &self.link_id)?;
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
            return alloc::vec![LinkAction::StateChanged {
                link_id: self.link_id,
                new_state: LinkState::Active,
                reason: None,
            }];
        }
        Vec::new()
    }

    /// Record that a proof was received (updates timing for stale detection).
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
                    actions.push(LinkAction::StateChanged {
                        link_id: self.link_id,
                        new_state: LinkState::Stale,
                        reason: None,
                    });
                }
            }
            LinkState::Stale => {
                // In Python, STALE immediately sends teardown and closes
                self.state = LinkState::Closed;
                actions.push(LinkAction::StateChanged {
                    link_id: self.link_id,
                    new_state: LinkState::Closed,
                    reason: Some(TeardownReason::Timeout),
                });
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

        // Only send keepalive when past keepalive interval from last inbound
        if now < last_inbound + self.keepalive_interval {
            return false;
        }

        should_send_keepalive(self.last_keepalive, self.keepalive_interval, now)
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

    /// Get the derived session key (needed for hole-punch token derivation).
    pub fn derived_key(&self) -> Option<&[u8]> {
        self.derived_key.as_deref()
    }

    pub fn keepalive_interval(&self) -> f64 {
        self.keepalive_interval
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
fn compute_mdu(mtu: usize) -> usize {
    use crate::constants::{AES128_BLOCKSIZE, HEADER_MINSIZE, IFAC_MIN_SIZE, TOKEN_OVERHEAD};
    let numerator = mtu.saturating_sub(IFAC_MIN_SIZE + HEADER_MINSIZE + TOKEN_OVERHEAD);
    (numerator / AES128_BLOCKSIZE) * AES128_BLOCKSIZE - 1
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::LINK_MDU;
    use rns_crypto::FixedRng;

    fn make_rng(seed: u8) -> FixedRng {
        FixedRng::new(&[seed; 128])
    }

    #[test]
    fn test_compute_mdu_default() {
        assert_eq!(compute_mdu(500), LINK_MDU);
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
        let (mut initiator, request_data) = LinkEngine::new_initiator(
            &dest_hash, 1, mode, Some(500), 100.0, &mut rng_init,
        );
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
        ).unwrap();
        assert_eq!(responder.state(), LinkState::Handshake);
        assert_eq!(responder.link_id(), initiator.link_id());

        // Step 3: Initiator validates LRPROOF
        let mut rng_lrrtt = make_rng(0x30);
        let (lrrtt_encrypted, actions) = initiator.handle_lrproof(
            &lrproof_data,
            &dest_sig_pub_bytes,
            100.8,
            &mut rng_lrrtt,
        ).unwrap();
        assert_eq!(initiator.state(), LinkState::Active);
        assert!(initiator.rtt().is_some());
        assert_eq!(actions.len(), 2); // StateChanged + LinkEstablished

        // Step 4: Responder handles LRRTT
        let actions = responder.handle_lrrtt(&lrrtt_encrypted, 101.0).unwrap();
        assert_eq!(responder.state(), LinkState::Active);
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
            &dest_hash, 1, LinkMode::Aes256Cbc, Some(500), 100.0, &mut rng_init,
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
            &dest_sig_prv, &dest_sig_pub_bytes, &request_data, &hashable,
            &dest_hash, 1, 100.5, &mut rng_resp,
        ).unwrap();

        let mut rng_lrrtt = make_rng(0x30);
        let (lrrtt_encrypted, _) = initiator.handle_lrproof(
            &lrproof_data, &dest_sig_pub_bytes, 100.8, &mut rng_lrrtt,
        ).unwrap();
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
        let (mut engine, _) = LinkEngine::new_initiator(
            &dest_hash, 1, LinkMode::Aes256Cbc, None, 100.0, &mut rng,
        );
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
            &dest_hash, 1, LinkMode::Aes256Cbc, Some(500), 100.0, &mut rng_init,
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
            &dest_sig_prv, &dest_sig_pub_bytes, &request_data, &hashable,
            &dest_hash, 1, 100.5, &mut rng_resp,
        ).unwrap();

        let mut rng_lrrtt = make_rng(0x30);
        initiator.handle_lrproof(&lrproof_data, &dest_sig_pub_bytes, 100.8, &mut rng_lrrtt).unwrap();
        assert_eq!(initiator.state(), LinkState::Active);

        // Advance time past stale_time
        let stale_time = initiator.stale_time;
        let actions = initiator.tick(100.8 + stale_time + 1.0);
        assert_eq!(initiator.state(), LinkState::Stale);
        assert_eq!(actions.len(), 1);

        // Next tick: STALE → CLOSED
        let actions = initiator.tick(100.8 + stale_time + 2.0);
        assert_eq!(initiator.state(), LinkState::Closed);
        assert_eq!(actions.len(), 1);
    }

    #[test]
    fn test_needs_keepalive() {
        let mut rng_id = make_rng(0x01);
        let dest_sig_prv = Ed25519PrivateKey::generate(&mut rng_id);
        let dest_sig_pub_bytes = dest_sig_prv.public_key().public_bytes();
        let dest_hash = [0xDD; 16];

        let mut rng_init = make_rng(0x10);
        let (mut initiator, request_data) = LinkEngine::new_initiator(
            &dest_hash, 1, LinkMode::Aes256Cbc, Some(500), 100.0, &mut rng_init,
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
            &dest_sig_prv, &dest_sig_pub_bytes, &request_data, &hashable,
            &dest_hash, 1, 100.5, &mut rng_resp,
        ).unwrap();

        let mut rng_lrrtt = make_rng(0x30);
        initiator.handle_lrproof(&lrproof_data, &dest_sig_pub_bytes, 100.8, &mut rng_lrrtt).unwrap();

        let ka = initiator.keepalive_interval();
        // Not yet
        assert!(!initiator.needs_keepalive(100.8 + ka - 1.0));
        // Past keepalive
        assert!(initiator.needs_keepalive(100.8 + ka + 1.0));
    }

    #[test]
    fn test_teardown() {
        let mut rng = make_rng(0x10);
        let (mut engine, _) = LinkEngine::new_initiator(
            &[0xDD; 16], 1, LinkMode::Aes256Cbc, None, 100.0, &mut rng,
        );
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
        let (mut engine, _) = LinkEngine::new_initiator(
            &[0xDD; 16], 1, LinkMode::Aes256Cbc, None, 100.0, &mut rng,
        );
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
            &dest_hash, 1, LinkMode::Aes256Cbc, Some(500), 100.0, &mut rng_init,
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
            &dest_sig_prv, &dest_sig_pub_bytes, &request_data, &hashable,
            &dest_hash, 1, 100.5, &mut rng_resp,
        ).unwrap();

        let mut rng_lrrtt = make_rng(0x30);
        let (lrrtt_encrypted, _) = initiator.handle_lrproof(
            &lrproof_data, &dest_sig_pub_bytes, 100.8, &mut rng_lrrtt,
        ).unwrap();
        responder.handle_lrrtt(&lrrtt_encrypted, 101.0).unwrap();

        // Create identity to identify with
        let mut rng_ident = make_rng(0x40);
        let my_identity = rns_crypto::identity::Identity::new(&mut rng_ident);

        // Initiator identifies itself to responder
        let mut rng_enc = make_rng(0x50);
        let identify_encrypted = initiator.build_identify(&my_identity, &mut rng_enc).unwrap();

        let actions = responder.handle_identify(&identify_encrypted).unwrap();
        assert_eq!(actions.len(), 1);
        match &actions[0] {
            LinkAction::RemoteIdentified { identity_hash, public_key, .. } => {
                assert_eq!(identity_hash, my_identity.hash());
                assert_eq!(public_key, &my_identity.get_public_key().unwrap());
            }
            _ => panic!("Expected RemoteIdentified"),
        }
    }

    #[test]
    fn test_aes128_mode_handshake() {
        let mut rng_id = make_rng(0x01);
        let dest_sig_prv = Ed25519PrivateKey::generate(&mut rng_id);
        let dest_sig_pub_bytes = dest_sig_prv.public_key().public_bytes();
        let dest_hash = [0xDD; 16];

        let mut rng_init = make_rng(0x10);
        let (mut initiator, request_data) = LinkEngine::new_initiator(
            &dest_hash, 1, LinkMode::Aes128Cbc, Some(500), 100.0, &mut rng_init,
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
            &dest_sig_prv, &dest_sig_pub_bytes, &request_data, &hashable,
            &dest_hash, 1, 100.5, &mut rng_resp,
        ).unwrap();

        let mut rng_lrrtt = make_rng(0x30);
        let (lrrtt_encrypted, _) = initiator.handle_lrproof(
            &lrproof_data, &dest_sig_pub_bytes, 100.8, &mut rng_lrrtt,
        ).unwrap();
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
}
