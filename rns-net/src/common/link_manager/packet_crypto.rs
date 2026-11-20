//! Packet encryption, decryption and proofs, through the proof pool.

use super::*;

impl LinkManager {
    /// The pool to verify a link proof on, started on first use when
    /// threads are configured and the driver can be woken.
    pub(super) fn proof_pool(&mut self) -> Option<&proof_pool::ProofPool> {
        if !self.proof_pool_settled {
            self.proof_pool_settled = true;
            let threads = self.proof_verify_threads.count();
            if let (true, Some(wake)) = (threads > 0, self.receive_worker_wake.clone()) {
                match proof_pool::ProofPool::start(threads, wake) {
                    Ok(pool) => self.proof_pool = Some(pool),
                    Err(error) => log::warn!("link proofs verified inline: {error}"),
                }
            }
        }
        self.proof_pool.as_ref()
    }

    /// Queue the check of a single packet's proof on the proof pool. False
    /// without a pool or when it is full, for the caller to check it inline.
    pub(crate) fn submit_packet_proof_check(
        &mut self,
        destination: [u8; 16],
        packet_hash: [u8; 32],
        signature: [u8; 64],
        key: Ed25519PublicKey,
        rtt: f64,
        proof_packet: [u8; 32],
    ) -> bool {
        self.proof_pool().is_some_and(|pool| {
            pool.submit_verify(
                proof_pool::Owner::Packet {
                    destination,
                    rtt,
                    interface: None,
                    proof_packet: Some(proof_packet),
                },
                packet_hash,
                signature,
                key,
            )
        })
    }

    /// Queue the signature of a single packet's proof on the proof pool;
    /// the proof goes back on `interface`, where the packet arrived. False
    /// without a pool or when it is full, for the caller to sign it inline.
    pub(crate) fn submit_packet_proof_sign(
        &mut self,
        destination: [u8; 16],
        packet_hash: [u8; 32],
        interface: Option<rns_core::transport::types::InterfaceId>,
        key: Ed25519PrivateKey,
    ) -> bool {
        self.proof_pool().is_some_and(|pool| {
            pool.submit_sign(
                proof_pool::Owner::Packet {
                    destination,
                    rtt: 0.0,
                    interface,
                    proof_packet: None,
                },
                packet_hash,
                key,
            )
        })
    }

    /// Queue a deferred send's encryption on the proof pool, or hand it back
    /// without a pool or when it is full, for the caller to encrypt inline.
    pub(crate) fn submit_packet_encrypt(
        &mut self,
        encryption: Box<proof_pool::Encryption>,
    ) -> Result<(), Box<proof_pool::Encryption>> {
        match self.proof_pool() {
            Some(pool) => pool.submit_encrypt(encryption),
            None => Err(encryption),
        }
    }

    /// Queue a delivered packet's decryption on the proof pool, or hand it
    /// back without a pool or when it is full, to decrypt inline.
    pub(crate) fn submit_packet_decrypt(
        &mut self,
        decryption: Box<proof_pool::Decryption>,
    ) -> Result<(), Box<proof_pool::Decryption>> {
        match self.proof_pool() {
            Some(pool) => pool.submit_decrypt(decryption),
            None => Err(decryption),
        }
    }

    /// Single-packet proofs the pool finished since the last call, taken by
    /// the driver after [`poll_proof_pool`](Self::poll_proof_pool).
    pub(crate) fn take_packet_proofs(&mut self, out: &mut Vec<proof_pool::Outcome>) {
        out.append(&mut self.packet_proof_outcomes);
    }

    /// Apply what the proof pool has ready: verified proofs, and signed ones
    /// to send; single packets' outcomes wait for
    /// [`take_packet_proofs`](Self::take_packet_proofs). `None` without a pool.
    pub(crate) fn poll_proof_pool(&mut self, rng: &mut dyn Rng) -> Option<Vec<LinkManagerAction>> {
        let pool = self.proof_pool.as_ref()?;
        let mut outcomes = core::mem::take(&mut self.proof_outcomes);
        pool.drain(&mut outcomes);
        let mut actions = Vec::new();
        for outcome in outcomes.drain(..) {
            match outcome {
                proof_pool::Outcome::Verified {
                    owner: proof_pool::Owner::Packet { .. },
                    ..
                }
                | proof_pool::Outcome::Signed {
                    owner: proof_pool::Owner::Packet { .. },
                    ..
                }
                | proof_pool::Outcome::Encrypted { .. }
                | proof_pool::Outcome::Decrypted { .. } => self.packet_proof_outcomes.push(outcome),
                proof_pool::Outcome::Verified {
                    owner: proof_pool::Owner::Link(link_id),
                    packet_hash,
                    valid: true,
                } => actions.extend(self.link_proof_verified(&link_id, &packet_hash, rng)),
                proof_pool::Outcome::Verified { .. } => {}
                proof_pool::Outcome::Signed {
                    owner: proof_pool::Owner::Link(link_id),
                    packet_hash,
                    signature,
                } => {
                    if self.links.contains_key(&link_id) {
                        actions.extend(Self::link_proof_packet(&link_id, &packet_hash, &signature));
                    }
                }
            }
        }
        self.proof_outcomes = outcomes;
        Some(actions)
    }

    /// Prove a packet received on `link_id`: the proof packet to send, signed
    /// with the link's key, or nothing when the link is gone.
    pub fn prove_link_packet(
        &mut self,
        link_id: &LinkId,
        packet_hash: &[u8; 32],
    ) -> Vec<LinkManagerAction> {
        self.build_link_packet_proof(link_id, packet_hash)
    }

    pub(super) fn build_link_packet_proof(
        &mut self,
        link_id: &LinkId,
        packet_hash: &[u8; 32],
    ) -> Vec<LinkManagerAction> {
        let Some(key) = self.links.get_mut(link_id).map(|link| {
            link.packet_proofs_sent += 1;
            link.engine.signing_key().clone()
        }) else {
            return Vec::new();
        };
        // Signed on the pool when there is one: the proof goes out once the
        // driver takes the signature back.
        if let Some(pool) = self.proof_pool() {
            if pool.submit_sign(proof_pool::Owner::Link(*link_id), *packet_hash, key.clone()) {
                return Vec::new();
            }
        }
        Self::link_proof_packet(link_id, packet_hash, &key.sign(packet_hash))
    }
}
