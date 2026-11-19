//! Registering destinations, link destinations and request handlers.

use super::*;

impl RnsNode {
    /// Register a local destination with the transport engine.
    pub fn register_destination(
        &self,
        dest_hash: [u8; 16],
        dest_type: u8,
    ) -> Result<(), SendError> {
        self.tx
            .send(Event::RegisterDestination {
                dest_hash,
                dest_type,
            })
            .map_err(|_| SendError)
    }

    /// Deregister a local destination.
    pub fn deregister_destination(&self, dest_hash: [u8; 16]) -> Result<(), SendError> {
        self.tx
            .send(Event::DeregisterDestination { dest_hash })
            .map_err(|_| SendError)
    }

    /// Deregister a link destination (stop accepting incoming links).
    pub fn deregister_link_destination(&self, dest_hash: [u8; 16]) -> Result<(), SendError> {
        self.tx
            .send(Event::DeregisterLinkDestination { dest_hash })
            .map_err(|_| SendError)
    }

    /// Register a link destination that can accept incoming links.
    ///
    /// `dest_hash`: the destination hash
    /// `sig_prv_bytes`: Ed25519 private signing key (32 bytes)
    /// `sig_pub_bytes`: Ed25519 public signing key (32 bytes)
    pub fn register_link_destination(
        &self,
        dest_hash: [u8; 16],
        sig_prv_bytes: [u8; 32],
        sig_pub_bytes: [u8; 32],
        resource_strategy: u8,
    ) -> Result<(), SendError> {
        self.register_link_destination_with_max_request_size(
            dest_hash,
            sig_prv_bytes,
            sig_pub_bytes,
            resource_strategy,
            None,
        )
    }

    /// Register a link destination with an optional maximum accepted request size.
    pub fn register_link_destination_with_max_request_size(
        &self,
        dest_hash: [u8; 16],
        sig_prv_bytes: [u8; 32],
        sig_pub_bytes: [u8; 32],
        resource_strategy: u8,
        max_request_size: Option<usize>,
    ) -> Result<(), SendError> {
        self.tx
            .send(Event::RegisterLinkDestination {
                dest_hash,
                sig_prv_bytes,
                sig_pub_bytes,
                resource_strategy,
                max_request_size,
            })
            .map_err(|_| SendError)
    }

    /// Set the required link establishment stamp cost for a destination.
    ///
    /// Mirrors `Destination.set_link_cost`: the cost is clamped to
    /// `0..=LINK_COST_CAP` and the clamped value is returned. Set it to 0 to
    /// disable. The cost is carried in the destination's announce extension
    /// (emitted when destination stamping is on) so initiators grind their
    /// link request stamps to it, and, when link request stamps are enforced,
    /// incoming link requests whose stamp value is below it are dropped.
    pub fn set_link_cost(&self, dest_hash: [u8; 16], cost: f64) -> f64 {
        self.tx.link_request_costs().set(dest_hash, cost).as_f64()
    }

    /// The link request stamp cost announced and required for a destination.
    ///
    /// Mirrors `Destination.get_link_cost`: the configured cost, or the
    /// default `LINK_REQUEST_STAMP_COST` (`Transport.LR_COST`) when none was
    /// set. Costs are fractional since upstream 796ef2d4 and held on the
    /// 1/256 grid they are announced and checked on, so 14.2 reads back as
    /// 14.19921875.
    pub fn link_cost(&self, dest_hash: &[u8; 16]) -> f64 {
        self.tx.link_request_costs().get(dest_hash).as_f64()
    }

    /// Override `Transport.LR_STAMPS_ENFORCED` for this node.
    ///
    /// When enabled, incoming link requests whose stamp value is below the
    /// destination's [`link_cost`](Self::link_cost) are dropped. Defaults to
    /// `rns_core::constants::LR_STAMPS_ENFORCED` (off, as upstream).
    pub fn set_link_request_stamps_enforced(&self, enforced: bool) {
        self.tx.link_request_costs().set_enforced(enforced);
    }

    /// Whether incoming link request stamps are enforced.
    pub fn link_request_stamps_enforced(&self) -> bool {
        self.tx.link_request_costs().enforced()
    }

    /// Register a request handler for a given path on established links.
    pub fn register_request_handler<F>(
        &self,
        path: &str,
        allowed_list: Option<Vec<[u8; 16]>>,
        handler: F,
    ) -> Result<(), SendError>
    where
        F: Fn([u8; 16], &str, &[u8], Option<&([u8; 16], [u8; 64])>) -> Option<Vec<u8>>
            + Send
            + 'static,
    {
        self.tx
            .send(Event::RegisterRequestHandler {
                path: path.to_string(),
                allowed_list,
                handler: Box::new(handler),
            })
            .map_err(|_| SendError)
    }

    /// Register a request handler that can return resource responses with metadata.
    pub fn register_request_handler_response<F>(
        &self,
        path: &str,
        allowed_list: Option<Vec<[u8; 16]>>,
        handler: F,
    ) -> Result<(), SendError>
    where
        F: Fn(
                [u8; 16],
                &str,
                &[u8],
                Option<&([u8; 16], [u8; 64])>,
            ) -> Option<crate::link_manager::RequestResponse>
            + Send
            + 'static,
    {
        self.tx
            .send(Event::RegisterRequestHandlerResponse {
                path: path.to_string(),
                allowed_list,
                handler: Box::new(handler),
            })
            .map_err(|_| SendError)
    }

    /// Register a request handler whose response is completed asynchronously
    /// with [`RnsNode::send_deferred_response`].
    pub fn register_deferred_request_handler<F>(
        &self,
        path: &str,
        allowed_list: Option<Vec<[u8; 16]>>,
        handler: F,
    ) -> Result<(), SendError>
    where
        F: Fn([u8; 16], &str, [u8; 16], &[u8], Option<&([u8; 16], [u8; 64])>) + Send + 'static,
    {
        self.tx
            .send(Event::RegisterDeferredRequestHandler {
                path: path.to_string(),
                allowed_list,
                handler: Box::new(handler),
            })
            .map_err(|_| SendError)
    }

    /// Complete a request accepted by a deferred request handler.
    pub fn send_deferred_response(
        &self,
        link_id: [u8; 16],
        request_id: [u8; 16],
        data: Vec<u8>,
    ) -> Result<(), SendError> {
        self.tx
            .send(Event::SendDeferredResponse {
                link_id,
                request_id,
                data,
            })
            .map_err(|_| SendError)
    }

    /// Attach the same private ratchet owner used by the application's receiver.
    /// Reattaching that Arc is idempotent; conflicting owners are rejected. The
    /// owner remains attached across destination deregistration/re-registration.
    pub fn attach_local_ratchets(&self, owner: Arc<crate::LocalRatchets>) -> io::Result<()> {
        let mut owners = crate::sync::lock_or_recover(self.tx.local_ratchets(), "local ratchets");
        if let Some(existing) = owners.get(&owner.destination_hash()) {
            if !Arc::ptr_eq(existing, &owner) {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "destination already has a ratchet owner",
                ));
            }
        }
        owners.insert(owner.destination_hash(), owner);
        Ok(())
    }

    /// Register a destination with the transport engine and set its proof strategy.
    ///
    /// `signing_key` is the full 64-byte identity private key (X25519 32 bytes +
    /// Ed25519 32 bytes), needed for ProveAll/ProveApp to sign proof packets.
    pub fn register_destination_with_proof(
        &self,
        dest: &crate::destination::Destination,
        signing_key: Option<[u8; 64]>,
    ) -> Result<(), SendError> {
        // Register with transport engine
        self.register_destination(dest.hash.0, dest.dest_type.to_wire_constant())?;

        // With its identity, a SINGLE IN destination can answer path
        // requests before it announces, as upstream's destinations do.
        if let (Some(identity_prv_key), rns_core::types::DestinationType::Single, true) = (
            signing_key,
            dest.dest_type,
            dest.direction == rns_core::types::Direction::In,
        ) {
            self.tx
                .send(Event::RegisterPathResponder {
                    destination: Box::new(dest.clone()),
                    identity_prv_key,
                })
                .map_err(|_| SendError)?;
        }

        // Register proof strategy if not ProveNone
        if dest.proof_strategy != rns_core::types::ProofStrategy::ProveNone {
            self.tx
                .send(Event::RegisterProofStrategy {
                    dest_hash: dest.hash.0,
                    strategy: dest.proof_strategy,
                    signing_key,
                })
                .map_err(|_| SendError)?;
        }

        Ok(())
    }
}
