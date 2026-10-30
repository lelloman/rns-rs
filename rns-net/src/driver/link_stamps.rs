//! Outbound link creation, including stamped link requests.
//!
//! Upstream `Link.__init__` defers key generation to a background thread when
//! the destination announced a link request cost, and a watchdog cancels the
//! work after `LINK_STAMP_TIMEOUT`, closing the link with `STAMP_FAILURE`.
//! The driver mirrors that: grinding a stamped X25519 key is unbounded work
//! and never runs on the driver thread. The keys come back through the
//! driver's own event queue as [`Event::CompleteStampedLink`], and a timeout
//! answers the caller with the all-zero link id that `RnsNode::create_link`
//! already maps to an error.

use std::sync::mpsc;
use std::time::{Duration, Instant};

use rns_core::stamp::StampCost;
use rns_crypto::ed25519::Ed25519PrivateKey;
use rns_crypto::x25519::X25519PrivateKey;

use super::*;
use crate::common::event::StampedLinkKeys;

impl Driver {
    /// Handle `Event::CreateLink`.
    ///
    /// Unstamped links are created immediately. When `STAMP_LRS` is enabled
    /// and the destination announced a non-zero link request cost, or
    /// `ALWAYS_STAMP_LRS` supplies the local `LR_COST` for one that announced
    /// none, the keys are generated on a helper thread and the link is
    /// completed later.
    pub(crate) fn handle_create_link(
        &mut self,
        dest_hash: [u8; 16],
        dest_sig_pub_bytes: [u8; 32],
        response_tx: mpsc::Sender<[u8; 16]>,
    ) {
        let stamp_cost = self
            .outbound_link_stamp_cost(&dest_hash)
            .filter(|cost| *cost > StampCost::ZERO && self.stamp_settings.stamp_lrs);
        match stamp_cost {
            Some(cost) => self.spawn_stamped_link_keys(
                dest_hash,
                dest_sig_pub_bytes,
                cost,
                self.stamp_settings.link_stamp_timeout(),
                response_tx,
            ),
            None => self.complete_create_link(dest_hash, dest_sig_pub_bytes, None, response_tx),
        }
    }

    /// The cost to stamp an outbound link request to `dest_hash` at, before
    /// `STAMP_LRS` and the non-zero check are applied: the announced cost,
    /// else `LR_COST` when `ALWAYS_STAMP_LRS` is set.
    ///
    /// Upstream `Link.__init__` since 34bb4ac8: `stamp_cost =
    /// recall_link_cost(h)`, then `LR_COST` only when that is `None` and
    /// `ALWAYS_STAMP_LRS` is set. An announced cost of 0 is kept, so the
    /// request goes unstamped.
    pub(crate) fn outbound_link_stamp_cost(&self, dest_hash: &[u8; 16]) -> Option<StampCost> {
        match self.recall_link_cost(dest_hash) {
            Some(cost) => Some(StampCost::from_whole(u32::from(cost))),
            None if self.stamp_settings.always_stamp_lrs => {
                Some(self.link_manager.link_request_costs().default_cost())
            }
            None => None,
        }
    }

    /// Grind stamped link request keys off the driver thread.
    ///
    /// On success the keys are posted back as `Event::CompleteStampedLink`.
    /// If the deadline passes first, the caller is answered with the all-zero
    /// link id and no link is created; this is upstream's `STAMP_FAILURE`.
    pub(crate) fn spawn_stamped_link_keys(
        &mut self,
        dest_hash: [u8; 16],
        dest_sig_pub_bytes: [u8; 32],
        stamp_cost: StampCost,
        timeout: Duration,
        response_tx: mpsc::Sender<[u8; 16]>,
    ) {
        let event_tx = self.event_tx.clone();
        let deadline = Instant::now() + timeout;
        log::debug!(
            "Stamping link request to {:02x?} with cost {}",
            &dest_hash[..4],
            stamp_cost
        );
        let worker_tx = response_tx.clone();
        let spawned = std::thread::Builder::new()
            .name("rns-link-stamp".into())
            .spawn(move || {
                let response_tx = worker_tx;
                let started = Instant::now();
                match crate::stamps::generate_stamped_link_keys(&dest_hash, stamp_cost, deadline) {
                    Some((prv, sig_prv, stamp_value)) => {
                        log::debug!(
                            "Stamped link request key for {:02x?} with value {} in {:?}",
                            &dest_hash[..4],
                            stamp_value,
                            started.elapsed()
                        );
                        let event = Event::CompleteStampedLink(Box::new(StampedLinkKeys {
                            dest_hash,
                            dest_sig_pub_bytes,
                            prv_bytes: prv.private_bytes(),
                            sig_prv_bytes: sig_prv.private_bytes(),
                            stamp_value,
                            response_tx: response_tx.clone(),
                        }));
                        if event_tx.send(event).is_err() {
                            let _ = response_tx.send([0u8; 16]);
                        }
                    }
                    None => {
                        log::warn!(
                            "Link request stamp generation for {:02x?} at cost {} timed out after {:?}; link establishment cancelled",
                            &dest_hash[..4],
                            stamp_cost,
                            started.elapsed()
                        );
                        let _ = response_tx.send([0u8; 16]);
                    }
                }
            });
        if let Err(error) = spawned {
            log::warn!("could not start link request stamp worker: {error}");
            let _ = response_tx.send([0u8; 16]);
        }
    }

    /// Create the outbound link and answer the caller with its link id.
    pub(crate) fn complete_create_link(
        &mut self,
        dest_hash: [u8; 16],
        dest_sig_pub_bytes: [u8; 32],
        keys: Option<(X25519PrivateKey, Ed25519PrivateKey)>,
        response_tx: mpsc::Sender<[u8; 16]>,
    ) {
        let next_hop_interface = self.engine.next_hop_interface(&dest_hash);
        let recalled_route_hint = if next_hop_interface.is_none() {
            self.known_destination_route_hint(&dest_hash)
        } else {
            None
        };
        if recalled_route_hint.is_some() {
            let _ = self.mark_known_destination_used(&dest_hash);
        }
        let attached_interface = next_hop_interface.or(recalled_route_hint.map(|(iface, _)| iface));
        let hops = self
            .engine
            .hops_to(&dest_hash)
            .or_else(|| recalled_route_hint.map(|(_, hops)| hops))
            .unwrap_or(0);
        let mtu = attached_interface
            .and_then(|iface_id| self.interfaces.get(&iface_id))
            .map(|entry| entry.info.mtu)
            .unwrap_or(rns_core::constants::MTU as u32);
        let (link_id, mut link_actions) = self.link_manager.create_link_with_keys(
            &dest_hash,
            &dest_sig_pub_bytes,
            hops,
            mtu,
            keys,
            &mut self.rng,
        );
        if let Some(iface) = attached_interface {
            self.link_manager.set_link_route_hint(&link_id, iface, None);
        }
        if next_hop_interface.is_none() {
            if let Some(iface) = attached_interface {
                for action in &mut link_actions {
                    if let LinkManagerAction::SendPacket {
                        dest_type,
                        attached_interface,
                        ..
                    } = action
                    {
                        if *dest_type == rns_core::constants::DESTINATION_LINK
                            && attached_interface.is_none()
                        {
                            *attached_interface = Some(iface);
                        }
                    }
                }
            }
        }
        let _ = response_tx.send(link_id);
        self.dispatch_link_actions(link_actions);
    }
}
