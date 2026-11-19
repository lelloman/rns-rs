//! Tunnel synthesis.

use super::*;

impl Driver {
    pub(crate) fn handle_tunnel_synth_delivery(
        &mut self,
        raw: &[u8],
        receiving_interface: InterfaceId,
    ) {
        // Extract the data payload from the raw packet
        let packet = match RawPacket::unpack(raw) {
            Ok(p) => p,
            Err(_) => return,
        };

        // Upstream 464e7598: only TCP, Backbone and I2P connections carry
        // tunnels. Since 13b98a6b each takes one synthesis: another one, or
        // one on an established tunnel, is a protocol violation.
        let Some(entry) = self.interfaces.get(&receiving_interface) else {
            return;
        };
        if !crate::interface::tunnels_allowed(&entry.interface_type) {
            return;
        }
        if self.engine.remote_transport(&receiving_interface).is_some() {
            self.tunnel_synthesis_violation(
                receiving_interface,
                "Tunnel synthesis packet on already established tunnel",
            );
            return;
        }
        if !self.engine.mark_synthesis_received(receiving_interface) {
            self.tunnel_synthesis_violation(
                receiving_interface,
                "Additional synthesis packet received",
            );
            return;
        }
        let data_len = packet.data().len();
        if data_len > rns_core::constants::MDU {
            self.tunnel_synthesis_violation(
                receiving_interface,
                "Excessive tunnel synthesis packet size",
            );
            return;
        }
        if data_len < rns_core::transport::tunnel::TUNNEL_SYNTH_LENGTH {
            self.tunnel_synthesis_violation(
                receiving_interface,
                "Insufficient tunnel synthesis packet size",
            );
            return;
        }

        // As `Transport.tunnel_synthesize_handler`: the tunnel belongs to
        // the interface the synthesis arrived on. One whose key cannot be
        // loaded, where Python raises, is a protocol violation.
        match rns_core::transport::tunnel::validate_tunnel_synthesize_data(packet.data()) {
            Ok(validated) => {
                let now = time::now();
                let remote = rns_core::hash::truncated_hash(&validated.public_key);
                // Upstream 350b7e26: a blackholed transport node's connection
                // is torn down instead.
                if self.engine.is_blackholed(&remote, now) {
                    log::debug!(
                        "Tunnel synthesis from blackholed transport node {}, tearing down {:?}",
                        remote
                            .iter()
                            .map(|b| format!("{b:02x}"))
                            .collect::<String>(),
                        receiving_interface
                    );
                    self.teardown_interface(receiving_interface);
                    return;
                }
                // Upstream b7a93b9b: the extension tells what the remote
                // node is. An invalid one is a protocol violation and no
                // tunnel. A node that has not synthesized on the interface
                // answers with a synthesis of its own.
                if !validated.extension.is_empty() {
                    match crate::common::tunnel_extension::decode(&validated.extension) {
                        Ok(info) => {
                            self.engine
                                .set_remote_transport_info(receiving_interface, info);
                        }
                        Err(description) => {
                            self.tunnel_synthesis_violation(receiving_interface, description);
                            return;
                        }
                    }
                    if !self.engine.synthesis_emitted(&receiving_interface) {
                        self.send_tunnel_synthesis(receiving_interface, true);
                    }
                }
                // The side that synthesized the interface's tunnel itself
                // only learns the remote transport; the other side attaches
                // the remote tunnel to the interface.
                let attach = self.engine.local_tunnel_id(&receiving_interface).is_none();
                self.engine
                    .set_remote_transport(receiving_interface, remote);
                if attach {
                    let tunnel_actions =
                        self.engine
                            .handle_tunnel(validated.tunnel_id, receiving_interface, now);
                    self.dispatch_all(tunnel_actions);
                }
            }
            Err(rns_core::transport::tunnel::TunnelError::InvalidPublicKey) => {
                self.tunnel_synthesis_violation(
                    receiving_interface,
                    "Invalid tunnel synthesis packet",
                );
            }
            // Upstream 3281e283, effective since 56b23c48: a bad signature
            // tears the interface down.
            Err(rns_core::transport::tunnel::TunnelError::InvalidSignature) => {
                log::debug!(
                    "Invalid tunnel synthesis signature, tearing down interface {:?}",
                    receiving_interface
                );
                self.teardown_interface(receiving_interface);
            }
            // The length was checked above.
            Err(rns_core::transport::tunnel::TunnelError::InvalidLength) => {}
        }
    }

    /// Count a protocol violation by a tunnel synthesis on `interface`, as
    /// upstream's handler does with `Interface.protocol_violation`.
    pub(super) fn tunnel_synthesis_violation(&mut self, interface: InterfaceId, description: &str) {
        if let Some(entry) = self.interfaces.get_mut(&interface) {
            entry.stats.protocol_violations += 1;
            log::debug!("Protocol violation on {}: {}", entry.info.name, description);
        }
    }

    /// Synthesize a tunnel on an interface that wants it.
    ///
    /// Called when an interface with `wants_tunnel` comes up.
    pub(crate) fn synthesize_tunnel_for_interface(&mut self, interface: InterfaceId) {
        self.send_tunnel_synthesis(interface, false);
    }

    /// Send a synthesis on `interface`, with this node's extension (upstream
    /// b7a93b9b): its implementation, version and transport status, and the
    /// interface's destination and path request stamp costs. A `reverse`
    /// synthesis answers one received on the interface.
    pub(super) fn send_tunnel_synthesis(&mut self, interface: InterfaceId, reverse: bool) {
        let Some(ref identity) = self.transport_identity else {
            return;
        };
        let Some(info) = self.engine.interface_info(&interface) else {
            return;
        };
        let requirements = self.engine.stamp_requirements();
        let extension = crate::common::tunnel_extension::encode(
            self.engine.transport_enabled(),
            info.stamp_costs.destination_cost(&requirements),
            info.stamp_costs.pr_cost(&requirements),
        );
        let actions =
            self.engine
                .synthesize_tunnel(identity, interface, &extension, reverse, &mut self.rng);
        self.dispatch_all(actions);
    }
}
