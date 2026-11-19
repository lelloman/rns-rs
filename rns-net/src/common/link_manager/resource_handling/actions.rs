//! Turning resource actions into link packets.

use super::*;

/// A link DATA packet with `context` whose payload is `plaintext`
/// link-encrypted in place: the ciphertext needs no buffer of its own.
pub(in crate::common::link_manager) fn encrypted_link_packet(
    engine: &rns_core::link::LinkEngine,
    link_id: &LinkId,
    context: u8,
    plaintext: &[u8],
    rng: &mut dyn Rng,
    max_mtu: usize,
) -> Option<rns_core::transport::types::PacketBytes> {
    let flags = PacketFlags {
        header_type: constants::HEADER_1,
        context_flag: constants::FLAG_UNSET,
        transport_type: constants::TRANSPORT_BROADCAST,
        destination_type: constants::DESTINATION_LINK,
        packet_type: constants::PACKET_TYPE_DATA,
    };
    let mut encrypted = Err(());
    let raw = RawPacket::pack_raw_shared_filled_with_max_mtu(
        flags,
        0,
        link_id,
        None,
        context,
        engine.encrypted_len(plaintext.len()),
        max_mtu,
        |payload| encrypted = engine.encrypt_into(plaintext, rng, payload).map_err(|_| ()),
    )
    .ok()?;
    encrypted.ok().map(|()| raw)
}

impl LinkManager {
    /// Convert ResourceActions to LinkManagerActions.
    pub(in crate::common::link_manager) fn process_resource_actions(
        &mut self,
        link_id: &LinkId,
        actions: Vec<ResourceAction>,
        rng: &mut dyn Rng,
    ) -> Vec<LinkManagerAction> {
        let mut out = Vec::new();
        self.process_resource_actions_into(link_id, actions, rng, &mut out);
        out
    }

    /// [`Self::process_resource_actions`], appending to `out`; `actions` may
    /// drain a reused buffer.
    pub(in crate::common::link_manager) fn process_resource_actions_into(
        &mut self,
        link_id: &LinkId,
        actions: impl IntoIterator<Item = ResourceAction>,
        rng: &mut dyn Rng,
        out: &mut Vec<LinkManagerAction>,
    ) {
        for action in actions {
            let requires_active_link = matches!(
                &action,
                ResourceAction::SendAdvertisement(_)
                    | ResourceAction::SendPart(_)
                    | ResourceAction::SendRequest(_)
                    | ResourceAction::SendHmu(_)
                    | ResourceAction::SendProof(_)
            );
            if requires_active_link && !self.resource_link_is_active(link_id) {
                out.extend(self.abort_resources_on_inactive_link(link_id));
                continue;
            }

            match action {
                ResourceAction::SendAdvertisement(data) => {
                    // Link-encrypt and send as CONTEXT_RESOURCE_ADV
                    self.build_encrypted_link_packet_into(
                        link_id,
                        constants::CONTEXT_RESOURCE_ADV,
                        &data,
                        rng,
                        out,
                    );
                }
                ResourceAction::SendPart(data) => {
                    // Parts are NOT link-encrypted — send raw as CONTEXT_RESOURCE
                    self.build_link_packet_into(link_id, constants::CONTEXT_RESOURCE, &data, out);
                }
                ResourceAction::SendRequest(data) => {
                    self.build_encrypted_link_packet_into(
                        link_id,
                        constants::CONTEXT_RESOURCE_REQ,
                        &data,
                        rng,
                        out,
                    );
                }
                ResourceAction::SendHmu(data) => {
                    self.build_encrypted_link_packet_into(
                        link_id,
                        constants::CONTEXT_RESOURCE_HMU,
                        &data,
                        rng,
                        out,
                    );
                }
                ResourceAction::SendProof(data) => {
                    let flags = PacketFlags {
                        header_type: constants::HEADER_1,
                        context_flag: constants::FLAG_UNSET,
                        transport_type: constants::TRANSPORT_BROADCAST,
                        destination_type: constants::DESTINATION_LINK,
                        packet_type: constants::PACKET_TYPE_PROOF,
                    };
                    if let Ok((raw, _packet_hash)) =
                        RawPacket::pack_raw_shared_with_hash_with_max_mtu(
                            flags,
                            0,
                            link_id,
                            None,
                            constants::CONTEXT_RESOURCE_PRF,
                            &data,
                            constants::MTU,
                        )
                    {
                        out.push(LinkManagerAction::SendPacket {
                            raw,
                            dest_type: constants::DESTINATION_LINK,
                            attached_interface: None,
                        });
                    }
                }
                ResourceAction::SendCancelInitiator(data) => {
                    if self
                        .links
                        .get(link_id)
                        .is_some_and(|link| link.engine.state() == LinkState::Active)
                    {
                        self.build_encrypted_link_packet_into(
                            link_id,
                            constants::CONTEXT_RESOURCE_ICL,
                            &data,
                            rng,
                            out,
                        );
                    }
                }
                ResourceAction::SendCancelReceiver(data) => {
                    if self
                        .links
                        .get(link_id)
                        .is_some_and(|link| link.engine.state() == LinkState::Active)
                    {
                        self.build_encrypted_link_packet_into(
                            link_id,
                            constants::CONTEXT_RESOURCE_RCL,
                            &data,
                            rng,
                            out,
                        );
                    }
                }
                ResourceAction::DataReceived {
                    data,
                    metadata,
                    app_flag,
                } => {
                    out.push(LinkManagerAction::ResourceReceived {
                        link_id: *link_id,
                        data,
                        metadata,
                        app_flag,
                    });
                }
                ResourceAction::Completed => {
                    out.push(LinkManagerAction::ResourceCompleted { link_id: *link_id });
                }
                ResourceAction::Failed(e) => {
                    out.push(LinkManagerAction::ResourceFailed {
                        link_id: *link_id,
                        error: format!("{}", e),
                    });
                }
                ResourceAction::TeardownLink => {
                    // Python `Resource.cancel` on a CORRUPT resource calls
                    // `Link.teardown()`, which sends LINKCLOSE to the peer.
                    out.extend(self.teardown_link(link_id));
                }
                ResourceAction::ProgressUpdate { received, total } => {
                    out.push(LinkManagerAction::ResourceProgress {
                        link_id: *link_id,
                        received,
                        total,
                    });
                }
            }
        }
    }

    /// Build a link DATA packet with a given context and data.
    #[cfg(test)]
    pub(in crate::common::link_manager) fn build_link_packet(
        &self,
        link_id: &LinkId,
        context: u8,
        data: &[u8],
    ) -> Vec<LinkManagerAction> {
        let mut out = Vec::new();
        self.build_link_packet_into(link_id, context, data, &mut out);
        out
    }

    /// [`Self::build_link_packet`], appending to `out`.
    pub(in crate::common::link_manager) fn build_link_packet_into(
        &self,
        link_id: &LinkId,
        context: u8,
        data: &[u8],
        out: &mut Vec<LinkManagerAction>,
    ) {
        let flags = PacketFlags {
            header_type: constants::HEADER_1,
            context_flag: constants::FLAG_UNSET,
            transport_type: constants::TRANSPORT_BROADCAST,
            destination_type: constants::DESTINATION_LINK,
            packet_type: constants::PACKET_TYPE_DATA,
        };
        let max_mtu = self
            .links
            .get(link_id)
            .map(|l| l.engine.mtu() as usize)
            .unwrap_or(constants::MTU);
        if let Ok(raw) =
            RawPacket::pack_raw_shared_with_max_mtu(flags, 0, link_id, None, context, data, max_mtu)
        {
            out.push(LinkManagerAction::SendPacket {
                raw,
                dest_type: constants::DESTINATION_LINK,
                attached_interface: None,
            });
        }
    }

    /// Link-encrypt `plaintext` straight into a new link DATA packet with
    /// `context`, appending it to `out`; nothing when the link is unknown or
    /// cannot encrypt.
    pub(in crate::common::link_manager) fn build_encrypted_link_packet_into(
        &self,
        link_id: &LinkId,
        context: u8,
        plaintext: &[u8],
        rng: &mut dyn Rng,
        out: &mut Vec<LinkManagerAction>,
    ) {
        let Some(link) = self.links.get(link_id) else {
            return;
        };
        let max_mtu = link.engine.mtu() as usize;
        if let Some(raw) =
            encrypted_link_packet(&link.engine, link_id, context, plaintext, rng, max_mtu)
        {
            out.push(LinkManagerAction::SendPacket {
                raw,
                dest_type: constants::DESTINATION_LINK,
                attached_interface: None,
            });
        }
    }
}
