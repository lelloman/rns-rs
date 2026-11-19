mod announces;
mod forwarding;
mod frames;
mod proofs;
#[cfg(test)]
mod tests;
mod verified_announce;

use super::*;

pub(super) fn extra_link_proof_timeout(interface: Option<&InterfaceInfo>) -> f64 {
    interface
        .and_then(|interface| interface.bitrate)
        .filter(|bitrate| *bitrate > 0)
        .map_or(0.0, |bitrate| {
            (constants::MTU as f64 * 8.0) / bitrate as f64
        })
}

/// How the destination type filter treats an inbound announce.
enum DestinationFilterVerdict {
    Admit,
    /// A blocked destination type.
    Blocked,
    /// With `required_destinations_only`, a type nobody allowed or wants.
    NotAllowed,
}

/// The ingress limiting outcome for an inbound announce.
enum HoldDecision {
    /// Not limited; processing continues.
    Pass,
    /// Held for later release.
    Held,
    /// Dropped or replacing a held announce: a filtered announce.
    Filtered,
}

impl TransportEngine {
    // =========================================================================
    // Inbound announce processing
    // =========================================================================

    // =========================================================================
    // Inbound proof processing
    // =========================================================================
}

#[cfg(test)]
mod local_client_announce_tests {
    use super::*;
    use crate::announce::AnnounceData;
    use crate::destination::{destination_hash, name_hash};
    use crate::packet::PacketFlags;
    use crate::transport::tests::{make_config, make_interface, make_local_client_interface};

    /// A signed announce, ratcheted or not, sent as `header_type` with
    /// `hops`, for `identity_seed`'s destination.
    fn announce(identity_seed: u8, ratchet: bool, header_type: u8, hops: u8) -> RawPacket {
        announce_in_context(
            identity_seed,
            ratchet,
            header_type,
            hops,
            constants::CONTEXT_NONE,
        )
    }

    /// [`announce`] in `context`.
    pub(super) fn announce_in_context(
        identity_seed: u8,
        ratchet: bool,
        header_type: u8,
        hops: u8,
        context: u8,
    ) -> RawPacket {
        let identity = rns_crypto::identity::Identity::from_private_key(&[identity_seed; 64]);
        let dest_hash = destination_hash("forward", &["test"], Some(identity.hash()));
        let ratchet_key = [0x3C; 32];
        let (data, _) = AnnounceData::pack(
            &identity,
            &dest_hash,
            &name_hash("forward", &["test"]),
            &[0x5C; 10],
            ratchet.then_some(&ratchet_key),
            None,
        )
        .unwrap();
        let h2 = header_type == constants::HEADER_2;
        RawPacket::pack(
            PacketFlags {
                header_type,
                context_flag: if ratchet {
                    constants::FLAG_SET
                } else {
                    constants::FLAG_UNSET
                },
                transport_type: if h2 {
                    constants::TRANSPORT_TRANSPORT
                } else {
                    constants::TRANSPORT_BROADCAST
                },
                destination_type: constants::DESTINATION_SINGLE,
                packet_type: constants::PACKET_TYPE_ANNOUNCE,
            },
            hops,
            &dest_hash,
            h2.then_some(&[0x29; 16]),
            context,
            &data,
        )
        .unwrap()
    }

    /// As upstream, an announce passed on to local clients is rebuilt as a
    /// HEADER_2 transport packet from this node, with the hops it arrived
    /// with and its context flag, which marks a ratchet.
    #[test]
    fn announce_for_local_clients_is_sent_on_from_this_transport() {
        for (seed, ratchet, header_type) in [
            (1, false, constants::HEADER_1),
            (2, true, constants::HEADER_1),
            (3, true, constants::HEADER_2),
        ] {
            let mut engine = TransportEngine::new(make_config(true));
            engine.register_interface(make_interface(1, constants::MODE_FULL));
            engine.register_interface(make_local_client_interface(2));
            let announce = announce(seed, ratchet, header_type, 2);
            let mut rng = rns_crypto::FixedRng::new(&[0x77; 32]);
            let actions = engine.handle_inbound(
                InboundFrame::new(&announce.raw, InterfaceId(1), 1000.0),
                &mut rng,
            );
            let raw = actions
                .iter()
                .find_map(|action| match action {
                    TransportAction::ForwardToLocalClients { raw, .. } => Some(raw),
                    _ => None,
                })
                .expect("announce passed on to local clients");
            let forwarded = RawPacket::unpack(raw).unwrap();
            assert_eq!(forwarded.flags.header_type, constants::HEADER_2);
            assert_eq!(
                forwarded.flags.transport_type,
                constants::TRANSPORT_TRANSPORT
            );
            assert_eq!(forwarded.flags.context_flag, announce.flags.context_flag);
            assert_eq!(
                forwarded.flags.destination_type,
                constants::DESTINATION_SINGLE
            );
            assert_eq!(forwarded.flags.packet_type, constants::PACKET_TYPE_ANNOUNCE);
            assert_eq!(forwarded.hops, 3);
            assert_eq!(forwarded.transport_id, Some([0x42; 16]));
            assert_eq!(forwarded.destination_hash, announce.destination_hash);
            assert_eq!(forwarded.data(), announce.data());
        }
    }
}
