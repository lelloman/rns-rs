//! Inbound frames: decoding them, deduplicating and filtering them,
//! and deciding where each packet goes.

use super::*;

impl TransportEngine {
    pub(super) fn record_invalid_announce(
        &self,
        announce: &AnnounceData,
        interface: InterfaceId,
        now: f64,
        actions: &mut Vec<TransportAction>,
    ) {
        let identity_hash = crate::hash::truncated_hash(&announce.public_key);
        if !self.is_blackholed(&identity_hash, now) {
            actions.push(TransportAction::ProtocolViolation { interface });
        }
    }

    /// Return whether an inbound frame passes parsing, hop, and packet filtering.
    /// This does not mutate deduplication or routing state.
    pub fn accepts_inbound_frame(&self, frame: InboundFrame<'_>) -> bool {
        self.prepare_inbound_packet(frame).is_some()
    }

    /// Process an inbound raw packet from a network interface.
    ///
    /// Returns a list of actions for the caller to execute.
    pub fn handle_inbound(
        &mut self,
        frame: InboundFrame<'_>,
        rng: &mut dyn Rng,
    ) -> Vec<TransportAction> {
        self.handle_inbound_with_announce_queue(frame, rng, None)
    }

    /// [`Self::handle_inbound`], queueing announces that need a signature check
    /// in `announce_queue` when one is given instead of verifying them inline.
    pub fn handle_inbound_with_announce_queue(
        &mut self,
        frame: InboundFrame<'_>,
        rng: &mut dyn Rng,
        announce_queue: Option<&mut AnnounceVerifyQueue>,
    ) -> Vec<TransportAction> {
        let Ok(decoded) = self.decode_inbound(PacketBytes::from(frame.raw)) else {
            return Vec::new();
        };
        self.handle_decoded_inbound_with_announce_queue(
            DecodedInboundFrame {
                decoded,
                iface: frame.iface,
                now: frame.now,
                rx: frame.rx,
            },
            rng,
            announce_queue,
        )
    }

    /// Decode an inbound frame for [`handle_decoded_inbound_with_announce_queue`].
    ///
    /// Link traffic that this node only forwards, in a context the packet
    /// filter admits without consulting deduplication, is not hashed: no
    /// step that handles it reads the hash. Its hash cannot reject any later
    /// packet either, since a packet with the same hash has the same context.
    /// Nor is a resource part, part request or resource proof for a local
    /// link (see [`RawPacket::is_unhashed_link_resource`]); its delivery
    /// carries a zeroed hash. [`DecodedPacket::packet_hash`] reports whether hashing was
    /// deferred.
    ///
    /// [`handle_decoded_inbound_with_announce_queue`]: Self::handle_decoded_inbound_with_announce_queue
    /// It takes ownership of the wire bytes, which the decoded packet keeps.
    pub fn decode_inbound(
        &self,
        raw: PacketBytes,
    ) -> Result<DecodedPacket, crate::packet::PacketError> {
        // Only link data and proofs qualify; decode everything else directly.
        let flags = raw
            .first()
            .map(|flags| crate::packet::PacketFlags::unpack(*flags));
        if !flags.is_some_and(|flags| {
            matches!(
                flags.packet_type,
                constants::PACKET_TYPE_DATA | constants::PACKET_TYPE_PROOF
            ) && flags.destination_type == constants::DESTINATION_LINK
        }) {
            return DecodedPacket::unpack_shared(raw);
        }
        let mut packet = RawPacket::unpack_shared_unhashed(raw)?;
        let hash_deferred = self.link_packet_hash_unread(&packet);
        if !hash_deferred {
            packet.hash_in_place();
        }
        Ok(DecodedPacket {
            packet,
            hash_deferred,
        })
    }

    /// Whether every inbound step that handles `packet` leaves its hash unread.
    pub(super) fn link_packet_hash_unread<B: AsRef<[u8]>>(&self, packet: &RawPacket<B>) -> bool {
        self.forwards_link_packet_unhashed(packet) || self.delivers_link_resource_unhashed(packet)
    }

    /// A resource part, part request or resource proof for a local link is
    /// only delivered, and its delivery hands the payload to the resource
    /// code. Path-table routing would key a reverse entry on the hash, so a
    /// destination with a path is excluded.
    pub(super) fn delivers_link_resource_unhashed<B: AsRef<[u8]>>(
        &self,
        packet: &RawPacket<B>,
    ) -> bool {
        packet.is_unhashed_link_resource()
            && self
                .local_destinations
                .contains_key(&packet.destination_hash)
            && !self.path_table.contains_key(&packet.destination_hash)
    }

    /// Whether `packet` is only relayed and leaves its hash unread: it is
    /// link data for a validated link this node relays, in a context
    /// that [`packet_filter_at_hops`](Self::packet_filter_at_hops) admits
    /// before deduplication, and it is neither delivered locally nor routed
    /// through the path table.
    pub(super) fn forwards_link_packet_unhashed<B: AsRef<[u8]>>(
        &self,
        packet: &RawPacket<B>,
    ) -> bool {
        packet.flags.packet_type == constants::PACKET_TYPE_DATA
            && packet.flags.destination_type == constants::DESTINATION_LINK
            && matches!(
                packet.context,
                constants::CONTEXT_KEEPALIVE
                    | constants::CONTEXT_RESOURCE_REQ
                    | constants::CONTEXT_RESOURCE
                    | constants::CONTEXT_CACHE_REQUEST
                    | constants::CONTEXT_CHANNEL
            )
            && (self.config.transport_enabled || self.config.identity_hash.is_some())
            && self
                .link_table
                .get(&packet.destination_hash)
                .is_some_and(|entry| entry.validated)
            && !self
                .local_destinations
                .contains_key(&packet.destination_hash)
            && !self.path_table.contains_key(&packet.destination_hash)
    }

    /// Recheck current routing/filter state and consume a previously decoded frame.
    pub fn handle_decoded_inbound_with_announce_queue(
        &mut self,
        frame: DecodedInboundFrame,
        rng: &mut dyn Rng,
        announce_queue: Option<&mut AnnounceVerifyQueue>,
    ) -> Vec<TransportAction> {
        let mut actions = Vec::new();
        self.handle_decoded_inbound_into(frame, rng, announce_queue, &mut actions);
        actions
    }

    /// [`Self::handle_decoded_inbound_with_announce_queue`], appending the
    /// actions to `actions` so a caller can reuse one buffer across packets.
    pub fn handle_decoded_inbound_into(
        &mut self,
        frame: DecodedInboundFrame,
        rng: &mut dyn Rng,
        announce_queue: Option<&mut AnnounceVerifyQueue>,
        actions: &mut Vec<TransportAction>,
    ) {
        self.inbound_filtered = false;
        self.inbound_filtered_announce = false;
        let Some(mut ctx) = self.prepare_decoded_packet(frame) else {
            self.inbound_filtered = true;
            return;
        };
        match self.destination_filter_verdict(&ctx) {
            DestinationFilterVerdict::Admit => {}
            DestinationFilterVerdict::Blocked => {
                self.inbound_filtered = true;
                return;
            }
            // Upstream 819076c3 counts this one as a filtered announce.
            DestinationFilterVerdict::NotAllowed => {
                self.filter_announce();
                return;
            }
        }
        // Routing state may have changed since decoding. Any packet whose hash
        // a step could now read is hashed first.
        if ctx.hash_deferred && !self.link_packet_hash_unread(&ctx.packet) {
            ctx.packet.hash_in_place();
            ctx.hash_deferred = false;
        }

        // A deferred packet's context bypasses deduplication.
        if !ctx.hash_deferred {
            self.remember_inbound_packet_hash(&ctx.packet);
        }
        self.bridge_plain_broadcast(&ctx, actions);
        self.handle_transport_forwarding(&ctx, actions);
        self.handle_link_table_routing(&ctx, actions);
        self.handle_inbound_announce(&ctx, rng, announce_queue, actions);

        if ctx.packet.flags.packet_type == constants::PACKET_TYPE_PROOF {
            self.process_inbound_proof(&ctx, actions);
        }

        self.handle_inbound_local_delivery(&ctx, actions);
    }

    /// The announce ingress filter of `Transport.inbound` (825c2e19), which
    /// runs before anything else sees the packet. Python's `hops == 1` after
    /// its increment means the announce was sent with zero hops; local
    /// client hops are not incremented here.
    pub(super) fn destination_filter_verdict(
        &self,
        ctx: &InboundPacketCtx,
    ) -> DestinationFilterVerdict {
        if ctx.packet.flags.packet_type != constants::PACKET_TYPE_ANNOUNCE {
            return DestinationFilterVerdict::Admit;
        }
        let start = constants::KEYSIZE / 8;
        let Some(name_hash) = ctx
            .packet
            .data()
            .get(start..start + constants::NAME_HASH_LENGTH / 8)
        else {
            // Malformed. The driver rejects a payload this short as a
            // protocol violation (upstream 096e6726); otherwise announce
            // unpacking reports it.
            return DestinationFilterVerdict::Admit;
        };
        let mut destination_type = [0u8; constants::NAME_HASH_LENGTH / 8];
        destination_type.copy_from_slice(name_hash);
        let own_local_announce = ctx.from_local_client && ctx.packet.hops == 0;
        if self.destination_filter.blocks(&destination_type) {
            DestinationFilterVerdict::Blocked
        } else if self
            .destination_filter
            .allows(&destination_type, own_local_announce)
        {
            DestinationFilterVerdict::Admit
        } else {
            DestinationFilterVerdict::NotAllowed
        }
    }

    /// Mark the inbound packet as a filtered announce: its bytes count as
    /// filtered and the interface's `afrxc` grows (upstream 819076c3).
    pub(super) fn filter_announce(&mut self) {
        self.inbound_filtered = true;
        self.inbound_filtered_announce = true;
    }

    pub(in crate::transport) fn prepare_inbound_packet(
        &self,
        frame: InboundFrame<'_>,
    ) -> Option<InboundPacketCtx> {
        let decoded = DecodedPacket::unpack(frame.raw).ok()?;
        self.prepare_decoded_packet(DecodedInboundFrame {
            decoded,
            iface: frame.iface,
            now: frame.now,
            rx: frame.rx,
        })
    }

    pub(in crate::transport) fn filtered_inbound_hops<B: AsRef<[u8]>>(
        &self,
        packet: &RawPacket<B>,
        iface: InterfaceId,
    ) -> Option<(u8, bool)> {
        let from_local_client = self
            .interfaces
            .get(&iface)
            .is_some_and(|i| i.is_local_client);
        let mut hops = packet.hops.checked_add(1)?;
        if from_local_client {
            hops = hops.saturating_sub(1);
        }
        self.packet_filter_at_hops(packet, hops)
            .then_some((hops, from_local_client))
    }

    /// Whether the packet filter accepts `decoded` as received on `iface`, with
    /// its hop count after this hop.
    pub fn accepts_decoded_packet(&self, decoded: &DecodedPacket, iface: InterfaceId) -> bool {
        self.filtered_inbound_hops(&decoded.packet, iface).is_some()
    }

    pub(in crate::transport) fn prepare_decoded_packet(
        &self,
        frame: DecodedInboundFrame,
    ) -> Option<InboundPacketCtx> {
        let hash_deferred = frame.decoded.hash_deferred;
        let mut packet = frame.decoded.packet;
        let (hops, from_local_client) = self.filtered_inbound_hops(&packet, frame.iface)?;
        packet.hops = hops;
        packet.rssi = frame.rx.rssi;
        packet.snr = frame.rx.snr;
        let retain_original_raw = packet.flags.packet_type == constants::PACKET_TYPE_ANNOUNCE;
        let original_raw = retain_original_raw.then(|| packet.raw.clone());
        Some(InboundPacketCtx {
            packet,
            hash_deferred,
            original_raw,
            iface: frame.iface,
            now: frame.now,
            from_local_client,
        })
    }

    pub(super) fn remember_inbound_packet_hash<B: AsRef<[u8]>>(&mut self, packet: &RawPacket<B>) {
        let remember_hash = !(self.link_table.contains_key(&packet.destination_hash)
            || (packet.flags.packet_type == constants::PACKET_TYPE_PROOF
                && packet.context == constants::CONTEXT_LRPROOF));
        if remember_hash {
            self.packet_hashlist.add(packet.packet_hash);
        }
    }
}
