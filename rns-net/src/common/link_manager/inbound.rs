//! Packets arriving on links and for local destinations.

use super::*;

impl LinkManager {
    /// Handle a packet delivered locally (via DeliverLocal).
    ///
    /// Returns actions for the driver to dispatch. The `dest_hash` is the
    /// packet's destination_hash field. `raw` is the full packet bytes.
    /// `packet_hash` is the SHA-256 hash, or zeroed for a resource part,
    /// part request or proof, whose hash nothing here reads.
    pub fn handle_local_delivery(
        &mut self,
        dest_hash: [u8; 16],
        raw: &[u8],
        packet_hash: [u8; 32],
        receiving_interface: rns_core::transport::types::InterfaceId,
        rng: &mut dyn Rng,
    ) -> Vec<LinkManagerAction> {
        let mut out = Vec::new();
        self.handle_local_delivery_into(
            dest_hash,
            raw,
            packet_hash,
            receiving_interface,
            rng,
            &mut out,
        );
        out
    }

    /// [`Self::handle_local_delivery`], appending to `out`.
    pub fn handle_local_delivery_into(
        &mut self,
        dest_hash: [u8; 16],
        raw: &[u8],
        packet_hash: [u8; 32],
        receiving_interface: rns_core::transport::types::InterfaceId,
        rng: &mut dyn Rng,
        out: &mut Vec<LinkManagerAction>,
    ) {
        // The transport engine hashed these bytes on receipt, unless they are
        // a resource part, part request or proof.
        // A view of the delivered bytes: handlers read the packet without
        // owning a copy of it.
        let packet = match RawPacket::view_prehashed(raw, packet_hash) {
            Ok(p) => p,
            Err(_) => return,
        };

        // Python accounts link traffic once the packet is accepted on its
        // attached interface, before dispatch/decryption of its context.
        if packet.flags.packet_type != constants::PACKET_TYPE_LINKREQUEST {
            if let Some(link) = self.links.get_mut(&dest_hash) {
                // `Link.__receive` drops a keepalive probe arriving at the
                // initiator, which sends them (an echo of its own probe), before
                // anything else: it is neither inbound activity nor traffic.
                if link.engine.is_initiator()
                    && packet.flags.packet_type == constants::PACKET_TYPE_DATA
                    && packet.context == constants::CONTEXT_KEEPALIVE
                    && packet.data() == [0xff]
                {
                    return;
                }
                link.engine.record_inbound_traffic(packet.data().len());
                // Every packet `Link.__receive` handles counts as inbound
                // and reactivates a STALE link, before it is dispatched or
                // decrypted (a responder answering a probe sees an ACTIVE
                // link). Proofs of sent packets only set `last_proof`, and
                // LRPROOF activates the link itself.
                if packet.flags.packet_type == constants::PACKET_TYPE_DATA
                    || packet.context == constants::CONTEXT_RESOURCE_PRF
                {
                    let inbound_actions = link.engine.record_inbound(time::now());
                    out.extend(self.process_link_actions(&dest_hash, &inbound_actions));
                }
            }
        }

        match packet.flags.packet_type {
            constants::PACKET_TYPE_LINKREQUEST => {
                out.extend(self.handle_linkrequest(&dest_hash, &packet, receiving_interface, rng))
            }
            constants::PACKET_TYPE_PROOF if packet.context == constants::CONTEXT_LRPROOF => {
                // LRPROOF: dest_hash is the link_id
                out.extend(self.handle_lrproof(&dest_hash, &packet, receiving_interface, rng))
            }
            constants::PACKET_TYPE_PROOF if packet.context == constants::CONTEXT_RESOURCE_PRF => {
                // Resource proofs are PROOF packets with raw proof data, not
                // encrypted DATA packets.
                out.extend(self.handle_resource_prf(&dest_hash, packet.data(), rng))
            }
            constants::PACKET_TYPE_PROOF => {
                out.extend(self.handle_link_proof(&dest_hash, &packet, rng))
            }
            constants::PACKET_TYPE_DATA => self.handle_link_data_into(
                &dest_hash,
                &packet,
                packet_hash,
                receiving_interface,
                rng,
                out,
            ),
            _ => {}
        }
    }

    /// Handle DATA packets on an established link.
    ///
    /// Structured to avoid borrow checker issues: we perform engine operations
    /// on the link, collect intermediate results, drop the mutable borrow, then
    /// call self methods that need immutable access.
    pub(super) fn handle_link_data_into(
        &mut self,
        link_id_bytes: &[u8; 16],
        packet: &RawPacket<&[u8]>,
        packet_hash: [u8; 32],
        receiving_interface: rns_core::transport::types::InterfaceId,
        rng: &mut dyn Rng,
        out: &mut Vec<LinkManagerAction>,
    ) {
        // First pass: perform engine operations, collect results
        enum LinkDataResult<'a> {
            DirectLink {
                link_id: LinkId,
                plaintext: Vec<u8>,
            },
            Lrrtt {
                link_id: LinkId,
                link_actions: Vec<LinkAction>,
            },
            Identify {
                link_id: LinkId,
                link_actions: Vec<LinkAction>,
            },
            Keepalive {
                link_id: LinkId,
                reply: bool,
                received_at: f64,
            },
            LinkClose {
                link_id: LinkId,
                teardown_actions: Vec<LinkAction>,
            },
            Channel {
                link_id: LinkId,
                plaintext: Vec<u8>,
                packet_hash: [u8; 32],
            },
            Request {
                link_id: LinkId,
                plaintext: Vec<u8>,
                request_id: [u8; 16],
            },
            Response {
                link_id: LinkId,
                plaintext: Vec<u8>,
            },
            Generic {
                link_id: LinkId,
                plaintext: Vec<u8>,
                context: u8,
                packet_hash: [u8; 32],
            },
            /// Resource advertisement (link-decrypted).
            ResourceAdv {
                link_id: LinkId,
                plaintext: Vec<u8>,
            },
            /// Resource part request (link-decrypted).
            ResourceReq {
                link_id: LinkId,
                plaintext: Vec<u8>,
            },
            /// Resource hashmap update (link-decrypted).
            ResourceHmu {
                link_id: LinkId,
                plaintext: Vec<u8>,
            },
            /// Resource part data (NOT link-decrypted; parts are pre-encrypted by ResourceSender).
            ResourcePart {
                link_id: LinkId,
                raw_data: &'a [u8],
            },
            /// Resource proof (feed to sender).
            ResourcePrf {
                link_id: LinkId,
                plaintext: Vec<u8>,
            },
            /// Resource cancel from initiator (link-decrypted).
            ResourceIcl {
                link_id: LinkId,
                resource_hash: Vec<u8>,
            },
            /// Resource cancel from receiver (link-decrypted).
            ResourceRcl {
                link_id: LinkId,
                resource_hash: Vec<u8>,
            },
            Error,
        }

        let mut scratch = core::mem::take(&mut self.plaintext_scratch);
        let result = {
            let link = match self.links.get_mut(link_id_bytes) {
                Some(l) => l,
                None => return,
            };

            // Python exposes ACTIVE to its utility thread before the proof thread
            // sends LRRTT. Preserve early identity/request ordering, but do not
            // invoke application handlers until the responder handshake completes.
            if !link.engine.is_initiator()
                && link.engine.state() == LinkState::Handshake
                && matches!(
                    packet.context,
                    constants::CONTEXT_LINKIDENTIFY | constants::CONTEXT_REQUEST
                )
            {
                let packet_bytes = packet.raw.len() + packet.data().len();
                let queued_bytes: usize = link
                    .pre_rtt_packets
                    .iter()
                    .map(|pending| pending.packet.raw.len() + pending.packet.data().len())
                    .sum();
                if link.pre_rtt_packets.len() < MAX_PRE_RTT_PACKETS
                    && packet_bytes <= MAX_PRE_RTT_BYTES.saturating_sub(queued_bytes)
                    && link.engine.decrypt(packet.data()).is_ok()
                {
                    link.pre_rtt_packets.push(PreRttPacket {
                        packet: packet.to_owned_packet(),
                        packet_hash,
                        receiving_interface,
                    });
                }
                return;
            }

            // Plaintexts are decrypted into a reused buffer, returned to
            // `plaintext_scratch` by the handler that reads them.
            let mut decrypt = |engine: &LinkEngine, ciphertext: &[u8]| {
                let mut plaintext = core::mem::take(&mut scratch);
                match engine.decrypt_into(ciphertext, &mut plaintext) {
                    Ok(()) => Ok(plaintext),
                    Err(error) => {
                        scratch = plaintext;
                        Err(error)
                    }
                }
            };

            let transport_id = if packet.flags.header_type == constants::HEADER_2 {
                packet.transport_id
            } else {
                None
            };
            match link.direct_route.as_mut() {
                None => {
                    link.route_interface = Some(receiving_interface);
                    if packet.flags.header_type == constants::HEADER_2 {
                        if transport_id.is_some() {
                            link.route_transport_id = transport_id;
                        }
                    } else {
                        link.route_transport_id = None;
                    }
                }
                // The direct path stays the route; packets the peer sends
                // on the original path keep that path current for the
                // fallback.
                Some(direct) if direct.interface != receiving_interface => {
                    direct.fallback_interface = Some(receiving_interface);
                    if packet.flags.header_type == constants::HEADER_2 {
                        if transport_id.is_some() {
                            direct.fallback_transport_id = transport_id;
                        }
                    } else {
                        direct.fallback_transport_id = None;
                    }
                }
                Some(_) => {}
            }

            match packet.context {
                constants::CONTEXT_LRRTT => {
                    match link.engine.handle_lrrtt_with_hops(
                        packet.data(),
                        Some(packet.hops),
                        time::now(),
                    ) {
                        Ok(link_actions) => {
                            let link_id = *link.engine.link_id();
                            LinkDataResult::Lrrtt {
                                link_id,
                                link_actions,
                            }
                        }
                        Err(e) => {
                            log::debug!("LRRTT handling failed: {}", e);
                            LinkDataResult::Error
                        }
                    }
                }
                constants::CONTEXT_LINKIDENTIFY => {
                    match link.engine.handle_identify(packet.data()) {
                        Ok(link_actions) => {
                            let link_id = *link.engine.link_id();
                            link.remote_identity = link.engine.remote_identity().cloned();
                            LinkDataResult::Identify {
                                link_id,
                                link_actions,
                            }
                        }
                        Err(e) => {
                            log::debug!("LINKIDENTIFY failed: {}", e);
                            LinkDataResult::Error
                        }
                    }
                }
                constants::CONTEXT_KEEPALIVE => {
                    let received_at = time::now();
                    // On a direct path (an rns-rs peer) every probe is
                    // answered: the initiator's inbound timer then never
                    // depends on the reply-suppression rule, and a stale
                    // link there means the path is silent.
                    let reply = link
                        .engine
                        .should_reply_keepalive(packet.data(), received_at)
                        || (link.direct_route.is_some()
                            && !link.engine.is_initiator()
                            && packet.data() == [0xff]);
                    let link_id = *link.engine.link_id();
                    LinkDataResult::Keepalive {
                        link_id,
                        reply,
                        received_at,
                    }
                }
                constants::CONTEXT_LINKCLOSE => match decrypt(&link.engine, packet.data()) {
                    Ok(plaintext) if plaintext.as_slice() == link_id_bytes => {
                        let teardown_actions = link.engine.handle_teardown();
                        let link_id = *link.engine.link_id();
                        LinkDataResult::LinkClose {
                            link_id,
                            teardown_actions,
                        }
                    }
                    _ => LinkDataResult::Error,
                },
                constants::CONTEXT_CHANNEL => match decrypt(&link.engine, packet.data()) {
                    Ok(plaintext) => {
                        let link_id = *link.engine.link_id();
                        LinkDataResult::Channel {
                            link_id,
                            plaintext,
                            packet_hash,
                        }
                    }
                    Err(_) => LinkDataResult::Error,
                },
                constants::CONTEXT_REQUEST => match decrypt(&link.engine, packet.data()) {
                    Ok(plaintext) => {
                        let link_id = *link.engine.link_id();
                        let request_id = packet.get_truncated_hash();
                        LinkDataResult::Request {
                            link_id,
                            plaintext,
                            request_id,
                        }
                    }
                    Err(_) => LinkDataResult::Error,
                },
                rns_core::holepunch::CONTEXT_DIRECT_LINK => {
                    match decrypt(&link.engine, packet.data()) {
                        Ok(plaintext) => {
                            let link_id = *link.engine.link_id();
                            LinkDataResult::DirectLink { link_id, plaintext }
                        }
                        Err(_) => LinkDataResult::Error,
                    }
                }
                constants::CONTEXT_RESPONSE => match decrypt(&link.engine, packet.data()) {
                    Ok(plaintext) => {
                        let link_id = *link.engine.link_id();
                        LinkDataResult::Response { link_id, plaintext }
                    }
                    Err(_) => LinkDataResult::Error,
                },
                // --- Resource contexts ---
                constants::CONTEXT_RESOURCE_ADV => match decrypt(&link.engine, packet.data()) {
                    Ok(plaintext) => {
                        let link_id = *link.engine.link_id();
                        LinkDataResult::ResourceAdv { link_id, plaintext }
                    }
                    Err(_) => LinkDataResult::Error,
                },
                constants::CONTEXT_RESOURCE_REQ => match decrypt(&link.engine, packet.data()) {
                    Ok(plaintext) => {
                        let link_id = *link.engine.link_id();
                        LinkDataResult::ResourceReq { link_id, plaintext }
                    }
                    Err(_) => LinkDataResult::Error,
                },
                constants::CONTEXT_RESOURCE_HMU => match decrypt(&link.engine, packet.data()) {
                    Ok(plaintext) => {
                        let link_id = *link.engine.link_id();
                        LinkDataResult::ResourceHmu { link_id, plaintext }
                    }
                    Err(_) => LinkDataResult::Error,
                },
                constants::CONTEXT_RESOURCE => {
                    // Resource parts are NOT link-decrypted — they're pre-encrypted by ResourceSender
                    let link_id = *link.engine.link_id();
                    LinkDataResult::ResourcePart {
                        link_id,
                        raw_data: packet.data(),
                    }
                }
                constants::CONTEXT_RESOURCE_PRF => match decrypt(&link.engine, packet.data()) {
                    Ok(plaintext) => {
                        let link_id = *link.engine.link_id();
                        LinkDataResult::ResourcePrf { link_id, plaintext }
                    }
                    Err(_) => LinkDataResult::Error,
                },
                constants::CONTEXT_RESOURCE_ICL => match decrypt(&link.engine, packet.data()) {
                    Ok(resource_hash) if resource_hash.len() == 32 => {
                        let link_id = *link.engine.link_id();
                        LinkDataResult::ResourceIcl {
                            link_id,
                            resource_hash,
                        }
                    }
                    _ => LinkDataResult::Error,
                },
                constants::CONTEXT_RESOURCE_RCL => match decrypt(&link.engine, packet.data()) {
                    Ok(resource_hash) if resource_hash.len() == 32 => {
                        let link_id = *link.engine.link_id();
                        LinkDataResult::ResourceRcl {
                            link_id,
                            resource_hash,
                        }
                    }
                    _ => LinkDataResult::Error,
                },
                _ => match decrypt(&link.engine, packet.data()) {
                    Ok(plaintext) => {
                        let link_id = *link.engine.link_id();
                        LinkDataResult::Generic {
                            link_id,
                            plaintext,
                            context: packet.context,
                            packet_hash,
                        }
                    }
                    Err(_) => LinkDataResult::Error,
                },
            }
        }; // mutable borrow of self.links dropped here
        self.plaintext_scratch = scratch;

        // Second pass: process results using self methods
        match result {
            LinkDataResult::Lrrtt {
                link_id,
                link_actions,
            } => {
                out.extend(self.process_link_actions(&link_id, &link_actions));
                // Initialize channel
                if let Some(link) = self.links.get_mut(&link_id) {
                    if link.engine.state() == LinkState::Active {
                        let rtt = link.engine.rtt().unwrap_or(1.0);
                        link.channel = Some(Channel::new(rtt));
                    }
                }
                let pending = self
                    .links
                    .get_mut(&link_id)
                    .map(|link| std::mem::take(&mut link.pre_rtt_packets))
                    .unwrap_or_default();
                for pending in pending {
                    self.handle_link_data_into(
                        &link_id,
                        &pending.packet.as_view(),
                        pending.packet_hash,
                        pending.receiving_interface,
                        rng,
                        out,
                    );
                }
            }
            LinkDataResult::Identify {
                link_id,
                link_actions,
            } => {
                out.extend(self.process_link_actions(&link_id, &link_actions));
            }
            LinkDataResult::Keepalive {
                link_id,
                reply,
                received_at,
            } => {
                log::debug!(
                    "Link keepalive received: link={:02x?} reply={reply}",
                    &link_id[..4]
                );
                if reply {
                    out.extend(Self::keepalive_packet(&link_id, 0xfe));
                    if let Some(link) = self.links.get_mut(&link_id) {
                        link.engine.record_outbound(received_at, true);
                    }
                }
            }
            LinkDataResult::LinkClose {
                link_id,
                teardown_actions,
            } => {
                out.extend(self.process_link_actions(&link_id, &teardown_actions));
            }
            LinkDataResult::DirectLink { link_id, plaintext } => {
                out.push(LinkManagerAction::DirectLinkSignal {
                    link_id,
                    data: plaintext,
                });
            }
            LinkDataResult::Channel {
                link_id,
                plaintext,
                packet_hash,
            } => {
                // Feed plaintext to channel
                if let Some(link) = self.links.get_mut(&link_id) {
                    if let Some(ref mut channel) = link.channel {
                        let chan_actions = channel.receive(&plaintext, time::now());
                        link.channel_messages_received += chan_actions
                            .iter()
                            .filter(|action| {
                                matches!(
                                    action,
                                    rns_core::channel::ChannelAction::MessageReceived { .. }
                                )
                            })
                            .count()
                            as u64;
                        // process_channel_actions needs immutable self, so collect first
                        let _ = link;
                        out.extend(self.process_channel_actions(&link_id, chan_actions, rng));
                    }
                }
                out.extend(self.build_link_packet_proof(&link_id, &packet_hash));
                self.recycle_plaintext(plaintext);
            }
            LinkDataResult::Request {
                link_id,
                plaintext,
                request_id,
            } => {
                let size_ok = self
                    .links
                    .get(&link_id)
                    .and_then(|link| link.max_request_size)
                    .is_none_or(|limit| plaintext.len() <= limit);
                if size_ok {
                    out.extend(self.handle_request(&link_id, &plaintext, request_id, rng));
                } else {
                    log::debug!(
                        "ignored request with excessive size {} bytes on link {:02x?}",
                        plaintext.len(),
                        &link_id[..4]
                    );
                }
                self.recycle_plaintext(plaintext);
            }
            LinkDataResult::Response { link_id, plaintext } => {
                // Unpack msgpack response: [Bin(request_id), response_value]
                out.extend(self.handle_response(&link_id, &plaintext, None, None));
                self.recycle_plaintext(plaintext);
            }
            LinkDataResult::Generic {
                link_id,
                plaintext,
                context,
                packet_hash,
            } => {
                out.push(LinkManagerAction::LinkDataReceived {
                    link_id,
                    context,
                    data: plaintext,
                });
                if let Some(link) = self.links.get(&link_id) {
                    out.push(LinkManagerAction::ProofRequired {
                        link_id,
                        dest_hash: link.dest_hash,
                        packet_hash,
                    });
                }
            }
            LinkDataResult::ResourceAdv { link_id, plaintext } => {
                out.extend(self.handle_resource_adv(&link_id, &plaintext, rng));
                self.recycle_plaintext(plaintext);
            }
            LinkDataResult::ResourceReq { link_id, plaintext } => {
                self.handle_resource_req_into(&link_id, &plaintext, rng, out);
                self.recycle_plaintext(plaintext);
            }
            LinkDataResult::ResourceHmu { link_id, plaintext } => {
                out.extend(self.handle_resource_hmu(&link_id, &plaintext, rng));
                self.recycle_plaintext(plaintext);
            }
            LinkDataResult::ResourcePart { link_id, raw_data } => {
                self.handle_resource_part_into(&link_id, raw_data, rng, out);
            }
            LinkDataResult::ResourcePrf { link_id, plaintext } => {
                out.extend(self.handle_resource_prf(&link_id, &plaintext, rng));
                self.recycle_plaintext(plaintext);
            }
            LinkDataResult::ResourceIcl {
                link_id,
                resource_hash,
            } => {
                out.extend(self.handle_resource_icl(&link_id, &resource_hash, rng));
            }
            LinkDataResult::ResourceRcl {
                link_id,
                resource_hash,
            } => {
                out.extend(self.handle_resource_rcl(&link_id, &resource_hash));
            }
            LinkDataResult::Error => {}
        }
    }
}
