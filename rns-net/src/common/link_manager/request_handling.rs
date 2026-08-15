use super::*;

impl LinkManager {
    /// Handle a request on a link.
    pub(super) fn handle_request(
        &mut self,
        link_id: &LinkId,
        plaintext: &[u8],
        request_id: [u8; 16],
        rng: &mut dyn Rng,
    ) -> Vec<LinkManagerAction> {
        use rns_core::msgpack::{self, Value};

        // Python-compatible format: msgpack([timestamp, Bin(path_hash), data_value])
        let arr = match msgpack::unpack_exact(plaintext) {
            Ok(Value::Array(arr)) if arr.len() >= 3 => arr,
            _ => return Vec::new(),
        };

        let path_hash_bytes = match &arr[1] {
            Value::Bin(b) if b.len() == 16 => b,
            _ => return Vec::new(),
        };
        let mut path_hash = [0u8; 16];
        path_hash.copy_from_slice(path_hash_bytes);

        // Re-encode the data element for the handler
        let request_data = msgpack::pack(&arr[2]);

        // Check if this is a management path (handled by the driver)
        if self.management_paths.contains(&path_hash) {
            let remote_identity = self
                .links
                .get(link_id)
                .and_then(|l| l.remote_identity)
                .map(|(h, k)| (h, k));
            return vec![LinkManagerAction::ManagementRequest {
                link_id: *link_id,
                path_hash,
                data: request_data,
                request_id,
                remote_identity,
            }];
        }

        if let Some(handler) = self
            .deferred_request_handlers
            .iter()
            .find(|handler| handler.path_hash == path_hash)
        {
            let remote_identity = self
                .links
                .get(link_id)
                .and_then(|link| link.remote_identity.as_ref());
            if let Some(allowed) = &handler.allowed_list {
                let Some((identity_hash, _)) = remote_identity else {
                    log::debug!("Deferred request denied: peer not identified");
                    return Vec::new();
                };
                if !allowed.contains(identity_hash) {
                    log::debug!("Deferred request denied: identity not in allowed list");
                    return Vec::new();
                }
            }
            (handler.handler)(
                *link_id,
                &handler.path,
                request_id,
                &request_data,
                remote_identity,
            );
            return Vec::new();
        }

        // Look up handler by path_hash
        let handler_idx = self
            .request_handlers
            .iter()
            .position(|h| h.path_hash == path_hash);
        let handler_idx = match handler_idx {
            Some(i) => i,
            None => return Vec::new(),
        };

        // Check ACL
        let remote_identity = self
            .links
            .get(link_id)
            .and_then(|l| l.remote_identity.as_ref());
        let handler = &self.request_handlers[handler_idx];
        if let Some(ref allowed) = handler.allowed_list {
            match remote_identity {
                Some((identity_hash, _)) => {
                    if !allowed.contains(identity_hash) {
                        log::debug!("Request denied: identity not in allowed list");
                        return Vec::new();
                    }
                }
                None => {
                    log::debug!("Request denied: peer not identified");
                    return Vec::new();
                }
            }
        }

        // Call handler
        let path = handler.path.clone();
        let response = (handler.handler)(*link_id, &path, &request_data, remote_identity);

        let mut actions = Vec::new();
        if let Some(response) = response {
            match response {
                RequestResponse::Bytes(response_data) => {
                    let mut response_actions =
                        self.build_response_packet(link_id, &request_id, &response_data, rng);
                    if response_actions.is_empty() {
                        response_actions.extend(self.send_response_resource(
                            link_id,
                            &request_id,
                            &response_data,
                            None,
                            true,
                            rng,
                        ));
                    }
                    actions.extend(response_actions);
                }
                RequestResponse::Resource {
                    data,
                    metadata,
                    auto_compress,
                } => {
                    actions.extend(self.send_response_resource(
                        link_id,
                        &request_id,
                        &data,
                        metadata.as_deref(),
                        auto_compress,
                        rng,
                    ));
                }
            }
        }

        actions
    }

    /// Build a response packet for a request.
    /// `response_data` is the msgpack-encoded response value.
    fn build_response_packet(
        &self,
        link_id: &LinkId,
        request_id: &[u8; 16],
        response_data: &[u8],
        rng: &mut dyn Rng,
    ) -> Vec<LinkManagerAction> {
        use rns_core::msgpack::{self, Value};

        let response_value = msgpack::unpack_exact(response_data)
            .unwrap_or_else(|_| Value::Bin(response_data.to_vec()));

        let response_array = Value::Array(vec![Value::Bin(request_id.to_vec()), response_value]);
        let response_plaintext = msgpack::pack(&response_array);

        let mut actions = Vec::new();
        if let Some(link) = self.links.get(link_id) {
            if let Ok(encrypted) = link.engine.encrypt(&response_plaintext, rng) {
                let flags = PacketFlags {
                    header_type: constants::HEADER_1,
                    context_flag: constants::FLAG_UNSET,
                    transport_type: constants::TRANSPORT_BROADCAST,
                    destination_type: constants::DESTINATION_LINK,
                    packet_type: constants::PACKET_TYPE_DATA,
                };
                let max_mtu = link.engine.mtu() as usize;
                if let Ok((raw, _packet_hash)) = RawPacket::pack_raw_with_hash_with_max_mtu(
                    flags,
                    0,
                    link_id,
                    None,
                    constants::CONTEXT_RESPONSE,
                    &encrypted,
                    max_mtu,
                ) {
                    actions.push(LinkManagerAction::SendPacket {
                        raw,
                        dest_type: constants::DESTINATION_LINK,
                        attached_interface: None,
                    });
                }
            }
        }
        actions
    }

    pub(super) fn send_response_resource(
        &mut self,
        link_id: &LinkId,
        request_id: &[u8; 16],
        response_data: &[u8],
        metadata: Option<&[u8]>,
        auto_compress: bool,
        rng: &mut dyn Rng,
    ) -> Vec<LinkManagerAction> {
        use rns_core::msgpack::{self, Value};

        let link = match self.links.get_mut(link_id) {
            Some(l) => l,
            None => return Vec::new(),
        };

        if link.engine.state() != LinkState::Active {
            return Vec::new();
        }

        let now = time::now();

        // Match Python resource response format from Link.handle_request:
        // packed_response = msgpack([request_id, response_value])
        // where response_value is decoded msgpack value, or Bin(raw bytes).
        let response_value = msgpack::unpack_exact(response_data)
            .unwrap_or_else(|_| Value::Bin(response_data.to_vec()));
        let response_array = Value::Array(vec![Value::Bin(request_id.to_vec()), response_value]);
        let resource_payload = msgpack::pack(&response_array);

        let senders = match Self::build_resource_senders(
            link,
            &resource_payload,
            metadata,
            auto_compress,
            true, // is_response
            Some(request_id.to_vec()),
            rng,
            now,
        ) {
            Ok(s) => s,
            Err(e) => {
                log::debug!("Failed to create response ResourceSender: {}", e);
                return Vec::new();
            }
        };

        let adv_actions = Self::start_resource_senders(link, senders, now);

        let _ = link;
        self.process_resource_actions(link_id, adv_actions, rng)
    }

    /// Send the value for a previously accepted deferred request.
    pub fn send_deferred_response(
        &mut self,
        link_id: &LinkId,
        request_id: &[u8; 16],
        response_data: &[u8],
        rng: &mut dyn Rng,
    ) -> Vec<LinkManagerAction> {
        let packet_actions = self.build_response_packet(link_id, request_id, response_data, rng);
        if !packet_actions.is_empty() {
            packet_actions
        } else {
            self.send_response_resource(link_id, request_id, response_data, None, true, rng)
        }
    }

    /// Send a management response on a link.
    /// Called by the driver after building the response for a ManagementRequest.
    pub fn send_management_response(
        &mut self,
        link_id: &LinkId,
        request_id: &[u8; 16],
        response_data: &[u8],
        rng: &mut dyn Rng,
    ) -> Vec<LinkManagerAction> {
        let mut actions = self.build_response_packet(link_id, request_id, response_data, rng);
        if actions.is_empty() {
            actions.extend(self.send_response_resource(
                link_id,
                request_id,
                response_data,
                None,
                true,
                rng,
            ));
        }
        actions
    }

    /// Send a request on a link.
    ///
    /// `data` is the msgpack-encoded request data value (e.g. msgpack([True]) for /status).
    ///
    /// Uses Python-compatible format: plaintext = msgpack([timestamp, path_hash_bytes, data_value]).
    /// Returns actions (the encrypted request packet). The response will arrive
    /// later via handle_local_delivery with CONTEXT_RESPONSE.
    pub fn send_request(
        &mut self,
        link_id: &LinkId,
        path: &str,
        data: &[u8],
        rng: &mut dyn Rng,
    ) -> Vec<LinkManagerAction> {
        self.send_request_with_max_response_size(link_id, path, data, None, rng)
    }

    /// Send a request with an optional maximum accepted response size.
    pub fn send_request_with_max_response_size(
        &mut self,
        link_id: &LinkId,
        path: &str,
        data: &[u8],
        max_response_size: Option<usize>,
        rng: &mut dyn Rng,
    ) -> Vec<LinkManagerAction> {
        use rns_core::msgpack::{self, Value};

        let link = match self.links.get_mut(link_id) {
            Some(l) => l,
            None => return Vec::new(),
        };

        if link.engine.state() != LinkState::Active {
            return Vec::new();
        }

        let path_hash = compute_path_hash(path);

        // Decode data bytes to msgpack Value (or use Bin if can't decode)
        let data_value = msgpack::unpack_exact(data).unwrap_or_else(|_| Value::Bin(data.to_vec()));

        // Python-compatible format: msgpack([timestamp, Bin(path_hash), data_value])
        let request_array = Value::Array(vec![
            Value::Float(time::now()),
            Value::Bin(path_hash.to_vec()),
            data_value,
        ]);
        let plaintext = msgpack::pack(&request_array);

        if plaintext.len() > link.engine.mdu() {
            let request_id = rns_core::hash::truncated_hash(&plaintext);
            let now = time::now();
            let senders = match Self::build_resource_senders(
                link,
                &plaintext,
                None,
                true,
                false,
                Some(request_id.to_vec()),
                rng,
                now,
            ) {
                Ok(senders) => senders,
                Err(e) => {
                    log::debug!("Failed to create request ResourceSender: {}", e);
                    return Vec::new();
                }
            };
            // Resource request response timing starts once the remote proves
            // receipt of the final request-resource segment.
            link.pending_requests.insert(
                request_id,
                PendingRequest {
                    deadline: None,
                    max_response_size,
                },
            );
            let adv_actions = Self::start_resource_senders(link, senders, now);
            let _ = link;
            return self.process_resource_actions(link_id, adv_actions, rng);
        }

        let encrypted = match link.engine.encrypt(&plaintext, rng) {
            Ok(e) => e,
            Err(_) => return Vec::new(),
        };

        let flags = PacketFlags {
            header_type: constants::HEADER_1,
            context_flag: constants::FLAG_UNSET,
            transport_type: constants::TRANSPORT_BROADCAST,
            destination_type: constants::DESTINATION_LINK,
            packet_type: constants::PACKET_TYPE_DATA,
        };

        let mut actions = Vec::new();
        let max_mtu = link.engine.mtu() as usize;
        if let Ok((raw, packet_hash)) = RawPacket::pack_raw_with_hash_with_max_mtu(
            flags,
            0,
            link_id,
            None,
            constants::CONTEXT_REQUEST,
            &encrypted,
            max_mtu,
        ) {
            let mut request_id = [0u8; 16];
            request_id.copy_from_slice(&packet_hash[..16]);
            let deadline = Self::request_response_deadline(link, time::now());
            link.pending_requests.insert(
                request_id,
                PendingRequest {
                    deadline: Some(deadline),
                    max_response_size,
                },
            );
            actions.push(LinkManagerAction::SendPacket {
                raw,
                dest_type: constants::DESTINATION_LINK,
                attached_interface: None,
            });
        }
        actions
    }

    /// Send encrypted data on a link with a given context.
    /// Handle a response on a link.
    pub(super) fn handle_response(
        &mut self,
        link_id: &LinkId,
        plaintext: &[u8],
        metadata: Option<Vec<u8>>,
        resource_request_id: Option<[u8; 16]>,
    ) -> Vec<LinkManagerAction> {
        use rns_core::msgpack;

        // Python-compatible packet response: msgpack([Bin(request_id), response_value]).
        let packet_response = msgpack::unpack_exact(plaintext).ok().and_then(|value| {
            let msgpack::Value::Array(arr) = value else {
                return None;
            };
            if arr.len() < 2 {
                return None;
            }
            let msgpack::Value::Bin(request_id_bytes) = &arr[0] else {
                return None;
            };
            if request_id_bytes.len() != 16 {
                return None;
            }
            let mut request_id = [0u8; 16];
            request_id.copy_from_slice(request_id_bytes);
            Some((request_id, msgpack::pack(&arr[1])))
        });

        let (request_id, response_data, check_size) = match packet_response {
            Some((request_id, response_data)) => (request_id, response_data, true),
            None => {
                let Some(request_id) = resource_request_id else {
                    return Vec::new();
                };
                (
                    request_id,
                    msgpack::pack(&msgpack::Value::Bin(plaintext.to_vec())),
                    false,
                )
            }
        };

        let Some(link) = self.links.get_mut(link_id) else {
            return Vec::new();
        };
        let Some(pending) = link.pending_requests.get(&request_id) else {
            return Vec::new();
        };
        if check_size {
            // Upstream excludes the two-byte MessagePack binary wrapper from
            // packet response sizes. Resource responses are checked from the
            // advertisement before their transfer is accepted.
            let response_size = response_data.len().saturating_sub(2) as u64;
            if let Some(maximum) = pending.max_response_size {
                if response_size > maximum as u64 {
                    link.pending_requests.remove(&request_id);
                    log::debug!(
                        "rejected response with excessive size {} bytes on link {:02x?}",
                        response_size,
                        &link_id[..4]
                    );
                    return vec![LinkManagerAction::RequestFailed {
                        link_id: *link_id,
                        request_id,
                        reason: RequestFailure::ResponseTooLarge {
                            size: response_size,
                            maximum,
                        },
                    }];
                }
            }
        }
        link.pending_requests.remove(&request_id);

        vec![LinkManagerAction::ResponseReceived {
            link_id: *link_id,
            request_id,
            data: response_data,
            metadata,
        }]
    }

    pub(super) fn response_request_id(request_id: &Option<Vec<u8>>) -> Option<[u8; 16]> {
        let bytes = request_id.as_deref()?;
        if bytes.len() != 16 {
            return None;
        }
        let mut out = [0u8; 16];
        out.copy_from_slice(bytes);
        Some(out)
    }
}
