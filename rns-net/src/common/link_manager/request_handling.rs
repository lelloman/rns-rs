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
        use rns_core::msgpack::{self, ValueRef};

        // Python-compatible format: msgpack([timestamp, Bin(path_hash), data_value])
        let request = match msgpack::unpack_exact_ref(plaintext) {
            Ok(request @ ValueRef::Array { len, .. }) if len >= 3 => request,
            _ => return Vec::new(),
        };
        let mut items = request.array_items().into_iter().flatten().skip(1);
        let (Some(ValueRef::Bin(path_hash_bytes)), Some(data_value)) = (items.next(), items.next())
        else {
            return Vec::new();
        };
        let Ok(path_hash) = <[u8; 16]>::try_from(path_hash_bytes) else {
            return Vec::new();
        };

        // Re-encode the data element for the handler
        let mut request_data = Vec::with_capacity(plaintext.len());
        msgpack::pack_ref_into(data_value, &mut request_data);

        // Check if this is a management path (handled by the driver)
        if self.management_paths.contains(&path_hash) {
            let remote_identity = self.links.get(link_id).and_then(|l| l.remote_identity);
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
                RequestResponse::File {
                    data,
                    metadata,
                    auto_compress,
                } => {
                    actions.extend(self.send_file_response_resource(
                        link_id,
                        &request_id,
                        &data,
                        Some(&metadata),
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
        let response_plaintext = pack_response(request_id, response_data);

        let mut actions = Vec::new();
        self.build_encrypted_link_packet_into(
            link_id,
            constants::CONTEXT_RESPONSE,
            &response_plaintext,
            rng,
            &mut actions,
        );
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
        let resource_payload = pack_response(request_id, response_data);
        self.send_file_response_resource(
            link_id,
            request_id,
            &resource_payload,
            metadata,
            auto_compress,
            rng,
        )
    }

    fn send_file_response_resource(
        &mut self,
        link_id: &LinkId,
        request_id: &[u8; 16],
        resource_payload: &[u8],
        metadata: Option<&[u8]>,
        auto_compress: bool,
        rng: &mut dyn Rng,
    ) -> Vec<LinkManagerAction> {
        let link = match self.links.get_mut(link_id) {
            Some(l) => l,
            None => return Vec::new(),
        };

        if link.engine.state() != LinkState::Active {
            return Vec::new();
        }

        let now = time::now();

        let senders = match Self::build_resource_senders(
            link,
            ResourceSendParams {
                compressor: &Bzip2Compressor,
                data: resource_payload,
                metadata,
                auto_compress,
                app_flag: false,
                is_response: true,
                request_id: Some(request_id.to_vec()),
                rng,
                now,
            },
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
        use rns_core::msgpack::{self, ValueRef};

        let link = match self.links.get_mut(link_id) {
            Some(l) => l,
            None => return Vec::new(),
        };

        if link.engine.state() != LinkState::Active {
            return Vec::new();
        }

        let path_hash = compute_path_hash(path);

        // Python-compatible format: msgpack([timestamp, Bin(path_hash), data_value]),
        // with the data as the msgpack it holds, or as Bin if it holds none.
        let mut plaintext = Vec::with_capacity(data.len() + 32);
        msgpack::pack_array_header(3, &mut plaintext);
        msgpack::pack_ref_into(ValueRef::Float(time::now()), &mut plaintext);
        msgpack::pack_bin_into(&path_hash, &mut plaintext);
        pack_msgpack_or_bin(data, &mut plaintext);

        if plaintext.len() > link.engine.mdu() {
            let request_id = rns_core::hash::truncated_hash(&plaintext);
            let now = time::now();
            let senders = match Self::build_resource_senders(
                link,
                ResourceSendParams {
                    compressor: &Bzip2Compressor,
                    data: &plaintext,
                    metadata: None,
                    auto_compress: true,
                    app_flag: false,
                    is_response: false,
                    request_id: Some(request_id.to_vec()),
                    rng,
                    now,
                },
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

        let mut actions = Vec::new();
        let max_mtu = link.engine.mtu() as usize;
        if let Some(raw) = super::resource_handling::encrypted_link_packet(
            &link.engine,
            link_id,
            constants::CONTEXT_REQUEST,
            &plaintext,
            rng,
            max_mtu,
        ) {
            let packet_hash = RawPacket::packet_hash_of(constants::HEADER_1, &raw);
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
        let packet_response = msgpack::unpack_exact_ref(plaintext).ok().and_then(|value| {
            let msgpack::ValueRef::Array { len, .. } = value else {
                return None;
            };
            if len < 2 {
                return None;
            }
            let mut items = value.array_items()?;
            let request_id = <[u8; 16]>::try_from(items.next()?.as_bin()?).ok()?;
            let mut response_data = Vec::with_capacity(plaintext.len());
            msgpack::pack_ref_into(items.next()?, &mut response_data);
            Some((request_id, response_data))
        });

        let (request_id, response_data, check_size) = match packet_response {
            Some((request_id, response_data)) => (request_id, response_data, true),
            None => {
                let Some(request_id) = resource_request_id else {
                    return Vec::new();
                };
                let mut response_data = Vec::with_capacity(plaintext.len() + 5);
                msgpack::pack_bin_into(plaintext, &mut response_data);
                (request_id, response_data, false)
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

/// Append `data` as the msgpack value it holds, or as Bin if it holds none.
fn pack_msgpack_or_bin(data: &[u8], buf: &mut Vec<u8>) {
    use rns_core::msgpack;
    match msgpack::unpack_exact_ref(data) {
        Ok(value) => msgpack::pack_ref_into(value, buf),
        Err(_) => msgpack::pack_bin_into(data, buf),
    }
}

/// Python-compatible response: msgpack([Bin(request_id), response_value]).
fn pack_response(request_id: &[u8; 16], response_data: &[u8]) -> Vec<u8> {
    let mut packed = Vec::with_capacity(response_data.len() + 24);
    rns_core::msgpack::pack_array_header(2, &mut packed);
    rns_core::msgpack::pack_bin_into(request_id, &mut packed);
    pack_msgpack_or_bin(response_data, &mut packed);
    packed
}
