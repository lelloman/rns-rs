//! HolePunchEngine: pure-logic state machine for NAT hole punching.
//!
//! Follows the asymmetric protocol from direct-link-protocol.md:
//!
//! Phase 1: A probes facilitator T → learns A_pub
//! Phase 2: A sends UPGRADE_REQUEST {facilitator: T, initiator_public: A_pub} → B
//!          B responds with UPGRADE_ACCEPT or UPGRADE_REJECT
//! Phase 3: B probes T (from request) → learns B_pub
//!          B sends UPGRADE_READY {responder_public: B_pub} → A
//! Phase 4: Both punch simultaneously; the first verified punch packet or
//!          acknowledgement from the peer establishes the direct path
//!
//! Methods return `Vec<HolePunchAction>` instead of performing I/O.

use alloc::vec::Vec;

use rns_crypto::hkdf::hkdf;
use rns_crypto::Rng;

use crate::msgpack::{self, Value};

use super::types::*;

/// Derives a 32-byte punch token from the link's derived key and session ID.
///
/// `HKDF(ikm=derived_key, salt=session_id, info="rns-holepunch-v1")[:32]`.
/// It keys the tags of the punch packets and their acknowledgements, and
/// never appears on the wire.
pub fn derive_punch_token(
    derived_key: &[u8],
    session_id: &[u8; 16],
) -> Result<[u8; 32], HolePunchError> {
    let result = hkdf(32, derived_key, Some(session_id), Some(b"rns-holepunch-v1"))
        .map_err(|_| HolePunchError::NoDerivedKey)?;
    let mut token = [0u8; 32];
    token.copy_from_slice(&result);
    Ok(token)
}

/// Derives the 32-byte key that authenticates the direct path's keepalives.
///
/// `HKDF(ikm=derived_key, salt=session_id, info="rns-holepunch-keepalive-v1")`.
/// Like the punch token, it never appears on the wire.
pub fn derive_keepalive_key(
    derived_key: &[u8],
    session_id: &[u8; 16],
) -> Result<[u8; 32], HolePunchError> {
    let result = hkdf(
        32,
        derived_key,
        Some(session_id),
        Some(b"rns-holepunch-keepalive-v1"),
    )
    .map_err(|_| HolePunchError::NoDerivedKey)?;
    let mut key = [0u8; 32];
    key.copy_from_slice(&result);
    Ok(key)
}

/// The hole-punch state machine for a single link.
pub struct HolePunchEngine {
    link_id: [u8; 16],
    session_id: [u8; 16],
    state: HolePunchState,
    is_initiator: bool,

    /// Our discovered public endpoint.
    our_public_endpoint: Option<Endpoint>,

    /// Peer's public endpoint.
    /// Initiator: received from UPGRADE_READY.
    /// Responder: received from UPGRADE_REQUEST.
    peer_public_endpoint: Option<Endpoint>,

    /// Our host candidates, sent with our public endpoint.
    our_host_endpoints: Vec<Endpoint>,

    /// The peer's host candidates, received with its public endpoint.
    peer_host_endpoints: Vec<Endpoint>,

    /// Facilitator (STUN probe) address.
    /// Initiator: our configured probe address.
    /// Responder: received from UPGRADE_REQUEST.
    facilitator_addr: Option<Endpoint>,

    /// Punch token derived from link key + session_id.
    punch_token: [u8; 32],

    /// Key authenticating the direct path's keepalives.
    keepalive_key: [u8; 32],

    /// Probe service address for endpoint discovery (configured on this node).
    probe_addr: Option<Endpoint>,

    /// Protocol to use for endpoint discovery.
    probe_protocol: ProbeProtocol,

    /// Timestamp of state entry (for timeout tracking).
    state_entered_at: f64,

    /// Initiator: the UPGRADE_REQUEST body, resent until the responder's
    /// READY arrives.
    request_payload: Option<Vec<u8>>,

    /// Initiator: when the UPGRADE_REQUEST was last sent.
    request_sent_at: f64,

    /// Largest link packet the peer accepts on the direct path (`m` in its
    /// UPGRADE_REQUEST or UPGRADE_READY), if it said.
    peer_max_packet: Option<u32>,
}

impl HolePunchEngine {
    /// Validate an upgrade request without creating or mutating a session.
    pub fn validate_upgrade_request(payload: &[u8]) -> Result<(), HolePunchError> {
        decode_upgrade_request(payload).map(|_| ())
    }

    /// Create a new engine for the given link. Does not start any session.
    pub fn new(
        link_id: [u8; 16],
        probe_addr: Option<Endpoint>,
        probe_protocol: ProbeProtocol,
    ) -> Self {
        HolePunchEngine {
            link_id,
            session_id: [0u8; 16],
            state: HolePunchState::Idle,
            is_initiator: false,
            our_public_endpoint: None,
            peer_public_endpoint: None,
            our_host_endpoints: Vec::new(),
            peer_host_endpoints: Vec::new(),
            facilitator_addr: None,
            punch_token: [0u8; 32],
            keepalive_key: [0u8; 32],
            probe_addr,
            probe_protocol,
            state_entered_at: 0.0,
            request_payload: None,
            request_sent_at: 0.0,
            peer_max_packet: None,
        }
    }

    /// The session an UPGRADE_REQUEST belongs to, without creating a session.
    pub fn request_session_id(payload: &[u8]) -> Result<[u8; 16], HolePunchError> {
        decode_upgrade_request(payload).map(|request| request.session_id)
    }

    /// Responder: the replies already sent for this session (ACCEPT, and
    /// READY once our endpoint is known), for answering a repeated
    /// UPGRADE_REQUEST whose earlier replies may have been lost.
    pub fn replay_replies(&self) -> Vec<HolePunchAction> {
        if self.is_initiator
            || !matches!(
                self.state,
                HolePunchState::Discovering | HolePunchState::Punching | HolePunchState::Connected
            )
        {
            return Vec::new();
        }
        let mut actions = alloc::vec![HolePunchAction::SendSignal {
            link_id: self.link_id,
            msgtype: UPGRADE_ACCEPT,
            payload: encode_upgrade_accept(&self.session_id),
        }];
        if let Some(ours) = &self.our_public_endpoint {
            actions.push(HolePunchAction::SendSignal {
                link_id: self.link_id,
                msgtype: UPGRADE_READY,
                payload: encode_upgrade_ready(&self.session_id, ours, &self.our_host_endpoints),
            });
        }
        actions
    }

    /// Current state.
    pub fn state(&self) -> HolePunchState {
        self.state
    }

    /// Current session ID; all zeroes when no session has started.
    pub fn session_id(&self) -> &[u8; 16] {
        &self.session_id
    }

    /// Whether this end proposed the current session.
    pub fn is_initiator(&self) -> bool {
        self.is_initiator
    }

    /// Punch token of the current session (see [`derive_punch_token`]).
    pub fn punch_token(&self) -> &[u8; 32] {
        &self.punch_token
    }

    /// Direct-path keepalive key of the current session (see [`derive_keepalive_key`]).
    pub fn keepalive_key(&self) -> &[u8; 32] {
        &self.keepalive_key
    }

    /// Override the facilitator address.
    ///
    /// Used when the orchestrator discovers that a different probe server
    /// succeeded (failover). Must be called before `endpoints_discovered()`
    /// so the UPGRADE_REQUEST carries the correct facilitator.
    pub fn set_facilitator(&mut self, addr: Endpoint) {
        self.facilitator_addr = Some(addr);
    }

    /// Peer's discovered public endpoint.
    pub fn peer_public_endpoint(&self) -> Option<&Endpoint> {
        self.peer_public_endpoint.as_ref()
    }

    /// Largest link packet the peer accepts on the direct path, if it
    /// advertised one (see [`DIRECT_MAX_PACKET`]).
    pub fn peer_max_packet(&self) -> Option<u32> {
        self.peer_max_packet
    }

    /// The peer's host candidates (at most [`MAX_HOST_CANDIDATES`]).
    pub fn peer_host_endpoints(&self) -> &[Endpoint] {
        &self.peer_host_endpoints
    }

    /// Set the host candidates sent with our public endpoint, before
    /// [`endpoints_discovered`](Self::endpoints_discovered). At most
    /// [`MAX_HOST_CANDIDATES`] are kept.
    pub fn set_host_endpoints(&mut self, mut hosts: Vec<Endpoint>) {
        hosts.truncate(MAX_HOST_CANDIDATES);
        self.our_host_endpoints = hosts;
    }

    /// Propose a direct connection (initiator side).
    ///
    /// Per the spec, the initiator first discovers its own public endpoint
    /// (Phase 1) before sending the upgrade request.
    ///
    /// Transitions: Idle -> Discovering.
    pub fn propose(
        &mut self,
        derived_key: &[u8],
        now: f64,
        rng: &mut dyn Rng,
    ) -> Result<Vec<HolePunchAction>, HolePunchError> {
        if self.state != HolePunchState::Idle {
            return Err(HolePunchError::InvalidState);
        }

        // Generate session ID
        let mut session_id = [0u8; 16];
        rng.fill_bytes(&mut session_id);
        self.session_id = session_id;
        self.is_initiator = true;

        // Derive punch token and keepalive key
        self.punch_token = derive_punch_token(derived_key, &session_id)?;
        self.keepalive_key = derive_keepalive_key(derived_key, &session_id)?;

        let probe_addr = self.probe_addr.clone().ok_or(HolePunchError::NoProbeAddr)?;
        self.facilitator_addr = Some(probe_addr.clone());

        // Phase 1: discover our public endpoint first
        self.state = HolePunchState::Discovering;
        self.state_entered_at = now;

        Ok(alloc::vec![HolePunchAction::DiscoverEndpoints {
            probe_addr,
            protocol: self.probe_protocol
        }])
    }

    /// Called when endpoint discovery completes.
    ///
    /// For initiator: Discovering -> Proposing (sends UPGRADE_REQUEST with facilitator + our addr).
    /// For responder: Discovering -> Punching (sends UPGRADE_READY with our addr, starts punch).
    pub fn endpoints_discovered(
        &mut self,
        public_endpoint: Endpoint,
        now: f64,
    ) -> Result<Vec<HolePunchAction>, HolePunchError> {
        if self.state != HolePunchState::Discovering {
            return Err(HolePunchError::InvalidState);
        }

        self.our_public_endpoint = Some(public_endpoint.clone());

        if self.is_initiator {
            // Initiator: Phase 1 complete -> Phase 2: send UPGRADE_REQUEST
            let facilitator = self
                .facilitator_addr
                .clone()
                .ok_or(HolePunchError::NoProbeAddr)?;

            let payload = encode_upgrade_request(
                &self.session_id,
                &facilitator,
                &public_endpoint,
                self.probe_protocol,
                &self.our_host_endpoints,
            );

            self.state = HolePunchState::Proposing;
            self.state_entered_at = now;
            self.request_payload = Some(payload.clone());
            self.request_sent_at = now;

            Ok(alloc::vec![HolePunchAction::SendSignal {
                link_id: self.link_id,
                msgtype: UPGRADE_REQUEST,
                payload,
            }])
        } else {
            // Responder: Phase 3 complete -> send UPGRADE_READY, start punching
            let payload =
                encode_upgrade_ready(&self.session_id, &public_endpoint, &self.our_host_endpoints);

            let peer_public = self
                .peer_public_endpoint
                .clone()
                .ok_or(HolePunchError::InvalidState)?;

            self.state = HolePunchState::Punching;
            self.state_entered_at = now;

            Ok(alloc::vec![
                HolePunchAction::SendSignal {
                    link_id: self.link_id,
                    msgtype: UPGRADE_READY,
                    payload,
                },
                HolePunchAction::StartUdpPunch {
                    peer_public,
                    peer_hosts: self.peer_host_endpoints.clone(),
                    punch_token: self.punch_token,
                    session_id: self.session_id,
                },
            ])
        }
    }

    /// Handle an incoming signaling message.
    ///
    /// `derived_key` is needed when handling UPGRADE_REQUEST (responder side).
    pub fn handle_signal(
        &mut self,
        msgtype: u8,
        payload: &[u8],
        derived_key: Option<&[u8]>,
        now: f64,
    ) -> Result<Vec<HolePunchAction>, HolePunchError> {
        match msgtype {
            UPGRADE_REQUEST => self.handle_upgrade_request(payload, derived_key, now),
            UPGRADE_ACCEPT => self.handle_upgrade_accept(payload, now),
            UPGRADE_REJECT => self.handle_upgrade_reject(payload, now),
            UPGRADE_READY => self.handle_upgrade_ready(payload, now),
            _ => Err(HolePunchError::InvalidPayload),
        }
    }

    /// Called when endpoint discovery fails.
    ///
    /// Transitions: Discovering -> Failed. A responder, which has already
    /// accepted, also tells the initiator with `UPGRADE_REJECT`
    /// (`REJECT_NO_ENDPOINT`) instead of leaving it waiting for READY.
    pub fn discovery_failed(&mut self, now: f64) -> Result<Vec<HolePunchAction>, HolePunchError> {
        if self.state != HolePunchState::Discovering {
            return Err(HolePunchError::InvalidState);
        }
        self.state = HolePunchState::Failed;
        self.state_entered_at = now;
        Ok(self.discovery_failure_actions())
    }

    fn discovery_failure_actions(&self) -> Vec<HolePunchAction> {
        let mut actions = Vec::new();
        if !self.is_initiator {
            actions.push(HolePunchAction::SendSignal {
                link_id: self.link_id,
                msgtype: UPGRADE_REJECT,
                payload: encode_upgrade_reject(&self.session_id, REJECT_NO_ENDPOINT),
            });
        }
        actions.push(HolePunchAction::Failed {
            session_id: self.session_id,
            reason: FAIL_PROBE,
        });
        actions
    }

    /// Called when the punch phase succeeds.
    ///
    /// Transitions: Punching -> Connected.
    pub fn punch_succeeded(&mut self, now: f64) -> Result<Vec<HolePunchAction>, HolePunchError> {
        if self.state != HolePunchState::Punching {
            return Err(HolePunchError::InvalidState);
        }

        self.state = HolePunchState::Connected;
        self.state_entered_at = now;

        Ok(alloc::vec![HolePunchAction::Succeeded {
            session_id: self.session_id,
        },])
    }

    /// Called when the punch phase fails.
    ///
    /// Transitions: Punching -> Failed.
    pub fn punch_failed(&mut self, now: f64) -> Result<Vec<HolePunchAction>, HolePunchError> {
        if self.state != HolePunchState::Punching {
            return Err(HolePunchError::InvalidState);
        }

        self.state = HolePunchState::Failed;
        self.state_entered_at = now;

        Ok(alloc::vec![HolePunchAction::Failed {
            session_id: self.session_id,
            reason: FAIL_TIMEOUT,
        },])
    }

    /// Periodic tick: check timeouts.
    pub fn tick(&mut self, now: f64) -> Vec<HolePunchAction> {
        let elapsed = now - self.state_entered_at;
        let retry_due = now - self.request_sent_at >= REQUEST_RETRY_INTERVAL;
        match self.state {
            HolePunchState::Discovering if elapsed > DISCOVER_TIMEOUT => {
                self.state = HolePunchState::Failed;
                self.state_entered_at = now;
                self.discovery_failure_actions()
            }
            HolePunchState::Proposing if elapsed > PROPOSE_TIMEOUT => {
                self.state = HolePunchState::Failed;
                self.state_entered_at = now;
                alloc::vec![HolePunchAction::Failed {
                    session_id: self.session_id,
                    reason: FAIL_TIMEOUT,
                }]
            }
            HolePunchState::WaitingReady if elapsed > READY_TIMEOUT => {
                self.state = HolePunchState::Failed;
                self.state_entered_at = now;
                alloc::vec![HolePunchAction::Failed {
                    session_id: self.session_id,
                    reason: FAIL_TIMEOUT,
                }]
            }
            // Signalling is not acknowledged: until READY arrives, repeat
            // the request, which the responder answers with its replies.
            HolePunchState::Proposing | HolePunchState::WaitingReady if retry_due => {
                self.request_sent_at = now;
                match &self.request_payload {
                    Some(payload) => alloc::vec![HolePunchAction::SendSignal {
                        link_id: self.link_id,
                        msgtype: UPGRADE_REQUEST,
                        payload: payload.clone(),
                    }],
                    None => Vec::new(),
                }
            }
            HolePunchState::Punching if elapsed > PUNCH_TIMEOUT => {
                self.state = HolePunchState::Failed;
                self.state_entered_at = now;
                alloc::vec![HolePunchAction::Failed {
                    session_id: self.session_id,
                    reason: FAIL_TIMEOUT,
                }]
            }
            _ => Vec::new(),
        }
    }

    /// Build a reject response for a request payload without creating a full session.
    ///
    /// Used when the policy rejects all proposals.
    pub fn build_reject(
        link_id: [u8; 16],
        request_payload: &[u8],
        reason: u8,
    ) -> Result<HolePunchAction, HolePunchError> {
        let session_id = decode_upgrade_request(request_payload)?.session_id;
        let payload = encode_upgrade_reject(&session_id, reason);
        Ok(HolePunchAction::SendSignal {
            link_id,
            msgtype: UPGRADE_REJECT,
            payload,
        })
    }

    /// Reset engine back to Idle state for reuse.
    pub fn reset(&mut self) {
        self.state = HolePunchState::Idle;
        self.session_id = [0u8; 16];
        self.is_initiator = false;
        self.our_public_endpoint = None;
        self.peer_public_endpoint = None;
        self.facilitator_addr = None;
        self.punch_token = [0u8; 32];
        self.keepalive_key = [0u8; 32];
        self.probe_protocol = ProbeProtocol::Rnsp;
        self.state_entered_at = 0.0;
        self.request_payload = None;
        self.request_sent_at = 0.0;
        self.peer_max_packet = None;
    }

    // --- Private handlers ---

    /// Responder receives UPGRADE_REQUEST.
    ///
    /// Spec Phase 2: B evaluates the request, sends UPGRADE_ACCEPT, then
    /// begins Phase 3 (STUN discovery using facilitator from the request).
    fn handle_upgrade_request(
        &mut self,
        payload: &[u8],
        derived_key: Option<&[u8]>,
        now: f64,
    ) -> Result<Vec<HolePunchAction>, HolePunchError> {
        if self.state != HolePunchState::Idle {
            // Already busy — reject
            let session_id = decode_upgrade_request(payload)?.session_id;
            let reject_payload = encode_upgrade_reject(&session_id, REJECT_BUSY);
            return Ok(alloc::vec![HolePunchAction::SendSignal {
                link_id: self.link_id,
                msgtype: UPGRADE_REJECT,
                payload: reject_payload,
            }]);
        }

        let derived_key = derived_key.ok_or(HolePunchError::NoDerivedKey)?;
        let UpgradeRequest {
            session_id,
            facilitator,
            initiator_public,
            protocol,
            hosts,
        } = decode_upgrade_request(payload)?;

        self.session_id = session_id;
        self.is_initiator = false;
        self.probe_protocol = protocol;
        self.punch_token = derive_punch_token(derived_key, &session_id)?;
        self.keepalive_key = derive_keepalive_key(derived_key, &session_id)?;

        // Store A's public address (we'll punch this later)
        self.peer_public_endpoint = Some(initiator_public);
        self.peer_max_packet = decode_max_packet(payload);
        self.peer_host_endpoints = hosts;

        // Use facilitator from the request for our own STUN discovery
        self.facilitator_addr = Some(facilitator.clone());

        self.state = HolePunchState::Discovering;
        self.state_entered_at = now;

        // Send UPGRADE_ACCEPT, then discover our endpoint using facilitator from request
        let accept_payload = encode_upgrade_accept(&session_id);

        Ok(alloc::vec![
            HolePunchAction::SendSignal {
                link_id: self.link_id,
                msgtype: UPGRADE_ACCEPT,
                payload: accept_payload,
            },
            HolePunchAction::DiscoverEndpoints {
                probe_addr: facilitator,
                protocol
            },
        ])
    }

    /// Initiator receives UPGRADE_ACCEPT.
    ///
    /// Transitions: Proposing -> WaitingReady (waiting for B's UPGRADE_READY).
    fn handle_upgrade_accept(
        &mut self,
        payload: &[u8],
        now: f64,
    ) -> Result<Vec<HolePunchAction>, HolePunchError> {
        let session_id = decode_upgrade_accept(payload)?;
        // A repeated ACCEPT answers a retransmitted request.
        if self.is_initiator
            && session_id == self.session_id
            && matches!(
                self.state,
                HolePunchState::WaitingReady | HolePunchState::Punching | HolePunchState::Connected
            )
        {
            return Ok(Vec::new());
        }
        if self.state != HolePunchState::Proposing || !self.is_initiator {
            return Err(HolePunchError::InvalidState);
        }

        if session_id != self.session_id {
            return Err(HolePunchError::SessionMismatch);
        }

        self.state = HolePunchState::WaitingReady;
        self.state_entered_at = now;

        Ok(Vec::new())
    }

    /// Initiator receives UPGRADE_REJECT.
    fn handle_upgrade_reject(
        &mut self,
        payload: &[u8],
        now: f64,
    ) -> Result<Vec<HolePunchAction>, HolePunchError> {
        // A responder may also give up after accepting (its probe failed).
        if !self.is_initiator
            || !matches!(
                self.state,
                HolePunchState::Proposing | HolePunchState::WaitingReady
            )
        {
            return Err(HolePunchError::InvalidState);
        }

        let (session_id, reason) = decode_upgrade_reject(payload)?;
        if session_id != self.session_id {
            return Err(HolePunchError::SessionMismatch);
        }

        self.state = HolePunchState::Failed;
        self.state_entered_at = now;

        Ok(alloc::vec![HolePunchAction::Failed {
            session_id: self.session_id,
            reason,
        }])
    }

    /// Initiator receives UPGRADE_READY from responder.
    ///
    /// Spec Phase 3 complete: B has discovered its endpoint and sent it to A.
    /// Both sides now start punching (Phase 4).
    fn handle_upgrade_ready(
        &mut self,
        payload: &[u8],
        now: f64,
    ) -> Result<Vec<HolePunchAction>, HolePunchError> {
        let (session_id, responder_public, hosts) = decode_upgrade_ready(payload)?;
        // A repeated READY answers a retransmitted request.
        if self.is_initiator
            && session_id == self.session_id
            && matches!(
                self.state,
                HolePunchState::Punching | HolePunchState::Connected
            )
        {
            return Ok(Vec::new());
        }
        if self.state != HolePunchState::WaitingReady || !self.is_initiator {
            return Err(HolePunchError::InvalidState);
        }

        if session_id != self.session_id {
            return Err(HolePunchError::SessionMismatch);
        }

        self.peer_public_endpoint = Some(responder_public.clone());
        self.peer_max_packet = decode_max_packet(payload);
        self.peer_host_endpoints = hosts.clone();

        self.state = HolePunchState::Punching;
        self.state_entered_at = now;

        Ok(alloc::vec![HolePunchAction::StartUdpPunch {
            peer_public: responder_public,
            peer_hosts: hosts,
            punch_token: self.punch_token,
            session_id: self.session_id,
        }])
    }
}

// --- Msgpack encode/decode helpers ---

/// A decoded `HELLO`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Hello {
    /// Highest signalling version the sender speaks.
    pub version: u8,
    /// The sender has not heard our `HELLO` yet and wants one back.
    pub reply_wanted: bool,
}

/// Encode a `HELLO` body: `{"v": version, "r": reply_wanted}`.
pub fn encode_hello(reply_wanted: bool) -> Vec<u8> {
    msgpack::pack(&Value::Map(alloc::vec![
        (
            Value::Str(alloc::string::String::from("v")),
            Value::UInt(DIRECT_LINK_VERSION as u64)
        ),
        (
            Value::Str(alloc::string::String::from("r")),
            Value::Bool(reply_wanted)
        ),
    ]))
}

/// Encode a `FALLBACK` body: `{"s": session_id, "r": reply_wanted}`.
pub fn encode_fallback(session_id: &[u8; 16], reply_wanted: bool) -> Vec<u8> {
    msgpack::pack(&Value::Map(alloc::vec![
        (
            Value::Str(alloc::string::String::from("s")),
            Value::Bin(session_id.to_vec())
        ),
        (
            Value::Str(alloc::string::String::from("r")),
            Value::Bool(reply_wanted)
        ),
    ]))
}

/// Decode a `FALLBACK` body into its session and whether a reply is wanted.
pub fn decode_fallback(data: &[u8]) -> Result<([u8; 16], bool), HolePunchError> {
    let (val, _) = msgpack::unpack(data).map_err(|_| HolePunchError::InvalidPayload)?;
    let session_id = extract_session_id(&val)?;
    let reply_wanted = val.map_get("r").and_then(|v| v.as_bool()).unwrap_or(false);
    Ok((session_id, reply_wanted))
}

/// Decode a `HELLO` body. Unknown fields are ignored, so later versions can
/// extend it.
pub fn decode_hello(data: &[u8]) -> Result<Hello, HolePunchError> {
    let (val, _) = msgpack::unpack(data).map_err(|_| HolePunchError::InvalidPayload)?;
    let version = val
        .map_get("v")
        .and_then(|v| v.as_uint())
        .ok_or(HolePunchError::InvalidPayload)?;
    let reply_wanted = val.map_get("r").and_then(|v| v.as_bool()).unwrap_or(false);
    Ok(Hello {
        version: version.min(u8::MAX as u64) as u8,
        reply_wanted,
    })
}

/// Whether `body` decodes as a signalling message of `kind`, without
/// acting on it.
pub fn validate_signal(kind: u8, body: &[u8]) -> Result<(), HolePunchError> {
    match kind {
        HELLO => decode_hello(body).map(|_| ()),
        UPGRADE_REQUEST => decode_upgrade_request(body).map(|_| ()),
        UPGRADE_ACCEPT => decode_upgrade_accept(body).map(|_| ()),
        UPGRADE_REJECT => decode_upgrade_reject(body).map(|_| ()),
        UPGRADE_READY => decode_upgrade_ready(body).map(|_| ()),
        FALLBACK => decode_fallback(body).map(|_| ()),
        CHANNEL_PART => super::channel_parts::decode_channel_part(body).map(|_| ()),
        CHANNEL_PART_ACK => super::channel_parts::decode_channel_part_ack(body).map(|_| ()),
        _ => Err(HolePunchError::InvalidPayload),
    }
}

fn encode_upgrade_request(
    session_id: &[u8; 16],
    facilitator: &Endpoint,
    initiator_public: &Endpoint,
    protocol: ProbeProtocol,
    hosts: &[Endpoint],
) -> Vec<u8> {
    let mut fields = alloc::vec![
        (
            Value::Str(alloc::string::String::from("s")),
            Value::Bin(session_id.to_vec())
        ),
        (
            Value::Str(alloc::string::String::from("f")),
            encode_endpoint(facilitator)
        ),
        (
            Value::Str(alloc::string::String::from("a")),
            encode_endpoint(initiator_public)
        ),
        max_packet_field(),
    ];
    // Only include "p" when not RNSP (backward compat: old nodes don't send it)
    if protocol != ProbeProtocol::Rnsp {
        fields.push((
            Value::Str(alloc::string::String::from("p")),
            Value::UInt(protocol as u64),
        ));
    }
    push_hosts(&mut fields, hosts);
    let val = Value::Map(fields);
    msgpack::pack(&val)
}

/// Add host candidates as `"h"`, when there are any.
fn push_hosts(fields: &mut Vec<(Value, Value)>, hosts: &[Endpoint]) {
    if !hosts.is_empty() {
        fields.push((
            Value::Str(alloc::string::String::from("h")),
            Value::Array(
                hosts
                    .iter()
                    .take(MAX_HOST_CANDIDATES)
                    .map(encode_endpoint)
                    .collect(),
            ),
        ));
    }
}

/// The host candidates in `"h"`: none when it is absent or not a list,
/// and entries that are not endpoints are skipped. At most
/// [`MAX_HOST_CANDIDATES`] are kept.
fn decode_hosts(val: &Value) -> Vec<Endpoint> {
    val.map_get("h")
        .and_then(|h| h.as_array())
        .map(|entries| {
            entries
                .iter()
                .filter_map(decode_endpoint)
                .take(MAX_HOST_CANDIDATES)
                .collect()
        })
        .unwrap_or_default()
}

/// A decoded `UPGRADE_REQUEST`.
struct UpgradeRequest {
    session_id: [u8; 16],
    facilitator: Endpoint,
    initiator_public: Endpoint,
    protocol: ProbeProtocol,
    hosts: Vec<Endpoint>,
}

fn decode_upgrade_request(data: &[u8]) -> Result<UpgradeRequest, HolePunchError> {
    let (val, _) = msgpack::unpack(data).map_err(|_| HolePunchError::InvalidPayload)?;
    let session_id = extract_session_id(&val)?;
    let facilitator = val
        .map_get("f")
        .and_then(decode_endpoint)
        .ok_or(HolePunchError::InvalidPayload)?;
    let initiator_public = val
        .map_get("a")
        .and_then(decode_endpoint)
        .ok_or(HolePunchError::InvalidPayload)?;
    // Fallback to Rnsp when "p" is absent (old nodes don't send it)
    let protocol = val
        .map_get("p")
        .and_then(|v| v.as_uint())
        .map(|p| match p {
            1 => ProbeProtocol::Stun,
            _ => ProbeProtocol::Rnsp,
        })
        .unwrap_or(ProbeProtocol::Rnsp);
    Ok(UpgradeRequest {
        session_id,
        facilitator,
        initiator_public,
        protocol,
        hosts: decode_hosts(&val),
    })
}

fn encode_upgrade_accept(session_id: &[u8; 16]) -> Vec<u8> {
    let val = Value::Map(alloc::vec![(
        Value::Str(alloc::string::String::from("s")),
        Value::Bin(session_id.to_vec())
    ),]);
    msgpack::pack(&val)
}

fn decode_upgrade_accept(data: &[u8]) -> Result<[u8; 16], HolePunchError> {
    let (val, _) = msgpack::unpack(data).map_err(|_| HolePunchError::InvalidPayload)?;
    extract_session_id(&val)
}

fn encode_upgrade_reject(session_id: &[u8; 16], reason: u8) -> Vec<u8> {
    let val = Value::Map(alloc::vec![
        (
            Value::Str(alloc::string::String::from("s")),
            Value::Bin(session_id.to_vec())
        ),
        (
            Value::Str(alloc::string::String::from("r")),
            Value::UInt(reason as u64)
        ),
    ]);
    msgpack::pack(&val)
}

fn decode_upgrade_reject(data: &[u8]) -> Result<([u8; 16], u8), HolePunchError> {
    let (val, _) = msgpack::unpack(data).map_err(|_| HolePunchError::InvalidPayload)?;
    let session_id = extract_session_id(&val)?;
    let reason = val
        .map_get("r")
        .and_then(|v| v.as_uint())
        .and_then(|r| u8::try_from(r).ok())
        .ok_or(HolePunchError::InvalidPayload)?;
    Ok((session_id, reason))
}

fn encode_upgrade_ready(
    session_id: &[u8; 16],
    responder_public: &Endpoint,
    hosts: &[Endpoint],
) -> Vec<u8> {
    let mut fields = alloc::vec![
        (
            Value::Str(alloc::string::String::from("s")),
            Value::Bin(session_id.to_vec())
        ),
        (
            Value::Str(alloc::string::String::from("a")),
            encode_endpoint(responder_public)
        ),
        max_packet_field(),
    ];
    push_hosts(&mut fields, hosts);
    msgpack::pack(&Value::Map(fields))
}

fn decode_upgrade_ready(
    data: &[u8],
) -> Result<([u8; 16], Endpoint, Vec<Endpoint>), HolePunchError> {
    let (val, _) = msgpack::unpack(data).map_err(|_| HolePunchError::InvalidPayload)?;
    let session_id = extract_session_id(&val)?;
    let responder_public = val
        .map_get("a")
        .and_then(decode_endpoint)
        .ok_or(HolePunchError::InvalidPayload)?;
    Ok((session_id, responder_public, decode_hosts(&val)))
}

/// The `m` field of UPGRADE_REQUEST and UPGRADE_READY: the largest link
/// packet this side accepts on the direct path.
fn max_packet_field() -> (Value, Value) {
    (
        Value::Str(alloc::string::String::from("m")),
        Value::UInt(DIRECT_MAX_PACKET as u64),
    )
}

/// The peer's `m`, if present and a valid size.
fn decode_max_packet(data: &[u8]) -> Option<u32> {
    let (val, _) = msgpack::unpack(data).ok()?;
    let m = val.map_get("m")?.as_uint()?;
    u32::try_from(m).ok()
}

fn encode_endpoint(ep: &Endpoint) -> Value {
    Value::Array(alloc::vec![
        Value::Bin(ep.addr.clone()),
        Value::UInt(ep.port as u64),
    ])
}

fn decode_endpoint(val: &Value) -> Option<Endpoint> {
    let [addr, port, ..] = val.as_array()? else {
        return None;
    };
    let addr = addr.as_bin()?.to_vec();
    // A port beyond 16 bits is malformed, not to be truncated into another.
    let port = u16::try_from(port.as_uint()?).ok()?;
    Some(Endpoint { addr, port })
}

#[cfg(test)]
fn encode_session_only(session_id: &[u8; 16]) -> Vec<u8> {
    let val = Value::Map(alloc::vec![(
        Value::Str(alloc::string::String::from("s")),
        Value::Bin(session_id.to_vec())
    ),]);
    msgpack::pack(&val)
}

#[cfg(test)]
fn decode_session_only(data: &[u8]) -> Result<[u8; 16], HolePunchError> {
    let (val, _) = msgpack::unpack(data).map_err(|_| HolePunchError::InvalidPayload)?;
    extract_session_id(&val)
}

fn extract_session_id(val: &Value) -> Result<[u8; 16], HolePunchError> {
    let bin = val
        .map_get("s")
        .and_then(|v| v.as_bin())
        .ok_or(HolePunchError::InvalidPayload)?;
    if bin.len() != 16 {
        return Err(HolePunchError::InvalidPayload);
    }
    let mut id = [0u8; 16];
    id.copy_from_slice(bin);
    Ok(id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rns_crypto::FixedRng;

    fn make_rng(seed: u8) -> FixedRng {
        FixedRng::new(&[seed; 128])
    }

    fn test_derived_key() -> Vec<u8> {
        vec![0xAA; 32]
    }

    fn test_probe_addr() -> Endpoint {
        Endpoint {
            addr: vec![127, 0, 0, 1],
            port: 4343,
        }
    }

    fn test_public_addr_a() -> Endpoint {
        Endpoint {
            addr: vec![1, 2, 3, 4],
            port: 41000,
        }
    }

    fn test_public_addr_b() -> Endpoint {
        Endpoint {
            addr: vec![5, 6, 7, 8],
            port: 52000,
        }
    }

    #[test]
    fn test_propose_initiator_discovers_first() {
        let link_id = [0x11; 16];
        let derived_key = test_derived_key();
        let mut rng = make_rng(0x42);

        let mut initiator =
            HolePunchEngine::new(link_id, Some(test_probe_addr()), ProbeProtocol::Rnsp);
        let actions = initiator.propose(&derived_key, 100.0, &mut rng).unwrap();

        // Should transition to Discovering, not Proposing
        assert_eq!(initiator.state(), HolePunchState::Discovering);
        assert_eq!(actions.len(), 1);
        assert!(matches!(
            &actions[0],
            HolePunchAction::DiscoverEndpoints { .. }
        ));
    }

    #[test]
    fn test_initiator_sends_request_after_discovery() {
        let link_id = [0x11; 16];
        let derived_key = test_derived_key();
        let mut rng = make_rng(0x42);

        let mut initiator =
            HolePunchEngine::new(link_id, Some(test_probe_addr()), ProbeProtocol::Rnsp);
        initiator.propose(&derived_key, 100.0, &mut rng).unwrap();

        // Initiator discovers its public endpoint
        let actions = initiator
            .endpoints_discovered(test_public_addr_a(), 101.0)
            .unwrap();

        // Should transition to Proposing and send UPGRADE_REQUEST
        assert_eq!(initiator.state(), HolePunchState::Proposing);
        assert_eq!(actions.len(), 1);
        match &actions[0] {
            HolePunchAction::SendSignal {
                msgtype, payload, ..
            } => {
                assert_eq!(*msgtype, UPGRADE_REQUEST);
                // Verify payload contains facilitator and initiator_public
                let UpgradeRequest {
                    session_id: sid,
                    facilitator,
                    initiator_public: init_pub,
                    protocol: _proto,
                    ..
                } = decode_upgrade_request(payload).unwrap();
                assert_eq!(sid, *initiator.session_id());
                assert_eq!(facilitator, test_probe_addr());
                assert_eq!(init_pub, test_public_addr_a());
            }
            _ => panic!("Expected SendSignal(UPGRADE_REQUEST)"),
        }
    }

    #[test]
    fn test_full_asymmetric_flow() {
        let link_id = [0x22; 16];
        let derived_key = test_derived_key();
        let mut rng = make_rng(0x42);

        // Phase 1: Initiator discovers its endpoint
        let mut initiator =
            HolePunchEngine::new(link_id, Some(test_probe_addr()), ProbeProtocol::Rnsp);
        initiator.propose(&derived_key, 100.0, &mut rng).unwrap();
        let actions = initiator
            .endpoints_discovered(test_public_addr_a(), 101.0)
            .unwrap();

        let request_payload = match &actions[0] {
            HolePunchAction::SendSignal { payload, .. } => payload.clone(),
            _ => panic!(),
        };

        // Phase 2: Responder receives UPGRADE_REQUEST
        let mut responder = HolePunchEngine::new(link_id, None, ProbeProtocol::Rnsp); // no probe_addr needed, uses facilitator from request
        let actions = responder
            .handle_signal(UPGRADE_REQUEST, &request_payload, Some(&derived_key), 102.0)
            .unwrap();

        assert_eq!(responder.state(), HolePunchState::Discovering);
        assert_eq!(actions.len(), 2); // UPGRADE_ACCEPT + DiscoverEndpoints

        let accept_payload = match &actions[0] {
            HolePunchAction::SendSignal {
                msgtype, payload, ..
            } => {
                assert_eq!(*msgtype, UPGRADE_ACCEPT);
                payload.clone()
            }
            _ => panic!("Expected UPGRADE_ACCEPT"),
        };

        // B discovers using facilitator from request
        match &actions[1] {
            HolePunchAction::DiscoverEndpoints { probe_addr, .. } => {
                assert_eq!(*probe_addr, test_probe_addr()); // facilitator from request
            }
            _ => panic!("Expected DiscoverEndpoints"),
        }

        // Initiator receives UPGRADE_ACCEPT -> WaitingReady
        let actions = initiator
            .handle_signal(UPGRADE_ACCEPT, &accept_payload, None, 103.0)
            .unwrap();
        assert_eq!(initiator.state(), HolePunchState::WaitingReady);
        assert!(actions.is_empty()); // Just waiting

        // Phase 3: Responder discovers its endpoint, sends UPGRADE_READY
        let actions = responder
            .endpoints_discovered(test_public_addr_b(), 104.0)
            .unwrap();

        assert_eq!(responder.state(), HolePunchState::Punching);
        assert_eq!(actions.len(), 2); // UPGRADE_READY + StartUdpPunch

        let ready_payload = match &actions[0] {
            HolePunchAction::SendSignal {
                msgtype, payload, ..
            } => {
                assert_eq!(*msgtype, UPGRADE_READY);
                payload.clone()
            }
            _ => panic!("Expected UPGRADE_READY"),
        };
        assert!(matches!(&actions[1], HolePunchAction::StartUdpPunch { .. }));

        // Phase 4: Initiator receives UPGRADE_READY -> Punching
        let actions = initiator
            .handle_signal(UPGRADE_READY, &ready_payload, None, 105.0)
            .unwrap();

        assert_eq!(initiator.state(), HolePunchState::Punching);
        assert_eq!(actions.len(), 1);
        match &actions[0] {
            HolePunchAction::StartUdpPunch { peer_public, .. } => {
                assert_eq!(*peer_public, test_public_addr_b());
            }
            _ => panic!("Expected StartUdpPunch"),
        }

        // Both derive the same punch token
        assert_eq!(initiator.punch_token(), responder.punch_token());
        // And each knows how large a packet the other accepts directly.
        assert_eq!(responder.peer_max_packet(), Some(DIRECT_MAX_PACKET));
        assert_eq!(initiator.peer_max_packet(), Some(DIRECT_MAX_PACKET));
    }

    #[test]
    fn peer_without_a_max_packet_advertises_none() {
        let link_id = [0x22; 16];
        let derived_key = test_derived_key();
        let fields = |a: &Endpoint| {
            alloc::vec![
                (
                    Value::Str(alloc::string::String::from("s")),
                    Value::Bin([0xAB; 16].to_vec())
                ),
                (
                    Value::Str(alloc::string::String::from("f")),
                    encode_endpoint(&test_probe_addr())
                ),
                (
                    Value::Str(alloc::string::String::from("a")),
                    encode_endpoint(a)
                ),
            ]
        };
        let request = msgpack::pack(&Value::Map(fields(&test_public_addr_a())));
        let mut responder = HolePunchEngine::new(link_id, None, ProbeProtocol::Rnsp);
        responder
            .handle_signal(UPGRADE_REQUEST, &request, Some(&derived_key), 1.0)
            .unwrap();
        assert_eq!(responder.peer_max_packet(), None);

        let mut rng = make_rng(0x42);
        let mut initiator =
            HolePunchEngine::new(link_id, Some(test_probe_addr()), ProbeProtocol::Rnsp);
        initiator.propose(&derived_key, 1.0, &mut rng).unwrap();
        initiator
            .endpoints_discovered(test_public_addr_a(), 2.0)
            .unwrap();
        let session = encode_session_only(initiator.session_id());
        initiator
            .handle_signal(UPGRADE_ACCEPT, &session, None, 3.0)
            .unwrap();
        let mut ready = fields(&test_public_addr_b());
        ready[0].1 = Value::Bin(initiator.session_id().to_vec());
        ready.remove(1);
        let ready = msgpack::pack(&Value::Map(ready));
        initiator
            .handle_signal(UPGRADE_READY, &ready, None, 4.0)
            .unwrap();
        assert_eq!(initiator.state(), HolePunchState::Punching);
        assert_eq!(initiator.peer_max_packet(), None);
        initiator.reset();
        assert_eq!(initiator.peer_max_packet(), None);
    }

    fn host(a: u8, port: u16) -> Endpoint {
        Endpoint {
            addr: alloc::vec![192, 168, 1, a],
            port,
        }
    }

    #[test]
    fn host_candidates_travel_both_ways() {
        let link_id = [0x23; 16];
        let derived_key = test_derived_key();
        let mut rng = make_rng(0x43);

        let mut initiator =
            HolePunchEngine::new(link_id, Some(test_probe_addr()), ProbeProtocol::Rnsp);
        initiator.propose(&derived_key, 100.0, &mut rng).unwrap();
        // Only the first MAX_HOST_CANDIDATES are kept.
        initiator.set_host_endpoints(alloc::vec![host(10, 4000), host(11, 4000), host(12, 4000)]);
        let actions = initiator
            .endpoints_discovered(test_public_addr_a(), 101.0)
            .unwrap();
        let request = signal(&actions[0]).unwrap().1;

        let mut responder = HolePunchEngine::new(link_id, None, ProbeProtocol::Rnsp);
        responder
            .handle_signal(UPGRADE_REQUEST, &request, Some(&derived_key), 102.0)
            .unwrap();
        assert_eq!(
            responder.peer_host_endpoints(),
            &[host(10, 4000), host(11, 4000)]
        );
        responder.set_host_endpoints(alloc::vec![host(20, 5000)]);
        let actions = responder
            .endpoints_discovered(test_public_addr_b(), 103.0)
            .unwrap();
        match &actions[1] {
            HolePunchAction::StartUdpPunch { peer_hosts, .. } => {
                assert_eq!(peer_hosts, &[host(10, 4000), host(11, 4000)]);
            }
            other => panic!("expected StartUdpPunch, got {other:?}"),
        }
        let ready = signal(&actions[0]).unwrap().1;
        // A replayed READY carries them too.
        let replayed = responder.replay_replies();
        assert_eq!(signal(&replayed[1]).unwrap().1, ready);

        initiator
            .handle_signal(
                UPGRADE_ACCEPT,
                &encode_upgrade_accept(initiator.session_id()),
                None,
                104.0,
            )
            .unwrap();
        let actions = initiator
            .handle_signal(UPGRADE_READY, &ready, None, 105.0)
            .unwrap();
        match &actions[0] {
            HolePunchAction::StartUdpPunch { peer_hosts, .. } => {
                assert_eq!(peer_hosts, &[host(20, 5000)]);
            }
            other => panic!("expected StartUdpPunch, got {other:?}"),
        }
    }

    #[test]
    fn out_of_range_ports_and_reasons_are_malformed_not_truncated() {
        let endpoint = |port: u64| {
            Value::Array(alloc::vec![
                Value::Bin(alloc::vec![203, 0, 113, 1]),
                Value::UInt(port)
            ])
        };
        assert_eq!(decode_endpoint(&endpoint(65535)).unwrap().port, 65535);
        // 65536 + 4343 would otherwise read as port 4343.
        assert!(decode_endpoint(&endpoint(65536 + 4343)).is_none());
        let ready = msgpack::pack(&Value::Map(alloc::vec![
            (
                Value::Str(alloc::string::String::from("s")),
                Value::Bin(alloc::vec![1; 16])
            ),
            (
                Value::Str(alloc::string::String::from("a")),
                endpoint(70000)
            ),
        ]));
        assert!(validate_signal(UPGRADE_READY, &ready).is_err());
        let reject = |reason: u64| {
            msgpack::pack(&Value::Map(alloc::vec![
                (
                    Value::Str(alloc::string::String::from("s")),
                    Value::Bin(alloc::vec![1; 16])
                ),
                (
                    Value::Str(alloc::string::String::from("r")),
                    Value::UInt(reason)
                ),
            ]))
        };
        assert_eq!(decode_upgrade_reject(&reject(2)).unwrap().1, REJECT_BUSY);
        // 0x102 would otherwise read as REJECT_BUSY.
        assert!(decode_upgrade_reject(&reject(0x102)).is_err());
    }

    #[test]
    fn an_unusable_max_packet_is_ignored_not_fatal() {
        for m in [
            Value::UInt(u64::MAX),
            Value::UInt(u64::from(u32::MAX) + 1),
            Value::Str(alloc::string::String::from("big")),
            Value::Nil,
        ] {
            let ready = msgpack::pack(&Value::Map(alloc::vec![
                (
                    Value::Str(alloc::string::String::from("s")),
                    Value::Bin(alloc::vec![1; 16])
                ),
                (
                    Value::Str(alloc::string::String::from("a")),
                    encode_endpoint(&test_public_addr_b())
                ),
                (Value::Str(alloc::string::String::from("m")), m.clone()),
            ]));
            assert!(validate_signal(UPGRADE_READY, &ready).is_ok(), "{m:?}");
            assert_eq!(decode_max_packet(&ready), None, "{m:?}");
        }
        let ready = encode_upgrade_ready(&[1; 16], &test_public_addr_b(), &[]);
        assert_eq!(decode_max_packet(&ready), Some(DIRECT_MAX_PACKET));
    }

    #[test]
    fn every_signal_kind_validates_its_own_encoding_only() {
        let session = [9; 16];
        assert!(validate_signal(HELLO, &encode_hello(true)).is_ok());
        assert!(validate_signal(UPGRADE_ACCEPT, &encode_upgrade_accept(&session)).is_ok());
        assert!(validate_signal(FALLBACK, &encode_fallback(&session, false)).is_ok());
        assert!(validate_signal(UPGRADE_REQUEST, &encode_upgrade_accept(&session)).is_err());
        assert!(validate_signal(0x7f, &encode_hello(true)).is_err());
        for kind in 0..=6 {
            assert!(validate_signal(kind, &[]).is_err());
            assert!(validate_signal(kind, &[0xc1]).is_err());
        }
    }

    #[test]
    fn malformed_host_candidates_are_skipped_not_fatal() {
        let session_id = [0x61; 16];
        let mut fields = alloc::vec![
            (
                Value::Str(alloc::string::String::from("s")),
                Value::Bin(session_id.to_vec())
            ),
            (
                Value::Str(alloc::string::String::from("a")),
                encode_endpoint(&test_public_addr_b())
            ),
        ];
        // Not a list: ignored.
        let mut not_a_list = fields.clone();
        not_a_list.push((Value::Str(alloc::string::String::from("h")), Value::UInt(7)));
        let (_, _, hosts) = decode_upgrade_ready(&msgpack::pack(&Value::Map(not_a_list))).unwrap();
        assert!(hosts.is_empty());
        // Junk entries are skipped, the rest kept.
        fields.push((
            Value::Str(alloc::string::String::from("h")),
            Value::Array(alloc::vec![
                Value::Str(alloc::string::String::from("junk")),
                Value::Array(alloc::vec![Value::UInt(1)]),
                encode_endpoint(&host(30, 6000)),
            ]),
        ));
        let (sid, public, hosts) =
            decode_upgrade_ready(&msgpack::pack(&Value::Map(fields))).unwrap();
        assert_eq!(sid, session_id);
        assert_eq!(public, test_public_addr_b());
        assert_eq!(hosts, alloc::vec![host(30, 6000)]);
    }

    #[test]
    fn test_punch_success() {
        let link_id = [0x33; 16];
        let derived_key = test_derived_key();
        let mut rng = make_rng(0x42);

        let mut engine =
            HolePunchEngine::new(link_id, Some(test_probe_addr()), ProbeProtocol::Rnsp);
        engine.propose(&derived_key, 100.0, &mut rng).unwrap();
        engine.state = HolePunchState::Punching;

        let actions = engine.punch_succeeded(105.0).unwrap();
        assert_eq!(engine.state(), HolePunchState::Connected);
        assert_eq!(actions.len(), 1);
        assert!(matches!(&actions[0], HolePunchAction::Succeeded { .. }));
    }

    #[test]
    fn test_punch_failed() {
        let link_id = [0x44; 16];
        let derived_key = test_derived_key();
        let mut rng = make_rng(0x42);

        let mut engine =
            HolePunchEngine::new(link_id, Some(test_probe_addr()), ProbeProtocol::Rnsp);
        engine.propose(&derived_key, 100.0, &mut rng).unwrap();
        engine.state = HolePunchState::Punching;

        let actions = engine.punch_failed(120.0).unwrap();
        assert_eq!(engine.state(), HolePunchState::Failed);
        assert_eq!(actions.len(), 1);
        assert!(matches!(&actions[0], HolePunchAction::Failed { .. }));
    }

    #[test]
    fn test_reject_when_busy() {
        let link_id = [0x55; 16];
        let derived_key = test_derived_key();
        let mut rng = make_rng(0x42);

        // Create a request payload
        let mut proposer =
            HolePunchEngine::new(link_id, Some(test_probe_addr()), ProbeProtocol::Rnsp);
        proposer.propose(&derived_key, 100.0, &mut rng).unwrap();
        let actions = proposer
            .endpoints_discovered(test_public_addr_a(), 101.0)
            .unwrap();
        let request_payload = match &actions[0] {
            HolePunchAction::SendSignal { payload, .. } => payload.clone(),
            _ => panic!(),
        };

        // Responder is already busy (set to Discovering manually)
        let mut responder =
            HolePunchEngine::new(link_id, Some(test_probe_addr()), ProbeProtocol::Rnsp);
        responder.state = HolePunchState::Discovering;

        let actions = responder
            .handle_signal(UPGRADE_REQUEST, &request_payload, Some(&derived_key), 102.0)
            .unwrap();

        // Should reject with REJECT_BUSY
        assert_eq!(actions.len(), 1);
        match &actions[0] {
            HolePunchAction::SendSignal { msgtype, .. } => {
                assert_eq!(*msgtype, UPGRADE_REJECT);
            }
            _ => panic!("Expected UPGRADE_REJECT"),
        }
    }

    #[test]
    fn test_initiator_receives_reject() {
        let link_id = [0x66; 16];
        let derived_key = test_derived_key();
        let mut rng = make_rng(0x42);

        let mut initiator =
            HolePunchEngine::new(link_id, Some(test_probe_addr()), ProbeProtocol::Rnsp);
        initiator.propose(&derived_key, 100.0, &mut rng).unwrap();
        initiator
            .endpoints_discovered(test_public_addr_a(), 101.0)
            .unwrap();
        assert_eq!(initiator.state(), HolePunchState::Proposing);

        let session_id = *initiator.session_id();
        let reject_payload = encode_upgrade_reject(&session_id, REJECT_POLICY);

        let actions = initiator
            .handle_signal(UPGRADE_REJECT, &reject_payload, None, 102.0)
            .unwrap();

        assert_eq!(initiator.state(), HolePunchState::Failed);
        assert_eq!(actions.len(), 1);
        assert!(
            matches!(&actions[0], HolePunchAction::Failed { reason, .. } if *reason == REJECT_POLICY)
        );
    }

    #[test]
    fn test_discover_timeout() {
        let link_id = [0x77; 16];
        let derived_key = test_derived_key();
        let mut rng = make_rng(0x42);

        let mut engine =
            HolePunchEngine::new(link_id, Some(test_probe_addr()), ProbeProtocol::Rnsp);
        engine.propose(&derived_key, 100.0, &mut rng).unwrap();
        assert_eq!(engine.state(), HolePunchState::Discovering);

        // Before timeout
        let actions = engine.tick(100.0 + DISCOVER_TIMEOUT - 1.0);
        assert!(actions.is_empty());

        // After timeout
        let actions = engine.tick(100.0 + DISCOVER_TIMEOUT + 1.0);
        assert_eq!(engine.state(), HolePunchState::Failed);
        assert!(
            matches!(&actions[0], HolePunchAction::Failed { reason, .. } if *reason == FAIL_PROBE)
        );
    }

    #[test]
    fn test_propose_timeout() {
        let link_id = [0x88; 16];
        let derived_key = test_derived_key();
        let mut rng = make_rng(0x42);

        let mut engine =
            HolePunchEngine::new(link_id, Some(test_probe_addr()), ProbeProtocol::Rnsp);
        engine.propose(&derived_key, 100.0, &mut rng).unwrap();
        engine
            .endpoints_discovered(test_public_addr_a(), 101.0)
            .unwrap();
        assert_eq!(engine.state(), HolePunchState::Proposing);

        // After timeout
        let actions = engine.tick(101.0 + PROPOSE_TIMEOUT + 1.0);
        assert_eq!(engine.state(), HolePunchState::Failed);
        assert!(
            matches!(&actions[0], HolePunchAction::Failed { reason, .. } if *reason == FAIL_TIMEOUT)
        );
    }

    #[test]
    fn test_waiting_ready_timeout() {
        let link_id = [0x99; 16];
        let derived_key = test_derived_key();
        let mut rng = make_rng(0x42);

        let mut engine =
            HolePunchEngine::new(link_id, Some(test_probe_addr()), ProbeProtocol::Rnsp);
        engine.propose(&derived_key, 200.0, &mut rng).unwrap();
        engine
            .endpoints_discovered(test_public_addr_a(), 201.0)
            .unwrap();
        engine.state = HolePunchState::WaitingReady;
        engine.state_entered_at = 202.0;

        // After timeout
        let actions = engine.tick(202.0 + READY_TIMEOUT + 1.0);
        assert_eq!(engine.state(), HolePunchState::Failed);
        assert!(
            matches!(&actions[0], HolePunchAction::Failed { reason, .. } if *reason == FAIL_TIMEOUT)
        );
    }

    #[test]
    fn test_punch_timeout() {
        let link_id = [0xAA; 16];
        let derived_key = test_derived_key();
        let mut rng = make_rng(0x42);

        let mut engine =
            HolePunchEngine::new(link_id, Some(test_probe_addr()), ProbeProtocol::Rnsp);
        engine.propose(&derived_key, 100.0, &mut rng).unwrap();
        engine.state = HolePunchState::Punching;
        engine.state_entered_at = 200.0;

        // Before timeout
        let actions = engine.tick(200.0 + PUNCH_TIMEOUT - 1.0);
        assert!(actions.is_empty());

        // After timeout
        let _actions = engine.tick(200.0 + PUNCH_TIMEOUT + 1.0);
        assert_eq!(engine.state(), HolePunchState::Failed);
    }

    #[test]
    fn test_message_serialization_roundtrip() {
        let session_id = [0xAB; 16];

        // UPGRADE_REQUEST (RNSP)
        let facilitator = test_probe_addr();
        let init_pub = test_public_addr_a();
        let data = encode_upgrade_request(
            &session_id,
            &facilitator,
            &init_pub,
            ProbeProtocol::Rnsp,
            &[],
        );
        let UpgradeRequest {
            session_id: sid,
            facilitator: f,
            initiator_public: a,
            protocol: proto,
            ..
        } = decode_upgrade_request(&data).unwrap();
        assert_eq!(sid, session_id);
        assert_eq!(f, facilitator);
        assert_eq!(a, init_pub);
        assert_eq!(proto, ProbeProtocol::Rnsp);

        // UPGRADE_ACCEPT
        let data = encode_upgrade_accept(&session_id);
        let sid = decode_upgrade_accept(&data).unwrap();
        assert_eq!(sid, session_id);

        // UPGRADE_REJECT
        let data = encode_upgrade_reject(&session_id, REJECT_POLICY);
        let (sid, r) = decode_upgrade_reject(&data).unwrap();
        assert_eq!(sid, session_id);
        assert_eq!(r, REJECT_POLICY);

        // UPGRADE_READY
        let resp_pub = test_public_addr_b();
        let data = encode_upgrade_ready(&session_id, &resp_pub, &[]);
        let (sid, rp, hosts) = decode_upgrade_ready(&data).unwrap();
        assert!(hosts.is_empty());
        assert_eq!(sid, session_id);
        assert_eq!(rp, resp_pub);

        // Session only
        let data = encode_session_only(&session_id);
        let sid = decode_session_only(&data).unwrap();
        assert_eq!(sid, session_id);
    }

    #[test]
    fn test_punch_token_derivation_consistency() {
        let derived_key = vec![0xBB; 32];
        let session_id = [0xCC; 16];

        let token1 = derive_punch_token(&derived_key, &session_id).unwrap();
        let token2 = derive_punch_token(&derived_key, &session_id).unwrap();
        assert_eq!(token1, token2);

        // Different session_id -> different token
        let session_id2 = [0xDD; 16];
        let token3 = derive_punch_token(&derived_key, &session_id2).unwrap();
        assert_ne!(token1, token3);
    }

    #[test]
    fn test_reset() {
        let link_id = [0xBB; 16];
        let derived_key = test_derived_key();
        let mut rng = make_rng(0x42);

        let mut engine =
            HolePunchEngine::new(link_id, Some(test_probe_addr()), ProbeProtocol::Rnsp);
        engine.propose(&derived_key, 100.0, &mut rng).unwrap();
        assert_eq!(engine.state(), HolePunchState::Discovering);

        engine.reset();
        assert_eq!(engine.state(), HolePunchState::Idle);
        assert_eq!(engine.session_id(), &[0u8; 16]);
    }

    #[test]
    fn test_build_reject_static() {
        let link_id = [0xCC; 16];
        let derived_key = test_derived_key();
        let mut rng = make_rng(0x42);

        let mut proposer =
            HolePunchEngine::new(link_id, Some(test_probe_addr()), ProbeProtocol::Rnsp);
        proposer.propose(&derived_key, 100.0, &mut rng).unwrap();
        let actions = proposer
            .endpoints_discovered(test_public_addr_a(), 101.0)
            .unwrap();
        let request_payload = match &actions[0] {
            HolePunchAction::SendSignal { payload, .. } => payload.clone(),
            _ => panic!(),
        };

        let action =
            HolePunchEngine::build_reject(link_id, &request_payload, REJECT_POLICY).unwrap();
        match action {
            HolePunchAction::SendSignal { msgtype, .. } => {
                assert_eq!(msgtype, UPGRADE_REJECT);
            }
            _ => panic!("Expected SendSignal(UPGRADE_REJECT)"),
        }
    }

    #[test]
    fn test_responder_needs_no_probe_addr() {
        // Responder uses facilitator from UPGRADE_REQUEST, doesn't need its own
        let link_id = [0xDD; 16];
        let derived_key = test_derived_key();
        let mut rng = make_rng(0x42);

        // Build a request
        let mut initiator =
            HolePunchEngine::new(link_id, Some(test_probe_addr()), ProbeProtocol::Rnsp);
        initiator.propose(&derived_key, 100.0, &mut rng).unwrap();
        let actions = initiator
            .endpoints_discovered(test_public_addr_a(), 101.0)
            .unwrap();
        let request_payload = match &actions[0] {
            HolePunchAction::SendSignal { payload, .. } => payload.clone(),
            _ => panic!(),
        };

        // Responder has NO probe_addr configured
        let mut responder = HolePunchEngine::new(link_id, None, ProbeProtocol::Rnsp);
        let actions = responder
            .handle_signal(UPGRADE_REQUEST, &request_payload, Some(&derived_key), 102.0)
            .unwrap();

        // Should still work — uses facilitator from the request
        assert_eq!(responder.state(), HolePunchState::Discovering);
        assert_eq!(actions.len(), 2);
        assert!(
            matches!(&actions[0], HolePunchAction::SendSignal { msgtype, .. } if *msgtype == UPGRADE_ACCEPT)
        );
        assert!(matches!(
            &actions[1],
            HolePunchAction::DiscoverEndpoints { .. }
        ));
    }

    #[test]
    fn test_stun_protocol_in_upgrade_request_roundtrip() {
        let session_id = [0xAB; 16];
        let facilitator = test_probe_addr();
        let init_pub = test_public_addr_a();

        // Encode with STUN protocol
        let data = encode_upgrade_request(
            &session_id,
            &facilitator,
            &init_pub,
            ProbeProtocol::Stun,
            &[],
        );
        let UpgradeRequest {
            session_id: sid,
            facilitator: f,
            initiator_public: a,
            protocol: proto,
            ..
        } = decode_upgrade_request(&data).unwrap();
        assert_eq!(sid, session_id);
        assert_eq!(f, facilitator);
        assert_eq!(a, init_pub);
        assert_eq!(proto, ProbeProtocol::Stun);
    }

    #[test]
    fn test_rnsp_protocol_omits_p_field() {
        let session_id = [0xAB; 16];
        let facilitator = test_probe_addr();
        let init_pub = test_public_addr_a();

        // Encode with RNSP (default) — should NOT include "p" field
        let data = encode_upgrade_request(
            &session_id,
            &facilitator,
            &init_pub,
            ProbeProtocol::Rnsp,
            &[],
        );
        let UpgradeRequest {
            session_id: sid,
            facilitator: f,
            initiator_public: a,
            protocol: proto,
            ..
        } = decode_upgrade_request(&data).unwrap();
        assert_eq!(sid, session_id);
        assert_eq!(f, facilitator);
        assert_eq!(a, init_pub);
        assert_eq!(proto, ProbeProtocol::Rnsp);
    }

    #[test]
    fn test_backward_compat_decode_without_p_field() {
        // Simulate old node payload that has no "p" field
        let session_id = [0xAB; 16];
        let facilitator = test_probe_addr();
        let init_pub = test_public_addr_a();

        // Manually encode without "p" field (old format)
        let val = Value::Map(alloc::vec![
            (
                Value::Str(alloc::string::String::from("s")),
                Value::Bin(session_id.to_vec())
            ),
            (
                Value::Str(alloc::string::String::from("f")),
                encode_endpoint(&facilitator)
            ),
            (
                Value::Str(alloc::string::String::from("a")),
                encode_endpoint(&init_pub)
            ),
        ]);
        let data = msgpack::pack(&val);

        let UpgradeRequest {
            session_id: sid,
            facilitator: f,
            initiator_public: a,
            protocol: proto,
            ..
        } = decode_upgrade_request(&data).unwrap();
        assert_eq!(sid, session_id);
        assert_eq!(f, facilitator);
        assert_eq!(a, init_pub);
        assert_eq!(proto, ProbeProtocol::Rnsp); // Default fallback
    }

    #[test]
    fn test_stun_initiator_responder_gets_stun_protocol() {
        let link_id = [0xEE; 16];
        let derived_key = test_derived_key();
        let mut rng = make_rng(0x42);

        // Initiator uses STUN
        let mut initiator =
            HolePunchEngine::new(link_id, Some(test_probe_addr()), ProbeProtocol::Stun);
        let actions = initiator.propose(&derived_key, 100.0, &mut rng).unwrap();

        // DiscoverEndpoints should carry Stun protocol
        match &actions[0] {
            HolePunchAction::DiscoverEndpoints { protocol, .. } => {
                assert_eq!(*protocol, ProbeProtocol::Stun);
            }
            _ => panic!("Expected DiscoverEndpoints"),
        }

        let actions = initiator
            .endpoints_discovered(test_public_addr_a(), 101.0)
            .unwrap();
        let request_payload = match &actions[0] {
            HolePunchAction::SendSignal { payload, .. } => payload.clone(),
            _ => panic!(),
        };

        // Responder decodes and gets Stun protocol
        let mut responder = HolePunchEngine::new(link_id, None, ProbeProtocol::Rnsp);
        let actions = responder
            .handle_signal(UPGRADE_REQUEST, &request_payload, Some(&derived_key), 102.0)
            .unwrap();

        // Responder's DiscoverEndpoints should carry Stun protocol (from request)
        match &actions[1] {
            HolePunchAction::DiscoverEndpoints { protocol, .. } => {
                assert_eq!(*protocol, ProbeProtocol::Stun);
            }
            _ => panic!("Expected DiscoverEndpoints"),
        }
    }

    fn signal(action: &HolePunchAction) -> Option<(u8, Vec<u8>)> {
        match action {
            HolePunchAction::SendSignal {
                msgtype, payload, ..
            } => Some((*msgtype, payload.clone())),
            _ => None,
        }
    }

    #[test]
    fn hello_round_trips_and_ignores_unknown_fields() {
        let hello = decode_hello(&encode_hello(true)).unwrap();
        assert_eq!(
            hello,
            Hello {
                version: DIRECT_LINK_VERSION,
                reply_wanted: true
            }
        );
        assert!(!decode_hello(&encode_hello(false)).unwrap().reply_wanted);
        // A later version may add fields and advertise a higher version.
        let extended = msgpack::pack(&Value::Map(vec![
            (Value::Str("v".into()), Value::UInt(7)),
            (Value::Str("x".into()), Value::Bin(vec![1, 2])),
        ]));
        assert_eq!(
            decode_hello(&extended).unwrap(),
            Hello {
                version: 7,
                reply_wanted: false
            }
        );
        assert!(decode_hello(&[0xC0]).is_err());
    }

    #[test]
    fn initiator_repeats_its_request_until_ready() {
        let derived_key = test_derived_key();
        let mut initiator =
            HolePunchEngine::new([0x31; 16], Some(test_probe_addr()), ProbeProtocol::Rnsp);
        initiator
            .propose(&derived_key, 100.0, &mut make_rng(1))
            .unwrap();
        let sent = initiator
            .endpoints_discovered(test_public_addr_a(), 100.0)
            .unwrap();
        let request = signal(&sent[0]).unwrap();
        assert_eq!(request.0, UPGRADE_REQUEST);

        assert!(initiator.tick(101.0).is_empty());
        let resent = initiator.tick(100.0 + REQUEST_RETRY_INTERVAL);
        assert_eq!(resent.len(), 1);
        assert_eq!(signal(&resent[0]), Some(request.clone()));

        // Still repeated after ACCEPT, until READY.
        let accept = encode_upgrade_accept(initiator.session_id());
        initiator
            .handle_signal(UPGRADE_ACCEPT, &accept, None, 102.5)
            .unwrap();
        assert_eq!(initiator.state(), HolePunchState::WaitingReady);
        let resent = initiator.tick(102.5 + REQUEST_RETRY_INTERVAL);
        assert_eq!(signal(&resent[0]), Some(request));
        // A repeated ACCEPT is harmless.
        assert!(initiator
            .handle_signal(UPGRADE_ACCEPT, &accept, None, 105.0)
            .unwrap()
            .is_empty());

        let ready = encode_upgrade_ready(initiator.session_id(), &test_public_addr_b(), &[]);
        let punch = initiator
            .handle_signal(UPGRADE_READY, &ready, None, 105.0)
            .unwrap();
        assert!(matches!(punch[0], HolePunchAction::StartUdpPunch { .. }));
        // Punching: no more requests, and a repeated READY starts nothing.
        assert!(initiator.tick(105.0 + REQUEST_RETRY_INTERVAL).is_empty());
        assert!(initiator
            .handle_signal(UPGRADE_READY, &ready, None, 106.0)
            .unwrap()
            .is_empty());
    }

    #[test]
    fn responder_replays_its_replies() {
        let derived_key = test_derived_key();
        let mut initiator =
            HolePunchEngine::new([0x32; 16], Some(test_probe_addr()), ProbeProtocol::Rnsp);
        initiator
            .propose(&derived_key, 100.0, &mut make_rng(2))
            .unwrap();
        let request = signal(
            &initiator
                .endpoints_discovered(test_public_addr_a(), 100.0)
                .unwrap()[0],
        )
        .unwrap()
        .1;
        assert_eq!(
            HolePunchEngine::request_session_id(&request).unwrap(),
            *initiator.session_id()
        );

        let mut responder = HolePunchEngine::new([0x32; 16], None, ProbeProtocol::Rnsp);
        assert!(responder.replay_replies().is_empty());
        responder
            .handle_signal(UPGRADE_REQUEST, &request, Some(&derived_key), 101.0)
            .unwrap();
        // Before our endpoint is known: ACCEPT only.
        let replay: Vec<_> = responder
            .replay_replies()
            .iter()
            .filter_map(signal)
            .collect();
        assert_eq!(replay.len(), 1);
        assert_eq!(replay[0].0, UPGRADE_ACCEPT);

        responder
            .endpoints_discovered(test_public_addr_b(), 102.0)
            .unwrap();
        let replay: Vec<_> = responder
            .replay_replies()
            .iter()
            .filter_map(signal)
            .collect();
        assert_eq!(
            replay.iter().map(|(kind, _)| *kind).collect::<Vec<_>>(),
            vec![UPGRADE_ACCEPT, UPGRADE_READY]
        );
        let (_, ready_endpoint, _) = decode_upgrade_ready(&replay[1].1).unwrap();
        assert_eq!(ready_endpoint, test_public_addr_b());
        // An initiator has nothing to replay.
        assert!(initiator.replay_replies().is_empty());
    }

    #[test]
    fn fallback_round_trips() {
        let body = encode_fallback(&[9; 16], true);
        assert_eq!(decode_fallback(&body).unwrap(), ([9; 16], true));
        assert_eq!(
            decode_fallback(&encode_fallback(&[3; 16], false)).unwrap(),
            ([3; 16], false)
        );
        assert!(decode_fallback(&encode_hello(true)).is_err());
    }

    #[test]
    fn keepalive_key_is_shared_by_both_sides_and_not_the_punch_token() {
        let derived_key = test_derived_key();
        let mut initiator =
            HolePunchEngine::new([0x33; 16], Some(test_probe_addr()), ProbeProtocol::Rnsp);
        initiator
            .propose(&derived_key, 100.0, &mut make_rng(4))
            .unwrap();
        let request = signal(
            &initiator
                .endpoints_discovered(test_public_addr_a(), 100.0)
                .unwrap()[0],
        )
        .unwrap()
        .1;
        let mut responder = HolePunchEngine::new([0x33; 16], None, ProbeProtocol::Rnsp);
        responder
            .handle_signal(UPGRADE_REQUEST, &request, Some(&derived_key), 101.0)
            .unwrap();
        assert_eq!(initiator.keepalive_key(), responder.keepalive_key());
        assert_ne!(initiator.keepalive_key(), initiator.punch_token());
        assert_ne!(*initiator.keepalive_key(), [0u8; 32]);
    }

    #[test]
    fn responder_that_cannot_probe_rejects_and_initiator_fails_fast() {
        let derived_key = test_derived_key();
        let mut initiator =
            HolePunchEngine::new([0x34; 16], Some(test_probe_addr()), ProbeProtocol::Rnsp);
        initiator
            .propose(&derived_key, 100.0, &mut make_rng(5))
            .unwrap();
        let request = signal(
            &initiator
                .endpoints_discovered(test_public_addr_a(), 100.0)
                .unwrap()[0],
        )
        .unwrap()
        .1;
        let mut responder = HolePunchEngine::new([0x34; 16], None, ProbeProtocol::Rnsp);
        let accept = signal(
            &responder
                .handle_signal(UPGRADE_REQUEST, &request, Some(&derived_key), 101.0)
                .unwrap()[0],
        )
        .unwrap()
        .1;
        initiator
            .handle_signal(UPGRADE_ACCEPT, &accept, None, 101.5)
            .unwrap();
        assert_eq!(initiator.state(), HolePunchState::WaitingReady);

        let actions = responder.discovery_failed(102.0).unwrap();
        assert_eq!(responder.state(), HolePunchState::Failed);
        let (kind, reject) = signal(&actions[0]).unwrap();
        assert_eq!(kind, UPGRADE_REJECT);
        assert!(matches!(
            actions[1],
            HolePunchAction::Failed {
                reason: FAIL_PROBE,
                ..
            }
        ));

        let failed = initiator
            .handle_signal(UPGRADE_REJECT, &reject, None, 102.5)
            .unwrap();
        assert_eq!(initiator.state(), HolePunchState::Failed);
        assert!(matches!(
            failed[0],
            HolePunchAction::Failed {
                reason: REJECT_NO_ENDPOINT,
                ..
            }
        ));
    }

    #[test]
    fn responder_discovery_timeout_also_rejects() {
        let derived_key = test_derived_key();
        let mut initiator =
            HolePunchEngine::new([0x35; 16], Some(test_probe_addr()), ProbeProtocol::Rnsp);
        initiator
            .propose(&derived_key, 100.0, &mut make_rng(6))
            .unwrap();
        // The initiator's own discovery timing out sends nothing.
        let actions = initiator.tick(100.0 + DISCOVER_TIMEOUT + 1.0);
        assert!(actions.iter().all(|a| signal(a).is_none()));

        let mut initiator =
            HolePunchEngine::new([0x35; 16], Some(test_probe_addr()), ProbeProtocol::Rnsp);
        initiator
            .propose(&derived_key, 100.0, &mut make_rng(6))
            .unwrap();
        let request = signal(
            &initiator
                .endpoints_discovered(test_public_addr_a(), 100.0)
                .unwrap()[0],
        )
        .unwrap()
        .1;
        let mut responder = HolePunchEngine::new([0x35; 16], None, ProbeProtocol::Rnsp);
        responder
            .handle_signal(UPGRADE_REQUEST, &request, Some(&derived_key), 101.0)
            .unwrap();
        let actions = responder.tick(101.0 + DISCOVER_TIMEOUT + 1.0);
        assert_eq!(signal(&actions[0]).unwrap().0, UPGRADE_REJECT);
    }

    fn request_payload_of(actions: &[HolePunchAction]) -> Vec<u8> {
        match &actions[0] {
            HolePunchAction::SendSignal {
                msgtype: UPGRADE_REQUEST,
                payload,
                ..
            } => payload.clone(),
            other => panic!("expected UPGRADE_REQUEST, got {other:?}"),
        }
    }

    /// An initiator that sent its request at 101.0, and the responder that
    /// accepted it at 102.0.
    fn proposing_pair() -> (HolePunchEngine, HolePunchEngine, Vec<u8>) {
        let link_id = [0x33; 16];
        let derived_key = test_derived_key();
        let mut rng = make_rng(0x42);
        let mut initiator =
            HolePunchEngine::new(link_id, Some(test_probe_addr()), ProbeProtocol::Rnsp);
        initiator.propose(&derived_key, 100.0, &mut rng).unwrap();
        let request = request_payload_of(
            &initiator
                .endpoints_discovered(test_public_addr_a(), 101.0)
                .unwrap(),
        );
        let mut responder = HolePunchEngine::new(link_id, None, ProbeProtocol::Rnsp);
        responder
            .handle_signal(UPGRADE_REQUEST, &request, Some(&derived_key), 102.0)
            .unwrap();
        (initiator, responder, request)
    }

    #[test]
    fn session_keys_are_derived_from_the_link_key_and_session() {
        let (initiator, responder, _) = proposing_pair();
        let derived_key = test_derived_key();
        let session_id = *initiator.session_id();
        assert_eq!(
            derive_keepalive_key(&derived_key, &session_id).unwrap()[..],
            hkdf(
                32,
                &derived_key,
                Some(&session_id),
                Some(b"rns-holepunch-keepalive-v1")
            )
            .unwrap()[..]
        );
        for engine in [&initiator, &responder] {
            assert_eq!(
                engine.punch_token(),
                &derive_punch_token(&derived_key, &session_id).unwrap()
            );
            assert_eq!(
                engine.keepalive_key(),
                &derive_keepalive_key(&derived_key, &session_id).unwrap()
            );
        }
    }

    #[test]
    fn each_side_knows_its_role_and_the_peer_endpoint() {
        let (initiator, responder, request) = proposing_pair();
        assert!(initiator.is_initiator());
        assert!(!responder.is_initiator());
        assert_eq!(
            responder.peer_public_endpoint(),
            Some(&test_public_addr_a())
        );
        assert!(HolePunchEngine::validate_upgrade_request(&request).is_ok());
        assert_eq!(
            HolePunchEngine::validate_upgrade_request(&[0x90]),
            Err(HolePunchError::InvalidPayload)
        );
    }

    #[test]
    fn overridden_facilitator_is_sent_in_the_request() {
        let mut rng = make_rng(0x42);
        let mut initiator =
            HolePunchEngine::new([0x44; 16], Some(test_probe_addr()), ProbeProtocol::Rnsp);
        initiator
            .propose(&test_derived_key(), 100.0, &mut rng)
            .unwrap();
        let other = Endpoint {
            addr: vec![9, 9, 9, 9],
            port: 7000,
        };
        initiator.set_facilitator(other.clone());
        let request = request_payload_of(
            &initiator
                .endpoints_discovered(test_public_addr_a(), 101.0)
                .unwrap(),
        );
        assert_eq!(decode_upgrade_request(&request).unwrap().facilitator, other);
    }

    #[test]
    fn timeouts_fire_strictly_after_their_duration() {
        let mut rng = make_rng(0x42);
        for (state, timeout) in [
            (HolePunchState::Discovering, DISCOVER_TIMEOUT),
            (HolePunchState::Proposing, PROPOSE_TIMEOUT),
            (HolePunchState::WaitingReady, READY_TIMEOUT),
            (HolePunchState::Punching, PUNCH_TIMEOUT),
        ] {
            let mut engine =
                HolePunchEngine::new([0x55; 16], Some(test_probe_addr()), ProbeProtocol::Rnsp);
            engine
                .propose(&test_derived_key(), 100.0, &mut rng)
                .unwrap();
            engine.state = state;
            engine.state_entered_at = 200.0;
            engine.request_sent_at = 200.0 + timeout;
            assert!(engine.tick(200.0 + timeout).is_empty(), "{state:?}");
            assert_eq!(engine.state(), state);
            engine.tick(200.0 + timeout + 0.001);
            assert_eq!(engine.state(), HolePunchState::Failed, "{state:?}");
        }
    }

    #[test]
    fn initiator_takes_replies_only_in_the_state_awaiting_them() {
        // Still discovering its own endpoint: no request went out yet.
        let mut rng = make_rng(0x42);
        let derived_key = test_derived_key();
        let mut initiator =
            HolePunchEngine::new([0x66; 16], Some(test_probe_addr()), ProbeProtocol::Rnsp);
        initiator.propose(&derived_key, 100.0, &mut rng).unwrap();
        let session_id = *initiator.session_id();
        for (msgtype, payload) in [
            (UPGRADE_ACCEPT, encode_upgrade_accept(&session_id)),
            (
                UPGRADE_REJECT,
                encode_upgrade_reject(&session_id, REJECT_POLICY),
            ),
            (
                UPGRADE_READY,
                encode_upgrade_ready(&session_id, &test_public_addr_b(), &[]),
            ),
        ] {
            assert_eq!(
                initiator
                    .handle_signal(msgtype, &payload, None, 101.0)
                    .err(),
                Some(HolePunchError::InvalidState),
                "{msgtype}"
            );
            assert_eq!(initiator.state(), HolePunchState::Discovering);
        }

        // READY before ACCEPT.
        let (mut initiator, _, _) = proposing_pair();
        let session_id = *initiator.session_id();
        let ready = encode_upgrade_ready(&session_id, &test_public_addr_b(), &[]);
        assert_eq!(
            initiator
                .handle_signal(UPGRADE_READY, &ready, None, 103.0)
                .err(),
            Some(HolePunchError::InvalidState)
        );
        assert_eq!(initiator.state(), HolePunchState::Proposing);
        assert_eq!(initiator.peer_public_endpoint(), None);
        initiator
            .handle_signal(
                UPGRADE_ACCEPT,
                &encode_upgrade_accept(&session_id),
                None,
                103.0,
            )
            .unwrap();
        initiator
            .handle_signal(UPGRADE_READY, &ready, None, 104.0)
            .unwrap();
        assert_eq!(
            initiator.peer_public_endpoint(),
            Some(&test_public_addr_b())
        );
    }

    #[test]
    fn endpoint_needs_an_address_and_a_port_and_ignores_the_rest() {
        let ep = test_public_addr_a();
        let mut fields = vec![Value::Bin(ep.addr.clone()), Value::UInt(ep.port as u64)];
        assert_eq!(
            decode_endpoint(&Value::Array(fields.clone())),
            Some(ep.clone())
        );
        fields.push(Value::Nil);
        assert_eq!(decode_endpoint(&Value::Array(fields.clone())), Some(ep));
        fields.truncate(1);
        assert_eq!(decode_endpoint(&Value::Array(fields)), None);
    }
}
