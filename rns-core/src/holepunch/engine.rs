//! HolePunchEngine: pure-logic state machine for NAT hole punching.
//!
//! Follows the asymmetric protocol from direct-link-protocol.md:
//!
//! Phase 1: A probes facilitator T → learns A_pub
//! Phase 2: A sends UPGRADE_REQUEST {facilitator: T, initiator_public: A_pub} → B
//!          B responds with UPGRADE_ACCEPT or UPGRADE_REJECT
//! Phase 3: B probes T (from request) → learns B_pub
//!          B sends UPGRADE_READY {responder_public: B_pub} → A
//! Phase 4: Both punch simultaneously
//! Phase 5: Direct link established
//!
//! Methods return `Vec<HolePunchAction>` instead of performing I/O.

use alloc::vec::Vec;

use rns_crypto::hkdf::hkdf;
use rns_crypto::Rng;

use crate::msgpack::{self, Value};

use super::types::*;

/// Derives a 32-byte punch token from the link's derived key and session ID.
///
/// `HKDF(ikm=derived_key, salt=session_id, info="rns-holepunch-v1")[:32]`
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

    /// Facilitator (STUN probe) address.
    /// Initiator: our configured probe address.
    /// Responder: received from UPGRADE_REQUEST.
    facilitator_addr: Option<Endpoint>,

    /// Punch token derived from link key + session_id.
    punch_token: [u8; 32],

    /// Probe service address for endpoint discovery (configured on this node).
    probe_addr: Option<Endpoint>,

    /// Protocol to use for endpoint discovery.
    probe_protocol: ProbeProtocol,

    /// Timestamp of state entry (for timeout tracking).
    state_entered_at: f64,
}

impl HolePunchEngine {
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
            facilitator_addr: None,
            punch_token: [0u8; 32],
            probe_addr,
            probe_protocol,
            state_entered_at: 0.0,
        }
    }

    pub fn state(&self) -> HolePunchState {
        self.state
    }

    pub fn session_id(&self) -> &[u8; 16] {
        &self.session_id
    }

    pub fn is_initiator(&self) -> bool {
        self.is_initiator
    }

    pub fn punch_token(&self) -> &[u8; 32] {
        &self.punch_token
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

        // Derive punch token
        self.punch_token = derive_punch_token(derived_key, &session_id)?;

        let probe_addr = self.probe_addr.clone().ok_or(HolePunchError::NoProbeAddr)?;
        self.facilitator_addr = Some(probe_addr.clone());

        // Phase 1: discover our public endpoint first
        self.state = HolePunchState::Discovering;
        self.state_entered_at = now;

        Ok(alloc::vec![HolePunchAction::DiscoverEndpoints { probe_addr, protocol: self.probe_protocol }])
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
            let facilitator = self.facilitator_addr.clone()
                .ok_or(HolePunchError::NoProbeAddr)?;

            let payload = encode_upgrade_request(
                &self.session_id,
                &facilitator,
                &public_endpoint,
                self.probe_protocol,
            );

            self.state = HolePunchState::Proposing;
            self.state_entered_at = now;

            Ok(alloc::vec![HolePunchAction::SendSignal {
                link_id: self.link_id,
                msgtype: UPGRADE_REQUEST,
                payload,
            }])
        } else {
            // Responder: Phase 3 complete -> send UPGRADE_READY, start punching
            let payload = encode_upgrade_ready(&self.session_id, &public_endpoint);

            let peer_public = self.peer_public_endpoint.clone()
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
        msgtype: u16,
        payload: &[u8],
        derived_key: Option<&[u8]>,
        now: f64,
    ) -> Result<Vec<HolePunchAction>, HolePunchError> {
        match msgtype {
            UPGRADE_REQUEST => self.handle_upgrade_request(payload, derived_key, now),
            UPGRADE_ACCEPT => self.handle_upgrade_accept(payload, now),
            UPGRADE_REJECT => self.handle_upgrade_reject(payload, now),
            UPGRADE_READY => self.handle_upgrade_ready(payload, now),
            UPGRADE_COMPLETE => self.handle_upgrade_complete(payload, now),
            _ => Err(HolePunchError::InvalidPayload),
        }
    }

    /// Called when the punch phase succeeds.
    ///
    /// Transitions: Punching -> Connected.
    pub fn punch_succeeded(
        &mut self,
        now: f64,
    ) -> Result<Vec<HolePunchAction>, HolePunchError> {
        if self.state != HolePunchState::Punching {
            return Err(HolePunchError::InvalidState);
        }

        self.state = HolePunchState::Connected;
        self.state_entered_at = now;

        Ok(alloc::vec![
            HolePunchAction::Succeeded {
                session_id: self.session_id,
            },
        ])
    }

    /// Called when the punch phase fails.
    ///
    /// Transitions: Punching -> Failed.
    pub fn punch_failed(
        &mut self,
        now: f64,
    ) -> Result<Vec<HolePunchAction>, HolePunchError> {
        if self.state != HolePunchState::Punching {
            return Err(HolePunchError::InvalidState);
        }

        self.state = HolePunchState::Failed;
        self.state_entered_at = now;

        Ok(alloc::vec![
            HolePunchAction::Failed {
                session_id: self.session_id,
                reason: FAIL_TIMEOUT,
            },
        ])
    }

    /// Periodic tick: check timeouts.
    pub fn tick(&mut self, now: f64) -> Vec<HolePunchAction> {
        let elapsed = now - self.state_entered_at;
        match self.state {
            HolePunchState::Discovering if elapsed > DISCOVER_TIMEOUT => {
                self.state = HolePunchState::Failed;
                self.state_entered_at = now;
                alloc::vec![HolePunchAction::Failed {
                    session_id: self.session_id,
                    reason: FAIL_PROBE,
                }]
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
        let (session_id, _, _, _) = decode_upgrade_request(request_payload)?;
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
        self.probe_protocol = ProbeProtocol::Rnsp;
        self.state_entered_at = 0.0;
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
            let (session_id, _, _, _) = decode_upgrade_request(payload)?;
            let reject_payload = encode_upgrade_reject(&session_id, REJECT_BUSY);
            return Ok(alloc::vec![HolePunchAction::SendSignal {
                link_id: self.link_id,
                msgtype: UPGRADE_REJECT,
                payload: reject_payload,
            }]);
        }

        let derived_key = derived_key.ok_or(HolePunchError::NoDerivedKey)?;
        let (session_id, facilitator, initiator_public, protocol) = decode_upgrade_request(payload)?;

        self.session_id = session_id;
        self.is_initiator = false;
        self.probe_protocol = protocol;
        self.punch_token = derive_punch_token(derived_key, &session_id)?;

        // Store A's public address (we'll punch this later)
        self.peer_public_endpoint = Some(initiator_public);

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
            HolePunchAction::DiscoverEndpoints { probe_addr: facilitator, protocol },
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
        if self.state != HolePunchState::Proposing || !self.is_initiator {
            return Err(HolePunchError::InvalidState);
        }

        let session_id = decode_upgrade_accept(payload)?;
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
        if self.state != HolePunchState::Proposing {
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
        if self.state != HolePunchState::WaitingReady || !self.is_initiator {
            return Err(HolePunchError::InvalidState);
        }

        let (session_id, responder_public) = decode_upgrade_ready(payload)?;
        if session_id != self.session_id {
            return Err(HolePunchError::SessionMismatch);
        }

        self.peer_public_endpoint = Some(responder_public.clone());

        self.state = HolePunchState::Punching;
        self.state_entered_at = now;

        Ok(alloc::vec![HolePunchAction::StartUdpPunch {
            peer_public: responder_public,
            punch_token: self.punch_token,
            session_id: self.session_id,
        }])
    }

    /// Receives UPGRADE_COMPLETE (over direct UDP channel after punch succeeds).
    fn handle_upgrade_complete(
        &mut self,
        payload: &[u8],
        now: f64,
    ) -> Result<Vec<HolePunchAction>, HolePunchError> {
        if self.state != HolePunchState::Punching && self.state != HolePunchState::Connected {
            return Err(HolePunchError::InvalidState);
        }

        let session_id = decode_session_only(payload)?;
        if session_id != self.session_id {
            return Err(HolePunchError::SessionMismatch);
        }

        if self.state == HolePunchState::Connected {
            // Already connected — peer is confirming
            return Ok(Vec::new());
        }

        self.state = HolePunchState::Connected;
        self.state_entered_at = now;

        Ok(alloc::vec![HolePunchAction::Succeeded {
            session_id: self.session_id,
        }])
    }
}

// --- Msgpack encode/decode helpers ---

fn encode_upgrade_request(
    session_id: &[u8; 16],
    facilitator: &Endpoint,
    initiator_public: &Endpoint,
    protocol: ProbeProtocol,
) -> Vec<u8> {
    let mut fields = alloc::vec![
        (Value::Str(alloc::string::String::from("s")), Value::Bin(session_id.to_vec())),
        (Value::Str(alloc::string::String::from("f")), encode_endpoint(facilitator)),
        (Value::Str(alloc::string::String::from("a")), encode_endpoint(initiator_public)),
    ];
    // Only include "p" when not RNSP (backward compat: old nodes don't send it)
    if protocol != ProbeProtocol::Rnsp {
        fields.push((Value::Str(alloc::string::String::from("p")), Value::UInt(protocol as u64)));
    }
    let val = Value::Map(fields);
    msgpack::pack(&val)
}

fn decode_upgrade_request(data: &[u8]) -> Result<([u8; 16], Endpoint, Endpoint, ProbeProtocol), HolePunchError> {
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
    Ok((session_id, facilitator, initiator_public, protocol))
}

fn encode_upgrade_accept(session_id: &[u8; 16]) -> Vec<u8> {
    let val = Value::Map(alloc::vec![
        (Value::Str(alloc::string::String::from("s")), Value::Bin(session_id.to_vec())),
    ]);
    msgpack::pack(&val)
}

fn decode_upgrade_accept(data: &[u8]) -> Result<[u8; 16], HolePunchError> {
    let (val, _) = msgpack::unpack(data).map_err(|_| HolePunchError::InvalidPayload)?;
    extract_session_id(&val)
}

fn encode_upgrade_reject(session_id: &[u8; 16], reason: u8) -> Vec<u8> {
    let val = Value::Map(alloc::vec![
        (Value::Str(alloc::string::String::from("s")), Value::Bin(session_id.to_vec())),
        (Value::Str(alloc::string::String::from("r")), Value::UInt(reason as u64)),
    ]);
    msgpack::pack(&val)
}

fn decode_upgrade_reject(data: &[u8]) -> Result<([u8; 16], u8), HolePunchError> {
    let (val, _) = msgpack::unpack(data).map_err(|_| HolePunchError::InvalidPayload)?;
    let session_id = extract_session_id(&val)?;
    let reason = val
        .map_get("r")
        .and_then(|v| v.as_uint())
        .ok_or(HolePunchError::InvalidPayload)? as u8;
    Ok((session_id, reason))
}

fn encode_upgrade_ready(session_id: &[u8; 16], responder_public: &Endpoint) -> Vec<u8> {
    let val = Value::Map(alloc::vec![
        (Value::Str(alloc::string::String::from("s")), Value::Bin(session_id.to_vec())),
        (Value::Str(alloc::string::String::from("a")), encode_endpoint(responder_public)),
    ]);
    msgpack::pack(&val)
}

fn decode_upgrade_ready(data: &[u8]) -> Result<([u8; 16], Endpoint), HolePunchError> {
    let (val, _) = msgpack::unpack(data).map_err(|_| HolePunchError::InvalidPayload)?;
    let session_id = extract_session_id(&val)?;
    let responder_public = val
        .map_get("a")
        .and_then(decode_endpoint)
        .ok_or(HolePunchError::InvalidPayload)?;
    Ok((session_id, responder_public))
}

fn encode_endpoint(ep: &Endpoint) -> Value {
    Value::Array(alloc::vec![
        Value::Bin(ep.addr.clone()),
        Value::UInt(ep.port as u64),
    ])
}

fn decode_endpoint(val: &Value) -> Option<Endpoint> {
    let arr = val.as_array()?;
    if arr.len() < 2 {
        return None;
    }
    let addr = arr[0].as_bin()?.to_vec();
    let port = arr[1].as_uint()? as u16;
    Some(Endpoint { addr, port })
}

#[cfg(test)]
fn encode_session_only(session_id: &[u8; 16]) -> Vec<u8> {
    let val = Value::Map(alloc::vec![
        (Value::Str(alloc::string::String::from("s")), Value::Bin(session_id.to_vec())),
    ]);
    msgpack::pack(&val)
}

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

        let mut initiator = HolePunchEngine::new(link_id, Some(test_probe_addr()), ProbeProtocol::Rnsp);
        let actions = initiator.propose(&derived_key, 100.0, &mut rng).unwrap();

        // Should transition to Discovering, not Proposing
        assert_eq!(initiator.state(), HolePunchState::Discovering);
        assert_eq!(actions.len(), 1);
        assert!(matches!(&actions[0], HolePunchAction::DiscoverEndpoints { .. }));
    }

    #[test]
    fn test_initiator_sends_request_after_discovery() {
        let link_id = [0x11; 16];
        let derived_key = test_derived_key();
        let mut rng = make_rng(0x42);

        let mut initiator = HolePunchEngine::new(link_id, Some(test_probe_addr()), ProbeProtocol::Rnsp);
        initiator.propose(&derived_key, 100.0, &mut rng).unwrap();

        // Initiator discovers its public endpoint
        let actions = initiator
            .endpoints_discovered(test_public_addr_a(), 101.0)
            .unwrap();

        // Should transition to Proposing and send UPGRADE_REQUEST
        assert_eq!(initiator.state(), HolePunchState::Proposing);
        assert_eq!(actions.len(), 1);
        match &actions[0] {
            HolePunchAction::SendSignal { msgtype, payload, .. } => {
                assert_eq!(*msgtype, UPGRADE_REQUEST);
                // Verify payload contains facilitator and initiator_public
                let (sid, facilitator, init_pub, _proto) = decode_upgrade_request(payload).unwrap();
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
        let mut initiator = HolePunchEngine::new(link_id, Some(test_probe_addr()), ProbeProtocol::Rnsp);
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
            HolePunchAction::SendSignal { msgtype, payload, .. } => {
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
            HolePunchAction::SendSignal { msgtype, payload, .. } => {
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
    }

    #[test]
    fn test_punch_success() {
        let link_id = [0x33; 16];
        let derived_key = test_derived_key();
        let mut rng = make_rng(0x42);

        let mut engine = HolePunchEngine::new(link_id, Some(test_probe_addr()), ProbeProtocol::Rnsp);
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

        let mut engine = HolePunchEngine::new(link_id, Some(test_probe_addr()), ProbeProtocol::Rnsp);
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
        let mut proposer = HolePunchEngine::new(link_id, Some(test_probe_addr()), ProbeProtocol::Rnsp);
        proposer.propose(&derived_key, 100.0, &mut rng).unwrap();
        let actions = proposer.endpoints_discovered(test_public_addr_a(), 101.0).unwrap();
        let request_payload = match &actions[0] {
            HolePunchAction::SendSignal { payload, .. } => payload.clone(),
            _ => panic!(),
        };

        // Responder is already busy (set to Discovering manually)
        let mut responder = HolePunchEngine::new(link_id, Some(test_probe_addr()), ProbeProtocol::Rnsp);
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

        let mut initiator = HolePunchEngine::new(link_id, Some(test_probe_addr()), ProbeProtocol::Rnsp);
        initiator.propose(&derived_key, 100.0, &mut rng).unwrap();
        initiator.endpoints_discovered(test_public_addr_a(), 101.0).unwrap();
        assert_eq!(initiator.state(), HolePunchState::Proposing);

        let session_id = *initiator.session_id();
        let reject_payload = encode_upgrade_reject(&session_id, REJECT_POLICY);

        let actions = initiator
            .handle_signal(UPGRADE_REJECT, &reject_payload, None, 102.0)
            .unwrap();

        assert_eq!(initiator.state(), HolePunchState::Failed);
        assert_eq!(actions.len(), 1);
        assert!(matches!(&actions[0], HolePunchAction::Failed { reason, .. } if *reason == REJECT_POLICY));
    }

    #[test]
    fn test_discover_timeout() {
        let link_id = [0x77; 16];
        let derived_key = test_derived_key();
        let mut rng = make_rng(0x42);

        let mut engine = HolePunchEngine::new(link_id, Some(test_probe_addr()), ProbeProtocol::Rnsp);
        engine.propose(&derived_key, 100.0, &mut rng).unwrap();
        assert_eq!(engine.state(), HolePunchState::Discovering);

        // Before timeout
        let actions = engine.tick(100.0 + DISCOVER_TIMEOUT - 1.0);
        assert!(actions.is_empty());

        // After timeout
        let actions = engine.tick(100.0 + DISCOVER_TIMEOUT + 1.0);
        assert_eq!(engine.state(), HolePunchState::Failed);
        assert!(matches!(&actions[0], HolePunchAction::Failed { reason, .. } if *reason == FAIL_PROBE));
    }

    #[test]
    fn test_propose_timeout() {
        let link_id = [0x88; 16];
        let derived_key = test_derived_key();
        let mut rng = make_rng(0x42);

        let mut engine = HolePunchEngine::new(link_id, Some(test_probe_addr()), ProbeProtocol::Rnsp);
        engine.propose(&derived_key, 100.0, &mut rng).unwrap();
        engine.endpoints_discovered(test_public_addr_a(), 101.0).unwrap();
        assert_eq!(engine.state(), HolePunchState::Proposing);

        // After timeout
        let actions = engine.tick(101.0 + PROPOSE_TIMEOUT + 1.0);
        assert_eq!(engine.state(), HolePunchState::Failed);
        assert!(matches!(&actions[0], HolePunchAction::Failed { reason, .. } if *reason == FAIL_TIMEOUT));
    }

    #[test]
    fn test_waiting_ready_timeout() {
        let link_id = [0x99; 16];
        let derived_key = test_derived_key();
        let mut rng = make_rng(0x42);

        let mut engine = HolePunchEngine::new(link_id, Some(test_probe_addr()), ProbeProtocol::Rnsp);
        engine.propose(&derived_key, 200.0, &mut rng).unwrap();
        engine.endpoints_discovered(test_public_addr_a(), 201.0).unwrap();
        engine.state = HolePunchState::WaitingReady;
        engine.state_entered_at = 202.0;

        // After timeout
        let actions = engine.tick(202.0 + READY_TIMEOUT + 1.0);
        assert_eq!(engine.state(), HolePunchState::Failed);
        assert!(matches!(&actions[0], HolePunchAction::Failed { reason, .. } if *reason == FAIL_TIMEOUT));
    }

    #[test]
    fn test_punch_timeout() {
        let link_id = [0xAA; 16];
        let derived_key = test_derived_key();
        let mut rng = make_rng(0x42);

        let mut engine = HolePunchEngine::new(link_id, Some(test_probe_addr()), ProbeProtocol::Rnsp);
        engine.propose(&derived_key, 100.0, &mut rng).unwrap();
        engine.state = HolePunchState::Punching;
        engine.state_entered_at = 200.0;

        // Before timeout
        let actions = engine.tick(200.0 + PUNCH_TIMEOUT - 1.0);
        assert!(actions.is_empty());

        // After timeout
        let actions = engine.tick(200.0 + PUNCH_TIMEOUT + 1.0);
        assert_eq!(engine.state(), HolePunchState::Failed);
    }

    #[test]
    fn test_message_serialization_roundtrip() {
        let session_id = [0xAB; 16];

        // UPGRADE_REQUEST (RNSP)
        let facilitator = test_probe_addr();
        let init_pub = test_public_addr_a();
        let data = encode_upgrade_request(&session_id, &facilitator, &init_pub, ProbeProtocol::Rnsp);
        let (sid, f, a, proto) = decode_upgrade_request(&data).unwrap();
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
        let data = encode_upgrade_ready(&session_id, &resp_pub);
        let (sid, rp) = decode_upgrade_ready(&data).unwrap();
        assert_eq!(sid, session_id);
        assert_eq!(rp, resp_pub);

        // Session only (UPGRADE_COMPLETE)
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

        let mut engine = HolePunchEngine::new(link_id, Some(test_probe_addr()), ProbeProtocol::Rnsp);
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

        let mut proposer = HolePunchEngine::new(link_id, Some(test_probe_addr()), ProbeProtocol::Rnsp);
        proposer.propose(&derived_key, 100.0, &mut rng).unwrap();
        let actions = proposer.endpoints_discovered(test_public_addr_a(), 101.0).unwrap();
        let request_payload = match &actions[0] {
            HolePunchAction::SendSignal { payload, .. } => payload.clone(),
            _ => panic!(),
        };

        let action = HolePunchEngine::build_reject(link_id, &request_payload, REJECT_POLICY).unwrap();
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
        let mut initiator = HolePunchEngine::new(link_id, Some(test_probe_addr()), ProbeProtocol::Rnsp);
        initiator.propose(&derived_key, 100.0, &mut rng).unwrap();
        let actions = initiator.endpoints_discovered(test_public_addr_a(), 101.0).unwrap();
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
        assert!(matches!(&actions[0], HolePunchAction::SendSignal { msgtype, .. } if *msgtype == UPGRADE_ACCEPT));
        assert!(matches!(&actions[1], HolePunchAction::DiscoverEndpoints { .. }));
    }

    #[test]
    fn test_stun_protocol_in_upgrade_request_roundtrip() {
        let session_id = [0xAB; 16];
        let facilitator = test_probe_addr();
        let init_pub = test_public_addr_a();

        // Encode with STUN protocol
        let data = encode_upgrade_request(&session_id, &facilitator, &init_pub, ProbeProtocol::Stun);
        let (sid, f, a, proto) = decode_upgrade_request(&data).unwrap();
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
        let data = encode_upgrade_request(&session_id, &facilitator, &init_pub, ProbeProtocol::Rnsp);
        let (sid, f, a, proto) = decode_upgrade_request(&data).unwrap();
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
            (Value::Str(alloc::string::String::from("s")), Value::Bin(session_id.to_vec())),
            (Value::Str(alloc::string::String::from("f")), encode_endpoint(&facilitator)),
            (Value::Str(alloc::string::String::from("a")), encode_endpoint(&init_pub)),
        ]);
        let data = msgpack::pack(&val);

        let (sid, f, a, proto) = decode_upgrade_request(&data).unwrap();
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
        let mut initiator = HolePunchEngine::new(link_id, Some(test_probe_addr()), ProbeProtocol::Stun);
        let actions = initiator.propose(&derived_key, 100.0, &mut rng).unwrap();

        // DiscoverEndpoints should carry Stun protocol
        match &actions[0] {
            HolePunchAction::DiscoverEndpoints { protocol, .. } => {
                assert_eq!(*protocol, ProbeProtocol::Stun);
            }
            _ => panic!("Expected DiscoverEndpoints"),
        }

        let actions = initiator.endpoints_discovered(test_public_addr_a(), 101.0).unwrap();
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
}
