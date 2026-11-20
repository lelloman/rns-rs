//! Handshake state machines for the two ends of a session. They do no I/O:
//! the caller sends and receives the messages and feeds in a monotonic
//! clock (`now`, a `Duration` since a fixed start of its choosing).

use std::fmt;
use std::net::Ipv4Addr;
use std::time::Duration;

use crate::policy::Cidr;
use crate::protocol::ControlMessage;

/// Where a [`ClientSession`] is in the handshake.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientState {
    /// Waiting for the Link to the gateway.
    PendingLink,
    /// Link up and identified to the gateway; hello not yet sent.
    Identified,
    /// Hello sent; waiting for the gateway's accept.
    Negotiating,
    /// Accept received; configuring the tunnel interface.
    DeviceSetup,
    /// `ClientReady` sent; waiting for `ServerReady`.
    AwaitingServerReady,
    /// Packets may flow.
    Active,
    /// Closing after a timeout or a local close.
    Closing,
}
/// Where a [`GatewaySession`] is in the handshake.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GatewayState {
    /// Link up; waiting for the client to identify itself.
    PendingIdentity,
    /// Identified; the hello is being answered.
    Negotiating,
    /// Accept sent; waiting for `ClientReady`.
    DeviceSetup,
    /// Packets may flow.
    Active,
    /// Closing after a timeout.
    Closing,
}

/// A handshake step that the state machine refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionError {
    /// The step is not allowed in the current state.
    InvalidState,
    /// The message names a different session epoch.
    EpochMismatch,
    /// A second, different hello arrived before identification.
    ConflictingDuplicate,
    /// A handshake deadline passed; the session is now closing.
    Timeout,
    /// The message is not the kind this step expects.
    ProtocolViolation,
}
impl fmt::Display for SessionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "rntun session error: {self:?}")
    }
}
impl std::error::Error for SessionError {}

/// The session terms from a gateway's `ServerAccept`, as the client took
/// them. Not validated here; the caller checks them against its own
/// configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcceptedConfig {
    /// Session epoch.
    pub epoch: u64,
    /// The client's tunnel address.
    pub address: Ipv4Addr,
    /// Prefix length of the tunnel subnet.
    pub prefix_len: u8,
    /// The gateway's tunnel address.
    pub gateway: Ipv4Addr,
    /// Routes granted through the tunnel.
    pub routes: Vec<Cidr>,
    /// Resolvers to install; non-empty for a full tunnel.
    pub dns_servers: Vec<Ipv4Addr>,
    /// Largest packet in bytes.
    pub mtu: u16,
    /// Time allowed from the accept to `ServerReady`.
    pub setup_timeout: Duration,
}

/// Client side of the handshake. Each method is one step and fails with
/// [`SessionError::InvalidState`] when called out of order.
pub struct ClientSession {
    state: ClientState,
    accepted: Option<AcceptedConfig>,
    deadline: Option<Duration>,
}
impl ClientSession {
    /// A session in [`ClientState::PendingLink`].
    pub fn new() -> Self {
        Self {
            state: ClientState::PendingLink,
            accepted: None,
            deadline: None,
        }
    }
    /// Current state.
    pub fn state(&self) -> ClientState {
        self.state
    }
    /// The accepted terms, once [`ClientSession::accept`] has succeeded.
    pub fn accepted(&self) -> Option<&AcceptedConfig> {
        self.accepted.as_ref()
    }
    /// The Link is up and the client has identified on it.
    pub fn link_established(&mut self) -> Result<(), SessionError> {
        if self.state != ClientState::PendingLink {
            return Err(SessionError::InvalidState);
        }
        self.state = ClientState::Identified;
        Ok(())
    }
    /// The `ClientHello` has been sent.
    pub fn hello_sent(&mut self) -> Result<(), SessionError> {
        if self.state != ClientState::Identified {
            return Err(SessionError::InvalidState);
        }
        self.state = ClientState::Negotiating;
        Ok(())
    }
    /// Take the server's accept, returning the configuration it grants.
    /// Starts the setup deadline from `now`. Fails with
    /// [`SessionError::ProtocolViolation`] for any other message.
    pub fn accept(
        &mut self,
        message: &ControlMessage,
        now: Duration,
    ) -> Result<&AcceptedConfig, SessionError> {
        let ControlMessage::ServerAccept {
            session_epoch,
            assigned_address,
            prefix_len,
            gateway_address,
            accepted_routes,
            dns_servers,
            packet_mtu,
            setup_timeout_secs,
            ..
        } = message
        else {
            return Err(SessionError::ProtocolViolation);
        };
        if self.state != ClientState::Negotiating {
            return Err(SessionError::InvalidState);
        };
        self.deadline = Some(now + Duration::from_secs(*setup_timeout_secs as u64));
        self.state = ClientState::DeviceSetup;
        Ok(self.accepted.insert(AcceptedConfig {
            epoch: *session_epoch,
            address: *assigned_address,
            prefix_len: *prefix_len,
            gateway: *gateway_address,
            routes: accepted_routes.clone(),
            dns_servers: dns_servers.clone(),
            mtu: *packet_mtu,
            setup_timeout: Duration::from_secs(*setup_timeout_secs as u64),
        }))
    }
    /// The tunnel interface is configured with `applied_dns`. Returns the
    /// `ClientReady` message to send.
    pub fn device_ready(
        &mut self,
        applied_dns: Vec<Ipv4Addr>,
    ) -> Result<ControlMessage, SessionError> {
        if self.state != ClientState::DeviceSetup {
            return Err(SessionError::InvalidState);
        };
        let epoch = self
            .accepted
            .as_ref()
            .ok_or(SessionError::InvalidState)?
            .epoch;
        self.state = ClientState::AwaitingServerReady;
        Ok(ControlMessage::ClientReady {
            session_epoch: epoch,
            dns_servers: applied_dns,
        })
    }
    /// The gateway's `ServerReady` for `epoch` arrived; the session becomes
    /// active and the deadline is cleared. A repeat for the active epoch is
    /// accepted again.
    pub fn server_ready(&mut self, epoch: u64) -> Result<(), SessionError> {
        if self.state == ClientState::Active
            && self.accepted.as_ref().is_some_and(|a| a.epoch == epoch)
        {
            return Ok(());
        }
        if self.state != ClientState::AwaitingServerReady {
            return Err(SessionError::InvalidState);
        };
        if self.accepted.as_ref().is_none_or(|a| a.epoch != epoch) {
            return Err(SessionError::EpochMismatch);
        }
        self.state = ClientState::Active;
        self.deadline = None;
        Ok(())
    }
    /// Fail with [`SessionError::Timeout`], moving to
    /// [`ClientState::Closing`], once the setup deadline has passed.
    pub fn check_timeout(&mut self, now: Duration) -> Result<(), SessionError> {
        if self.deadline.is_some_and(|d| now >= d) {
            self.state = ClientState::Closing;
            return Err(SessionError::Timeout);
        }
        Ok(())
    }
    /// Move to [`ClientState::Closing`] and return the `Close` message to
    /// send. Before an accept the message has epoch 0, which does not
    /// encode.
    pub fn begin_close(
        &mut self,
        reason: u16,
        diagnostic: String,
    ) -> Result<ControlMessage, SessionError> {
        if self.state == ClientState::Closing {
            return Err(SessionError::InvalidState);
        }
        self.state = ClientState::Closing;
        Ok(ControlMessage::Close {
            session_epoch: self.accepted.as_ref().map_or(0, |a| a.epoch),
            reason,
            diagnostic,
        })
    }
}
impl Default for ClientSession {
    fn default() -> Self {
        Self::new()
    }
}

/// Gateway side of the handshake for one incoming Link. Each method is one
/// step and fails with [`SessionError::InvalidState`] when called out of
/// order.
pub struct GatewaySession {
    state: GatewayState,
    identity: Option<[u8; 16]>,
    buffered_hello: Option<Vec<u8>>,
    epoch: Option<u64>,
    identify_deadline: Duration,
    setup_deadline: Option<Duration>,
}
impl GatewaySession {
    /// A session for a Link that came up at `now`; the client must identify
    /// within `identify_timeout`.
    pub fn new(now: Duration, identify_timeout: Duration) -> Self {
        Self {
            state: GatewayState::PendingIdentity,
            identity: None,
            buffered_hello: None,
            epoch: None,
            identify_deadline: now + identify_timeout,
            setup_deadline: None,
        }
    }
    /// Current state.
    pub fn state(&self) -> GatewayState {
        self.state
    }
    /// The client's identity hash, once identified.
    pub fn identity(&self) -> Option<[u8; 16]> {
        self.identity
    }
    /// Hold an encoded hello that arrived before the client identified, to
    /// be handled after [`GatewaySession::identified`]. An identical repeat
    /// is ignored; a different one fails with
    /// [`SessionError::ConflictingDuplicate`].
    pub fn receive_preidentify_hello(&mut self, encoded: Vec<u8>) -> Result<(), SessionError> {
        if self.state != GatewayState::PendingIdentity {
            return Err(SessionError::InvalidState);
        };
        match &self.buffered_hello {
            None => {
                self.buffered_hello = Some(encoded);
                Ok(())
            }
            Some(existing) if existing == &encoded => Ok(()),
            Some(_) => Err(SessionError::ConflictingDuplicate),
        }
    }
    /// The client identified as `identity`. Returns the hello held by
    /// [`GatewaySession::receive_preidentify_hello`], if any.
    pub fn identified(&mut self, identity: [u8; 16]) -> Result<Option<Vec<u8>>, SessionError> {
        if self.state != GatewayState::PendingIdentity {
            return Err(SessionError::InvalidState);
        };
        self.identity = Some(identity);
        self.state = GatewayState::Negotiating;
        Ok(self.buffered_hello.take())
    }
    /// A `ServerAccept` with `epoch` (nonzero) was sent at `now`; the client
    /// has `setup_timeout` to answer with `ClientReady`.
    pub fn accepted(
        &mut self,
        epoch: u64,
        now: Duration,
        setup_timeout: Duration,
    ) -> Result<(), SessionError> {
        if self.state != GatewayState::Negotiating || epoch == 0 {
            return Err(SessionError::InvalidState);
        }
        self.epoch = Some(epoch);
        self.setup_deadline = Some(now + setup_timeout);
        self.state = GatewayState::DeviceSetup;
        Ok(())
    }
    /// The client's `ClientReady` for `epoch` arrived; the session becomes
    /// active. Returns the `ServerReady` to send, also for a repeat on the
    /// active epoch.
    pub fn client_ready(&mut self, epoch: u64) -> Result<ControlMessage, SessionError> {
        if self.state == GatewayState::Active && self.epoch == Some(epoch) {
            return Ok(ControlMessage::ServerReady {
                session_epoch: epoch,
            });
        }
        if self.state != GatewayState::DeviceSetup {
            return Err(SessionError::InvalidState);
        }
        if self.epoch != Some(epoch) {
            return Err(SessionError::EpochMismatch);
        }
        self.state = GatewayState::Active;
        self.setup_deadline = None;
        Ok(ControlMessage::ServerReady {
            session_epoch: epoch,
        })
    }
    /// Whether packet fragments may be accepted (the session is active).
    pub fn permits_packet_data(&self) -> bool {
        self.state == GatewayState::Active
    }
    /// Fail with [`SessionError::Timeout`], moving to
    /// [`GatewayState::Closing`], once the identify or setup deadline has
    /// passed.
    pub fn check_timeout(&mut self, now: Duration) -> Result<(), SessionError> {
        if self.state == GatewayState::PendingIdentity && now >= self.identify_deadline
            || self.setup_deadline.is_some_and(|d| now >= d)
        {
            self.state = GatewayState::Closing;
            return Err(SessionError::Timeout);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn accept() -> ControlMessage {
        ControlMessage::ServerAccept {
            session_epoch: 7,
            assigned_address: "10.77.0.2".parse().unwrap(),
            prefix_len: 24,
            gateway_address: "10.77.0.1".parse().unwrap(),
            accepted_routes: vec![],
            dns_servers: vec![],
            packet_mtu: 1280,
            setup_timeout_secs: 60,
            idle_timeout_secs: 0,
        }
    }
    #[test]
    fn client_requires_ready_ack() {
        let mut c = ClientSession::new();
        c.link_established().unwrap();
        c.hello_sent().unwrap();
        c.accept(&accept(), Duration::ZERO).unwrap();
        assert_eq!(c.state(), ClientState::DeviceSetup);
        c.device_ready(vec![]).unwrap();
        assert_eq!(c.state(), ClientState::AwaitingServerReady);
        c.server_ready(7).unwrap();
        assert_eq!(c.state(), ClientState::Active);
    }
    #[test]
    fn gateway_holds_one_hello() {
        let mut g = GatewaySession::new(Duration::ZERO, Duration::from_secs(10));
        g.receive_preidentify_hello(vec![1]).unwrap();
        assert_eq!(
            g.receive_preidentify_hello(vec![2]),
            Err(SessionError::ConflictingDuplicate)
        );
        assert_eq!(g.identified([3; 16]).unwrap(), Some(vec![1]));
    }
}
