use std::fmt;
use std::net::Ipv4Addr;
use std::time::Duration;

use crate::policy::Cidr;
use crate::protocol::ControlMessage;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientState {
    PendingLink,
    Identified,
    Negotiating,
    DeviceSetup,
    AwaitingServerReady,
    Active,
    Closing,
    Closed,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GatewayState {
    PendingIdentity,
    Negotiating,
    DeviceSetup,
    Active,
    Closing,
    Closed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionError {
    InvalidState,
    EpochMismatch,
    ConflictingDuplicate,
    Timeout,
    ProtocolViolation,
}
impl fmt::Display for SessionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "rntun session error: {self:?}")
    }
}
impl std::error::Error for SessionError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcceptedConfig {
    pub epoch: u64,
    pub address: Ipv4Addr,
    pub prefix_len: u8,
    pub gateway: Ipv4Addr,
    pub routes: Vec<Cidr>,
    pub dns_servers: Vec<Ipv4Addr>,
    pub mtu: u16,
    pub setup_timeout: Duration,
}

pub struct ClientSession {
    state: ClientState,
    accepted: Option<AcceptedConfig>,
    deadline: Option<Duration>,
}
impl ClientSession {
    pub fn new() -> Self {
        Self {
            state: ClientState::PendingLink,
            accepted: None,
            deadline: None,
        }
    }
    pub fn state(&self) -> ClientState {
        self.state
    }
    pub fn accepted(&self) -> Option<&AcceptedConfig> {
        self.accepted.as_ref()
    }
    pub fn link_established(&mut self) -> Result<(), SessionError> {
        if self.state != ClientState::PendingLink {
            return Err(SessionError::InvalidState);
        }
        self.state = ClientState::Identified;
        Ok(())
    }
    pub fn hello_sent(&mut self) -> Result<(), SessionError> {
        if self.state != ClientState::Identified {
            return Err(SessionError::InvalidState);
        }
        self.state = ClientState::Negotiating;
        Ok(())
    }
    pub fn accept(&mut self, message: &ControlMessage, now: Duration) -> Result<(), SessionError> {
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
        self.accepted = Some(AcceptedConfig {
            epoch: *session_epoch,
            address: *assigned_address,
            prefix_len: *prefix_len,
            gateway: *gateway_address,
            routes: accepted_routes.clone(),
            dns_servers: dns_servers.clone(),
            mtu: *packet_mtu,
            setup_timeout: Duration::from_secs(*setup_timeout_secs as u64),
        });
        self.deadline = Some(now + Duration::from_secs(*setup_timeout_secs as u64));
        self.state = ClientState::DeviceSetup;
        Ok(())
    }
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
    pub fn check_timeout(&mut self, now: Duration) -> Result<(), SessionError> {
        if self.deadline.is_some_and(|d| now >= d) {
            self.state = ClientState::Closing;
            return Err(SessionError::Timeout);
        }
        Ok(())
    }
    pub fn begin_close(
        &mut self,
        reason: u16,
        diagnostic: String,
    ) -> Result<ControlMessage, SessionError> {
        if matches!(self.state, ClientState::Closed | ClientState::Closing) {
            return Err(SessionError::InvalidState);
        };
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

pub struct GatewaySession {
    state: GatewayState,
    identity: Option<[u8; 16]>,
    buffered_hello: Option<Vec<u8>>,
    epoch: Option<u64>,
    identify_deadline: Duration,
    setup_deadline: Option<Duration>,
}
impl GatewaySession {
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
    pub fn state(&self) -> GatewayState {
        self.state
    }
    pub fn identity(&self) -> Option<[u8; 16]> {
        self.identity
    }
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
    pub fn identified(&mut self, identity: [u8; 16]) -> Result<Option<Vec<u8>>, SessionError> {
        if self.state != GatewayState::PendingIdentity {
            return Err(SessionError::InvalidState);
        };
        self.identity = Some(identity);
        self.state = GatewayState::Negotiating;
        Ok(self.buffered_hello.take())
    }
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
    pub fn permits_packet_data(&self) -> bool {
        self.state == GatewayState::Active
    }
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
