//! Per-session packet transport: validates and authorizes IPv4 packets and
//! turns them into encoded fragments and back.

use std::collections::{HashSet, VecDeque};
use std::fmt;
use std::net::Ipv4Addr;
use std::time::Duration;

use crate::packet::{
    fragment_packet, valid_icmp_error_exception, validate_ipv4, PacketError, Reassembler,
    ValidatedIpv4,
};
use crate::policy::Cidr;
use crate::protocol::{PacketFragment, ProtocolError, FRAGMENT_HEADER_LEN};

/// Which way a packet travels; selects the address checks applied.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketDirection {
    /// From the client into the tunnel: the source must be the client's
    /// address and the destination inside an accepted route.
    ClientToGateway,
    /// From the gateway to the client: the destination must be the client's
    /// address and the source the gateway or inside an accepted route.
    GatewayToClient,
}

/// Why a packet or fragment was refused.
#[derive(Debug)]
pub enum TransportError {
    /// The IPv4 packet or the reassembly failed.
    Packet(PacketError),
    /// The fragment frame did not decode or encode.
    Protocol(ProtocolError),
    /// The fragment belongs to another session epoch, or the transport was
    /// created with epoch 0.
    WrongEpoch,
    /// The source address is not allowed in this direction.
    UnauthorizedSource(Ipv4Addr),
    /// The destination address is not allowed in this direction.
    UnauthorizedDestination(Ipv4Addr),
    /// The Link MDU leaves no room for payload after the fragment header.
    LinkMduTooSmall,
    /// Packet ids have run out; the session must be renegotiated.
    PacketIdExhausted,
    /// A fragment of a recently delivered packet arrived again.
    Replay,
}
impl fmt::Display for TransportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "rntun packet transport error: {self:?}")
    }
}
impl std::error::Error for TransportError {}
impl From<PacketError> for TransportError {
    fn from(value: PacketError) -> Self {
        Self::Packet(value)
    }
}
impl From<ProtocolError> for TransportError {
    fn from(value: ProtocolError) -> Self {
        Self::Protocol(value)
    }
}

/// One session's packet path in both directions. Outgoing packets get
/// increasing packet ids; incoming ones are reassembled (at most 32 pending
/// packets, 48 000 bytes, 30 s idle expiry) and checked against the last
/// 1024 delivered ids for replays.
pub struct PacketTransport {
    epoch: u64,
    assigned: Ipv4Addr,
    gateway: Ipv4Addr,
    routes: Vec<Cidr>,
    mtu: usize,
    next_packet_id: u64,
    reassembler: Reassembler,
    recent_ids: VecDeque<u64>,
    recent_id_set: HashSet<u64>,
}

impl PacketTransport {
    /// A transport for session `epoch` (nonzero) with the client at
    /// `assigned`, the gateway at `gateway`, the accepted `routes` and the
    /// negotiated `mtu` in bytes. Outgoing packet ids start at
    /// `initial_packet_id`; pick it at random so ids differ across sessions.
    pub fn new(
        epoch: u64,
        assigned: Ipv4Addr,
        gateway: Ipv4Addr,
        routes: Vec<Cidr>,
        mtu: u16,
        initial_packet_id: u64,
    ) -> Result<Self, TransportError> {
        if epoch == 0 {
            return Err(TransportError::WrongEpoch);
        }
        Ok(Self {
            epoch,
            assigned,
            gateway,
            routes,
            mtu: mtu as usize,
            next_packet_id: initial_packet_id,
            reassembler: Reassembler::new(32, 48_000, Duration::from_secs(30)),
            recent_ids: VecDeque::new(),
            recent_id_set: HashSet::new(),
        })
    }

    /// Validate and authorize `packet` for `direction`, then split it into
    /// encoded fragment frames that each fit in `link_mdu` bytes.
    pub fn packetize(
        &mut self,
        packet: &[u8],
        direction: PacketDirection,
        link_mdu: usize,
    ) -> Result<Vec<Vec<u8>>, TransportError> {
        let parsed = validate_ipv4(packet, self.mtu)?;
        self.authorize(packet, parsed, direction)?;
        if self.next_packet_id == u64::MAX {
            return Err(TransportError::PacketIdExhausted);
        }
        let maximum_payload = link_mdu
            .checked_sub(FRAGMENT_HEADER_LEN)
            .filter(|value| *value > 0)
            .ok_or(TransportError::LinkMduTooSmall)?;
        let packet_id = self.next_packet_id;
        self.next_packet_id += 1;
        fragment_packet(packet, self.epoch, packet_id, maximum_payload)?
            .into_iter()
            .map(|fragment| fragment.encode().map_err(TransportError::from))
            .collect()
    }

    /// Take one encoded fragment received for `direction` at `now` (a
    /// monotonic clock). Returns the packet once complete and authorized,
    /// `None` while fragments are missing.
    pub fn receive(
        &mut self,
        encoded: &[u8],
        direction: PacketDirection,
        now: Duration,
    ) -> Result<Option<Vec<u8>>, TransportError> {
        let fragment = PacketFragment::decode(encoded)?;
        if fragment.session_epoch != self.epoch {
            return Err(TransportError::WrongEpoch);
        }
        if self.recent_id_set.contains(&fragment.packet_id) {
            return Err(TransportError::Replay);
        }
        let packet_id = fragment.packet_id;
        let Some(packet) = self.reassembler.push(fragment, now)? else {
            return Ok(None);
        };
        let parsed = validate_ipv4(&packet, self.mtu)?;
        self.authorize(&packet, parsed, direction)?;
        self.recent_ids.push_back(packet_id);
        self.recent_id_set.insert(packet_id);
        if self.recent_ids.len() > 1024 {
            if let Some(expired) = self.recent_ids.pop_front() {
                self.recent_id_set.remove(&expired);
            }
        }
        Ok(Some(packet))
    }

    fn authorize(
        &self,
        packet: &[u8],
        parsed: ValidatedIpv4,
        direction: PacketDirection,
    ) -> Result<(), TransportError> {
        match direction {
            PacketDirection::ClientToGateway => {
                if parsed.source != self.assigned {
                    return Err(TransportError::UnauthorizedSource(parsed.source));
                }
                if !self
                    .routes
                    .iter()
                    .any(|route| route.contains(parsed.destination))
                {
                    return Err(TransportError::UnauthorizedDestination(parsed.destination));
                }
            }
            PacketDirection::GatewayToClient => {
                if parsed.destination != self.assigned
                    && !valid_icmp_error_exception(packet, self.assigned, &self.routes)
                {
                    return Err(TransportError::UnauthorizedDestination(parsed.destination));
                }
                if parsed.source != self.gateway
                    && !self
                        .routes
                        .iter()
                        .any(|route| route.contains(parsed.source))
                {
                    return Err(TransportError::UnauthorizedSource(parsed.source));
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::checksum;

    fn packet(source: [u8; 4], destination: [u8; 4]) -> Vec<u8> {
        let mut packet = vec![0; 20];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&20u16.to_be_bytes());
        packet[6..8].copy_from_slice(&0x4000u16.to_be_bytes());
        packet[8] = 64;
        packet[9] = 17;
        packet[12..16].copy_from_slice(&source);
        packet[16..20].copy_from_slice(&destination);
        let sum = checksum(&packet);
        packet[10..12].copy_from_slice(&sum.to_be_bytes());
        packet
    }

    fn transport() -> PacketTransport {
        PacketTransport::new(
            7,
            "10.77.0.2".parse().unwrap(),
            "10.77.0.1".parse().unwrap(),
            vec!["10.20.0.0/16".parse().unwrap()],
            1280,
            1,
        )
        .unwrap()
    }

    #[test]
    fn round_trip_authorized_packet() {
        let packet = packet([10, 77, 0, 2], [10, 20, 0, 4]);
        let mut sender = transport();
        let frames = sender
            .packetize(&packet, PacketDirection::ClientToGateway, 80)
            .unwrap();
        let mut receiver = transport();
        let mut result = None;
        for frame in frames {
            result = receiver
                .receive(&frame, PacketDirection::ClientToGateway, Duration::ZERO)
                .unwrap()
                .or(result);
        }
        assert_eq!(result, Some(packet));
    }

    #[test]
    fn rejects_spoofed_client_source() {
        let packet = packet([10, 77, 0, 3], [10, 20, 0, 4]);
        assert!(matches!(
            transport().packetize(&packet, PacketDirection::ClientToGateway, 500),
            Err(TransportError::UnauthorizedSource(_))
        ));
    }

    #[test]
    fn rejects_packet_id_wrap() {
        let packet = packet([10, 77, 0, 2], [10, 20, 0, 4]);
        let mut transport = PacketTransport::new(
            7,
            "10.77.0.2".parse().unwrap(),
            "10.77.0.1".parse().unwrap(),
            vec!["10.20.0.0/16".parse().unwrap()],
            1280,
            u64::MAX,
        )
        .unwrap();
        assert!(matches!(
            transport.packetize(&packet, PacketDirection::ClientToGateway, 500),
            Err(TransportError::PacketIdExhausted)
        ));
    }

    #[test]
    fn rejects_completed_packet_replay() {
        let packet = packet([10, 77, 0, 2], [10, 20, 0, 4]);
        let mut sender = transport();
        let frame = sender
            .packetize(&packet, PacketDirection::ClientToGateway, 500)
            .unwrap()
            .remove(0);
        let mut receiver = transport();
        assert!(receiver
            .receive(&frame, PacketDirection::ClientToGateway, Duration::ZERO)
            .unwrap()
            .is_some());
        assert!(matches!(
            receiver.receive(
                &frame,
                PacketDirection::ClientToGateway,
                Duration::from_secs(1)
            ),
            Err(TransportError::Replay)
        ));
    }
}
