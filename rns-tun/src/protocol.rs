//! The rntun wire format: control messages, carried on a Reticulum Channel,
//! and packet fragments, carried as Link packets.
//!
//! Every frame starts with [`MAGIC`], the protocol version, a kind byte and
//! a 16-bit flags field that must be zero. Integers are big-endian.

use std::fmt;
use std::net::Ipv4Addr;

use crate::policy::Cidr;

/// The protocol version this crate speaks. Version 1 had `Ping`/`Pong`
/// kinds and a capabilities field in `ClientHello`; version 2 has neither.
pub const VERSION: u8 = 2;
/// First four bytes of every frame.
pub const MAGIC: [u8; 4] = *b"RNTU";
/// Largest control frame in bytes, header included.
pub const CONTROL_FRAME_MAX: usize = 384;
/// Longest diagnostic string in a reject or close message, in bytes.
pub const DIAGNOSTIC_MAX: usize = 128;
/// Most routes a hello or accept message may carry.
pub const ROUTE_MAX: usize = 32;
/// Most DNS servers an accept or ready message may carry.
pub const DNS_MAX: usize = 4;
/// Most protocol versions a client hello may offer.
pub const VERSION_MAX: usize = 4;
/// Largest tunnelled IPv4 packet in bytes.
pub const PACKET_MAX: usize = 1500;
/// Most fragments one packet may be split into.
pub const FRAGMENT_MAX: usize = 32;
/// Size in bytes of a packet fragment's header, before its payload.
pub const FRAGMENT_HEADER_LEN: usize = 30;

const KIND_CLIENT_HELLO: u8 = 1;
const KIND_SERVER_ACCEPT: u8 = 2;
const KIND_SERVER_REJECT: u8 = 3;
const KIND_CLIENT_READY: u8 = 4;
const KIND_SERVER_READY: u8 = 5;
// Kinds 6 and 7 were `Ping` and `Pong` in version 1; they stay unassigned.
const KIND_CLOSE: u8 = 8;
const KIND_CLOSE_ACK: u8 = 9;
const KIND_PACKET_FRAGMENT: u8 = 0x20;

/// Why a frame could not be encoded or decoded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProtocolError {
    /// The frame ends before a field it must hold.
    Truncated,
    /// The frame does not start with [`MAGIC`].
    InvalidMagic,
    /// The frame's version byte is not [`VERSION`].
    UnsupportedVersion(u8),
    /// The kind byte is not a known message (or not a fragment where one
    /// was expected).
    UnknownKind(u8),
    /// The flags field is not zero.
    UnknownFlags(u16),
    /// A length field disagrees with the frame size, or bytes are left over.
    InvalidLength,
    /// A count or size is over its protocol limit; names the field.
    LimitExceeded(&'static str),
    /// A field holds a value the protocol forbids, such as a zero session
    /// epoch; names the field.
    InvalidValue(&'static str),
    /// A diagnostic string is not UTF-8.
    InvalidUtf8,
}

impl fmt::Display for ProtocolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated => write!(f, "truncated rntun frame"),
            Self::InvalidMagic => write!(f, "invalid rntun magic"),
            Self::UnsupportedVersion(v) => write!(f, "unsupported rntun version {v}"),
            Self::UnknownKind(v) => write!(f, "unknown rntun message kind {v}"),
            Self::UnknownFlags(v) => write!(f, "unknown rntun flags 0x{v:04x}"),
            Self::InvalidLength => write!(f, "invalid rntun frame length"),
            Self::LimitExceeded(name) => write!(f, "rntun {name} limit exceeded"),
            Self::InvalidValue(name) => write!(f, "invalid rntun {name}"),
            Self::InvalidUtf8 => write!(f, "invalid UTF-8 diagnostic"),
        }
    }
}

impl std::error::Error for ProtocolError {}

/// A control message. The handshake is `ClientHello`, `ServerAccept` (or
/// `ServerReject`), `ClientReady`, `ServerReady`; after that packets flow.
/// Session epochs are never zero.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ControlMessage {
    /// Client's opening message.
    ClientHello {
        /// Protocol versions the client speaks, 1..=[`VERSION_MAX`] of them.
        versions: Vec<u8>,
        /// Largest IPv4 packet, in bytes, the client will send or receive.
        maximum_packet_size: u16,
        /// Networks the client wants routed through the tunnel.
        requested_routes: Vec<Cidr>,
    },
    /// Gateway's acceptance: the session's addressing and limits.
    ServerAccept {
        /// Nonzero id of this session; tags every later message and
        /// fragment.
        session_epoch: u64,
        /// The client's tunnel address.
        assigned_address: Ipv4Addr,
        /// Prefix length of the tunnel subnet.
        prefix_len: u8,
        /// The gateway's tunnel address.
        gateway_address: Ipv4Addr,
        /// The granted subset of the requested routes.
        accepted_routes: Vec<Cidr>,
        /// Resolvers the client must use; set for a full tunnel.
        dns_servers: Vec<Ipv4Addr>,
        /// Largest IPv4 packet in bytes either side may send.
        packet_mtu: u16,
        /// Seconds the client has to send `ClientReady`.
        setup_timeout_secs: u16,
        /// Seconds of inactivity after which the gateway drops the session;
        /// 0 for never.
        idle_timeout_secs: u32,
    },
    /// Gateway's refusal of a hello.
    ServerReject {
        /// Reason code: 1 identity not authorized, 2 malformed message,
        /// 3 DNS mismatch, 4 no common version or MTU, 5 no full-tunnel DNS
        /// on the gateway, 6 gateway at capacity.
        reason: u16,
        /// Human-readable detail, at most [`DIAGNOSTIC_MAX`] bytes.
        diagnostic: String,
    },
    /// Client's confirmation that its tunnel interface is configured.
    ClientReady {
        /// Epoch from `ServerAccept`.
        session_epoch: u64,
        /// The resolvers the client actually applied; must match the ones
        /// offered.
        dns_servers: Vec<Ipv4Addr>,
    },
    /// Gateway's confirmation that the session is active.
    ServerReady {
        /// Epoch from `ServerAccept`.
        session_epoch: u64,
    },
    /// Either side ends the session.
    Close {
        /// Epoch of the session being closed.
        session_epoch: u64,
        /// Reason code, application defined.
        reason: u16,
        /// Human-readable detail, at most [`DIAGNOSTIC_MAX`] bytes.
        diagnostic: String,
    },
    /// Acknowledges a `Close`.
    CloseAck {
        /// Epoch from the `Close`.
        session_epoch: u64,
    },
}

impl ControlMessage {
    /// Encode as one control frame. Fails when a list or string exceeds its
    /// limit, an epoch is zero, or the frame would exceed
    /// [`CONTROL_FRAME_MAX`].
    pub fn encode(&self) -> Result<Vec<u8>, ProtocolError> {
        let mut body = Vec::new();
        let kind = match self {
            Self::ClientHello {
                versions,
                maximum_packet_size,
                requested_routes,
            } => {
                put_count(&mut body, versions.len(), VERSION_MAX, "version count")?;
                body.extend_from_slice(versions);
                put_u16(&mut body, *maximum_packet_size);
                put_routes(&mut body, requested_routes)?;
                KIND_CLIENT_HELLO
            }
            Self::ServerAccept {
                session_epoch,
                assigned_address,
                prefix_len,
                gateway_address,
                accepted_routes,
                dns_servers,
                packet_mtu,
                setup_timeout_secs,
                idle_timeout_secs,
            } => {
                if *session_epoch == 0 {
                    return Err(ProtocolError::InvalidValue("session epoch"));
                }
                put_u64(&mut body, *session_epoch);
                body.extend_from_slice(&assigned_address.octets());
                body.push(*prefix_len);
                body.extend_from_slice(&gateway_address.octets());
                put_u16(&mut body, *packet_mtu);
                put_u16(&mut body, *setup_timeout_secs);
                put_u32(&mut body, *idle_timeout_secs);
                put_routes(&mut body, accepted_routes)?;
                put_ips(&mut body, dns_servers)?;
                KIND_SERVER_ACCEPT
            }
            Self::ServerReject { reason, diagnostic } => {
                put_u16(&mut body, *reason);
                put_string(&mut body, diagnostic)?;
                KIND_SERVER_REJECT
            }
            Self::ClientReady {
                session_epoch,
                dns_servers,
            } => {
                put_epoch(&mut body, *session_epoch)?;
                put_ips(&mut body, dns_servers)?;
                KIND_CLIENT_READY
            }
            Self::ServerReady { session_epoch } => {
                put_epoch(&mut body, *session_epoch)?;
                KIND_SERVER_READY
            }
            Self::Close {
                session_epoch,
                reason,
                diagnostic,
            } => {
                put_epoch(&mut body, *session_epoch)?;
                put_u16(&mut body, *reason);
                put_string(&mut body, diagnostic)?;
                KIND_CLOSE
            }
            Self::CloseAck { session_epoch } => {
                put_epoch(&mut body, *session_epoch)?;
                KIND_CLOSE_ACK
            }
        };
        let total = 10usize
            .checked_add(body.len())
            .ok_or(ProtocolError::InvalidLength)?;
        if total > CONTROL_FRAME_MAX {
            return Err(ProtocolError::LimitExceeded("control frame"));
        }
        let mut frame = Vec::with_capacity(total);
        frame.extend_from_slice(&MAGIC);
        frame.push(VERSION);
        frame.push(kind);
        put_u16(&mut frame, 0);
        put_u16(&mut frame, body.len() as u16);
        frame.extend_from_slice(&body);
        Ok(frame)
    }

    /// Decode one whole control frame, rejecting trailing bytes and every
    /// limit [`ControlMessage::encode`] enforces.
    pub fn decode(frame: &[u8]) -> Result<Self, ProtocolError> {
        let Some((header, body)) = frame.split_first_chunk::<10>() else {
            return Err(ProtocolError::Truncated);
        };
        if frame.len() > CONTROL_FRAME_MAX {
            return Err(ProtocolError::LimitExceeded("control frame"));
        }
        let [m0, m1, m2, m3, version, kind, f0, f1, l0, l1] = *header;
        if [m0, m1, m2, m3] != MAGIC {
            return Err(ProtocolError::InvalidMagic);
        }
        if version != VERSION {
            return Err(ProtocolError::UnsupportedVersion(version));
        }
        let flags = u16::from_be_bytes([f0, f1]);
        if flags != 0 {
            return Err(ProtocolError::UnknownFlags(flags));
        }
        let body_len = u16::from_be_bytes([l0, l1]) as usize;
        if body_len != body.len() {
            return Err(ProtocolError::InvalidLength);
        }
        let mut reader = Reader::new(body);
        let message = match kind {
            KIND_CLIENT_HELLO => {
                let count = reader.u8()? as usize;
                if count == 0 || count > VERSION_MAX {
                    return Err(ProtocolError::LimitExceeded("version count"));
                }
                let versions = reader.bytes(count)?.to_vec();
                let maximum_packet_size = reader.u16()?;
                let requested_routes = reader.routes()?;
                Self::ClientHello {
                    versions,
                    maximum_packet_size,
                    requested_routes,
                }
            }
            KIND_SERVER_ACCEPT => {
                let session_epoch = reader.epoch()?;
                let assigned_address = reader.ip()?;
                let prefix_len = reader.u8()?;
                let gateway_address = reader.ip()?;
                let packet_mtu = reader.u16()?;
                let setup_timeout_secs = reader.u16()?;
                let idle_timeout_secs = reader.u32()?;
                let accepted_routes = reader.routes()?;
                let dns_servers = reader.ips()?;
                Self::ServerAccept {
                    session_epoch,
                    assigned_address,
                    prefix_len,
                    gateway_address,
                    accepted_routes,
                    dns_servers,
                    packet_mtu,
                    setup_timeout_secs,
                    idle_timeout_secs,
                }
            }
            KIND_SERVER_REJECT => Self::ServerReject {
                reason: reader.u16()?,
                diagnostic: reader.string()?,
            },
            KIND_CLIENT_READY => Self::ClientReady {
                session_epoch: reader.epoch()?,
                dns_servers: reader.ips()?,
            },
            KIND_SERVER_READY => Self::ServerReady {
                session_epoch: reader.epoch()?,
            },
            KIND_CLOSE => Self::Close {
                session_epoch: reader.epoch()?,
                reason: reader.u16()?,
                diagnostic: reader.string()?,
            },
            KIND_CLOSE_ACK => Self::CloseAck {
                session_epoch: reader.epoch()?,
            },
            other => return Err(ProtocolError::UnknownKind(other)),
        };
        if !reader.finished() {
            return Err(ProtocolError::InvalidLength);
        }
        Ok(message)
    }
}

/// One piece of a tunnelled IPv4 packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PacketFragment {
    /// Epoch of the session the packet belongs to; nonzero.
    pub session_epoch: u64,
    /// Sender-chosen id shared by all fragments of one packet.
    pub packet_id: u64,
    /// Length of the whole packet in bytes, 1..=[`PACKET_MAX`].
    pub total_len: u16,
    /// Byte offset of `payload` within the packet.
    pub offset: u16,
    /// The fragment's bytes; never empty.
    pub payload: Vec<u8>,
}

impl PacketFragment {
    /// Encode as a [`FRAGMENT_HEADER_LEN`]-byte header followed by the
    /// payload. Fails on a zero epoch, an empty payload or a range outside
    /// `total_len`.
    pub fn encode(&self) -> Result<Vec<u8>, ProtocolError> {
        if self.session_epoch == 0 {
            return Err(ProtocolError::InvalidValue("session epoch"));
        }
        if self.total_len == 0 || self.total_len as usize > PACKET_MAX {
            return Err(ProtocolError::InvalidValue("packet length"));
        }
        if self.payload.is_empty() || self.payload.len() > u16::MAX as usize {
            return Err(ProtocolError::InvalidValue("fragment length"));
        }
        let end = self.offset as usize + self.payload.len();
        if end > self.total_len as usize {
            return Err(ProtocolError::InvalidValue("fragment range"));
        }
        let mut frame = Vec::with_capacity(FRAGMENT_HEADER_LEN + self.payload.len());
        frame.extend_from_slice(&MAGIC);
        frame.push(VERSION);
        frame.push(KIND_PACKET_FRAGMENT);
        put_u16(&mut frame, 0);
        put_u64(&mut frame, self.session_epoch);
        put_u64(&mut frame, self.packet_id);
        put_u16(&mut frame, self.total_len);
        put_u16(&mut frame, self.offset);
        put_u16(&mut frame, self.payload.len() as u16);
        frame.extend_from_slice(&self.payload);
        Ok(frame)
    }

    /// Decode one whole fragment frame, checking the same rules as
    /// [`PacketFragment::encode`].
    pub fn decode(frame: &[u8]) -> Result<Self, ProtocolError> {
        if frame.len() < FRAGMENT_HEADER_LEN {
            return Err(ProtocolError::Truncated);
        }
        let Some((&[m0, m1, m2, m3, version, kind, f0, f1], body)) = frame.split_first_chunk::<8>()
        else {
            return Err(ProtocolError::Truncated);
        };
        if [m0, m1, m2, m3] != MAGIC {
            return Err(ProtocolError::InvalidMagic);
        }
        if version != VERSION {
            return Err(ProtocolError::UnsupportedVersion(version));
        }
        if kind != KIND_PACKET_FRAGMENT {
            return Err(ProtocolError::UnknownKind(kind));
        }
        let flags = u16::from_be_bytes([f0, f1]);
        if flags != 0 {
            return Err(ProtocolError::UnknownFlags(flags));
        }
        let mut reader = Reader::new(body);
        let session_epoch = reader.epoch()?;
        let packet_id = reader.u64()?;
        let total_len = reader.u16()?;
        let offset = reader.u16()?;
        let fragment_len = reader.u16()? as usize;
        if fragment_len == 0 || fragment_len != reader.remaining() {
            return Err(ProtocolError::InvalidLength);
        }
        if total_len == 0
            || total_len as usize > PACKET_MAX
            || offset as usize + fragment_len > total_len as usize
        {
            return Err(ProtocolError::InvalidValue("fragment range"));
        }
        Ok(Self {
            session_epoch,
            packet_id,
            total_len,
            offset,
            payload: reader.bytes(fragment_len)?.to_vec(),
        })
    }
}

fn put_u16(out: &mut Vec<u8>, value: u16) {
    out.extend_from_slice(&value.to_be_bytes());
}
fn put_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_be_bytes());
}
fn put_u64(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&value.to_be_bytes());
}
fn put_epoch(out: &mut Vec<u8>, value: u64) -> Result<(), ProtocolError> {
    if value == 0 {
        Err(ProtocolError::InvalidValue("session epoch"))
    } else {
        put_u64(out, value);
        Ok(())
    }
}
fn put_count(
    out: &mut Vec<u8>,
    count: usize,
    max: usize,
    name: &'static str,
) -> Result<(), ProtocolError> {
    if count > max || count > u8::MAX as usize {
        return Err(ProtocolError::LimitExceeded(name));
    }
    out.push(count as u8);
    Ok(())
}
fn put_routes(out: &mut Vec<u8>, routes: &[Cidr]) -> Result<(), ProtocolError> {
    put_count(out, routes.len(), ROUTE_MAX, "route count")?;
    for route in routes {
        out.extend_from_slice(&route.network().octets());
        out.push(route.prefix_len());
    }
    Ok(())
}
fn put_ips(out: &mut Vec<u8>, ips: &[Ipv4Addr]) -> Result<(), ProtocolError> {
    put_count(out, ips.len(), DNS_MAX, "DNS server count")?;
    for ip in ips {
        out.extend_from_slice(&ip.octets());
    }
    Ok(())
}
fn put_string(out: &mut Vec<u8>, value: &str) -> Result<(), ProtocolError> {
    if value.len() > DIAGNOSTIC_MAX {
        return Err(ProtocolError::LimitExceeded("diagnostic"));
    }
    out.push(value.len() as u8);
    out.extend_from_slice(value.as_bytes());
    Ok(())
}

struct Reader<'a> {
    bytes: &'a [u8],
    offset: usize,
}
impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }
    fn remaining(&self) -> usize {
        self.bytes.len().saturating_sub(self.offset)
    }
    fn finished(&self) -> bool {
        self.offset == self.bytes.len()
    }
    fn bytes(&mut self, n: usize) -> Result<&'a [u8], ProtocolError> {
        let end = self
            .offset
            .checked_add(n)
            .ok_or(ProtocolError::InvalidLength)?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(ProtocolError::Truncated)?;
        self.offset = end;
        Ok(value)
    }
    fn u8(&mut self) -> Result<u8, ProtocolError> {
        self.array().map(u8::from_be_bytes)
    }
    fn u16(&mut self) -> Result<u16, ProtocolError> {
        self.array().map(u16::from_be_bytes)
    }
    fn array<const N: usize>(&mut self) -> Result<[u8; N], ProtocolError> {
        let v = self.bytes(N)?;
        v.first_chunk().copied().ok_or(ProtocolError::Truncated)
    }
    fn u32(&mut self) -> Result<u32, ProtocolError> {
        self.array().map(u32::from_be_bytes)
    }
    fn u64(&mut self) -> Result<u64, ProtocolError> {
        self.array().map(u64::from_be_bytes)
    }
    fn epoch(&mut self) -> Result<u64, ProtocolError> {
        let v = self.u64()?;
        if v == 0 {
            Err(ProtocolError::InvalidValue("session epoch"))
        } else {
            Ok(v)
        }
    }
    fn ip(&mut self) -> Result<Ipv4Addr, ProtocolError> {
        self.array::<4>().map(Ipv4Addr::from)
    }
    fn routes(&mut self) -> Result<Vec<Cidr>, ProtocolError> {
        let n = self.u8()? as usize;
        if n > ROUTE_MAX {
            return Err(ProtocolError::LimitExceeded("route count"));
        }
        let mut out = Vec::with_capacity(n);
        for _ in 0..n {
            let ip = self.ip()?;
            let prefix = self.u8()?;
            out.push(Cidr::new(ip, prefix).map_err(|_| ProtocolError::InvalidValue("CIDR"))?);
        }
        Ok(out)
    }
    fn ips(&mut self) -> Result<Vec<Ipv4Addr>, ProtocolError> {
        let n = self.u8()? as usize;
        if n > DNS_MAX {
            return Err(ProtocolError::LimitExceeded("DNS server count"));
        }
        let mut out = Vec::with_capacity(n);
        for _ in 0..n {
            out.push(self.ip()?);
        }
        Ok(out)
    }
    fn string(&mut self) -> Result<String, ProtocolError> {
        let n = self.u8()? as usize;
        if n > DIAGNOSTIC_MAX {
            return Err(ProtocolError::LimitExceeded("diagnostic"));
        }
        String::from_utf8(self.bytes(n)?.to_vec()).map_err(|_| ProtocolError::InvalidUtf8)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn control_round_trip() {
        let message = ControlMessage::ServerAccept {
            session_epoch: 9,
            assigned_address: "10.77.0.2".parse().unwrap(),
            prefix_len: 24,
            gateway_address: "10.77.0.1".parse().unwrap(),
            accepted_routes: vec!["10.20.0.0/16".parse().unwrap()],
            dns_servers: vec!["10.77.0.1".parse().unwrap()],
            packet_mtu: 1280,
            setup_timeout_secs: 60,
            idle_timeout_secs: 0,
        };
        assert_eq!(
            ControlMessage::decode(&message.encode().unwrap()).unwrap(),
            message
        );
    }

    #[test]
    fn hello_wire_format_is_stable() {
        let encoded = ControlMessage::ClientHello {
            versions: vec![VERSION],
            maximum_packet_size: 1280,
            requested_routes: vec!["10.20.0.0/16".parse().unwrap()],
        }
        .encode()
        .unwrap();
        assert_eq!(
            encoded,
            b"RNTU\x02\x01\x00\x00\x00\x0a\x01\x02\x05\x00\x01\x0a\x14\x00\x00\x10"
        );
    }

    #[test]
    fn server_ready_wire_format_is_stable() {
        let encoded = ControlMessage::ServerReady {
            session_epoch: 0x0102_0304_0506_0708,
        }
        .encode()
        .unwrap();
        assert_eq!(
            encoded,
            b"RNTU\x02\x05\x00\x00\x00\x08\x01\x02\x03\x04\x05\x06\x07\x08"
        );
    }

    #[test]
    fn rejects_version_1_frames_and_retired_kinds() {
        let mut encoded = ControlMessage::ServerReady { session_epoch: 1 }
            .encode()
            .unwrap();
        encoded[4] = 1;
        assert!(matches!(
            ControlMessage::decode(&encoded),
            Err(ProtocolError::UnsupportedVersion(1))
        ));
        for kind in [6, 7] {
            let mut encoded = ControlMessage::ServerReady { session_epoch: 1 }
                .encode()
                .unwrap();
            encoded[5] = kind;
            assert!(matches!(
                ControlMessage::decode(&encoded),
                Err(ProtocolError::UnknownKind(k)) if k == kind
            ));
        }
    }

    #[test]
    fn fragment_round_trip_and_range_rejection() {
        let fragment = PacketFragment {
            session_epoch: 1,
            packet_id: 2,
            total_len: 5,
            offset: 1,
            payload: vec![2, 3],
        };
        assert_eq!(
            PacketFragment::decode(&fragment.encode().unwrap()).unwrap(),
            fragment
        );
        let bad = PacketFragment {
            offset: 4,
            ..fragment
        };
        assert!(bad.encode().is_err());
    }

    #[test]
    fn fragment_wire_format_is_stable() {
        let encoded = PacketFragment {
            session_epoch: 1,
            packet_id: 2,
            total_len: 3,
            offset: 1,
            payload: vec![0xaa, 0xbb],
        }
        .encode()
        .unwrap();
        assert_eq!(
            encoded,
            b"RNTU\x02\x20\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\
              \x00\x00\x00\x00\x00\x00\x00\x02\x00\x03\x00\x01\x00\x02\xaa\xbb"
        );
    }

    #[test]
    fn rejects_unknown_flags_and_trailing_data() {
        let mut encoded = ControlMessage::ServerReady { session_epoch: 1 }
            .encode()
            .unwrap();
        encoded[7] = 1;
        assert!(matches!(
            ControlMessage::decode(&encoded),
            Err(ProtocolError::UnknownFlags(1))
        ));
        let mut encoded = ControlMessage::ServerReady { session_epoch: 1 }
            .encode()
            .unwrap();
        encoded.push(0);
        assert!(matches!(
            ControlMessage::decode(&encoded),
            Err(ProtocolError::InvalidLength)
        ));
    }
}
