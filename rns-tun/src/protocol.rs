use std::fmt;
use std::net::Ipv4Addr;

use crate::policy::Cidr;

pub const VERSION: u8 = 1;
pub const MAGIC: [u8; 4] = *b"RNTU";
pub const CONTROL_FRAME_MAX: usize = 384;
pub const DIAGNOSTIC_MAX: usize = 128;
pub const ROUTE_MAX: usize = 32;
pub const DNS_MAX: usize = 4;
pub const VERSION_MAX: usize = 4;
pub const PACKET_MAX: usize = 1500;
pub const FRAGMENT_MAX: usize = 32;
pub const FRAGMENT_HEADER_LEN: usize = 30;

const KIND_CLIENT_HELLO: u8 = 1;
const KIND_SERVER_ACCEPT: u8 = 2;
const KIND_SERVER_REJECT: u8 = 3;
const KIND_CLIENT_READY: u8 = 4;
const KIND_SERVER_READY: u8 = 5;
const KIND_PING: u8 = 6;
const KIND_PONG: u8 = 7;
const KIND_CLOSE: u8 = 8;
const KIND_CLOSE_ACK: u8 = 9;
const KIND_PACKET_FRAGMENT: u8 = 0x20;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProtocolError {
    Truncated,
    InvalidMagic,
    UnsupportedVersion(u8),
    UnknownKind(u8),
    UnknownFlags(u16),
    InvalidLength,
    LimitExceeded(&'static str),
    InvalidValue(&'static str),
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ControlMessage {
    ClientHello {
        versions: Vec<u8>,
        capabilities: u32,
        maximum_packet_size: u16,
        requested_routes: Vec<Cidr>,
    },
    ServerAccept {
        session_epoch: u64,
        assigned_address: Ipv4Addr,
        prefix_len: u8,
        gateway_address: Ipv4Addr,
        accepted_routes: Vec<Cidr>,
        dns_servers: Vec<Ipv4Addr>,
        packet_mtu: u16,
        setup_timeout_secs: u16,
        idle_timeout_secs: u32,
    },
    ServerReject {
        reason: u16,
        diagnostic: String,
    },
    ClientReady {
        session_epoch: u64,
        dns_servers: Vec<Ipv4Addr>,
    },
    ServerReady {
        session_epoch: u64,
    },
    Ping {
        nonce: u64,
    },
    Pong {
        nonce: u64,
    },
    Close {
        session_epoch: u64,
        reason: u16,
        diagnostic: String,
    },
    CloseAck {
        session_epoch: u64,
    },
}

impl ControlMessage {
    pub fn encode(&self) -> Result<Vec<u8>, ProtocolError> {
        let mut body = Vec::new();
        let kind = match self {
            Self::ClientHello {
                versions,
                capabilities,
                maximum_packet_size,
                requested_routes,
            } => {
                put_count(&mut body, versions.len(), VERSION_MAX, "version count")?;
                body.extend_from_slice(versions);
                put_u32(&mut body, *capabilities);
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
            Self::Ping { nonce } => {
                put_u64(&mut body, *nonce);
                KIND_PING
            }
            Self::Pong { nonce } => {
                put_u64(&mut body, *nonce);
                KIND_PONG
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

    pub fn decode(frame: &[u8]) -> Result<Self, ProtocolError> {
        if frame.len() < 10 {
            return Err(ProtocolError::Truncated);
        }
        if frame.len() > CONTROL_FRAME_MAX {
            return Err(ProtocolError::LimitExceeded("control frame"));
        }
        if frame[..4] != MAGIC {
            return Err(ProtocolError::InvalidMagic);
        }
        if frame[4] != VERSION {
            return Err(ProtocolError::UnsupportedVersion(frame[4]));
        }
        let kind = frame[5];
        let flags = u16::from_be_bytes([frame[6], frame[7]]);
        if flags != 0 {
            return Err(ProtocolError::UnknownFlags(flags));
        }
        let body_len = u16::from_be_bytes([frame[8], frame[9]]) as usize;
        if body_len != frame.len() - 10 {
            return Err(ProtocolError::InvalidLength);
        }
        let mut reader = Reader::new(&frame[10..]);
        let message = match kind {
            KIND_CLIENT_HELLO => {
                let count = reader.u8()? as usize;
                if count == 0 || count > VERSION_MAX {
                    return Err(ProtocolError::LimitExceeded("version count"));
                }
                let versions = reader.bytes(count)?.to_vec();
                let capabilities = reader.u32()?;
                let maximum_packet_size = reader.u16()?;
                let requested_routes = reader.routes()?;
                Self::ClientHello {
                    versions,
                    capabilities,
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
            KIND_PING => Self::Ping {
                nonce: reader.u64()?,
            },
            KIND_PONG => Self::Pong {
                nonce: reader.u64()?,
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PacketFragment {
    pub session_epoch: u64,
    pub packet_id: u64,
    pub total_len: u16,
    pub offset: u16,
    pub payload: Vec<u8>,
}

impl PacketFragment {
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

    pub fn decode(frame: &[u8]) -> Result<Self, ProtocolError> {
        if frame.len() < FRAGMENT_HEADER_LEN {
            return Err(ProtocolError::Truncated);
        }
        if frame[..4] != MAGIC {
            return Err(ProtocolError::InvalidMagic);
        }
        if frame[4] != VERSION {
            return Err(ProtocolError::UnsupportedVersion(frame[4]));
        }
        if frame[5] != KIND_PACKET_FRAGMENT {
            return Err(ProtocolError::UnknownKind(frame[5]));
        }
        let flags = u16::from_be_bytes([frame[6], frame[7]]);
        if flags != 0 {
            return Err(ProtocolError::UnknownFlags(flags));
        }
        let mut reader = Reader::new(&frame[8..]);
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
        if end > self.bytes.len() {
            return Err(ProtocolError::Truncated);
        }
        let value = &self.bytes[self.offset..end];
        self.offset = end;
        Ok(value)
    }
    fn u8(&mut self) -> Result<u8, ProtocolError> {
        Ok(self.bytes(1)?[0])
    }
    fn u16(&mut self) -> Result<u16, ProtocolError> {
        let v = self.bytes(2)?;
        Ok(u16::from_be_bytes([v[0], v[1]]))
    }
    fn u32(&mut self) -> Result<u32, ProtocolError> {
        let v = self.bytes(4)?;
        Ok(u32::from_be_bytes(v.try_into().unwrap()))
    }
    fn u64(&mut self) -> Result<u64, ProtocolError> {
        let v = self.bytes(8)?;
        Ok(u64::from_be_bytes(v.try_into().unwrap()))
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
        let v = self.bytes(4)?;
        Ok(Ipv4Addr::new(v[0], v[1], v[2], v[3]))
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
    fn ping_wire_format_is_stable() {
        let encoded = ControlMessage::Ping {
            nonce: 0x0102_0304_0506_0708,
        }
        .encode()
        .unwrap();
        assert_eq!(
            encoded,
            b"RNTU\x01\x06\x00\x00\x00\x08\x01\x02\x03\x04\x05\x06\x07\x08"
        );
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
            b"RNTU\x01\x20\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\
              \x00\x00\x00\x00\x00\x00\x00\x02\x00\x03\x00\x01\x00\x02\xaa\xbb"
        );
    }

    #[test]
    fn rejects_unknown_flags_and_trailing_data() {
        let mut encoded = ControlMessage::Ping { nonce: 1 }.encode().unwrap();
        encoded[7] = 1;
        assert!(matches!(
            ControlMessage::decode(&encoded),
            Err(ProtocolError::UnknownFlags(1))
        ));
        let mut encoded = ControlMessage::Ping { nonce: 1 }.encode().unwrap();
        encoded.push(0);
        assert!(matches!(
            ControlMessage::decode(&encoded),
            Err(ProtocolError::InvalidLength)
        ));
    }
}
