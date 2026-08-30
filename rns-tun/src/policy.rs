use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::net::Ipv4Addr;
use std::str::FromStr;

use serde::Deserialize;

use crate::protocol::ROUTE_MAX;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Cidr {
    network: Ipv4Addr,
    prefix_len: u8,
}

impl Cidr {
    pub fn new(address: Ipv4Addr, prefix_len: u8) -> Result<Self, PolicyError> {
        if prefix_len > 32 {
            return Err(PolicyError::InvalidCidr);
        }
        let mask = prefix_mask(prefix_len);
        Ok(Self {
            network: Ipv4Addr::from(u32::from(address) & mask),
            prefix_len,
        })
    }
    pub fn network(self) -> Ipv4Addr {
        self.network
    }
    pub fn prefix_len(self) -> u8 {
        self.prefix_len
    }
    pub fn contains(self, address: Ipv4Addr) -> bool {
        (u32::from(address) & prefix_mask(self.prefix_len)) == u32::from(self.network)
    }
    pub fn contains_cidr(self, other: Cidr) -> bool {
        self.prefix_len <= other.prefix_len && self.contains(other.network)
    }
    pub fn intersection(self, other: Cidr) -> Option<Cidr> {
        if self.contains_cidr(other) {
            Some(other)
        } else if other.contains_cidr(self) {
            Some(self)
        } else {
            None
        }
    }
    pub fn broadcast(self) -> Ipv4Addr {
        Ipv4Addr::from(u32::from(self.network) | !prefix_mask(self.prefix_len))
    }
}

impl fmt::Display for Cidr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.network, self.prefix_len)
    }
}
impl FromStr for Cidr {
    type Err = PolicyError;
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let (ip, prefix) = value.split_once('/').ok_or(PolicyError::InvalidCidr)?;
        let ip = ip.parse().map_err(|_| PolicyError::InvalidCidr)?;
        let prefix = prefix.parse().map_err(|_| PolicyError::InvalidCidr)?;
        Self::new(ip, prefix)
    }
}

fn prefix_mask(prefix: u8) -> u32 {
    if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyError {
    InvalidCidr,
    InvalidIdentity,
    InvalidGatewaySubnet,
    InvalidClientAddress(String),
    DuplicateAddress(Ipv4Addr),
    ContradictoryInternetGrant(String),
    TooManyRoutes(String),
    InvalidToml(String),
}

impl fmt::Display for PolicyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidCidr => write!(f, "invalid IPv4 CIDR"),
            Self::InvalidIdentity => write!(f, "invalid 32-character identity hash"),
            Self::InvalidGatewaySubnet => {
                write!(f, "gateway subnet must have prefix /1 through /30")
            }
            Self::InvalidClientAddress(id) => write!(f, "invalid client address for {id}"),
            Self::DuplicateAddress(ip) => write!(f, "duplicate client address {ip}"),
            Self::ContradictoryInternetGrant(id) => {
                write!(f, "client {id} grants 0.0.0.0/0 without allow_internet")
            }
            Self::TooManyRoutes(id) => write!(f, "client {id} has more than {ROUTE_MAX} routes"),
            Self::InvalidToml(e) => write!(f, "invalid policy TOML: {e}"),
        }
    }
}
impl std::error::Error for PolicyError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientGrant {
    pub enabled: bool,
    pub address: Ipv4Addr,
    pub allow_routes: Vec<Cidr>,
    pub allow_internet: bool,
    pub allow_peers: BTreeSet<[u8; 16]>,
    pub idle_timeout_secs: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GatewayPolicy {
    pub gateway: Cidr,
    pub gateway_address: Ipv4Addr,
    pub clients: BTreeMap<[u8; 16], ClientGrant>,
}

impl GatewayPolicy {
    pub fn parse_toml(input: &str) -> Result<Self, PolicyError> {
        let raw: RawPolicy =
            toml::from_str(input).map_err(|e| PolicyError::InvalidToml(e.to_string()))?;
        let gateway: Cidr = raw.gateway.address.parse()?;
        if gateway.prefix_len == 0 || gateway.prefix_len > 30 {
            return Err(PolicyError::InvalidGatewaySubnet);
        }
        let gateway_ip: Ipv4Addr = raw
            .gateway
            .address
            .split_once('/')
            .unwrap()
            .0
            .parse()
            .map_err(|_| PolicyError::InvalidGatewaySubnet)?;
        let mut clients = BTreeMap::new();
        let mut addresses = BTreeSet::new();
        for (identity_text, client) in raw.clients {
            let identity = parse_identity_hash(&identity_text)?;
            if clients.contains_key(&identity) {
                return Err(PolicyError::InvalidIdentity);
            }
            let address: Ipv4Addr = client
                .address
                .parse()
                .map_err(|_| PolicyError::InvalidClientAddress(identity_text.clone()))?;
            if !gateway.contains(address)
                || address == gateway.network()
                || address == gateway.broadcast()
                || address == gateway_ip
            {
                return Err(PolicyError::InvalidClientAddress(identity_text));
            }
            if !addresses.insert(address) {
                return Err(PolicyError::DuplicateAddress(address));
            }
            if client.allow_routes.len() > ROUTE_MAX {
                return Err(PolicyError::TooManyRoutes(identity_text));
            }
            let mut routes = Vec::new();
            for route in client.allow_routes {
                routes.push(route.parse()?);
            }
            routes = canonicalize_routes(routes);
            if routes.iter().any(|route| route.prefix_len == 0) && !client.allow_internet {
                return Err(PolicyError::ContradictoryInternetGrant(identity_text));
            }
            let mut peers = BTreeSet::new();
            for peer in client.allow_peers {
                peers.insert(parse_identity_hash(&peer)?);
            }
            clients.insert(
                identity,
                ClientGrant {
                    enabled: client.enabled,
                    address,
                    allow_routes: routes,
                    allow_internet: client.allow_internet,
                    allow_peers: peers,
                    idle_timeout_secs: client.idle_timeout_seconds,
                },
            );
        }
        Ok(Self {
            gateway: Cidr::new(gateway_ip, gateway.prefix_len)?,
            gateway_address: gateway_ip,
            clients,
        })
    }

    pub fn grant(&self, identity: &[u8; 16]) -> Option<&ClientGrant> {
        self.clients.get(identity).filter(|g| g.enabled)
    }

    pub fn accepted_routes(&self, identity: &[u8; 16], requested: &[Cidr]) -> Vec<Cidr> {
        let Some(grant) = self.grant(identity) else {
            return Vec::new();
        };
        let mut accepted = Vec::new();
        for request in requested {
            if request.prefix_len == 0 && !grant.allow_internet {
                continue;
            }
            for allowed in &grant.allow_routes {
                if let Some(route) = request.intersection(*allowed) {
                    accepted.push(route);
                }
            }
        }
        for peer in &grant.allow_peers {
            if let Some(peer_grant) = self.grant(peer) {
                let peer_route = Cidr::new(peer_grant.address, 32).expect("/32 is valid");
                if requested
                    .iter()
                    .any(|request| request.contains_cidr(peer_route))
                {
                    accepted.push(peer_route);
                }
            }
        }
        canonicalize_routes(accepted)
    }

    pub fn peer_allowed(&self, source: &[u8; 16], destination: &[u8; 16]) -> bool {
        self.grant(source)
            .is_some_and(|grant| grant.allow_peers.contains(destination))
            && self.grant(destination).is_some()
    }
}

pub fn intersect_route_sets(requested: &[Cidr], allowed: &[Cidr]) -> Vec<Cidr> {
    let mut result = Vec::new();
    for request in requested {
        for grant in allowed {
            if let Some(route) = request.intersection(*grant) {
                result.push(route);
            }
        }
    }
    canonicalize_routes(result)
}

pub fn canonicalize_routes(mut routes: Vec<Cidr>) -> Vec<Cidr> {
    routes.sort();
    routes.dedup();
    let mut result = Vec::new();
    for route in routes {
        if !result
            .iter()
            .any(|parent: &Cidr| parent.contains_cidr(route))
        {
            result.push(route);
        }
    }
    result
}

pub fn parse_identity_hash(value: &str) -> Result<[u8; 16], PolicyError> {
    if value.len() != 32 {
        return Err(PolicyError::InvalidIdentity);
    }
    let mut out = [0u8; 16];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&value[i * 2..i * 2 + 2], 16)
            .map_err(|_| PolicyError::InvalidIdentity)?;
    }
    Ok(out)
}

pub fn is_forbidden_special(address: Ipv4Addr) -> bool {
    let value = u32::from(address);
    (value & 0xff00_0000) == 0
        || (value & 0xff00_0000) == 0x7f00_0000
        || (value & 0xffff_0000) == 0xa9fe_0000
        || (value & 0xf000_0000) == 0xe000_0000
        || (value & 0xf000_0000) == 0xf000_0000
}

#[derive(Deserialize)]
struct RawPolicy {
    gateway: RawGateway,
    #[serde(default)]
    clients: BTreeMap<String, RawClient>,
}
#[derive(Deserialize)]
struct RawGateway {
    address: String,
}
#[derive(Deserialize)]
struct RawClient {
    #[serde(default = "default_true")]
    enabled: bool,
    address: String,
    #[serde(default)]
    allow_routes: Vec<String>,
    #[serde(default)]
    allow_internet: bool,
    #[serde(default)]
    allow_peers: Vec<String>,
    idle_timeout_seconds: Option<u32>,
}
fn default_true() -> bool {
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn intersection_is_narrower() {
        let a: Cidr = "10.0.0.0/8".parse().unwrap();
        let b: Cidr = "10.2.0.0/16".parse().unwrap();
        assert_eq!(a.intersection(b), Some(b));
    }
    #[test]
    fn canonical_removes_contained() {
        let routes = canonicalize_routes(vec![
            "10.1.0.0/16".parse().unwrap(),
            "10.0.0.0/8".parse().unwrap(),
        ]);
        assert_eq!(routes, vec!["10.0.0.0/8".parse().unwrap()]);
    }
    #[test]
    fn empty_policy_denies() {
        let p = GatewayPolicy::parse_toml("[gateway]\naddress='10.77.0.1/24'\n").unwrap();
        assert!(p.grant(&[0; 16]).is_none());
    }
    #[test]
    fn parses_directional_peers() {
        let input="[gateway]\naddress='10.77.0.1/24'\n[clients.00112233445566778899aabbccddeeff]\naddress='10.77.0.2'\nallow_routes=['10.20.0.0/16']\nallow_peers=['ffeeddccbbaa99887766554433221100']\n[clients.ffeeddccbbaa99887766554433221100]\naddress='10.77.0.3'\n";
        let p = GatewayPolicy::parse_toml(input).unwrap();
        assert!(p.peer_allowed(
            &parse_identity_hash("00112233445566778899aabbccddeeff").unwrap(),
            &parse_identity_hash("ffeeddccbbaa99887766554433221100").unwrap()
        ));
    }
}
