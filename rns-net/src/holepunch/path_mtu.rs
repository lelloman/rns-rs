//! Path MTU discovery on a direct UDP path.
//!
//! A direct path starts at [`MTU_FLOOR`], which crosses practically any
//! internet path without fragmentation. Each side then probes its sending
//! direction once with a short ladder of larger sizes and moves the path
//! to the largest the peer acknowledged:
//!
//! - probe: `"RNSM" | session id (16) | nonce (8) | size (u16 BE) | zeros | tag (16)`,
//!   exactly `size` bytes long;
//! - acknowledgement: `"RNSN" | session id (16) | nonce (8) | size (u16 BE) | tag (16)`.
//!
//! The tag is the first 16 bytes of HMAC-SHA256 over everything before it,
//! keyed with the path's keepalive key. A probe is acknowledged only if its
//! length is the size it states, and an acknowledgement counts only if it
//! echoes the nonce and size of a probe still outstanding.
//!
//! Probing is bounded: [`PROBE_ROUNDS`] rounds [`ROUND_INTERVAL`] apart,
//! each sending one probe per ladder size above the best acknowledged so
//! far, so at most 9 probes over about 3 seconds. A size that is never
//! acknowledged, whether the network or the sending host drops it, is
//! simply not used.

#![allow(unsafe_code, reason = "OS calls through libc")]

use std::net::SocketAddr;
use std::time::{Duration, Instant};

/// The MTU a direct path starts with, and keeps if no larger probe is
/// acknowledged: 1200 bytes of UDP payload fit the IPv6 minimum link MTU
/// (1280, less 40 bytes of IPv6 and 8 of UDP header) with room for a
/// tunnel or PPPoE header on the way, and any IPv4 path that carries
/// ordinary internet traffic.
pub(crate) const MTU_FLOOR: u32 = 1200;

/// Sizes probed above the floor, largest first: the UDP payload of a
/// 1500-byte Ethernet path (1472 over IPv4, 1452 over IPv6), a size that
/// fits common tunnels and PPPoE, and one that fits the IPv6 minimum MTU
/// on an IPv4 path.
fn ladder(ipv4: bool) -> [u32; 3] {
    if ipv4 {
        [1472, 1400, 1280]
    } else {
        [1452, 1400, 1280]
    }
}

/// Rounds of probes sent.
pub(crate) const PROBE_ROUNDS: u32 = 3;
/// Time between rounds, and after the last one before probing ends.
pub(crate) const ROUND_INTERVAL: Duration = Duration::from_secs(1);
/// Upper bound on acknowledgements a path sends over its life.
pub(crate) const MAX_ACKS: u32 = 32;

const PROBE_MAGIC: &[u8; 4] = b"RNSM";
const ACK_MAGIC: &[u8; 4] = b"RNSN";
const NONCE_LEN: usize = 8;
const TAG_LEN: usize = 16;
/// Magic, session id, nonce and size.
const HEADER_LEN: usize = 4 + 16 + NONCE_LEN + 2;
const ACK_LEN: usize = HEADER_LEN + TAG_LEN;

/// Whether `data` is a path MTU probe or acknowledgement.
pub(crate) fn is_pmtu_datagram(data: &[u8]) -> bool {
    matches!(data.first_chunk::<4>(), Some(b"RNSM" | b"RNSN"))
}

fn header(magic: &[u8; 4], session_id: &[u8; 16], nonce: &[u8; NONCE_LEN], size: u16) -> Vec<u8> {
    let mut packet = Vec::with_capacity(size.max(ACK_LEN as u16) as usize);
    packet.extend_from_slice(magic);
    packet.extend_from_slice(session_id);
    packet.extend_from_slice(nonce);
    packet.extend_from_slice(&size.to_be_bytes());
    packet
}

fn seal(key: &[u8; 32], mut packet: Vec<u8>) -> Vec<u8> {
    let tag = rns_crypto::hmac::hmac_sha256(key, &packet);
    packet.extend_from_slice(&tag[..TAG_LEN]);
    packet
}

/// The nonce and size of `data`, if it is a `magic` packet of the session
/// with a valid tag.
fn open(
    data: &[u8],
    magic: &[u8; 4],
    session_id: &[u8; 16],
    key: &[u8; 32],
) -> Option<([u8; NONCE_LEN], u16)> {
    if data.len() < ACK_LEN {
        return None;
    }
    // [magic:4][session id:16][nonce][size:2][padding][tag]
    let (signed, received_tag) = data.split_last_chunk::<TAG_LEN>()?;
    let (packet_magic, rest) = signed.split_first_chunk::<4>()?;
    let (packet_session_id, rest) = rest.split_first_chunk::<16>()?;
    if packet_magic != magic || packet_session_id != session_id {
        return None;
    }
    let tag = rns_crypto::hmac::hmac_sha256(key, signed);
    if !super::constant_time_eq(&tag[..TAG_LEN], received_tag) {
        return None;
    }
    let (nonce, rest) = rest.split_first_chunk::<NONCE_LEN>()?;
    let size = u16::from_be_bytes(*rest.first_chunk::<2>()?);
    Some((*nonce, size))
}

fn build_probe(
    key: &[u8; 32],
    session_id: &[u8; 16],
    nonce: &[u8; NONCE_LEN],
    size: u16,
) -> Vec<u8> {
    let mut packet = header(PROBE_MAGIC, session_id, nonce, size);
    packet.resize(size as usize - TAG_LEN, 0);
    seal(key, packet)
}

fn build_ack(key: &[u8; 32], session_id: &[u8; 16], nonce: &[u8; NONCE_LEN], size: u16) -> Vec<u8> {
    seal(key, header(ACK_MAGIC, session_id, nonce, size))
}

/// What the path MTU discovery of one direct path wants done.
#[derive(Debug, PartialEq)]
pub(crate) enum PmtuOutput {
    /// Send this datagram to the peer.
    Send(Vec<u8>),
    /// Probing ended: the path's MTU is this.
    Discovered(u32),
}

/// Path MTU discovery of one direct path: its own probes, and the answers
/// to the peer's.
pub(crate) struct PathMtu {
    key: [u8; 32],
    session_id: [u8; 16],
    ladder: [u32; 3],
    best: u32,
    /// Probes sent and not yet acknowledged: nonce and size.
    outstanding: Vec<([u8; NONCE_LEN], u32)>,
    rounds_sent: u32,
    next_round: Instant,
    done: bool,
    acks_sent: u32,
}

impl PathMtu {
    /// Discovery for a path to `peer`, starting with the first round at
    /// `now`.
    pub(crate) fn new(key: [u8; 32], session_id: [u8; 16], peer: SocketAddr, now: Instant) -> Self {
        let ipv4 = super::canonical(peer).is_ipv4();
        PathMtu {
            key,
            session_id,
            ladder: ladder(ipv4),
            best: MTU_FLOOR,
            outstanding: Vec::new(),
            rounds_sent: 0,
            next_round: now,
            done: false,
            acks_sent: 0,
        }
    }

    /// When [`on_timer`](Self::on_timer) next has something to do.
    pub(crate) fn deadline(&self) -> Option<Instant> {
        (!self.done).then_some(self.next_round)
    }

    /// Whether probing is still under way.
    pub(crate) fn probing(&self) -> bool {
        !self.done
    }

    /// Send the next round, or end probing, when due.
    pub(crate) fn on_timer(&mut self, now: Instant) -> Vec<PmtuOutput> {
        if self.done || now < self.next_round {
            return Vec::new();
        }
        if self.rounds_sent >= PROBE_ROUNDS {
            return self.finish();
        }
        use rns_crypto::Rng;
        let mut out = Vec::new();
        for size in self.ladder.into_iter().filter(|&size| size > self.best) {
            let mut nonce = [0u8; NONCE_LEN];
            rns_crypto::OsRng.fill_bytes(&mut nonce);
            self.outstanding.push((nonce, size));
            out.push(PmtuOutput::Send(build_probe(
                &self.key,
                &self.session_id,
                &nonce,
                size as u16,
            )));
        }
        self.rounds_sent += 1;
        self.next_round = now + ROUND_INTERVAL;
        out
    }

    fn finish(&mut self) -> Vec<PmtuOutput> {
        self.done = true;
        self.outstanding.clear();
        vec![PmtuOutput::Discovered(self.best)]
    }

    /// A probe or acknowledgement from the peer.
    pub(crate) fn receive(&mut self, data: &[u8]) -> Vec<PmtuOutput> {
        if let Some((nonce, size)) = open(data, PROBE_MAGIC, &self.session_id, &self.key) {
            // Only a probe that arrived whole is acknowledged.
            if data.len() != size as usize || self.acks_sent >= MAX_ACKS {
                return Vec::new();
            }
            self.acks_sent += 1;
            return vec![PmtuOutput::Send(build_ack(
                &self.key,
                &self.session_id,
                &nonce,
                size,
            ))];
        }
        let Some((nonce, size)) = open(data, ACK_MAGIC, &self.session_id, &self.key) else {
            return Vec::new();
        };
        if data.len() != ACK_LEN || self.done {
            return Vec::new();
        }
        let Some(index) = self
            .outstanding
            .iter()
            .position(|(sent, sent_size)| *sent == nonce && *sent_size == size as u32)
        else {
            return Vec::new();
        };
        self.outstanding.swap_remove(index);
        self.best = self.best.max(size as u32);
        // Nothing larger is left to learn.
        if self.best >= self.ladder[0] {
            return self.finish();
        }
        Vec::new()
    }
}

/// Set how the kernel treats the "don't fragment" bit on `socket`: with
/// `probing`, every datagram goes out unfragmented and one larger than the
/// local interface allows is refused, so a probe that arrives proves the
/// path; otherwise the kernel's default path MTU discovery applies.
#[cfg(target_os = "linux")]
pub(crate) fn set_probing(socket: &std::net::UdpSocket, probing: bool) {
    use std::os::fd::AsRawFd;
    let fd = socket.as_raw_fd();
    let set = |level: libc::c_int, name: libc::c_int, value: libc::c_int| {
        // SAFETY: `fd` is an open socket, and the option value is a c_int
        // of the size passed.
        unsafe {
            libc::setsockopt(
                fd,
                level,
                name,
                &value as *const libc::c_int as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            )
        }
    };
    let (v4, v6) = if probing {
        (libc::IP_PMTUDISC_PROBE, libc::IPV6_PMTUDISC_PROBE)
    } else {
        (libc::IP_PMTUDISC_WANT, libc::IPV6_PMTUDISC_WANT)
    };
    // An IPv6 socket may reach IPv4-mapped peers, so it takes both.
    let _ = set(libc::IPPROTO_IP, libc::IP_MTU_DISCOVER, v4);
    if socket.local_addr().is_ok_and(|a| a.is_ipv6()) {
        let _ = set(libc::IPPROTO_IPV6, libc::IPV6_MTU_DISCOVER, v6);
    }
}

#[cfg(not(target_os = "linux"))]
pub(crate) fn set_probing(_socket: &std::net::UdpSocket, _probing: bool) {}

/// Feed `data` to a path's MTU discovery, raw and sealed as a probe or
/// acknowledgement of the session (its first byte choosing which) with the
/// rest of `data` as nonce, size and padding. For fuzzing.
pub(crate) fn fuzz_datagram(data: &[u8]) {
    let key = [0x6e; 32];
    let session_id = [0x7f; 16];
    let now = Instant::now();
    let mut pmtu = PathMtu::new(key, session_id, ([192, 0, 2, 1], 4000).into(), now);
    let _ = pmtu.on_timer(now);
    let _ = pmtu.receive(data);
    let _ = is_pmtu_datagram(data);
    if let Some((first, rest)) = data.split_first() {
        let magic = if first & 1 == 1 {
            ACK_MAGIC
        } else {
            PROBE_MAGIC
        };
        let mut packet = Vec::with_capacity(20 + rest.len() + TAG_LEN);
        packet.extend_from_slice(magic);
        packet.extend_from_slice(&session_id);
        packet.extend_from_slice(rest);
        let sealed = seal(&key, packet);
        let _ = pmtu.receive(&sealed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: [u8; 32] = [7; 32];
    const SESSION: [u8; 16] = [9; 16];

    fn peer() -> SocketAddr {
        "1.2.3.4:5000".parse().unwrap()
    }

    fn sent(out: Vec<PmtuOutput>) -> Vec<Vec<u8>> {
        out.into_iter()
            .map(|o| match o {
                PmtuOutput::Send(packet) => packet,
                other => panic!("expected a datagram, got {other:?}"),
            })
            .collect()
    }

    /// The peer's side, answering `probes` that arrived.
    fn answer(peer: &mut PathMtu, probes: &[Vec<u8>]) -> Vec<Vec<u8>> {
        probes.iter().flat_map(|p| sent(peer.receive(p))).collect()
    }

    #[test]
    fn probes_have_the_size_they_state_and_are_authenticated() {
        let now = Instant::now();
        let mut ours = PathMtu::new(KEY, SESSION, peer(), now);
        let probes = sent(ours.on_timer(now));
        let sizes: Vec<usize> = probes.iter().map(Vec::len).collect();
        assert_eq!(sizes, vec![1472, 1400, 1280]);
        for probe in &probes {
            assert!(is_pmtu_datagram(probe));
            assert!(open(probe, PROBE_MAGIC, &SESSION, &KEY).is_some());
            assert!(open(probe, PROBE_MAGIC, &SESSION, &[8; 32]).is_none());
        }
        let v6 = PathMtu::new(KEY, SESSION, "[2001:db8::1]:5000".parse().unwrap(), now);
        assert_eq!(v6.ladder[0], 1452);
        let mapped = PathMtu::new(KEY, SESSION, "[::ffff:1.2.3.4]:5000".parse().unwrap(), now);
        assert_eq!(mapped.ladder[0], 1472);
    }

    #[test]
    fn largest_acknowledged_size_wins_at_once() {
        let now = Instant::now();
        let mut ours = PathMtu::new(KEY, SESSION, peer(), now);
        let mut theirs = PathMtu::new(KEY, SESSION, peer(), now);
        let probes = sent(ours.on_timer(now));
        let acks = answer(&mut theirs, &probes);
        assert_eq!(acks.len(), 3);
        // The largest acknowledgement ends probing.
        let mut outcome = Vec::new();
        for ack in &acks {
            outcome.extend(ours.receive(ack));
        }
        assert_eq!(outcome, vec![PmtuOutput::Discovered(1472)]);
        assert!(!ours.probing());
        assert!(ours.on_timer(now + Duration::from_secs(10)).is_empty());
    }

    #[test]
    fn sizes_the_path_drops_are_not_used_and_probing_is_bounded() {
        let start = Instant::now();
        let mut ours = PathMtu::new(KEY, SESSION, peer(), start);
        let mut theirs = PathMtu::new(KEY, SESSION, peer(), start);
        let mut sent_probes = 0;
        let mut discovered = None;
        let mut now = start;
        while discovered.is_none() {
            assert!(now < start + Duration::from_secs(10), "probing did not end");
            for out in ours.on_timer(now) {
                match out {
                    PmtuOutput::Send(probe) => {
                        sent_probes += 1;
                        // A path that carries at most 1420 bytes.
                        if probe.len() <= 1420 {
                            for ack in answer(&mut theirs, &[probe]) {
                                assert!(ours.receive(&ack).is_empty());
                            }
                        }
                    }
                    PmtuOutput::Discovered(mtu) => discovered = Some(mtu),
                }
            }
            now += Duration::from_millis(100);
        }
        assert_eq!(discovered, Some(1400));
        // 3 sizes, then only the one above the best, for 2 more rounds.
        assert_eq!(sent_probes, 5);
        assert!(now - start <= Duration::from_millis(3200));
    }

    #[test]
    fn nothing_acknowledged_keeps_the_floor() {
        let start = Instant::now();
        let mut ours = PathMtu::new(KEY, SESSION, peer(), start);
        let mut sent_probes = 0;
        let mut now = start;
        let discovered = loop {
            let out = ours.on_timer(now);
            if let Some(PmtuOutput::Discovered(mtu)) = out.last() {
                break *mtu;
            }
            sent_probes += out.len();
            now += Duration::from_millis(100);
        };
        assert_eq!(discovered, MTU_FLOOR);
        assert_eq!(sent_probes, 9);
    }

    #[test]
    fn forged_replayed_or_truncated_packets_do_not_count() {
        let now = Instant::now();
        let mut ours = PathMtu::new(KEY, SESSION, peer(), now);
        let mut theirs = PathMtu::new(KEY, SESSION, peer(), now);
        let probes = sent(ours.on_timer(now));

        // An acknowledgement for a probe never sent, and one for a size
        // other than the probe's.
        assert!(ours
            .receive(&build_ack(&KEY, &SESSION, &[1; 8], 1472))
            .is_empty());
        let nonce: [u8; 8] = probes[0][20..28].try_into().unwrap();
        assert!(ours
            .receive(&build_ack(&KEY, &SESSION, &nonce, 1400))
            .is_empty());
        // Signed with another key, or for another session.
        assert!(ours
            .receive(&build_ack(&[8; 32], &SESSION, &nonce, 1472))
            .is_empty());
        assert!(ours
            .receive(&build_ack(&KEY, &[1; 16], &nonce, 1472))
            .is_empty());
        assert_eq!(ours.best, MTU_FLOOR);

        // A probe cut short on the way is not acknowledged.
        let mut cut = probes[0].clone();
        cut.truncate(1000);
        assert!(theirs.receive(&cut).is_empty());
        // A probe claiming a size other than its length.
        let mut short = header(PROBE_MAGIC, &SESSION, &[2; 8], 1472);
        short.resize(1000 - TAG_LEN, 0);
        assert!(theirs.receive(&seal(&KEY, short)).is_empty());

        // The real acknowledgement counts once.
        let ack = answer(&mut theirs, &probes[1..2]).remove(0);
        assert!(ours.receive(&ack).is_empty());
        assert_eq!(ours.best, 1400);
        let outstanding = ours.outstanding.len();
        assert!(ours.receive(&ack).is_empty());
        assert_eq!(ours.outstanding.len(), outstanding);
    }

    #[test]
    fn acknowledgements_are_capped() {
        let now = Instant::now();
        let mut theirs = PathMtu::new(KEY, SESSION, peer(), now);
        let probe = build_probe(&KEY, &SESSION, &[3; 8], 1280);
        let acks: usize = (0..100).map(|_| theirs.receive(&probe).len()).sum();
        assert_eq!(acks, MAX_ACKS as usize);
    }
}
