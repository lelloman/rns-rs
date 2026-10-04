use crate::{
    protocol::{self, Command, Message},
    scenario::{self, Case},
};
use anyhow::{bail, ensure, Result};
use rns_core::{constants, types::LinkId};
use rns_crypto::{identity::Identity, OsRng};
use rns_net::{
    AnnouncedIdentity, Callbacks, DestHash, Destination, IdentityHash, InterfaceConfig,
    InterfaceId, NodeConfig, PacketHash, RnsNode, TcpClientConfig, TcpServerConfig,
};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    mpsc::{self, SyncSender},
    Arc,
};
use std::time::{Duration, Instant};

enum Event {
    Command(Command),
    Announce(DestHash),
    Up,
    Link(LinkId),
    Received(LinkId, u64, usize),
    Proof(LinkId),
    Ack(LinkId, u64),
    Probe(LinkId, Vec<u8>, Instant),
    Error(String),
}

struct Callback {
    tx: SyncSender<Event>,
    overflow: Arc<AtomicBool>,
    expected: [u8; 32],
    bytes: usize,
}
impl Callback {
    fn emit(&self, e: Event) {
        if self.tx.try_send(e).is_err() {
            self.overflow.store(true, Ordering::Relaxed);
        }
    }
}
impl Callbacks for Callback {
    fn on_announce(&mut self, a: AnnouncedIdentity) {
        self.emit(Event::Announce(a.dest_hash));
    }
    fn on_path_updated(&mut self, _: DestHash, _: u8) {}
    fn on_local_delivery(&mut self, _: DestHash, _: Vec<u8>, _: PacketHash) {}
    fn on_interface_up(&mut self, _: InterfaceId) {
        self.emit(Event::Up);
    }
    fn on_link_established(&mut self, id: LinkId, _: DestHash, _: f64, _: bool) {
        self.emit(Event::Link(id));
    }
    fn on_resource_received(&mut self, link: LinkId, data: Vec<u8>, metadata: Option<Vec<u8>>) {
        let id = metadata
            .and_then(|v| <[u8; 8]>::try_from(v).ok())
            .map(u64::from_le_bytes);
        match id {
            Some(id)
                if data.len() == self.bytes
                    && rns_crypto::sha256::sha256(&data) == self.expected =>
            {
                self.emit(Event::Received(link, id, data.len()));
            }
            _ => self.emit(Event::Error(
                "Resource length/digest/operation ID mismatch".into(),
            )),
        }
    }
    fn on_resource_completed(&mut self, id: LinkId) {
        self.emit(Event::Proof(id));
    }
    fn on_resource_failed(&mut self, _: LinkId, e: String) {
        self.emit(Event::Error(e));
    }
    fn on_link_data(&mut self, link: LinkId, _: u8, data: Vec<u8>) {
        if data.len() == 64 {
            self.emit(Event::Probe(link, data, Instant::now()));
            return;
        }
        match <[u8; 8]>::try_from(data) {
            Ok(id) => self.emit(Event::Ack(link, u64::from_le_bytes(id))),
            Err(_) => self.emit(Event::Error("invalid application acknowledgement".into())),
        }
    }
}

pub fn run(role: &str, port: u16, c: Case) -> Result<()> {
    ensure!(
        role == "sender" || role == "receiver",
        "invalid participant role"
    );
    let receiver = role == "receiver";
    let payload = scenario::payload(&c);
    let (tx, rx) = mpsc::sync_channel(if c.probes.is_some() { 512 } else { 64 });
    let overflow = Arc::new(AtomicBool::new(false));
    let callbacks = Callback {
        tx: tx.clone(),
        overflow: overflow.clone(),
        expected: rns_crypto::sha256::sha256(&payload),
        bytes: payload.len(),
    };
    let command_tx = tx.clone();
    std::thread::spawn(move || {
        let mut input = std::io::stdin().lock();
        loop {
            let command = match protocol::read_line(&mut input).and_then(|line| {
                line.map(|v| serde_json::from_str::<Command>(&v).map_err(Into::into))
                    .transpose()
            }) {
                Ok(Some(c)) => Event::Command(c),
                Ok(None) => Event::Command(Command::Stop),
                Err(e) => Event::Error(format!("control input: {e}")),
            };
            let stop = matches!(command, Event::Command(Command::Stop) | Event::Error(_));
            if command_tx.send(command).is_err() || stop {
                break;
            }
        }
    });
    let identity = Identity::new(&mut OsRng);
    let dest = Destination::single_in("rns_bench", &["resource"], IdentityHash(*identity.hash()));
    let public = identity.get_public_key().unwrap();
    let signing: [u8; 32] = public[32..].try_into().unwrap();
    let config_data: Box<dyn rns_net::interface::InterfaceConfigData> = if receiver {
        Box::new(TcpServerConfig {
            listen_ip: "127.0.0.1".into(),
            listen_port: port,
            interface_id: InterfaceId(1),
            ..Default::default()
        })
    } else {
        Box::new(TcpClientConfig {
            target_host: "127.0.0.1".into(),
            target_port: port,
            interface_id: InterfaceId(1),
            ..Default::default()
        })
    };
    let node = RnsNode::start(
        NodeConfig {
            interfaces: vec![InterfaceConfig {
                name: role.into(),
                type_name: if receiver {
                    "TCPServerInterface"
                } else {
                    "TCPClientInterface"
                }
                .into(),
                config_data,
                mode: constants::MODE_FULL,
                gravity: 0,
                recursive_prs: false,
                announces_from_internal: true,
                announces_to_internal: None,
                ingress_control: rns_core::transport::types::IngressControlConfig::disabled(),
                ifac: None,
                discovery: None,
            }],
            panic_on_interface_error: true,
            ..Default::default()
        },
        Box::new(callbacks),
    )?;
    if receiver {
        node.register_destination_with_proof(&dest, identity.get_private_key())?;
        node.register_link_destination(
            dest.hash.0,
            identity.get_private_key().unwrap()[32..]
                .try_into()
                .unwrap(),
            signing,
            1, // AcceptAll; verification still checks every byte and operation ID.
        )?;
    }
    let mut output = std::io::stdout().lock();
    protocol::write_json(
        &mut output,
        &Message::Ready {
            version: 1,
            destination: dest.hash.0,
            signing_key: signing,
        },
    )?;
    let mut peer: Option<([u8; 16], [u8; 32])> = None;
    let mut announced = None;
    let mut connecting = false;
    let mut link = None;
    let mut probe_link = None;
    let mut train: Option<crate::probes::Train> = None;
    let mut rounds = 0u64;
    let mut probes_received = 0u64;
    let mut pending: Option<(u64, Instant, bool, bool)> = None;
    let mut received = 0u64;
    let mut completed = 0u64;
    let mut up_sent = false;
    loop {
        ensure!(
            !overflow.load(Ordering::Relaxed),
            "participant event queue overflow"
        );
        if let Some(t) = train.as_mut() {
            ensure!(
                t.started.elapsed() < Duration::from_secs(c.timeout_secs),
                "probe train deadline exceeded"
            );
            if c.background && !t.bulk_started && Instant::now() >= t.bulk_due() {
                let data = payload.clone();
                let started = Instant::now();
                node.send_resource_with_auto_compress(
                    link.unwrap(),
                    data,
                    Some(t.round.to_le_bytes().to_vec()),
                    c.compression,
                )?;
                pending = Some((t.round, started, false, false));
                t.start_bulk(started);
            }
            if t.next_due().is_some_and(|due| Instant::now() >= due) {
                let bytes = crate::probes::packet(t.next_id());
                let submitted = Instant::now();
                // Admission is nonblocking. Missing transmission/echo cannot pass:
                // every admitted probe must be verified before this round completes.
                drop(node.try_send_on_link(probe_link.unwrap(), bytes, constants::CONTEXT_NONE)?);
                t.submitted(submitted)?;
            }
        }
        let mut wait = Duration::from_secs(c.timeout_secs);
        if let Some(t) = &train {
            let next = t
                .next_due()
                .into_iter()
                .chain((c.background && !t.bulk_started).then(|| t.bulk_due()))
                .min();
            if let Some(next) = next {
                wait = wait.min(next.saturating_duration_since(Instant::now()));
            }
        }
        let e = match rx.recv_timeout(wait) {
            Ok(e) => e,
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) if train.is_some() => continue,
            Err(e) => return Err(e.into()),
        };
        match e {
            Event::Command(Command::Stop) => break,
            Event::Command(Command::Snapshot) => protocol::write_json(
                &mut output,
                &Message::Snapshot {
                    metrics: protocol::metrics()?,
                    received,
                    completed,
                    probes_received,
                },
            )?,
            Event::Command(Command::Announce) => {
                ensure!(receiver, "sender cannot announce");
                node.announce_queued(&dest, &identity, None)?;
            }
            Event::Command(Command::ConnectProbes) => {
                ensure!(
                    !receiver && c.probes.is_some() && link.is_some() && probe_link.is_none(),
                    "invalid probe connection request"
                );
                let (destination, key) = peer.unwrap();
                node.create_link(destination, key)?;
            }
            Event::Command(Command::Connect {
                destination,
                signing_key,
            }) => {
                ensure!(!receiver && peer.is_none(), "unexpected connect");
                peer = Some((destination, signing_key));
            }
            Event::Up => {
                if !up_sent {
                    protocol::write_json(&mut output, &Message::Connected)?;
                    up_sent = true;
                }
            }
            Event::Announce(hash) => announced = Some(hash.0),
            Event::Link(id) => {
                if link.is_none() {
                    link = Some(id.0);
                    protocol::write_json(&mut output, &Message::Linked)?;
                } else {
                    ensure!(
                        c.probes.is_some() && probe_link.is_none(),
                        "unexpected additional link"
                    );
                    probe_link = Some(id.0);
                    protocol::write_json(&mut output, &Message::ProbeLinked)?;
                }
            }
            Event::Command(Command::Transfer { id }) => {
                ensure!(
                    !receiver && pending.is_none() && train.is_none() && id == rounds,
                    "unexpected transfer ID/state"
                );
                if let Some(q) = &c.probes {
                    ensure!(probe_link.is_some(), "probe link not ready");
                    train = Some(crate::probes::Train::new(id, q.clone()));
                    continue;
                }
                let data = payload.clone(); // payload preparation is outside operation timing
                let started = Instant::now();
                node.send_resource_with_auto_compress(
                    link.ok_or_else(|| anyhow::anyhow!("link not ready"))?,
                    data,
                    Some(id.to_le_bytes().to_vec()),
                    c.compression,
                )?;
                pending = Some((id, started, false, false));
            }
            Event::Received(id, n, bytes) => {
                ensure!(
                    receiver && n == received && Some(id.0) == link,
                    "duplicate/out-of-order/unexpected delivery"
                );
                received += 1;
                node.try_send_on_link(id.0, n.to_le_bytes().to_vec(), constants::CONTEXT_NONE)?
                    .wait()?;
                protocol::write_json(&mut output, &Message::Received { id: n, bytes })?;
            }
            Event::Proof(id) => {
                ensure!(Some(id.0) == link, "proof on wrong link");
                if receiver {
                    // The current driver also emits ResourceCompleted after receive.
                    ensure!(completed < received, "unexpected receiver completion");
                    completed += 1;
                    continue;
                }
                let p = pending
                    .as_mut()
                    .ok_or_else(|| anyhow::anyhow!("unexpected proof"))?;
                ensure!(!p.2, "duplicate proof");
                p.2 = true;
            }
            Event::Ack(ack_link, id) => {
                ensure!(Some(ack_link.0) == link, "acknowledgement on wrong link");
                let p = pending
                    .as_mut()
                    .ok_or_else(|| anyhow::anyhow!("unexpected acknowledgement"))?;
                ensure!(p.0 == id && !p.3, "wrong/duplicate acknowledgement");
                p.3 = true;
            }
            Event::Probe(id, data, at) => {
                ensure!(Some(id.0) == probe_link, "probe on wrong link");
                let sequence = crate::probes::decode(&data)?;
                if receiver {
                    ensure!(
                        sequence == probes_received,
                        "duplicate/out-of-order probe request"
                    );
                    drop(node.try_send_on_link(id.0, data, constants::CONTEXT_NONE)?);
                } else {
                    train
                        .as_mut()
                        .ok_or_else(|| anyhow::anyhow!("unexpected probe echo"))?
                        .receive(sequence, at)?;
                }
                probes_received += 1;
            }
            Event::Error(e) => bail!(e),
        }
        if let Some((destination, key)) = peer {
            if !connecting && announced == Some(destination) {
                node.create_link(destination, key)?;
                connecting = true;
            }
        }
        if let Some((id, start, true, true)) = pending {
            let at = Instant::now();
            let elapsed_ns = at.duration_since(start).as_nanos().try_into()?;
            if let Some(t) = train.as_mut() {
                t.end_bulk(at, elapsed_ns);
            } else {
                protocol::write_json(
                    &mut output,
                    &Message::Completed {
                        id,
                        elapsed_ns,
                        probes: None,
                        resource_elapsed_ns: Some(elapsed_ns),
                    },
                )?;
                rounds += 1;
            }
            completed += 1;
            pending = None;
        }
        if train.as_ref().is_some_and(|t| t.complete(c.background)) {
            let t = train.take().unwrap();
            let id = t.round;
            let elapsed_ns = t.started.elapsed().as_nanos().try_into()?;
            let resource_elapsed_ns = t.resource_elapsed_ns;
            protocol::write_json(
                &mut output,
                &Message::Completed {
                    id,
                    elapsed_ns,
                    probes: Some(t.summary()),
                    resource_elapsed_ns,
                },
            )?;
            rounds += 1;
        }
    }
    node.shutdown();
    protocol::write_json(&mut output, &Message::Stopped)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn corrupted_or_unidentified_payload_never_counts_as_delivery() {
        let (tx, rx) = mpsc::sync_channel(4);
        let mut callback = Callback {
            tx,
            overflow: Arc::new(AtomicBool::new(false)),
            expected: rns_crypto::sha256::sha256(b"good"),
            bytes: 4,
        };
        callback.on_resource_received(
            LinkId([1; 16]),
            b"evil".to_vec(),
            Some(0u64.to_le_bytes().to_vec()),
        );
        assert!(matches!(rx.recv().unwrap(), Event::Error(_)));
        callback.on_resource_received(LinkId([1; 16]), b"good".to_vec(), None);
        assert!(matches!(rx.recv().unwrap(), Event::Error(_)));
        callback.on_resource_received(
            LinkId([1; 16]),
            b"good".to_vec(),
            Some(0u64.to_le_bytes().to_vec()),
        );
        assert!(matches!(rx.recv().unwrap(), Event::Received(_, 0, 4)));
    }
    #[test]
    fn callback_overflow_is_fatal_not_silent_data_loss() {
        let (tx, _rx) = mpsc::sync_channel(1);
        let overflow = Arc::new(AtomicBool::new(false));
        let callback = Callback {
            tx,
            overflow: overflow.clone(),
            expected: [0; 32],
            bytes: 0,
        };
        callback.emit(Event::Up);
        callback.emit(Event::Up);
        assert!(overflow.load(Ordering::Relaxed));
    }
}
