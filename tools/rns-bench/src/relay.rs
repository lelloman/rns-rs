//! A transport process for verified loopback relay workloads.
use crate::protocol::{self, Command, Message};
use anyhow::{bail, Result};
use rns_core::constants;
use rns_net::{
    AnnouncedIdentity, Callbacks, DestHash, InterfaceConfig, InterfaceId, NodeConfig, PacketHash,
    RnsNode, TcpServerConfig,
};

struct RelayCallbacks;
impl Callbacks for RelayCallbacks {
    fn on_announce(&mut self, _: AnnouncedIdentity) {}
    fn on_path_updated(&mut self, _: DestHash, _: u8) {}
    fn on_local_delivery(&mut self, _: DestHash, _: Vec<u8>, _: PacketHash) {}
}

pub fn run(port: u16) -> Result<()> {
    let node = RnsNode::start(
        NodeConfig {
            transport_enabled: true,
            panic_on_interface_error: true,
            interfaces: vec![InterfaceConfig {
                name: "benchmark-relay".into(),
                type_name: "TCPServerInterface".into(),
                config_data: Box::new(TcpServerConfig {
                    listen_ip: "127.0.0.1".into(),
                    listen_port: port,
                    interface_id: InterfaceId(1),
                    ..Default::default()
                }),
                mode: constants::MODE_FULL,
                gravity: 0,
                recursive_prs: false,
                announces_from_internal: true,
                announces_to_internal: None,
                ingress_control: rns_core::transport::types::IngressControlConfig::disabled(),
                ifac: None,
                discovery: None,
            }],
            ..Default::default()
        },
        Box::new(RelayCallbacks),
    )?;
    let mut input = std::io::stdin().lock();
    let mut output = std::io::stdout().lock();
    protocol::write_json(
        &mut output,
        &Message::Ready {
            version: 1,
            destination: [0; 16],
            signing_key: [0; 32],
        },
    )?;
    while let Some(line) = protocol::read_line(&mut input)? {
        match serde_json::from_str::<Command>(&line)? {
            Command::Snapshot => protocol::write_json(
                &mut output,
                &Message::Snapshot {
                    metrics: protocol::metrics()?,
                    received: 0,
                    completed: 0,
                    probes_received: 0,
                },
            )?,
            Command::Stop => break,
            _ => bail!("relay accepts only snapshot and stop"),
        }
    }
    node.shutdown();
    protocol::write_json(&mut output, &Message::Stopped)?;
    Ok(())
}
