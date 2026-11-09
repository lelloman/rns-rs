use std::time::Duration;

use rns_net::event;
use rns_net::interface::local::start_client;
use rns_net::{Event, InterfaceId, LocalClientConfig};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let _ = env_logger::try_init();

    let instance_name = std::env::var("RNS_INSTANCE_NAME").unwrap_or_else(|_| "default".into());
    let port = std::env::var("RNS_SHARED_INSTANCE_PORT")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(37428);

    let (tx, rx) = event::channel();
    let config = LocalClientConfig {
        name: "issue-2-repro".into(),
        instance_name,
        port,
        interface_id: InterfaceId(9002),
        reconnect_wait: Duration::from_secs(1),
        use_af_unix: true,
    };

    let _writer = start_client(config, tx)?;

    match rx.recv_timeout(Duration::from_secs(2))? {
        Event::InterfaceUp(id, _, _) => {
            println!("connected with interface id {}", id.0);
            Ok(())
        }
        other => Err(format!("unexpected event after connect: {:?}", other).into()),
    }
}
