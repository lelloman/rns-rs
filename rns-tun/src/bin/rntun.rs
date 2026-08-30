use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

fn main() {
    if let Err(error) = run() {
        eprintln!("rntun: {error}");
        std::process::exit(1)
    }
}
fn run() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let Some(command) = args.next() else {
        print_help();
        return Ok(());
    };
    if command == "--help" || command == "help" {
        print_help();
        return Ok(());
    }
    if command == "--version" {
        println!("rntun {}", env!("CARGO_PKG_VERSION"));
        return Ok(());
    }
    let mut config = None;
    let mut positional = Vec::new();
    let mut json = false;
    let mut route_overrides = Vec::new();
    let mut dns_overrides = Vec::new();
    let mut default_route = false;
    while let Some(arg) = args.next() {
        if arg == "--config" || arg == "-c" {
            config = args.next().map(PathBuf::from);
        } else if arg == "--json" {
            json = true;
        } else if arg == "--route" {
            route_overrides.push(args.next().ok_or("--route requires a CIDR")?);
        } else if arg == "--dns" {
            dns_overrides.push(args.next().ok_or("--dns requires an IPv4 address")?);
        } else if arg == "--default-route" {
            default_route = true;
        } else if arg.starts_with('-') {
            return Err(format!("unknown option {arg}").into());
        } else {
            positional.push(arg);
        }
    }
    let path = config.unwrap_or_else(rns_tun::config::default_config_path);
    let mut parsed = rns_tun::Config::load(&path)?;
    if !route_overrides.is_empty() || !dns_overrides.is_empty() || default_route {
        if command != "connect" {
            return Err("--route, --dns and --default-route are connect options".into());
        }
        let client = parsed.client.as_mut().ok_or("client section is required")?;
        for route in route_overrides {
            route.parse::<rns_tun::Cidr>()?;
            if !client.requested_routes.contains(&route) {
                client.requested_routes.push(route);
            }
        }
        for dns in dns_overrides {
            let dns = dns.parse()?;
            if !client.allowed_dns.contains(&dns) {
                client.allowed_dns.push(dns);
            }
        }
        if default_route {
            if !client
                .allowed_routes
                .iter()
                .any(|route| route == "0.0.0.0/0")
            {
                return Err("--default-route requires 0.0.0.0/0 in client.allowed_routes".into());
            }
            if !client
                .requested_routes
                .iter()
                .any(|route| route == "0.0.0.0/0")
            {
                client.requested_routes.push("0.0.0.0/0".into());
            }
            client.allow_default_route = true;
        }
        parsed.validate()?;
    }
    match command.as_str() {
        "check" => println!("configuration is valid: {}", path.display()),
        "identity" => {
            let identity_path = if let Some(gateway) = &parsed.gateway {
                gateway
                    .identity_file
                    .clone()
                    .unwrap_or_else(|| parsed.state_dir.join("gateway_identity"))
            } else if let Some(client) = &parsed.client {
                client
                    .identity_file
                    .clone()
                    .unwrap_or_else(|| parsed.state_dir.join("client_identity"))
            } else {
                unreachable!("configuration validation requires a mode")
            };
            let identity = rns_tun::identity::load_or_create(&identity_path)?;
            println!("{}", hex(identity.hash()));
        }
        "listen" => {
            let stop = install_signal_handler()?;
            let (_status_server, status) = start_status(&parsed, "gateway")?;
            rns_tun::gateway::run_linux_gateway(&parsed, &stop, status)?;
        }
        "connect" => {
            let destination = positional
                .first()
                .ok_or("connect requires a 32-character destination hash")?;
            let destination = parse_hash(destination)?;
            let stop = install_signal_handler()?;
            let (_status_server, status) = start_status(&parsed, "client")?;
            rns_tun::client::run_linux_client(&parsed, destination, &stop, status)?;
        }
        "status" => {
            let socket = parsed
                .status_socket
                .clone()
                .unwrap_or_else(|| parsed.state_dir.join("status.sock"));
            let status = rns_tun::runtime::status_socket::query(&socket)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&status)?);
            } else {
                println!(
                    "mode={} lifecycle={} sessions={} reconnecting={} full_tunnel_verified={}",
                    status.mode,
                    status.lifecycle,
                    status.sessions.len(),
                    status.reconnecting,
                    status.full_tunnel_verified
                );
            }
        }
        "cleanup" => {
            rns_tun::client::cleanup_linux(&parsed)?;
            println!("stale rntun-owned Linux state removed");
        }
        _ => {
            print_help();
            return Err(format!("unknown command {command}").into());
        }
    }
    Ok(())
}

fn install_signal_handler() -> Result<Arc<AtomicBool>, Box<dyn std::error::Error>> {
    let stop = Arc::new(AtomicBool::new(false));
    let signal_stop = Arc::clone(&stop);
    ctrlc::set_handler(move || signal_stop.store(true, Ordering::Relaxed))?;
    Ok(stop)
}

fn start_status(
    config: &rns_tun::Config,
    mode: &str,
) -> Result<
    (
        rns_tun::runtime::status_socket::StatusServer,
        rns_tun::runtime::SharedStatus,
    ),
    Box<dyn std::error::Error>,
> {
    let path = config
        .status_socket
        .clone()
        .unwrap_or_else(|| config.state_dir.join("status.sock"));
    let status = rns_tun::runtime::SharedStatus::new(rns_tun::status::RuntimeStatus {
        mode: mode.into(),
        lifecycle: "active".into(),
        ..Default::default()
    });
    let server = rns_tun::runtime::status_socket::StatusServer::start(path, status.clone())?;
    Ok((server, status))
}

fn parse_hash(value: &str) -> Result<[u8; 16], Box<dyn std::error::Error>> {
    if value.len() != 32 {
        return Err("destination hash must contain 32 hexadecimal characters".into());
    }
    let mut result = [0; 16];
    for (index, byte) in result.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)?;
    }
    Ok(result)
}

fn hex(value: &[u8]) -> String {
    value.iter().map(|byte| format!("{byte:02x}")).collect()
}
fn print_help() {
    println!("rntun - IPv4 tunnelling over Reticulum\n\nUSAGE:\n    rntun check [--config FILE]\n    rntun identity [--config FILE]\n    rntun listen [--config FILE]\n    rntun connect DESTINATION [--config FILE] [--route CIDR ...] [--default-route]\n    rntun status [--config FILE] [--json]\n    rntun cleanup [--config FILE]")
}
