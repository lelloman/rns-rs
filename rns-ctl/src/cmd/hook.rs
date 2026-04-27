//! Hook management subcommands.
//!
//! Connects to a running rns-ctl HTTP server to list, load, and unload hooks.

use crate::args::Args;

pub fn run(args: Args) {
    if args.has("help") {
        print_usage();
        return;
    }

    let base_url = args
        .get("url")
        .unwrap_or("http://127.0.0.1:8080")
        .to_string();
    let token = args
        .get("token")
        .or_else(|| args.get("t"))
        .map(|s| s.to_string());

    match args.positional.first().map(|s| s.as_str()) {
        Some("list") => do_list(&base_url, token.as_deref()),
        Some("load") => do_load(&args, &base_url, token.as_deref()),
        Some("unload") => do_unload(&args, &base_url, token.as_deref()),
        Some("reload") => do_reload(&args, &base_url, token.as_deref()),
        Some("enable") => do_set_enabled(&args, &base_url, token.as_deref(), true),
        Some("disable") => do_set_enabled(&args, &base_url, token.as_deref(), false),
        Some("set-priority") => do_set_priority(&args, &base_url, token.as_deref()),
        _ => print_usage(),
    }
}

fn do_list(base_url: &str, token: Option<&str>) {
    let url = format!("{}/api/hooks", base_url);
    match simple_get(&url, token) {
        Ok(body) => match serde_json::from_str::<serde_json::Value>(&body) {
            Ok(val) => {
                if let Some(hooks) = val["hooks"].as_array() {
                    if hooks.is_empty() {
                        println!("No hooks loaded");
                        return;
                    }
                    println!(
                        "{:<20} {:<8} {:<28} {:>8} {:>8} {:>6}",
                        "Name", "Type", "Attach Point", "Priority", "Traps", "On"
                    );
                    println!("{}", "-".repeat(83));
                    for h in hooks {
                        println!(
                            "{:<20} {:<8} {:<28} {:>8} {:>8} {:>6}",
                            h["name"].as_str().unwrap_or(""),
                            h["type"].as_str().unwrap_or("wasm"),
                            h["attach_point"].as_str().unwrap_or(""),
                            h["priority"].as_i64().unwrap_or(0),
                            h["consecutive_traps"].as_u64().unwrap_or(0),
                            if h["enabled"].as_bool().unwrap_or(false) {
                                "yes"
                            } else {
                                "no"
                            },
                        );
                    }
                } else {
                    println!("{}", body);
                }
            }
            Err(_) => println!("{}", body),
        },
        Err(e) => {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    }
}

fn do_load(args: &Args, base_url: &str, token: Option<&str>) {
    let path = match args.positional.get(1) {
        Some(p) => p,
        None => {
            eprintln!("Missing hook file path");
            print_usage();
            std::process::exit(1);
        }
    };
    let attach_point = match args.get("point") {
        Some(p) => p.to_string(),
        None => {
            eprintln!("Missing --point <HookPoint>");
            print_usage();
            std::process::exit(1);
        }
    };
    let priority: i32 = args
        .get("priority")
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let hook_type = args.get("type").unwrap_or("wasm").to_string();
    let name = args.get("name").map(|s| s.to_string()).unwrap_or_else(|| {
        std::path::Path::new(path)
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("hook")
            .to_string()
    });

    let body = serde_json::json!({
        "name": name,
        "path": path,
        "type": hook_type,
        "attach_point": attach_point,
        "priority": priority,
    });

    let url = format!("{}/api/hook/load", base_url);
    match simple_post(&url, &body.to_string(), token) {
        Ok(resp) => println!("{}", resp),
        Err(e) => {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    }
}

fn do_unload(args: &Args, base_url: &str, token: Option<&str>) {
    let name = match args.positional.get(1) {
        Some(n) => n,
        None => {
            eprintln!("Missing hook name");
            print_usage();
            std::process::exit(1);
        }
    };
    let attach_point = match args.get("point") {
        Some(p) => p.to_string(),
        None => {
            eprintln!("Missing --point <HookPoint>");
            print_usage();
            std::process::exit(1);
        }
    };

    let body = serde_json::json!({
        "name": name,
        "attach_point": attach_point,
    });

    let url = format!("{}/api/hook/unload", base_url);
    match simple_post(&url, &body.to_string(), token) {
        Ok(resp) => println!("{}", resp),
        Err(e) => {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    }
}

fn do_reload(args: &Args, base_url: &str, token: Option<&str>) {
    let name = match args.positional.get(1) {
        Some(n) => n,
        None => {
            eprintln!("Missing hook name");
            print_usage();
            std::process::exit(1);
        }
    };
    let attach_point = match args.get("point") {
        Some(p) => p.to_string(),
        None => {
            eprintln!("Missing --point <HookPoint>");
            print_usage();
            std::process::exit(1);
        }
    };
    let path = match args.get("path") {
        Some(p) => p.to_string(),
        None => {
            eprintln!("Missing --path <hook_file>");
            print_usage();
            std::process::exit(1);
        }
    };
    let hook_type = args.get("type").unwrap_or("wasm").to_string();

    let body = serde_json::json!({
        "name": name,
        "path": path,
        "type": hook_type,
        "attach_point": attach_point,
    });

    let url = format!("{}/api/hook/reload", base_url);
    match simple_post(&url, &body.to_string(), token) {
        Ok(resp) => println!("{}", resp),
        Err(e) => {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    }
}

fn do_set_enabled(args: &Args, base_url: &str, token: Option<&str>, enabled: bool) {
    let name = match args.positional.get(1) {
        Some(n) => n,
        None => {
            eprintln!("Missing hook name");
            print_usage();
            std::process::exit(1);
        }
    };
    let attach_point = match args.get("point") {
        Some(p) => p.to_string(),
        None => {
            eprintln!("Missing --point <HookPoint>");
            print_usage();
            std::process::exit(1);
        }
    };

    let body = serde_json::json!({
        "name": name,
        "attach_point": attach_point,
    });
    let url = format!(
        "{}/api/hook/{}",
        base_url,
        if enabled { "enable" } else { "disable" }
    );
    match simple_post(&url, &body.to_string(), token) {
        Ok(resp) => println!("{}", resp),
        Err(e) => {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    }
}

fn do_set_priority(args: &Args, base_url: &str, token: Option<&str>) {
    let name = match args.positional.get(1) {
        Some(n) => n,
        None => {
            eprintln!("Missing hook name");
            print_usage();
            std::process::exit(1);
        }
    };
    let attach_point = match args.get("point") {
        Some(p) => p.to_string(),
        None => {
            eprintln!("Missing --point <HookPoint>");
            print_usage();
            std::process::exit(1);
        }
    };
    let priority: i32 = match args.get("priority").and_then(|s| s.parse().ok()) {
        Some(priority) => priority,
        None => {
            eprintln!("Missing --priority <N>");
            print_usage();
            std::process::exit(1);
        }
    };

    let body = serde_json::json!({
        "name": name,
        "attach_point": attach_point,
        "priority": priority,
    });
    let url = format!("{}/api/hook/priority", base_url);
    match simple_post(&url, &body.to_string(), token) {
        Ok(resp) => println!("{}", resp),
        Err(e) => {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    }
}

/// Simple HTTP GET using std::net::TcpStream (no external HTTP client dependency).
fn simple_get(url: &str, token: Option<&str>) -> Result<String, String> {
    let (host, port, path) = parse_url(url)?;
    let addr = format!("{}:{}", host, port);
    let mut stream =
        std::net::TcpStream::connect(&addr).map_err(|e| format!("connect to {}: {}", addr, e))?;

    use std::io::{Read, Write};
    let auth = match token {
        Some(t) => format!("Authorization: Bearer {}\r\n", t),
        None => String::new(),
    };
    let request = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\n{}Connection: close\r\n\r\n",
        path, host, auth
    );
    stream
        .write_all(request.as_bytes())
        .map_err(|e| format!("write: {}", e))?;

    let mut response = String::new();
    stream
        .read_to_string(&mut response)
        .map_err(|e| format!("read: {}", e))?;

    extract_body(&response)
}

/// Simple HTTP POST using std::net::TcpStream.
fn simple_post(url: &str, body: &str, token: Option<&str>) -> Result<String, String> {
    let (host, port, path) = parse_url(url)?;
    let addr = format!("{}:{}", host, port);
    let mut stream =
        std::net::TcpStream::connect(&addr).map_err(|e| format!("connect to {}: {}", addr, e))?;

    use std::io::{Read, Write};
    let auth = match token {
        Some(t) => format!("Authorization: Bearer {}\r\n", t),
        None => String::new(),
    };
    let request = format!(
        "POST {} HTTP/1.1\r\nHost: {}\r\n{}Content-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        path, host, auth, body.len(), body
    );
    stream
        .write_all(request.as_bytes())
        .map_err(|e| format!("write: {}", e))?;

    let mut response = String::new();
    stream
        .read_to_string(&mut response)
        .map_err(|e| format!("read: {}", e))?;

    extract_body(&response)
}

fn parse_url(url: &str) -> Result<(String, u16, String), String> {
    let url = url.strip_prefix("http://").unwrap_or(url);
    let (hostport, path) = match url.find('/') {
        Some(i) => (&url[..i], &url[i..]),
        None => (url, "/"),
    };
    let (host, port) = match hostport.rfind(':') {
        Some(i) => (
            &hostport[..i],
            hostport[i + 1..]
                .parse::<u16>()
                .map_err(|_| "invalid port".to_string())?,
        ),
        None => (hostport, 80),
    };
    Ok((host.to_string(), port, path.to_string()))
}

fn extract_body(response: &str) -> Result<String, String> {
    match response.find("\r\n\r\n") {
        Some(i) => Ok(response[i + 4..].to_string()),
        None => Ok(response.to_string()),
    }
}

fn print_usage() {
    println!("Usage: rns-ctl hook <COMMAND> [OPTIONS]");
    println!();
    println!("COMMANDS:");
    println!("    list                               List loaded hooks");
    println!("    load <path> --point <HookPoint>     Load a hook");
    println!("         [--type wasm|native] [--priority N] [--name name]");
    println!("    unload <name> --point <HookPoint>   Unload a hook");
    println!("    reload <name> --point <HookPoint>   Reload a hook");
    println!("         --path <hook_file> [--type wasm|native]");
    println!("    enable <name> --point <HookPoint>   Enable a loaded hook");
    println!("    disable <name> --point <HookPoint>  Disable a loaded hook");
    println!("    set-priority <name> --point <HookPoint> --priority N");
    println!();
    println!("OPTIONS:");
    println!("    --url URL          HTTP server URL (default: http://127.0.0.1:8080)");
    println!("    --token TOKEN, -t  Bearer auth token (printed by rns-ctl http on start)");
    println!();
    println!("HOOK POINTS:");
    println!("    PreIngress, PreDispatch, AnnounceReceived, PathUpdated,");
    println!("    AnnounceRetransmit, LinkRequestReceived, LinkEstablished,");
    println!("    LinkClosed, InterfaceUp, InterfaceDown, InterfaceConfigChanged,");
    println!("    SendOnInterface, BroadcastOnAllInterfaces, DeliverLocal,");
    println!("    TunnelSynthesize, Tick");
}
