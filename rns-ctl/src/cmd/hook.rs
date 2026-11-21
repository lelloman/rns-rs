//! Hook management subcommands.
//!
//! Connects to a running rns-ctl HTTP server to list, load, and unload hooks.

use std::fmt;
use std::io::{self, Read, Write};

use crate::args::Args;
use rns_cli::exit::{Exit, Status};

/// Hook type used when the caller omits `type`. Native hooks must be
/// requested explicitly.
const DEFAULT_HOOK_TYPE: &str = {
    #[cfg(feature = "rns-hooks-wasm")]
    {
        "wasm"
    }
    #[cfg(not(feature = "rns-hooks-wasm"))]
    {
        "builtin"
    }
};

/// Run `rns-ctl hook`: manage hooks through the HTTP API of a running
/// `rns-ctl http` (`--url`, default `http://127.0.0.1:8080`, with the bearer
/// token from `--token`). Prints help for an unknown or missing command;
// gives status 1 when a request fails.
pub fn run(args: Args) -> Status {
    if args.has("help") {
        crate::cli::HOOK.print_help("rns-ctl hook");
        return Ok(());
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
        _ => {
            crate::cli::HOOK.print_help("rns-ctl hook");
            Ok(())
        }
    }
}

fn do_list(base_url: &str, token: Option<&str>) -> Status {
    let url = format!("{}/api/hooks", base_url);
    match simple_get(&url, token) {
        Ok(body) => match serde_json::from_str::<serde_json::Value>(&body) {
            Ok(val) => {
                if let Some(hooks) = val.get("hooks").and_then(serde_json::Value::as_array) {
                    if hooks.is_empty() {
                        println!("No hooks loaded");
                        return Ok(());
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
                            h["type"].as_str().unwrap_or(DEFAULT_HOOK_TYPE),
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
            return Err(Exit::FAILURE);
        }
    }
    Ok(())
}

fn do_load(args: &Args, base_url: &str, token: Option<&str>) -> Status {
    let path = match args.positional.get(1) {
        Some(p) => p,
        None => {
            crate::cli::HOOK.error("rns-ctl hook", "Missing hook file path");
        }
    };
    let attach_point = match args.get("point") {
        Some(p) => p.to_string(),
        None => {
            crate::cli::HOOK.error("rns-ctl hook", "Missing --point <HookPoint>");
        }
    };
    let priority: i32 = args
        .get("priority")
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let hook_type = args.get("type").unwrap_or(DEFAULT_HOOK_TYPE).to_string();
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
        "builtin_id": args.get("builtin").or_else(|| args.get("id")),
        "attach_point": attach_point,
        "priority": priority,
    });

    let url = format!("{}/api/hook/load", base_url);
    match simple_post(&url, &body.to_string(), token) {
        Ok(resp) => println!("{}", resp),
        Err(e) => {
            eprintln!("Error: {}", e);
            return Err(Exit::FAILURE);
        }
    }
    Ok(())
}

fn do_unload(args: &Args, base_url: &str, token: Option<&str>) -> Status {
    let name = match args.positional.get(1) {
        Some(n) => n,
        None => {
            crate::cli::HOOK.error("rns-ctl hook", "Missing hook name");
        }
    };
    let attach_point = match args.get("point") {
        Some(p) => p.to_string(),
        None => {
            crate::cli::HOOK.error("rns-ctl hook", "Missing --point <HookPoint>");
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
            return Err(Exit::FAILURE);
        }
    }
    Ok(())
}

fn do_reload(args: &Args, base_url: &str, token: Option<&str>) -> Status {
    let name = match args.positional.get(1) {
        Some(n) => n,
        None => {
            crate::cli::HOOK.error("rns-ctl hook", "Missing hook name");
        }
    };
    let attach_point = match args.get("point") {
        Some(p) => p.to_string(),
        None => {
            crate::cli::HOOK.error("rns-ctl hook", "Missing --point <HookPoint>");
        }
    };
    let path = match args.get("path") {
        Some(p) => p.to_string(),
        None => {
            crate::cli::HOOK.error("rns-ctl hook", "Missing --path <hook_file>");
        }
    };
    let hook_type = args.get("type").unwrap_or(DEFAULT_HOOK_TYPE).to_string();

    let body = serde_json::json!({
        "name": name,
        "path": path,
        "type": hook_type,
        "builtin_id": args.get("builtin").or_else(|| args.get("id")),
        "attach_point": attach_point,
    });

    let url = format!("{}/api/hook/reload", base_url);
    match simple_post(&url, &body.to_string(), token) {
        Ok(resp) => println!("{}", resp),
        Err(e) => {
            eprintln!("Error: {}", e);
            return Err(Exit::FAILURE);
        }
    }
    Ok(())
}

fn do_set_enabled(args: &Args, base_url: &str, token: Option<&str>, enabled: bool) -> Status {
    let name = match args.positional.get(1) {
        Some(n) => n,
        None => {
            crate::cli::HOOK.error("rns-ctl hook", "Missing hook name");
        }
    };
    let attach_point = match args.get("point") {
        Some(p) => p.to_string(),
        None => {
            crate::cli::HOOK.error("rns-ctl hook", "Missing --point <HookPoint>");
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
            return Err(Exit::FAILURE);
        }
    }
    Ok(())
}

fn do_set_priority(args: &Args, base_url: &str, token: Option<&str>) -> Status {
    let name = match args.positional.get(1) {
        Some(n) => n,
        None => {
            crate::cli::HOOK.error("rns-ctl hook", "Missing hook name");
        }
    };
    let attach_point = match args.get("point") {
        Some(p) => p.to_string(),
        None => {
            crate::cli::HOOK.error("rns-ctl hook", "Missing --point <HookPoint>");
        }
    };
    let priority: i32 = match args.get("priority").and_then(|s| s.parse().ok()) {
        Some(priority) => priority,
        None => {
            crate::cli::HOOK.error("rns-ctl hook", "Missing --priority <N>");
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
            return Err(Exit::FAILURE);
        }
    }
    Ok(())
}

/// Why a request to the HTTP API failed. `Display` is what is printed
/// after `Error: `.
#[derive(Debug)]
enum RequestError {
    /// The URL's port is not a number.
    InvalidPort,
    /// The server could not be reached.
    Connect { addr: String, source: io::Error },
    /// Sending the request failed.
    Write(io::Error),
    /// Reading the response failed.
    Read(io::Error),
}

impl fmt::Display for RequestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPort => f.write_str("invalid port"),
            Self::Connect { addr, source } => write!(f, "connect to {}: {}", addr, source),
            Self::Write(e) => write!(f, "write: {}", e),
            Self::Read(e) => write!(f, "read: {}", e),
        }
    }
}

/// Simple HTTP GET using std::net::TcpStream (no external HTTP client dependency).
fn simple_get(url: &str, token: Option<&str>) -> Result<String, RequestError> {
    request("GET", url, None, token)
}

/// Simple HTTP POST of a JSON `body` using std::net::TcpStream.
fn simple_post(url: &str, body: &str, token: Option<&str>) -> Result<String, RequestError> {
    request("POST", url, Some(body), token)
}

/// One HTTP/1.1 request on a connection of its own; the response body.
fn request(
    method: &str,
    url: &str,
    body: Option<&str>,
    token: Option<&str>,
) -> Result<String, RequestError> {
    let (host, port, path) = parse_url(url)?;
    let addr = format!("{}:{}", host, port);
    let mut stream = std::net::TcpStream::connect(&addr)
        .map_err(|source| RequestError::Connect { addr, source })?;

    let auth = match token {
        Some(t) => format!("Authorization: Bearer {}\r\n", t),
        None => String::new(),
    };
    let request = match body {
        Some(body) => format!(
            "{} {} HTTP/1.1\r\nHost: {}\r\n{}Content-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            method, path, host, auth, body.len(), body
        ),
        None => format!(
            "{} {} HTTP/1.1\r\nHost: {}\r\n{}Connection: close\r\n\r\n",
            method, path, host, auth
        ),
    };
    stream
        .write_all(request.as_bytes())
        .map_err(RequestError::Write)?;

    let mut response = String::new();
    stream
        .read_to_string(&mut response)
        .map_err(RequestError::Read)?;

    Ok(extract_body(&response))
}

fn parse_url(url: &str) -> Result<(String, u16, String), RequestError> {
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
                .map_err(|_| RequestError::InvalidPort)?,
        ),
        None => (hostport, 80),
    };
    Ok((host.to_string(), port, path.to_string()))
}

/// What follows the headers, or the whole response without any.
fn extract_body(response: &str) -> String {
    match response.find("\r\n\r\n") {
        Some(i) => response[i + 4..].to_string(),
        None => response.to_string(),
    }
}
