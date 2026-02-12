//! Remote management query helper.
//!
//! Connects as a shared client, creates a link to a remote management
//! destination, sends a request, and returns the response data.

use std::path::Path;
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use rns_net::{Callbacks, RnsNode};
use rns_net::shared_client::SharedClientConfig;

/// Parse a 32-hex-char destination hash.
pub fn parse_hex_hash(s: &str) -> Option<[u8; 16]> {
    let s = s.trim();
    if s.len() != 32 {
        return None;
    }
    let bytes: Vec<u8> = (0..s.len())
        .step_by(2)
        .filter_map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect();
    if bytes.len() != 16 {
        return None;
    }
    let mut result = [0u8; 16];
    result.copy_from_slice(&bytes);
    Some(result)
}

/// Result from a remote management query.
pub struct RemoteQueryResult {
    /// Raw response data from the management request.
    pub data: Vec<u8>,
}

/// Callbacks that capture link establishment and response data.
struct RemoteCallbacks {
    link_established_tx: mpsc::Sender<rns_net::LinkId>,
    response_data: Arc<Mutex<Option<Vec<u8>>>>,
    response_tx: mpsc::Sender<()>,
}

impl Callbacks for RemoteCallbacks {
    fn on_announce(&mut self, _announced: rns_net::AnnouncedIdentity) {}

    fn on_path_updated(&mut self, _dest_hash: rns_net::DestHash, _hops: u8) {}

    fn on_local_delivery(&mut self, _dest_hash: rns_net::DestHash, _raw: Vec<u8>, _packet_hash: rns_net::PacketHash) {}

    fn on_link_established(&mut self, link_id: rns_net::LinkId, _dest_hash: rns_net::DestHash, _rtt: f64, _is_initiator: bool) {
        let _ = self.link_established_tx.send(link_id);
    }

    fn on_response(&mut self, _link_id: rns_net::LinkId, _request_id: [u8; 16], data: Vec<u8>) {
        *self.response_data.lock().unwrap() = Some(data);
        let _ = self.response_tx.send(());
    }
}

/// Perform a remote management query.
///
/// 1. Connects as a shared client
/// 2. Creates a link to the management destination
/// 3. Identifies on the link
/// 4. Sends a request to the specified path
/// 5. Returns the response data
///
/// Returns `None` if the query fails or times out.
pub fn remote_query(
    dest_hash: [u8; 16],
    dest_sig_pub: [u8; 32],
    identity_prv_key: [u8; 64],
    path: &str,
    data: &[u8],
    config_path: Option<&Path>,
    timeout: Duration,
) -> Option<RemoteQueryResult> {
    let (link_tx, link_rx) = mpsc::channel();
    let (resp_tx, resp_rx) = mpsc::channel();
    let response_data = Arc::new(Mutex::new(None));

    let callbacks = RemoteCallbacks {
        link_established_tx: link_tx,
        response_data: response_data.clone(),
        response_tx: resp_tx,
    };

    // Load config for shared instance connection
    let config_dir = rns_net::storage::resolve_config_dir(config_path);
    let config_file = config_dir.join("config");
    let rns_config = if config_file.exists() {
        rns_net::config::parse_file(&config_file).ok()?
    } else {
        rns_net::config::parse("").ok()?
    };

    let shared_config = SharedClientConfig {
        instance_name: rns_config.reticulum.instance_name.clone(),
        port: rns_config.reticulum.shared_instance_port,
        rpc_port: rns_config.reticulum.instance_control_port,
    };

    let node = RnsNode::connect_shared(shared_config, Box::new(callbacks)).ok()?;

    // Wait briefly for connection
    std::thread::sleep(Duration::from_millis(500));

    // Create link to management destination
    let link_id = node.create_link(dest_hash, dest_sig_pub).ok()?;

    // Wait for link establishment
    let _established_link_id = link_rx.recv_timeout(timeout).ok()?;

    // Identify on the link
    node.identify_on_link(link_id, identity_prv_key).ok()?;
    std::thread::sleep(Duration::from_millis(200));

    // Send the request
    node.send_request(link_id, path, data).ok()?;

    // Wait for response
    resp_rx.recv_timeout(timeout).ok()?;

    let data = response_data.lock().unwrap().take()?;
    node.shutdown();

    Some(RemoteQueryResult { data })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_hex_hash_valid() {
        let hash = parse_hex_hash("0123456789abcdef0123456789abcdef").unwrap();
        assert_eq!(hash[0], 0x01);
        assert_eq!(hash[15], 0xef);
    }

    #[test]
    fn parse_hex_hash_invalid() {
        assert!(parse_hex_hash("short").is_none());
        assert!(parse_hex_hash("0123456789abcdef0123456789abcdef00").is_none());
        assert!(parse_hex_hash("xyz3456789abcdef0123456789abcdef").is_none());
    }

    #[test]
    fn parse_hex_hash_trimmed() {
        let hash = parse_hex_hash("  0123456789abcdef0123456789abcdef  ").unwrap();
        assert_eq!(hash[0], 0x01);
    }
}
