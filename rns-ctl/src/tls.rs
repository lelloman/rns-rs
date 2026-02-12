use std::fs::File;
use std::io::{self, BufReader};
use std::sync::Arc;

use rustls::ServerConfig;
use rustls_pemfile;

/// Load a TLS server configuration from PEM certificate and key files.
pub fn load_tls_config(cert_path: &str, key_path: &str) -> io::Result<Arc<ServerConfig>> {
    let cert_file = File::open(cert_path)
        .map_err(|e| io::Error::new(e.kind(), format!("Failed to open cert file '{}': {}", cert_path, e)))?;
    let key_file = File::open(key_path)
        .map_err(|e| io::Error::new(e.kind(), format!("Failed to open key file '{}': {}", key_path, e)))?;

    let certs: Vec<_> = rustls_pemfile::certs(&mut BufReader::new(cert_file))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("Failed to parse certs: {}", e)))?;

    if certs.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("No certificates found in '{}'", cert_path),
        ));
    }

    let key = rustls_pemfile::private_key(&mut BufReader::new(key_file))?
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("No private key found in '{}'", key_path),
            )
        })?;

    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("TLS config error: {}", e)))?;

    Ok(Arc::new(config))
}
