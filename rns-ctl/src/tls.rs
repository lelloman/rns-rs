use std::fs;
use std::io;
use std::sync::Arc;

use rustls::pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer};
use rustls::ServerConfig;

/// Load a TLS server configuration from PEM certificate and key files.
pub fn load_tls_config(cert_path: &str, key_path: &str) -> io::Result<Arc<ServerConfig>> {
    let cert_pem = fs::read(cert_path).map_err(|e| {
        io::Error::new(
            e.kind(),
            format!("Failed to open cert file '{}': {}", cert_path, e),
        )
    })?;
    let key_pem = fs::read(key_path).map_err(|e| {
        io::Error::new(
            e.kind(),
            format!("Failed to open key file '{}': {}", key_path, e),
        )
    })?;

    let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(&cert_pem)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Failed to parse certs: {}", e),
            )
        })?;

    if certs.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("No certificates found in '{}'", cert_path),
        ));
    }

    let key = PrivateKeyDer::from_pem_slice(&key_pem).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("Failed to parse private key: {}", e),
        )
    })?;

    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("TLS config error: {}", e),
            )
        })?;

    Ok(Arc::new(config))
}
