#![cfg(feature = "tls")]

use std::fs;
use std::io::Cursor;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use rustls::pki_types::{pem::PemObject, CertificateDer, ServerName};

static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);

struct CertificateFiles {
    directory: PathBuf,
    cert_path: PathBuf,
    key_path: PathBuf,
}

impl CertificateFiles {
    fn new(cert_pem: &str, key_pem: &str) -> Self {
        let sequence = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
        let directory =
            std::env::temp_dir().join(format!("rns-ctl-rcgen-{}-{sequence}", std::process::id()));
        fs::create_dir(&directory).unwrap();
        let cert_path = directory.join("certificate.pem");
        let key_path = directory.join("private-key.pem");
        fs::write(&cert_path, cert_pem).unwrap();
        fs::write(&key_path, key_pem).unwrap();
        Self {
            directory,
            cert_path,
            key_path,
        }
    }

    fn load_server_config(&self) -> std::io::Result<Arc<rustls::ServerConfig>> {
        rns_ctl::tls::load_tls_config(path_str(&self.cert_path), path_str(&self.key_path))
    }
}

impl Drop for CertificateFiles {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.directory);
    }
}

fn path_str(path: &Path) -> &str {
    path.to_str().expect("test path must be UTF-8")
}

fn generate(names: &[&str]) -> (String, String) {
    let certified = rcgen::generate_simple_self_signed(
        names
            .iter()
            .map(|name| (*name).to_owned())
            .collect::<Vec<_>>(),
    )
    .unwrap();
    (certified.cert.pem(), certified.signing_key.serialize_pem())
}

fn trust_store(cert_pem: &str) -> rustls::RootCertStore {
    let certificates = CertificateDer::pem_slice_iter(cert_pem.as_bytes())
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert_eq!(certificates.len(), 1);
    let mut roots = rustls::RootCertStore::empty();
    roots.add(certificates.into_iter().next().unwrap()).unwrap();
    roots
}

fn handshake(
    server_config: Arc<rustls::ServerConfig>,
    roots: rustls::RootCertStore,
    server_name: &str,
) -> Result<(), rustls::Error> {
    let client_config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let name = ServerName::try_from(server_name.to_owned()).unwrap();
    let mut client = rustls::ClientConnection::new(Arc::new(client_config), name).unwrap();
    let mut server = rustls::ServerConnection::new(server_config).unwrap();

    for _ in 0..20 {
        let mut client_bytes = Vec::new();
        client.write_tls(&mut client_bytes).unwrap();
        if !client_bytes.is_empty() {
            server.read_tls(&mut Cursor::new(client_bytes)).unwrap();
            server.process_new_packets()?;
        }

        let mut server_bytes = Vec::new();
        server.write_tls(&mut server_bytes).unwrap();
        if !server_bytes.is_empty() {
            client.read_tls(&mut Cursor::new(server_bytes)).unwrap();
            client.process_new_packets()?;
        }

        if !client.is_handshaking() && !server.is_handshaking() {
            return Ok(());
        }
    }

    panic!("TLS handshake did not complete");
}

#[test]
fn generated_pem_contains_one_certificate_and_a_loadable_private_key() {
    let (cert_pem, key_pem) = generate(&["localhost", "example.test"]);
    assert!(cert_pem.starts_with("-----BEGIN CERTIFICATE-----"));
    assert!(key_pem.starts_with("-----BEGIN PRIVATE KEY-----"));

    let files = CertificateFiles::new(&cert_pem, &key_pem);
    files.load_server_config().unwrap();
    assert_eq!(trust_store(&cert_pem).len(), 1);
}

#[test]
fn generated_certificate_completes_a_rustls_handshake_for_its_dns_name() {
    let (cert_pem, key_pem) = generate(&["localhost"]);
    let files = CertificateFiles::new(&cert_pem, &key_pem);

    handshake(
        files.load_server_config().unwrap(),
        trust_store(&cert_pem),
        "localhost",
    )
    .unwrap();
}

#[test]
fn generated_certificate_is_rejected_for_an_unlisted_dns_name() {
    let (cert_pem, key_pem) = generate(&["localhost"]);
    let files = CertificateFiles::new(&cert_pem, &key_pem);

    assert!(handshake(
        files.load_server_config().unwrap(),
        trust_store(&cert_pem),
        "wrong.example",
    )
    .is_err());
}

#[test]
fn generated_certificate_is_rejected_by_an_unrelated_trust_store() {
    let (cert_pem, key_pem) = generate(&["localhost"]);
    let (unrelated_cert, _) = generate(&["localhost"]);
    let files = CertificateFiles::new(&cert_pem, &key_pem);

    assert!(handshake(
        files.load_server_config().unwrap(),
        trust_store(&unrelated_cert),
        "localhost",
    )
    .is_err());
}

#[test]
fn loader_rejects_a_private_key_from_a_different_generated_certificate() {
    let (cert_pem, _) = generate(&["localhost"]);
    let (_, unrelated_key) = generate(&["localhost"]);
    let files = CertificateFiles::new(&cert_pem, &unrelated_key);

    let error = files.load_server_config().unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
    assert!(error.to_string().contains("key"));
}
