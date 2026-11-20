//! Shared support for native Reticulum application utilities.

use std::io;
use std::path::{Path, PathBuf};
use std::time::Duration;

use rns_core::msgpack::{self, Value};
use rns_crypto::identity::Identity;

/// The directory in `$HOME`, or `.` when `HOME` is unset.
pub fn home_dir() -> PathBuf {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."))
}

/// Expands a leading `~` or `~/` to [`home_dir`]; any other path is taken as
/// given.
pub fn expand_path(value: &str) -> PathBuf {
    if value == "~" {
        return home_dir();
    }
    if let Some(rest) = value.strip_prefix("~/") {
        return home_dir().join(rest);
    }
    PathBuf::from(value)
}

/// The Reticulum config directory: `explicit` with `~` expanded, else
/// `~/.reticulum`.
pub fn rns_config(explicit: Option<&str>) -> PathBuf {
    explicit
        .map(expand_path)
        .unwrap_or_else(|| home_dir().join(".reticulum"))
}

/// The config directory of the application `app`: `explicit` with `~`
/// expanded, else `~/.config/<app>`.
pub fn app_config(app: &str, explicit: Option<&str>) -> PathBuf {
    explicit
        .map(expand_path)
        .unwrap_or_else(|| home_dir().join(".config").join(app))
}

pub use rns_net::storage::load_or_create_identity_file as load_or_create_identity;

/// Parses a 32-character hex string into a 16-byte destination or identity
/// hash. `None` for any other length or a non-hex digit.
pub fn parse_hash_16(value: &str) -> Option<[u8; 16]> {
    rns_core::encoding::hex_decode_array(value)
}

/// The Ed25519 signing halves of `identity`'s keys, as (private, public).
///
/// Fails with [`io::ErrorKind::InvalidData`] when the identity lacks either
/// key, as a public-only identity does.
pub fn signature_keys(identity: &Identity) -> io::Result<([u8; 32], [u8; 32])> {
    let private = identity
        .get_private_key()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "identity has no private key"))?;
    let public = identity
        .get_public_key()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "identity has no public key"))?;
    let mut signature_private = [0u8; 32];
    signature_private.copy_from_slice(&private[32..64]);
    let mut signature_public = [0u8; 32];
    signature_public.copy_from_slice(&public[32..64]);
    Ok((signature_private, signature_public))
}

/// Resource metadata carrying `filename`: a msgpack map `{"name": <bytes>}`.
pub fn filename_metadata(filename: &str) -> Vec<u8> {
    msgpack::pack(&Value::Map(vec![(
        Value::Str("name".into()),
        Value::Bin(filename.as_bytes().to_vec()),
    )]))
}

/// The file name in resource metadata built as [`filename_metadata`] does;
/// the name may be bytes or a string. `None` when the metadata is not such a
/// map or the name is not UTF-8.
pub fn metadata_filename(metadata: &[u8]) -> Option<String> {
    let Value::Map(entries) = msgpack::unpack_exact(metadata).ok()? else {
        return None;
    };
    entries.into_iter().find_map(|(key, value)| {
        if !matches!(key, Value::Str(ref key) if key == "name") {
            return None;
        }
        match value {
            Value::Bin(bytes) => String::from_utf8(bytes).ok(),
            Value::Str(value) => Some(value),
            _ => None,
        }
    })
}

/// Where to save a received file named `filename` in `directory`.
///
/// Only the final component of `filename` is used, so a sender cannot
/// write outside `directory`. Unless `overwrite` is set, an existing file is
/// kept and the first free `<name>.1`, `<name>.2`, ... is returned instead.
/// Fails when `filename` has no usable final component or `directory`
/// cannot be canonicalized.
pub fn collision_destination(
    directory: &Path,
    filename: &str,
    overwrite: bool,
) -> io::Result<PathBuf> {
    let filename = Path::new(filename)
        .file_name()
        .and_then(|value| value.to_str())
        .filter(|value| !value.is_empty())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid resource filename"))?;
    let directory = directory.canonicalize()?;
    let candidate = directory.join(filename);
    if overwrite || !candidate.exists() {
        return Ok(candidate);
    }
    for suffix in 1u64.. {
        let candidate = directory.join(format!("{filename}.{suffix}"));
        if !candidate.exists() {
            return Ok(candidate);
        }
    }
    unreachable!()
}

/// Decodes a request payload that is a single msgpack string or UTF-8 bytes.
pub fn decode_request_string(data: &[u8]) -> Option<String> {
    match msgpack::unpack_exact(data).ok()? {
        Value::Str(value) => Some(value),
        Value::Bin(value) => String::from_utf8(value).ok(),
        _ => None,
    }
}

/// `value` encoded as a msgpack boolean, for a request response.
pub fn bool_value(value: bool) -> Vec<u8> {
    msgpack::pack(&Value::Bool(value))
}

/// `value` encoded as a msgpack unsigned integer, for a request response.
pub fn uint_value(value: u64) -> Vec<u8> {
    msgpack::pack(&Value::UInt(value))
}

/// The path request timeout to use: `configured`, raised to the node's
/// adaptive medium path timeout (see `RnsNode::medium_path_timeout`) when
/// that is longer.
pub fn adaptive_path_timeout(node: &rns_net::RnsNode, configured: Duration) -> Duration {
    let medium = node.medium_path_timeout().unwrap_or(0.0).max(0.0);
    configured.max(Duration::from_secs_f64(medium))
}

/// How long to wait for a link to `destination` to establish: the per-hop
/// establishment timeout times the hop count from the path table (1 when
/// the path is unknown).
pub fn link_establishment_timeout(node: &rns_net::RnsNode, destination: [u8; 16]) -> Duration {
    let hops = node
        .hops_to(&rns_core::types::DestHash(destination))
        .ok()
        .flatten()
        .unwrap_or(1);
    Duration::from_secs_f64(rns_core::link::keepalive::compute_establishment_timeout(
        rns_core::constants::LINK_ESTABLISHMENT_TIMEOUT_PER_HOP,
        hops,
    ))
}
