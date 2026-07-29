//! Shared support for native Reticulum application utilities.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use rns_core::msgpack::{self, Value};
use rns_crypto::identity::Identity;
use rns_crypto::OsRng;

pub fn home_dir() -> PathBuf {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."))
}

pub fn expand_path(value: &str) -> PathBuf {
    if value == "~" {
        return home_dir();
    }
    if let Some(rest) = value.strip_prefix("~/") {
        return home_dir().join(rest);
    }
    PathBuf::from(value)
}

pub fn rns_config(explicit: Option<&str>) -> PathBuf {
    explicit
        .map(expand_path)
        .unwrap_or_else(|| home_dir().join(".reticulum"))
}

pub fn app_config(app: &str, explicit: Option<&str>) -> PathBuf {
    explicit
        .map(expand_path)
        .unwrap_or_else(|| home_dir().join(".config").join(app))
}

pub fn load_or_create_identity(path: &Path) -> io::Result<Identity> {
    if let Some(parent) = path.parent().filter(|path| !path.as_os_str().is_empty()) {
        fs::create_dir_all(parent)?;
    }
    if path.exists() {
        rns_net::storage::load_identity(path)
    } else {
        let identity = Identity::new(&mut OsRng);
        rns_net::storage::save_identity(&identity, path)?;
        Ok(identity)
    }
}

pub fn parse_hash_16(value: &str) -> Option<[u8; 16]> {
    if value.len() != 32 {
        return None;
    }
    let mut result = [0u8; 16];
    for (index, byte) in result.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16).ok()?;
    }
    Some(result)
}

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

pub fn filename_metadata(filename: &str) -> Vec<u8> {
    msgpack::pack(&Value::Map(vec![(
        Value::Str("name".into()),
        Value::Bin(filename.as_bytes().to_vec()),
    )]))
}

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

pub fn decode_request_string(data: &[u8]) -> Option<String> {
    match msgpack::unpack_exact(data).ok()? {
        Value::Str(value) => Some(value),
        Value::Bin(value) => String::from_utf8(value).ok(),
        _ => None,
    }
}

pub fn bool_value(value: bool) -> Vec<u8> {
    msgpack::pack(&Value::Bool(value))
}

pub fn uint_value(value: u64) -> Vec<u8> {
    msgpack::pack(&Value::UInt(value))
}
