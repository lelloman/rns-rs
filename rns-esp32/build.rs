use std::env;
use std::fs;
use std::path::PathBuf;
use std::process::Command;

const MAX_CONTROL_IDENTITIES: usize = 3;

fn main() {
    if env::var_os("CARGO_FEATURE_FIRMWARE").is_some() {
        embuild::espidf::sysenv::output();
    }

    println!("cargo:rerun-if-changed=../.git/HEAD");
    println!("cargo:rerun-if-changed=../.git/refs");

    let pkg_version = env!("CARGO_PKG_VERSION");
    let mut parts = pkg_version.split('.');
    let major = parts.next().unwrap_or("0").parse::<u8>().unwrap_or(0);
    let minor = parts.next().unwrap_or("0").parse::<u8>().unwrap_or(0);

    let commit_count = git_output(&["rev-list", "--count", "HEAD"]).unwrap_or_else(|| "0".into());
    let commit_hash =
        git_output(&["rev-parse", "--short", "HEAD"]).unwrap_or_else(|| "unknown".into());
    let dirty = Command::new("git")
        .args(["diff", "--quiet", "--ignore-submodules", "HEAD", "--"])
        .status()
        .map(|status| !status.success())
        .unwrap_or(false);

    let full_version = if dirty {
        format!("{}.{}.{}-{}-dirty", major, minor, commit_count, commit_hash)
    } else {
        format!("{}.{}.{}-{}", major, minor, commit_count, commit_hash)
    };

    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR not set"));
    let version_rs = out_dir.join("firmware_version.rs");
    fs::write(
        &version_rs,
        format!(
            "pub const PKG_VERSION: &str = {:?};\n\
             pub const FULL_VERSION: &str = {:?};\n\
             pub const GIT_HASH: &str = {:?};\n\
             pub const COMMIT_COUNT: &str = {:?};\n\
             pub const DIRTY: bool = {};\n\
             pub const RNODE_PROTOCOL_MAJOR: u8 = {};\n\
             pub const RNODE_PROTOCOL_MINOR: u8 = {};\n",
            pkg_version, full_version, commit_hash, commit_count, dirty, major, minor
        ),
    )
    .expect("write firmware_version.rs");

    let control_rs = out_dir.join("control_build_config.rs");
    fs::write(
        &control_rs,
        build_control_config(
            env::var("RNS_ESP32_CONTROL_PUBKEYS").ok(),
            env::var("RNS_ESP32_BT_OPEN_DEFAULT").ok(),
        ),
    )
    .expect("write control_build_config.rs");
}

fn git_output(args: &[&str]) -> Option<String> {
    Command::new("git")
        .args(args)
        .output()
        .ok()
        .filter(|output| output.status.success())
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .map(|stdout| stdout.trim().to_string())
}

fn build_control_config(pubkeys_env: Option<String>, ble_default_env: Option<String>) -> String {
    let keys = parse_control_pubkeys(pubkeys_env.as_deref())
        .unwrap_or_else(|err| panic!("invalid RNS_ESP32_CONTROL_PUBKEYS: {err}"));
    let ble_default = parse_bool_env(ble_default_env.as_deref(), false)
        .unwrap_or_else(|err| panic!("invalid RNS_ESP32_BT_OPEN_DEFAULT: {err}"));

    let mut rendered = String::new();
    rendered.push_str(&format!(
        "pub const CONTROL_CONTROLLER_COUNT: usize = {};\n",
        keys.len()
    ));
    rendered.push_str("pub const CONTROL_CONTROLLER_KEYS: [[u8; 64]; 3] = [\n");
    for idx in 0..MAX_CONTROL_IDENTITIES {
        if let Some(key) = keys.get(idx) {
            rendered.push_str("    [");
            for (byte_idx, byte) in key.iter().enumerate() {
                if byte_idx > 0 {
                    rendered.push_str(", ");
                }
                rendered.push_str(&format!("0x{byte:02X}"));
            }
            rendered.push_str("],\n");
        } else {
            rendered.push_str("    [0u8; 64],\n");
        }
    }
    rendered.push_str("];\n");
    rendered.push_str(&format!(
        "pub const BLE_OPEN_CONTROL_DEFAULT: bool = {};\n",
        ble_default
    ));
    rendered
}

fn parse_control_pubkeys(value: Option<&str>) -> Result<Vec<[u8; 64]>, String> {
    let Some(value) = value.map(str::trim) else {
        return Ok(Vec::new());
    };
    if value.is_empty() {
        return Ok(Vec::new());
    }

    let mut keys = Vec::new();
    for entry in value.split(',').map(str::trim) {
        if entry.is_empty() {
            return Err("empty controller public key entry".into());
        }
        let bytes = parse_hex(entry)?;
        if bytes.len() != 64 {
            return Err(format!(
                "controller public key must be exactly 64 bytes, got {} bytes",
                bytes.len()
            ));
        }
        let mut key = [0u8; 64];
        key.copy_from_slice(&bytes);
        if keys.contains(&key) {
            return Err("duplicate controller public key".into());
        }
        keys.push(key);
    }

    if keys.len() > MAX_CONTROL_IDENTITIES {
        return Err(format!(
            "at most {MAX_CONTROL_IDENTITIES} controller identities are supported"
        ));
    }

    Ok(keys)
}

fn parse_bool_env(value: Option<&str>, default: bool) -> Result<bool, String> {
    let Some(value) = value.map(str::trim) else {
        return Ok(default);
    };
    if value.is_empty() {
        return Ok(default);
    }

    match value.to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Ok(true),
        "0" | "false" | "no" | "off" => Ok(false),
        _ => Err(format!("expected boolean value, got {value:?}")),
    }
}

fn parse_hex(input: &str) -> Result<Vec<u8>, String> {
    if input.len() % 2 != 0 {
        return Err("hex string must have even length".into());
    }

    let mut bytes = Vec::with_capacity(input.len() / 2);
    let chars: Vec<_> = input.as_bytes().to_vec();
    for pair in chars.chunks_exact(2) {
        let hi = decode_hex_nibble(pair[0])?;
        let lo = decode_hex_nibble(pair[1])?;
        bytes.push((hi << 4) | lo);
    }
    Ok(bytes)
}

fn decode_hex_nibble(byte: u8) -> Result<u8, String> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(format!("invalid hex character {:?}", byte as char)),
    }
}
