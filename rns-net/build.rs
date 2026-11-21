//! Build script: cfg aliases for interface feature sets, and the version
//! string with the commit it was built from.

use std::process::Command;

/// cfg aliases for feature sets that gate code in several places:
/// `(alias, features any of which enables it)`.
const CFG_ALIASES: &[(&str, &[&str])] = &[
    // Interfaces with runtime-configurable settings (driver/runtime_config).
    (
        "runtime_config_ifaces",
        &[
            "IFACE_TCP",
            "IFACE_UDP",
            "IFACE_AUTO",
            "IFACE_PIPE",
            "IFACE_RNODE",
            "IFACE_BACKBONE",
            "IFACE_I2P",
        ],
    ),
    // Interfaces that read frames with interface::stream_read.
    (
        "stream_read_ifaces",
        &[
            "IFACE_TCP",
            "IFACE_LOCAL",
            "IFACE_SERIAL",
            "IFACE_PIPE",
            "IFACE_BACKBONE",
            "IFACE_I2P",
        ],
    ),
    // Any built-in interface.
    (
        "any_iface",
        &[
            "IFACE_TCP",
            "IFACE_UDP",
            "IFACE_LOCAL",
            "IFACE_AUTO",
            "IFACE_SERIAL",
            "IFACE_KISS",
            "IFACE_AX25_KISS",
            "IFACE_PIPE",
            "IFACE_RNODE",
            "IFACE_BACKBONE",
            "IFACE_I2P",
            "IFACE_WEAVE",
        ],
    ),
];

fn main() {
    // The Weave interface exists on Linux only.
    let linux = std::env::var("CARGO_CFG_TARGET_OS").is_ok_and(|os| os == "linux");
    let enabled = |feature: &str| {
        std::env::var_os(format!("CARGO_FEATURE_{feature}")).is_some()
            && (feature != "IFACE_WEAVE" || linux)
    };
    for (alias, features) in CFG_ALIASES {
        println!("cargo::rustc-check-cfg=cfg({alias})");
        if features.iter().any(|feature| enabled(feature)) {
            println!("cargo::rustc-cfg={alias}");
        }
    }

    println!("cargo:rerun-if-changed=../.git/HEAD");
    println!("cargo:rerun-if-changed=../.git/refs");

    let pkg_version = env!("CARGO_PKG_VERSION");
    let parts: Vec<&str> = pkg_version.split('.').collect();
    let major = parts.first().unwrap_or(&"0");
    let minor = parts.get(1).unwrap_or(&"0");

    let commit_count = Command::new("git")
        .args(["rev-list", "--count", "HEAD"])
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| "0".to_string());

    let commit_hash = Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| "unknown".to_string());

    let version = format!("{}.{}.{}-{}", major, minor, commit_count, commit_hash);
    println!("cargo:rustc-env=FULL_VERSION={}", version);
}
