use std::env;
use std::fs;
use std::path::PathBuf;
use std::process::Command;

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
