use std::env;
use std::path::{Path, PathBuf};
use std::process::Command;

#[path = "build_common.rs"]
mod build_common;

fn main() {
    build_common::emit_git_rerun_inputs();
    println!("cargo:rerun-if-changed=../rns-stats-hook/src/lib.rs");
    println!("cargo:rerun-if-changed=../rns-stats-hook/Cargo.toml");
    println!("cargo:rerun-if-changed=../rns-sentinel-hook/src/lib.rs");
    println!("cargo:rerun-if-changed=../rns-sentinel-hook/Cargo.toml");
    build_common::emit_full_version();

    if env::var_os("CARGO_FEATURE_RNS_HOOKS_WASM").is_some() {
        embed_stats_hook().expect("failed to build embedded stats hook");
        embed_sentinel_hook().expect("failed to build embedded sentinel hook");
    }
}

fn embed_stats_hook() -> anyhow::Result<()> {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR")?);
    let cargo = env::var("CARGO").unwrap_or_else(|_| "cargo".to_string());
    let profile = if env::var("PROFILE").unwrap_or_else(|_| "debug".to_string()) == "release" {
        "release"
    } else {
        "debug"
    };
    let hook_manifest = resolve_stats_hook_manifest(&manifest_dir, &cargo)?;

    let mut cmd = Command::new(cargo);
    let target_root = PathBuf::from(env::var("OUT_DIR")?).join("embedded-hook-target");
    cmd.arg("build")
        .arg("--manifest-path")
        .arg(&hook_manifest)
        .arg("--target")
        .arg("wasm32-unknown-unknown")
        .arg("--target-dir")
        .arg(&target_root);
    allow_undefined_wasm_imports(&mut cmd);
    if profile == "release" {
        cmd.arg("--release");
    }
    let status = cmd.status()?;
    if !status.success() {
        anyhow::bail!("stats hook build failed with status {}", status);
    }

    let wasm_path = target_root
        .join("wasm32-unknown-unknown")
        .join(profile)
        .join("rns_stats_hook.wasm");
    if !Path::new(&wasm_path).exists() {
        anyhow::bail!("expected embedded hook at {}", wasm_path.display());
    }

    println!(
        "cargo:rustc-env=RNS_STATSD_HOOK_WASM={}",
        wasm_path.display()
    );
    Ok(())
}

fn resolve_stats_hook_manifest(manifest_dir: &Path, cargo: &str) -> anyhow::Result<PathBuf> {
    let local = manifest_dir.join("../rns-stats-hook/Cargo.toml");
    if local.exists() {
        return Ok(local);
    }

    let output = Command::new(cargo)
        .args(["metadata", "--format-version", "1"])
        .current_dir(manifest_dir)
        .output()?;
    if !output.status.success() {
        anyhow::bail!("cargo metadata failed with status {}", output.status);
    }

    let value: serde_json::Value = serde_json::from_slice(&output.stdout)?;
    let packages = value
        .get("packages")
        .and_then(|v| v.as_array())
        .ok_or_else(|| anyhow::anyhow!("cargo metadata response missing packages"))?;

    let manifest = packages.iter().find_map(|pkg| {
        let name = pkg.get("name").and_then(|v| v.as_str())?;
        (name == "rns-stats-hook")
            .then(|| pkg.get("manifest_path").and_then(|v| v.as_str()))
            .flatten()
            .map(PathBuf::from)
    });

    manifest.ok_or_else(|| anyhow::anyhow!("could not locate rns-stats-hook manifest"))
}

fn embed_sentinel_hook() -> anyhow::Result<()> {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR")?);
    let cargo = env::var("CARGO").unwrap_or_else(|_| "cargo".to_string());
    let profile = if env::var("PROFILE").unwrap_or_else(|_| "debug".to_string()) == "release" {
        "release"
    } else {
        "debug"
    };
    let hook_manifest = resolve_sentinel_hook_manifest(&manifest_dir, &cargo)?;

    let mut cmd = Command::new(cargo);
    let target_root = PathBuf::from(env::var("OUT_DIR")?).join("embedded-sentinel-hook-target");
    cmd.arg("build")
        .arg("--manifest-path")
        .arg(&hook_manifest)
        .arg("--target")
        .arg("wasm32-unknown-unknown")
        .arg("--target-dir")
        .arg(&target_root);
    allow_undefined_wasm_imports(&mut cmd);
    if profile == "release" {
        cmd.arg("--release");
    }
    let status = cmd.status()?;
    if !status.success() {
        anyhow::bail!("sentinel hook build failed with status {}", status);
    }

    let wasm_path = target_root
        .join("wasm32-unknown-unknown")
        .join(profile)
        .join("rns_sentinel_hook.wasm");
    if !Path::new(&wasm_path).exists() {
        anyhow::bail!("expected embedded sentinel hook at {}", wasm_path.display());
    }

    println!(
        "cargo:rustc-env=RNS_SENTINEL_HOOK_WASM={}",
        wasm_path.display()
    );
    Ok(())
}

fn resolve_sentinel_hook_manifest(manifest_dir: &Path, cargo: &str) -> anyhow::Result<PathBuf> {
    let local = manifest_dir.join("../rns-sentinel-hook/Cargo.toml");
    if local.exists() {
        return Ok(local);
    }

    let output = Command::new(cargo)
        .args(["metadata", "--format-version", "1"])
        .current_dir(manifest_dir)
        .output()?;
    if !output.status.success() {
        anyhow::bail!("cargo metadata failed with status {}", output.status);
    }

    let value: serde_json::Value = serde_json::from_slice(&output.stdout)?;
    let packages = value
        .get("packages")
        .and_then(|v| v.as_array())
        .ok_or_else(|| anyhow::anyhow!("cargo metadata response missing packages"))?;

    let manifest = packages.iter().find_map(|pkg| {
        let name = pkg.get("name").and_then(|v| v.as_str())?;
        (name == "rns-sentinel-hook")
            .then(|| pkg.get("manifest_path").and_then(|v| v.as_str()))
            .flatten()
            .map(PathBuf::from)
    });

    manifest.ok_or_else(|| anyhow::anyhow!("could not locate rns-sentinel-hook manifest"))
}
fn allow_undefined_wasm_imports(cmd: &mut Command) {
    if let Ok(mut encoded_flags) = env::var("CARGO_ENCODED_RUSTFLAGS") {
        if !encoded_flags.is_empty() {
            encoded_flags.push('\x1f');
            encoded_flags.push_str("-Clink-arg=--allow-undefined");
            cmd.env("CARGO_ENCODED_RUSTFLAGS", encoded_flags);
            return;
        }
    }

    let rustflags = env::var("RUSTFLAGS")
        .map(|flags| format!("{flags} -C link-arg=--allow-undefined"))
        .unwrap_or_else(|_| "-C link-arg=--allow-undefined".to_string());
    cmd.env_remove("CARGO_ENCODED_RUSTFLAGS");
    cmd.env("RUSTFLAGS", rustflags);
}
