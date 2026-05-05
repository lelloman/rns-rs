use std::process::Command;

pub fn emit_git_rerun_inputs() {
    println!("cargo:rerun-if-changed=../.git/HEAD");
    println!("cargo:rerun-if-changed=../.git/refs");
}

pub fn emit_full_version() {
    let pkg_version = env!("CARGO_PKG_VERSION");
    let parts: Vec<&str> = pkg_version.split('.').collect();
    let major = parts.first().unwrap_or(&"0");
    let minor = parts.get(1).unwrap_or(&"0");

    let commit_count = git_stdout(["rev-list", "--count", "HEAD"]).unwrap_or_else(|| "0".into());
    let commit_hash =
        git_stdout(["rev-parse", "--short", "HEAD"]).unwrap_or_else(|| "unknown".into());

    let version = format!("{}.{}.{}-{}", major, minor, commit_count, commit_hash);
    println!("cargo:rustc-env=FULL_VERSION={}", version);
}

fn git_stdout<const N: usize>(args: [&str; N]) -> Option<String> {
    Command::new("git")
        .args(args)
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
}
