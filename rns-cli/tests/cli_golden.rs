//! Byte-exact snapshot of the utilities' offline output: `--help`,
//! `--version`, an unknown option and argument errors that are reported
//! before any shared instance is contacted.
//!
//! The snapshot lives in tests/fixtures/cli_golden/<tool>.txt. To rewrite it
//! after an intended change, run with `RNS_GOLDEN_BLESS=1`:
//!
//!     RNS_GOLDEN_BLESS=1 cargo test -p rns-cli --test cli_golden
//!
//! Each run gets its own HOME and config directory, whose path is replaced
//! by `<TMP>` in the recorded output.

use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::process::Command;

struct Tool {
    name: &'static str,
    exe: &'static str,
    /// Extra invocations beyond `--help`, `--version` and an unknown option.
    cases: &'static [&'static [&'static str]],
}

const TOOLS: &[Tool] = &[
    Tool {
        name: "rnsd",
        exe: env!("CARGO_BIN_EXE_rnsd"),
        cases: &[],
    },
    Tool {
        name: "rnstatus",
        exe: env!("CARGO_BIN_EXE_rnstatus"),
        cases: &[],
    },
    Tool {
        name: "rnpath",
        exe: env!("CARGO_BIN_EXE_rnpath"),
        cases: &[],
    },
    Tool {
        name: "rnid",
        exe: env!("CARGO_BIN_EXE_rnid"),
        cases: &[&["-i", "/nonexistent/identity", "-p"]],
    },
    Tool {
        name: "rnprobe",
        exe: env!("CARGO_BIN_EXE_rnprobe"),
        cases: &[&["example.aspect", "zz"], &[]],
    },
    Tool {
        name: "rnsh",
        exe: env!("CARGO_BIN_EXE_rnsh"),
        cases: &[],
    },
    Tool {
        name: "rncp",
        exe: env!("CARGO_BIN_EXE_rncp"),
        cases: &[&["/nonexistent/file", "zz"]],
    },
    Tool {
        name: "rnx",
        exe: env!("CARGO_BIN_EXE_rnx"),
        cases: &[&["zz"]],
    },
    Tool {
        name: "rnir",
        exe: env!("CARGO_BIN_EXE_rnir"),
        cases: &[],
    },
    Tool {
        name: "rnpkg",
        exe: env!("CARGO_BIN_EXE_rnpkg"),
        cases: &[],
    },
];

fn golden_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../tests/fixtures/cli_golden")
}

fn run(tool: &Tool, args: &[&str]) -> String {
    let tmp = tempfile::tempdir().expect("tempdir");
    let home = tmp.path().join("home");
    let config = tmp.path().join("config");
    std::fs::create_dir_all(&home).expect("home dir");
    let mut argv: Vec<String> = vec!["--config".into(), config.display().to_string()];
    argv.extend(args.iter().map(|a| a.to_string()));
    let output = Command::new(tool.exe)
        .args(&argv)
        .env_clear()
        .env("HOME", &home)
        .env("PATH", "/usr/bin:/bin")
        .env("LANG", "C")
        .output()
        .unwrap_or_else(|e| panic!("run {}: {e}", tool.name));
    let tmp_path = tmp.path().display().to_string();
    let clean = |bytes: &[u8]| String::from_utf8_lossy(bytes).replace(&tmp_path, "<TMP>");
    let mut out = String::new();
    writeln!(out, "$ {} {}", tool.name, args.join(" ")).unwrap();
    writeln!(out, "exit: {:?}", output.status.code()).unwrap();
    writeln!(out, "--- stdout").unwrap();
    out.push_str(&clean(&output.stdout));
    writeln!(out, "--- stderr").unwrap();
    out.push_str(&clean(&output.stderr));
    writeln!(out, "--- end").unwrap();
    out
}

fn transcript(tool: &Tool) -> String {
    let mut all = String::new();
    let standard: [&[&str]; 3] = [&["--help"], &["--version"], &["--no-such-option"]];
    for args in standard.iter().chain(tool.cases.iter()) {
        all.push_str(&run(tool, args));
        all.push('\n');
    }
    all
}

#[test]
fn utilities_offline_output_matches_snapshot() {
    let bless = std::env::var_os("RNS_GOLDEN_BLESS").is_some();
    let dir = golden_dir();
    let mut failures = Vec::new();
    for tool in TOOLS {
        let actual = transcript(tool);
        let path = dir.join(format!("{}.txt", tool.name));
        if bless {
            std::fs::create_dir_all(&dir).expect("golden dir");
            std::fs::write(&path, &actual).expect("write golden");
            continue;
        }
        let expected = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
        if actual != expected {
            let line = expected
                .lines()
                .zip(actual.lines())
                .position(|(e, a)| e != a)
                .unwrap_or_else(|| expected.lines().count().min(actual.lines().count()));
            failures.push(format!(
                "{}: first difference at line {}\n  expected: {:?}\n  actual:   {:?}",
                tool.name,
                line + 1,
                expected.lines().nth(line).unwrap_or("<end>"),
                actual.lines().nth(line).unwrap_or("<end>"),
            ));
        }
    }
    assert!(
        failures.is_empty(),
        "output changed:\n{}",
        failures.join("\n")
    );
}
