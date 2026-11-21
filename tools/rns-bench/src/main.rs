//! Benchmark driver: runs scenarios between nodes and records what they
//! cost.

// A failed precondition aborts the measurement, which is what a benchmark
// run should do; the workspace lints against unwrap and expect are for
// shipped code.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "a benchmark run aborts on failure"
)]

#[cfg(feature = "allocation-profiler")]
mod allocations;
#[cfg(feature = "allocation-profiler")]
mod heap;
#[cfg(feature = "allocation-profiler")]
mod hotpath;
mod network;
mod participant;
mod probes;
mod profile;
mod protocol;
mod relay;
mod runner;
mod scenario;

use anyhow::{bail, Context, Result};
use std::path::{Path, PathBuf};

/// `value[key]`, as serde_json's indexing reads it: the field, or null when
/// it is missing or `value` is not an object.
pub(crate) fn json_field<'a>(value: &'a serde_json::Value, key: &str) -> &'a serde_json::Value {
    static NULL: serde_json::Value = serde_json::Value::Null;
    value.get(key).unwrap_or(&NULL)
}

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("workspace root")
}

fn main() {
    if let Err(e) = main_result() {
        eprintln!("rns-bench: {e:#}");
        std::process::exit(1);
    }
}
fn main_result() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let command = args.first().map(String::as_str).unwrap_or("help");
    if command == "allocations" {
        #[cfg(feature = "allocation-profiler")]
        {
            if args.get(1).map(String::as_str) == Some("--help") {
                println!("./scripts/bench-allocations [--output DIR] | report RUN_DIR\nRust-managed heap only; native malloc excluded; no timing results.");
                return Ok(());
            }
            if args.get(1).map(String::as_str) == Some("report") {
                let [_, _, dir] = args.as_slice() else {
                    bail!("allocations report RUN_DIR");
                };
                return allocations::report(Path::new(dir));
            }
            let output = match args.as_slice() {
                [_] => None,
                [_, flag, dir] if flag == "--output" => Some(PathBuf::from(dir)),
                _ => bail!("allocations [--output DIR] | allocations report RUN_DIR"),
            };
            return allocations::run(&root(), output);
        }
        #[cfg(not(feature = "allocation-profiler"))]
        bail!("use ./scripts/bench-allocations to build the allocation profiler");
    }
    if command == "hotpath" {
        #[cfg(feature = "allocation-profiler")]
        return hotpath::main(args.get(1..).unwrap_or_default());
        #[cfg(not(feature = "allocation-profiler"))]
        bail!("use ./scripts/hotpath to build the hot-path gate");
    }
    anyhow::ensure!(!cfg!(feature = "allocation-profiler") || matches!(command, "help" | "--help" | "doctor"),
        "allocation-instrumented executable cannot run timing workloads; rebuild with ./scripts/bench");
    if command == "native-workload" {
        let [_, family, compression, sdu, cycles] = args.as_slice() else {
            bail!("native-workload FAMILY COMPRESSION SDU CYCLES");
        };
        return profile::native_workload(
            family,
            compression.parse()?,
            sdu.parse()?,
            cycles.parse()?,
        );
    }
    if command == "cpu-workload" {
        let [_, family, compression, sdu, seconds] = args.as_slice() else {
            bail!("cpu-workload FAMILY COMPRESSION SDU SECONDS");
        };
        return profile::cpu_workload(family, compression.parse()?, sdu.parse()?, seconds.parse()?);
    }
    if command == "profile" {
        if args.get(1).map(String::as_str) == Some("report") {
            let [_, _, dir] = args.as_slice() else {
                bail!("profile report RUN_DIR");
            };
            return profile::report(Path::new(dir));
        }
        anyhow::ensure!(
            args.get(1).map(String::as_str) == Some("resources"),
            "profile resources [--output DIR]"
        );
        let output = match args.as_slice() {
            [_, _] => None,
            [_, _, flag, dir] if flag == "--output" => Some(PathBuf::from(dir)),
            _ => bail!("profile resources [--output DIR]"),
        };
        return profile::run(&root(), output);
    }
    if command == "participant" {
        let [_, role, port, case_file] = args.as_slice() else {
            bail!("participant ROLE PORT CASE_FILE");
        };
        let c = serde_json::from_slice(&std::fs::read(case_file)?)?;
        let result = if role == "relay" {
            relay::run(port.parse()?)
        } else {
            participant::run(role, port.parse()?, c)
        };
        if let Err(ref e) = result {
            let _ = protocol::write_json(
                &mut std::io::stdout(),
                &protocol::Message::Error {
                    message: format!("{e:#}"),
                },
            );
        }
        return result;
    }
    if command == "help" || command == "--help" {
        println!("rns-bench doctor | list | plan/run [--suite resource-transfer|resource-mixed] [--profile NAME] [--rate-bps BIT_PER_SECOND] [--output DIR] | report RUN_DIR\nProfiles: smoke, quick, mixed-smoke, mixed-quick\nAdd --relay for three-process forwarding; run accepts --relay-executable PATH to keep endpoints fixed.\nrns-bench profile resources [--output DIR] | profile report RUN_DIR\nRuns are exploratory; full qualification and baseline comparison are not implemented.");
        return Ok(());
    }
    if command == "doctor" {
        anyhow::ensure!(args.len() == 1, "doctor takes no options");
        println!(
            "{}",
            serde_json::to_string_pretty(&runner::environment(&root())?)?
        );
        return Ok(());
    }
    if command == "report" {
        let [_, dir] = args.as_slice() else {
            bail!("report RUN_DIR");
        };
        return runner::report(Path::new(dir));
    }
    if !matches!(command, "list" | "plan" | "run") {
        bail!("unknown command {command}");
    }
    if command == "list" && args.len() == 1 {
        println!("resource-transfer v2: verified Resources, including SHA-256-derived data\nresource-mixed v1: scheduled echoes on a separate link, with/without a Resource");
        return Ok(());
    }
    let mut profile = "smoke";
    let mut suite = "resource-transfer";
    let mut output = None;
    let mut rate_bps = None;
    let mut transport_relay = false;
    let mut relay_executable = None;
    let mut i = 1;
    while let Some(arg) = args.get(i) {
        if arg == "--relay" && matches!(command, "plan" | "run") {
            transport_relay = true;
            i += 1;
            continue;
        }
        let value = args.get(i + 1).context("option requires a value")?;
        match arg.as_str() {
            "--profile" if command != "list" => profile = value,
            "--suite" => suite = value,
            "--rate-bps" if command != "list" => rate_bps = Some(value.parse::<u64>()?),
            "--output" if command == "run" => output = Some(PathBuf::from(value)),
            "--relay-executable" if command == "run" => {
                relay_executable = Some(PathBuf::from(value));
                transport_relay = true;
            }
            other => bail!("unsupported option {other}"),
        }
        i += 2;
    }
    anyhow::ensure!(
        matches!(profile, "smoke" | "quick" | "mixed-smoke" | "mixed-quick"),
        "unsupported profile"
    );
    anyhow::ensure!(
        matches!(suite, "resource-transfer" | "resource-mixed"),
        "unsupported suite"
    );
    anyhow::ensure!(
        !(transport_relay && rate_bps.is_some()),
        "relay mode does not support synthetic rate limits"
    );
    let mut s: scenario::Scenario =
        scenario::read(&root().join(format!("bench/scenarios/{suite}.toml")))?;
    let p: scenario::Profile =
        scenario::read(&root().join(format!("bench/profiles/{profile}.toml")))?;
    let mut cases = scenario::expand(&s, &p)?;
    scenario::apply_rate(&mut cases, rate_bps)?;
    if transport_relay {
        s.topology = "three-process-rns-relay-v1".into();
        for c in &mut cases {
            c.id.push_str("-relay-v1");
        }
    }
    match command {
        "list" => println!(
            "{}: verified Resources; direct Rust APIs, two processes, loopback TCP",
            s.id
        ),
        "plan" => println!(
            "{}",
            serde_json::to_string_pretty(
                &serde_json::json!({"scenario":s,"profile":p,"cases":cases,"worst_case_operation_seconds":cases.iter().map(|c| (c.operations+c.warmup_operations) as u64*c.timeout_secs).sum::<u64>()})
            )?
        ),
        "run" => runner::run_with_relay(
            &root(),
            s,
            p,
            cases,
            output,
            transport_relay,
            relay_executable,
        )?,
        _ => unreachable!(),
    }
    Ok(())
}
