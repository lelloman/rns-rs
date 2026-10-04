#[cfg(feature = "allocation-profiler")]
mod allocations;
#[cfg(feature = "allocation-profiler")]
mod heap;
mod network;
mod participant;
mod probes;
mod profile;
mod protocol;
mod runner;
mod scenario;

use anyhow::{bail, Context, Result};
use std::path::{Path, PathBuf};

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
                anyhow::ensure!(args.len() == 3, "allocations report RUN_DIR");
                return allocations::report(Path::new(&args[2]));
            }
            let output = match args.len() {
                1 => None,
                3 if args[1] == "--output" => Some(PathBuf::from(&args[2])),
                _ => bail!("allocations [--output DIR] | allocations report RUN_DIR"),
            };
            return allocations::run(&root(), output);
        }
        #[cfg(not(feature = "allocation-profiler"))]
        bail!("use ./scripts/bench-allocations to build the allocation profiler");
    }
    anyhow::ensure!(!cfg!(feature = "allocation-profiler") || matches!(command, "help" | "--help" | "doctor"),
        "allocation-instrumented executable cannot run timing workloads; rebuild with ./scripts/bench");
    if command == "native-workload" {
        anyhow::ensure!(
            args.len() == 5,
            "native-workload FAMILY COMPRESSION SDU CYCLES"
        );
        return profile::native_workload(
            &args[1],
            args[2].parse()?,
            args[3].parse()?,
            args[4].parse()?,
        );
    }
    if command == "cpu-workload" {
        anyhow::ensure!(
            args.len() == 5,
            "cpu-workload FAMILY COMPRESSION SDU SECONDS"
        );
        return profile::cpu_workload(
            &args[1],
            args[2].parse()?,
            args[3].parse()?,
            args[4].parse()?,
        );
    }
    if command == "profile" {
        if args.get(1).map(String::as_str) == Some("report") {
            anyhow::ensure!(args.len() == 3, "profile report RUN_DIR");
            return profile::report(Path::new(&args[2]));
        }
        anyhow::ensure!(
            args.get(1).map(String::as_str) == Some("resources"),
            "profile resources [--output DIR]"
        );
        let output = match args.len() {
            2 => None,
            4 if args[2] == "--output" => Some(PathBuf::from(&args[3])),
            _ => bail!("profile resources [--output DIR]"),
        };
        return profile::run(&root(), output);
    }
    if command == "participant" {
        anyhow::ensure!(args.len() == 4, "participant ROLE PORT CASE_FILE");
        let c = serde_json::from_slice(&std::fs::read(&args[3])?)?;
        let result = participant::run(&args[1], args[2].parse()?, c);
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
        println!("rns-bench doctor | list | plan/run [--suite resource-transfer|resource-mixed] [--profile NAME] [--rate-bps BIT_PER_SECOND] [--output DIR] | report RUN_DIR\nProfiles: smoke, quick, mixed-smoke, mixed-quick\nrns-bench profile resources [--output DIR] | profile report RUN_DIR\nRuns are exploratory; full qualification and baseline comparison are not implemented.");
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
        anyhow::ensure!(args.len() == 2, "report RUN_DIR");
        return runner::report(Path::new(&args[1]));
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
    let mut i = 1;
    while i < args.len() {
        let value = args.get(i + 1).context("option requires a value")?;
        match args[i].as_str() {
            "--profile" if command != "list" => profile = value,
            "--suite" => suite = value,
            "--rate-bps" if command != "list" => rate_bps = Some(value.parse::<u64>()?),
            "--output" if command == "run" => output = Some(PathBuf::from(value)),
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
    let s: scenario::Scenario =
        scenario::read(&root().join(format!("bench/scenarios/{suite}.toml")))?;
    let p: scenario::Profile =
        scenario::read(&root().join(format!("bench/profiles/{profile}.toml")))?;
    let mut cases = scenario::expand(&s, &p)?;
    scenario::apply_rate(&mut cases, rate_bps)?;
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
        "run" => runner::run(&root(), s, p, cases, output)?,
        _ => unreachable!(),
    }
    Ok(())
}
