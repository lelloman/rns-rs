mod participant;
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
        println!("rns-bench doctor | list | plan/run [--profile smoke|quick] [--output DIR] | report RUN_DIR\nRuns are exploratory; full qualification and baseline comparison are not implemented.");
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
    let mut profile = "smoke";
    let mut output = None;
    let mut i = 1;
    while i < args.len() {
        let value = args.get(i + 1).context("option requires a value")?;
        match args[i].as_str() {
            "--profile" if command != "list" => profile = value,
            "--output" if command == "run" => output = Some(PathBuf::from(value)),
            other => bail!("unsupported option {other}"),
        }
        i += 2;
    }
    anyhow::ensure!(
        matches!(profile, "smoke" | "quick"),
        "only smoke and quick are implemented"
    );
    let s: scenario::Scenario =
        scenario::read(&root().join("bench/scenarios/resource-transfer.toml"))?;
    let p: scenario::Profile =
        scenario::read(&root().join(format!("bench/profiles/{profile}.toml")))?;
    let cases = scenario::expand(&s, &p)?;
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
