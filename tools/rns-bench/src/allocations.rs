//! Allocation-only observations of the shared verified Resource driver.
use crate::{
    heap::{Snapshot, COUNTERS},
    profile, runner,
};
use anyhow::{ensure, Context, Result};
use serde::{Deserialize, Serialize};
use std::{
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

const PHASES: [&str; 6] = [
    "start",
    "sender-prepared",
    "receiver-ready",
    "parts-delivered",
    "settled",
    "cleaned-up",
];
const SIZES: [usize; 3] = [4096, 1048576, 2097152];
const SDUS: [usize; 2] = [464, 16348];
const FAMILIES: [&str; 3] = ["repeated", "seeded", "sha256-counter"];
const REPETITIONS: usize = 3;
const EXPECTED: usize = SIZES.len() * SDUS.len() * FAMILIES.len() * 2 * REPETITIONS;

#[derive(Serialize, Deserialize)]
struct Sample {
    family: String,
    payload_bytes: usize,
    compression: bool,
    compression_used: bool,
    sdu: usize,
    repetition: usize,
    points: [Snapshot; 6],
}

fn capture(
    data: &[u8],
    family: &str,
    compression: bool,
    sdu: usize,
    repetition: usize,
) -> Result<Sample> {
    // Callback storage is stack-only: recording must not allocate inside the window.
    let mut points = [Snapshot::default(); 6];
    let mut index = 0;
    let result =
        profile::cycle_observed(data, family, compression, sdu, repetition, &mut |phase| {
            assert_eq!(phase, PHASES[index]);
            if index == 0 {
                COUNTERS.reset_peak();
            }
            points[index] = COUNTERS.snapshot();
            index += 1;
        })?;
    ensure!(index == PHASES.len(), "incomplete allocation checkpoints");
    let sample = Sample {
        family: family.into(),
        payload_bytes: data.len(),
        compression,
        compression_used: result.compression_used,
        sdu,
        repetition,
        points,
    };
    validate(&sample)?;
    Ok(sample)
}

fn validate(s: &Sample) -> Result<()> {
    ensure!(
        FAMILIES.contains(&s.family.as_str())
            && SIZES.contains(&s.payload_bytes)
            && SDUS.contains(&s.sdu)
            && s.repetition < REPETITIONS,
        "unknown allocation cell"
    );
    ensure!(
        s.compression || !s.compression_used,
        "compression used when disabled"
    );
    let base = s.points[0];
    ensure!(
        base.peak_live_bytes == base.live_bytes,
        "peak not reset at measurement start"
    );
    for pair in s.points.windows(2) {
        let (a, b) = (pair[0], pair[1]);
        ensure!(
            b.allocation_calls >= a.allocation_calls
                && b.reallocation_calls >= a.reallocation_calls
                && b.allocated_bytes >= a.allocated_bytes
                && b.freed_bytes >= a.freed_bytes
                && b.peak_live_bytes >= a.peak_live_bytes
                && b.peak_live_bytes >= b.live_bytes,
            "nonmonotonic allocation counters"
        );
        ensure!(
            b.live_bytes as i128 - a.live_bytes as i128
                == (b.allocated_bytes - a.allocated_bytes) as i128
                    - (b.freed_bytes - a.freed_bytes) as i128,
            "inconsistent live allocation accounting"
        );
    }
    ensure!(
        s.points[4].allocation_calls > base.allocation_calls,
        "empty allocation workload"
    );
    Ok(())
}

pub fn run(root: &Path, requested: Option<PathBuf>) -> Result<()> {
    ensure!(
        !cfg!(debug_assertions),
        "allocation profiling requires a release build"
    );
    let dir = requested.unwrap_or_else(|| {
        root.join("target/bench-results").join(format!(
            "resource-allocations-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ))
    });
    if let Some(parent) = dir.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::create_dir(&dir).context("output directory must not already exist")?;
    runner::atomic_json(
        &dir.join("status.json"),
        &serde_json::json!({"status":"interrupted"}),
    )?;
    runner::atomic_json(
        &dir.join("manifest.json"),
        &serde_json::json!({
            "schema_version":1,"allocation_profile_version":1,"environment":runner::environment(root)?,
            "instrumentation":"Rust GlobalAlloc delegating to System; allocation-profiler feature",
            "sizes":SIZES,"sdus":SDUS,"families":FAMILIES,"repetitions":REPETITIONS,"expected_samples":EXPECTED,
            "warmups_per_cell":1,"phases":PHASES,"seed":87123,
            "boundaries":"single-threaded verified core Resource cycle; setup fixtures/key/expected digest excluded; sender/receiver/queue/advertisement teardown included; CPU/RSS polling and JSON reporting excluded",
            "limitations":"Rust requested sizes only, NOT total process heap: native bzip2 malloc, allocator bookkeeping/reserved pages and realloc internal overlap excluded; no timing claims; peak is logical live bytes; post-cleanup delta is not a leak verdict"
        }),
    )?;
    std::fs::copy(std::env::current_exe()?, dir.join("profiler.bin"))?;
    let mut samples = Vec::with_capacity(EXPECTED);
    runner::atomic_json(&dir.join("samples.json"), &samples)?;
    println!("Allocation artifacts: {}", dir.display());
    let result = (|| -> Result<()> {
        for family in FAMILIES {
            for bytes in SIZES {
                let data = profile::payload(family, bytes);
                for sdu in SDUS {
                    for compression in [false, true] {
                        profile::cycle_observed(&data, family, compression, sdu, 0, &mut |_| {})?;
                    }
                    for rep in 0..REPETITIONS {
                        for compression in if rep % 2 == 0 {
                            [false, true]
                        } else {
                            [true, false]
                        } {
                            samples.push(capture(&data, family, compression, sdu, rep)?);
                            runner::atomic_json(&dir.join("samples.json"), &samples)?;
                        }
                    }
                    println!("Verified {family}, {bytes} B, SDU {sdu}");
                }
            }
        }
        Ok(())
    })();
    match result {
        Ok(()) => runner::atomic_json(
            &dir.join("status.json"),
            &serde_json::json!({"status":"complete","verified_samples":samples.len()}),
        )?,
        Err(e) => {
            runner::atomic_json(
                &dir.join("status.json"),
                &serde_json::json!({"status":"failed","verified_samples":samples.len(),"error":format!("{e:#}")}),
            )?;
            report(&dir)?;
            return Err(e);
        }
    }
    report(&dir)
}

pub fn report(dir: &Path) -> Result<()> {
    let manifest: serde_json::Value =
        serde_json::from_slice(&std::fs::read(dir.join("manifest.json"))?)?;
    ensure!(
        manifest["schema_version"] == 1
            && manifest["allocation_profile_version"] == 1
            && manifest["expected_samples"] == EXPECTED,
        "unsupported allocation profile"
    );
    let status: serde_json::Value =
        serde_json::from_slice(&std::fs::read(dir.join("status.json"))?)?;
    let samples: Vec<Sample> = serde_json::from_slice(&std::fs::read(dir.join("samples.json"))?)?;
    let mut ids = std::collections::BTreeSet::new();
    for s in &samples {
        validate(s)?;
        ensure!(
            ids.insert((
                &s.family,
                s.payload_bytes,
                s.sdu,
                s.compression,
                s.repetition
            )),
            "duplicate allocation sample"
        );
    }
    let complete = status["status"] == "complete"
        && status["verified_samples"] == samples.len()
        && samples.len() == EXPECTED;
    let mut text = format!("Resource Rust-heap allocation profile\nStatus: {} (recorded: {})\nVerified samples: {}/{}\nRust requested bytes ONLY; native bzip2 malloc and allocator overhead excluded. No timing measurements.\nPeak/live deltas relative to prepared-fixture baseline; retained delta is not a leak verdict.\n\nfamily | payload B | SDU | compression | n | alloc calls | realloc calls | allocated B | peak growth B | retained delta B\n", if complete {"complete"} else {"INCOMPLETE OR FAILED"}, status["status"], samples.len(), EXPECTED);
    if let Some(error) = status["error"].as_str() {
        text.push_str(&format!("Failure: {error}\n"));
    }
    for family in FAMILIES {
        for bytes in SIZES {
            for sdu in SDUS {
                for compression in [false, true] {
                    let rows: Vec<_> = samples
                        .iter()
                        .filter(|s| {
                            s.family == family
                                && s.payload_bytes == bytes
                                && s.sdu == sdu
                                && s.compression == compression
                        })
                        .collect();
                    if rows.is_empty() {
                        text.push_str(&format!(
                            "{family} | {bytes} | {sdu} | {compression} | MISSING\n"
                        ));
                        continue;
                    }
                    let median = |metric: fn(&Sample) -> i128| {
                        let mut values: Vec<_> = rows.iter().map(|s| metric(s)).collect();
                        values.sort_unstable();
                        values[values.len() / 2]
                    };
                    text.push_str(&format!("{family} | {bytes} | {sdu} | {compression} | {} | {} | {} | {} | {} | {}\n", rows.len(),
            median(|s| (s.points[5].allocation_calls-s.points[0].allocation_calls) as i128),
            median(|s| (s.points[5].reallocation_calls-s.points[0].reallocation_calls) as i128),
            median(|s| (s.points[5].allocated_bytes-s.points[0].allocated_bytes) as i128),
            median(|s| (s.points[5].peak_live_bytes-s.points[0].live_bytes) as i128),
            median(|s| s.points[5].live_bytes as i128-s.points[0].live_bytes as i128)));
                    for (i, phase) in PHASES.iter().enumerate().skip(1) {
                        let mut volumes: Vec<_> = rows
                            .iter()
                            .map(|s| s.points[i].allocated_bytes - s.points[i - 1].allocated_bytes)
                            .collect();
                        volumes.sort_unstable();
                        let mut lives: Vec<_> = rows
                            .iter()
                            .map(|s| {
                                s.points[i].live_bytes as i128 - s.points[0].live_bytes as i128
                            })
                            .collect();
                        lives.sort_unstable();
                        text.push_str(&format!(
                            "  {}: allocated={} B; live delta={} B (medians)\n",
                            phase,
                            volumes[volumes.len() / 2],
                            lives[lives.len() / 2]
                        ));
                    }
                }
            }
        }
    }
    std::fs::write(dir.join("report.txt.tmp"), &text)?;
    std::fs::rename(dir.join("report.txt.tmp"), dir.join("report.txt"))?;
    print!("{text}");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn sample() -> Sample {
        let values = [
            (1, 0, 100, 0, 100, 100),
            (2, 0, 140, 0, 140, 140),
            (3, 0, 160, 0, 160, 160),
            (3, 1, 240, 40, 200, 200),
            (3, 1, 240, 120, 120, 200),
            (3, 1, 240, 140, 100, 200),
        ];
        Sample {
            family: "repeated".into(),
            payload_bytes: 4096,
            compression: false,
            compression_used: false,
            sdu: 464,
            repetition: 0,
            points: values.map(
                |(
                    allocation_calls,
                    reallocation_calls,
                    allocated_bytes,
                    freed_bytes,
                    live_bytes,
                    peak_live_bytes,
                )| Snapshot {
                    allocation_calls,
                    reallocation_calls,
                    allocated_bytes,
                    freed_bytes,
                    live_bytes,
                    peak_live_bytes,
                },
            ),
        }
    }
    #[test]
    fn accounting_rejects_inconsistent_counters_but_preserves_retention() {
        let mut s = sample();
        validate(&s).unwrap();
        s.points[5] = s.points[4]; // Deliberately retained bytes are evidence, not corruption.
        validate(&s).unwrap();
        s.points[3].freed_bytes += 1;
        assert!(validate(&s).is_err());
        let mut s = sample();
        s.points[0].peak_live_bytes += 1;
        assert!(validate(&s).is_err());
    }
    #[test]
    fn report_marks_missing_cells_and_rejects_duplicate_samples() {
        let dir = tempfile::tempdir().unwrap();
        runner::atomic_json(&dir.path().join("manifest.json"), &serde_json::json!({"schema_version":1,"allocation_profile_version":1,"expected_samples":EXPECTED})).unwrap();
        runner::atomic_json(
            &dir.path().join("status.json"),
            &serde_json::json!({"status":"complete","verified_samples":1}),
        )
        .unwrap();
        runner::atomic_json(&dir.path().join("samples.json"), &vec![sample()]).unwrap();
        report(dir.path()).unwrap();
        let text = std::fs::read_to_string(dir.path().join("report.txt")).unwrap();
        assert!(text.contains("INCOMPLETE OR FAILED") && text.contains("MISSING"));
        runner::atomic_json(&dir.path().join("samples.json"), &vec![sample(), sample()]).unwrap();
        assert!(report(dir.path()).is_err());
    }
}
