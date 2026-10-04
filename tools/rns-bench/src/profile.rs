//! Stage instrumentation of real Resource state machines, without sockets.
use crate::{
    runner,
    scenario::{self, Case, Payload},
};
use anyhow::{bail, ensure, Result};
use rns_core::{
    buffer::types::{Compressor, DecompressError},
    resource::{ResourceAction, ResourceReceiver, ResourceSender, ResourceStatus},
};
use rns_crypto::{sha256::sha256, token::Token, OsRng, Rng};
use rns_net::compressor::Bzip2Compressor;
use serde::{Deserialize, Serialize};
use std::{
    cell::{Cell, RefCell},
    collections::VecDeque,
    path::{Path, PathBuf},
    time::{Instant, SystemTime, UNIX_EPOCH},
};

#[derive(Default)]
struct TimedCompressor {
    compress_ns: Cell<u64>,
    decompress_ns: Cell<u64>,
    input_bytes: Cell<usize>,
    output_bytes: Cell<Option<usize>>,
}
fn elapsed(start: Instant) -> u64 {
    start
        .elapsed()
        .as_nanos()
        .try_into()
        .expect("profile duration fits u64")
}
impl Compressor for TimedCompressor {
    fn compress(&self, data: &[u8]) -> Option<Vec<u8>> {
        let start = Instant::now();
        let result = Bzip2Compressor.compress(data);
        self.compress_ns
            .set(self.compress_ns.get() + elapsed(start));
        self.input_bytes.set(data.len());
        self.output_bytes.set(result.as_ref().map(Vec::len));
        result
    }
    fn decompress_bounded(&self, data: &[u8], limit: usize) -> Result<Vec<u8>, DecompressError> {
        let start = Instant::now();
        let result = Bzip2Compressor.decompress_bounded(data, limit);
        self.decompress_ns
            .set(self.decompress_ns.get() + elapsed(start));
        result
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct Sample {
    family: String,
    compression: bool,
    sdu: usize,
    repetition: usize,
    payload_bytes: usize,
    compressed_input_bytes: usize,
    compressed_output_bytes: Option<usize>,
    compression_used: bool,
    encrypted_transfer_bytes: usize,
    parts: usize,
    requests: usize,
    hashmap_updates: usize,
    total_ns: u64,
    sender_prepare_ns: u64,
    compression_ns: u64,
    encryption_ns: u64,
    receiver_setup_ns: u64,
    sender_serve_ns: u64,
    receiver_ingest_ns: u64,
    receiver_assemble_ns: u64,
    decryption_ns: u64,
    decompression_ns: u64,
    application_verify_ns: u64,
    proof_settlement_ns: u64,
    cpu_seconds: f64,
}

fn payload(family: &str, bytes: usize) -> Vec<u8> {
    scenario::payload(&Case {
        rate_bps: None,
        id: "profile".into(),
        payload: match family {
            "repeated" => Payload::Repeated,
            "seeded" => Payload::Seeded,
            "sha256-counter" => Payload::Sha256Counter,
            _ => unreachable!("profile family is fixed by the manifest"),
        },
        bytes,
        compression: false,
        seed: 87123,
        repetition: 0,
        operations: 1,
        warmup_operations: 0,
        timeout_secs: 30,
        probes: None,
        background: true,
    })
}

fn cycle(
    data: &[u8],
    family: &str,
    compression: bool,
    sdu: usize,
    repetition: usize,
) -> Result<Sample> {
    let compressor = TimedCompressor::default();
    let encryption_ns = Cell::new(0);
    let decryption_ns = Cell::new(0);
    let rng = RefCell::new(OsRng);
    let mut key = [0u8; 64];
    OsRng.fill_bytes(&mut key);
    let token = Token::new(&key).map_err(|e| anyhow::anyhow!("{e}"))?;
    let encrypt = |plain: &[u8]| {
        let t = Instant::now();
        let v = token.encrypt(plain, &mut *rng.borrow_mut());
        encryption_ns.set(encryption_ns.get() + elapsed(t));
        v
    };
    let decrypt = |cipher: &[u8]| {
        let t = Instant::now();
        let v = token.decrypt(cipher).map_err(|_| ());
        decryption_ns.set(decryption_ns.get() + elapsed(t));
        v
    };
    let expected = sha256(data);
    let metadata = 0u64.to_le_bytes();
    let cpu_before = crate::protocol::metrics()?;
    let total = Instant::now();
    let t = Instant::now();
    let mut sender = ResourceSender::new(
        data,
        Some(&metadata),
        sdu,
        &encrypt,
        &compressor,
        &mut OsRng,
        1.0,
        compression,
        false,
        None,
        1,
        1,
        None,
        0.01,
        6.0,
    )
    .map_err(|e| anyhow::anyhow!("sender: {e}"))?;
    let sender_prepare_ns = elapsed(t);
    let t = Instant::now();
    let adv = sender
        .advertise(1.0)
        .into_iter()
        .find_map(|a| {
            if let ResourceAction::SendAdvertisement(v) = a {
                Some(v)
            } else {
                None
            }
        })
        .ok_or_else(|| anyhow::anyhow!("missing advertisement"))?;
    let mut receiver = ResourceReceiver::from_advertisement(&adv, sdu, 0.01, 1.0, None, None)
        .map_err(|e| anyhow::anyhow!("receiver: {e}"))?;
    let mut queue: VecDeque<_> = receiver.accept(1.0).into();
    let receiver_setup_ns = elapsed(t);
    let mut sender_serve_ns = 0;
    let mut receiver_ingest_ns = 0;
    let mut requests = 0;
    let mut parts = 0;
    let mut hashmap_updates = 0;
    let mut steps = 0;
    while let Some(action) = queue.pop_front() {
        steps += 1;
        ensure!(
            steps < 100000 && total.elapsed().as_secs() < 30,
            "profile driver budget exceeded"
        );
        // Virtual protocol timestamps drive window progression, never wall-clock metrics.
        let now = 1.0 + steps as f64 * 0.00001;
        match action {
            ResourceAction::SendRequest(v) => {
                requests += 1;
                let t = Instant::now();
                let a = sender.handle_request(&v, now);
                sender_serve_ns += elapsed(t);
                queue.extend(a);
            }
            ResourceAction::SendPart(v) => {
                parts += 1;
                let t = Instant::now();
                let a = receiver.receive_part(&v, now);
                receiver_ingest_ns += elapsed(t);
                queue.extend(a);
            }
            ResourceAction::SendHmu(v) => {
                hashmap_updates += 1;
                let t = Instant::now();
                let a = receiver.handle_hashmap_update(&v, now);
                receiver_ingest_ns += elapsed(t);
                queue.extend(a);
            }
            ResourceAction::ProgressUpdate { .. } => {}
            other => bail!("unexpected transfer action: {other:?}"),
        }
    }
    let (received, expected_parts) = receiver.progress();
    ensure!(
        received == expected_parts && received > 0 && parts == sender.total_parts(),
        "incomplete/duplicate part delivery"
    );
    let t = Instant::now();
    let actions = receiver.assemble(&decrypt, &compressor);
    let receiver_assemble_ns = elapsed(t);
    let mut verified = false;
    let mut proved = false;
    let mut receiver_completed = false;
    let mut application_verify_ns = 0;
    let mut proof_settlement_ns = 0;
    for action in actions {
        match action {
            ResourceAction::SendProof(v) => {
                let t = Instant::now();
                let a = sender.handle_proof(&v, 2.0);
                proof_settlement_ns += elapsed(t);
                ensure!(
                    !proved && a == vec![ResourceAction::Completed],
                    "proof not settled exactly once"
                );
                proved = true;
            }
            ResourceAction::DataReceived {
                data: got,
                metadata: meta,
            } => {
                let t = Instant::now();
                ensure!(
                    !verified
                        && got.len() == data.len()
                        && sha256(&got) == expected
                        && meta.as_deref() == Some(metadata.as_slice()),
                    "corrupt/duplicate application delivery"
                );
                application_verify_ns += elapsed(t);
                verified = true;
            }
            ResourceAction::Completed => {
                ensure!(!receiver_completed, "duplicate receiver completion");
                receiver_completed = true;
            }
            other => bail!("assembly failed: {other:?}"),
        }
    }
    ensure!(
        verified && proved && receiver_completed && sender.status == ResourceStatus::Complete,
        "incomplete profile cycle"
    );
    let total_ns = elapsed(total);
    let cpu_after = crate::protocol::metrics()?;
    Ok(Sample {
        family: family.into(),
        compression,
        sdu,
        repetition,
        payload_bytes: data.len(),
        compressed_input_bytes: compressor.input_bytes.get(),
        compressed_output_bytes: compressor.output_bytes.get(),
        compression_used: sender.flags.compressed,
        encrypted_transfer_bytes: sender.transfer_size,
        parts,
        requests,
        hashmap_updates,
        total_ns,
        sender_prepare_ns,
        compression_ns: compressor.compress_ns.get(),
        encryption_ns: encryption_ns.get(),
        receiver_setup_ns,
        sender_serve_ns,
        receiver_ingest_ns,
        receiver_assemble_ns,
        decryption_ns: decryption_ns.get(),
        decompression_ns: compressor.decompress_ns.get(),
        application_verify_ns,
        proof_settlement_ns,
        cpu_seconds: cpu_after.user_cpu_seconds + cpu_after.system_cpu_seconds
            - cpu_before.user_cpu_seconds
            - cpu_before.system_cpu_seconds,
    })
}

pub fn run(root: &Path, output: Option<PathBuf>) -> Result<()> {
    ensure!(!cfg!(debug_assertions), "profiling requires release build");
    let dir = output.unwrap_or_else(|| {
        root.join("target/bench-results").join(format!(
            "resource-profile-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ))
    });
    if let Some(parent) = dir.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::create_dir(&dir)?;
    runner::atomic_json(
        &dir.join("status.json"),
        &serde_json::json!({"status":"interrupted"}),
    )?;
    runner::atomic_json(
        &dir.join("manifest.json"),
        &serde_json::json!({"schema_version":1,"profile_version":1,"environment":runner::environment(root)?,"payload_bytes":1048576,"seed":87123,"repetitions":5,"warmups_per_cell":1,"sdus":[464,16348],"families":["repeated","seeded","sha256-counter"],"crypto":"AES256 Token, fresh OS key per cycle; no link handshake","boundaries":"real Resource state machines, no sockets or LinkManager; wall-clock stage timers; virtual protocol timestamps; excludes payload generation, key setup and sender/receiver teardown; nested crypto/compression timers are subsets, not additive"}),
    )?;
    println!("Profile artifacts: {}", dir.display());
    let mut samples = Vec::new();
    let result = (|| -> Result<()> {
        for family in ["repeated", "seeded", "sha256-counter"] {
            let data = payload(family, 1048576);
            for sdu in [464, 16348] {
                // Warm both settings; alternate order across repetitions.
                for compress in [false, true] {
                    cycle(&data, family, compress, sdu, usize::MAX)?;
                }
                for rep in 0..5 {
                    for compress in if rep % 2 == 0 {
                        [false, true]
                    } else {
                        [true, false]
                    } {
                        samples.push(cycle(&data, family, compress, sdu, rep)?);
                        runner::atomic_json(&dir.join("samples.json"), &samples)?;
                    }
                }
                println!("Verified {family}, SDU {sdu}");
            }
        }
        Ok(())
    })();
    if let Err(e) = result {
        runner::atomic_json(
            &dir.join("status.json"),
            &serde_json::json!({"status":"failed","error":format!("{e:#}"),"verified_samples":samples.len()}),
        )?;
        return Err(e);
    }
    runner::atomic_json(
        &dir.join("status.json"),
        &serde_json::json!({"status":"complete","verified_samples":samples.len()}),
    )?;
    report(&dir)
}

pub fn report(dir: &Path) -> Result<()> {
    let manifest: serde_json::Value =
        serde_json::from_slice(&std::fs::read(dir.join("manifest.json"))?)?;
    ensure!(
        manifest["schema_version"] == 1 && manifest["profile_version"] == 1,
        "unsupported profile evidence"
    );
    let status: serde_json::Value =
        serde_json::from_slice(&std::fs::read(dir.join("status.json"))?)?;
    let samples: Vec<Sample> = serde_json::from_slice(&std::fs::read(dir.join("samples.json"))?)?;
    ensure!(
        samples.iter().all(|r| matches!(
            r.family.as_str(),
            "repeated" | "seeded" | "sha256-counter"
        ) && matches!(r.sdu, 464 | 16348)),
        "unknown profile cell"
    );
    let mut text=format!("Resource stage profile\nRecorded status: {}\nVerified samples retained: {}\nTimes below are per-configuration medians in milliseconds.\nCompression/encryption are INCLUDED in preparation; decompression/decryption are INCLUDED in assembly.\nCore state-machine cycles; not live-link latency. No call-stack or allocation sampling.\n\nfamily | SDU | compression | n | total | prepare | compress | encrypt | serve | ingest | assemble | decompress | decrypt | verify\n",status["status"],samples.len());
    for family in ["repeated", "seeded", "sha256-counter"] {
        for sdu in [464, 16348] {
            for compression in [false, true] {
                let rows: Vec<_> = samples
                    .iter()
                    .filter(|s| s.family == family && s.sdu == sdu && s.compression == compression)
                    .collect();
                if rows.is_empty() {
                    text.push_str(&format!("{family} | {sdu} | {compression} | MISSING\n"));
                    continue;
                }
                let mut reps = std::collections::BTreeSet::new();
                ensure!(
                    rows.iter().all(|r| r.repetition < 5
                        && reps.insert(r.repetition)
                        && r.payload_bytes == 1048576
                        && r.total_ns > 0),
                    "invalid/duplicate profile samples"
                );
                let med = |f: fn(&Sample) -> u64| {
                    let mut v: Vec<_> = rows.iter().map(|r| f(r)).collect();
                    v.sort_unstable();
                    v[v.len() / 2] as f64 / 1e6
                };
                text.push_str(&format!("{family} | {sdu} | {compression} | {} | {:.3} | {:.3} | {:.3} | {:.3} | {:.3} | {:.3} | {:.3} | {:.3} | {:.3} | {:.3}\n",rows.len(),med(|r|r.total_ns),med(|r|r.sender_prepare_ns),med(|r|r.compression_ns),med(|r|r.encryption_ns),med(|r|r.sender_serve_ns),med(|r|r.receiver_ingest_ns),med(|r|r.receiver_assemble_ns),med(|r|r.decompression_ns),med(|r|r.decryption_ns),med(|r|r.application_verify_ns)));
                let first = rows[0];
                text.push_str(&format!("  compression accepted: {}; candidate bytes: {:?} / {}; encrypted Resource bytes: {}; parts: {}; total range: {:.3}..{:.3} ms\n",first.compression_used,first.compressed_output_bytes,first.compressed_input_bytes,first.encrypted_transfer_bytes,first.parts,rows.iter().map(|r|r.total_ns).min().unwrap() as f64/1e6,rows.iter().map(|r|r.total_ns).max().unwrap() as f64/1e6));
            }
        }
    }
    if status["status"] != "complete" || samples.len() != 60 {
        text.push_str("INCOMPLETE RUN: do not treat this as the full configured matrix.\n");
    }
    let tmp = dir.join("report.txt.tmp");
    std::fs::write(&tmp, &text)?;
    std::fs::rename(tmp, dir.join("report.txt"))?;
    print!("{text}");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn profile_verifies_actual_cycles_and_compression_decisions() {
        let repeated = payload("repeated", 4096);
        let a = cycle(&repeated, "repeated", false, 464, 0).unwrap();
        let b = cycle(&repeated, "repeated", true, 464, 0).unwrap();
        assert!(!a.compression_used && a.compression_ns == 0 && a.decompression_ns == 0);
        assert!(b.compression_used && b.parts < a.parts && b.decompression_ns > 0);
        let random = payload("sha256-counter", 4096);
        let r = cycle(&random, "sha256-counter", true, 464, 0).unwrap();
        assert!(
            !r.compression_used
                && r.compressed_output_bytes.unwrap() > r.compressed_input_bytes
                && r.decompression_ns == 0
        );
    }
    #[test]
    fn profile_handles_multiple_hashmap_windows() {
        let data = payload("sha256-counter", 128 * 1024);
        let r = cycle(&data, "sha256-counter", false, 464, 0).unwrap();
        assert!(r.hashmap_updates > 0 && r.requests > 1);
    }
}
