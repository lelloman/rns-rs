use anyhow::{bail, ensure, Context, Result};
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Scenario {
    pub schema_version: u32,
    pub workload_version: u32,
    pub id: String,
    pub layer: String,
    pub adapter: String,
    pub topology: String,
    pub payloads: Vec<Payload>,
    pub sizes: Vec<usize>,
    pub compression: Vec<bool>,
    pub seed: u64,
    pub concurrency: usize,
    pub timeout_secs: u64,
    pub completion: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Payload {
    Repeated,
    Seeded,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Profile {
    pub schema_version: u32,
    pub name: String,
    pub repetitions: usize,
    pub warmup_operations: usize,
    pub operations: usize,
    pub max_payload_bytes: usize,
    pub max_cases: usize,
    pub performance_claims: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Case {
    pub id: String,
    pub payload: Payload,
    pub bytes: usize,
    pub compression: bool,
    pub seed: u64,
    pub repetition: usize,
    pub operations: usize,
    pub warmup_operations: usize,
    pub timeout_secs: u64,
}

pub fn read<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T> {
    toml::from_str(&std::fs::read_to_string(path)?).with_context(|| path.display().to_string())
}

pub fn expand(s: &Scenario, p: &Profile) -> Result<Vec<Case>> {
    ensure!(
        s.schema_version == 1 && p.schema_version == 1,
        "unsupported schema version"
    );
    ensure!(
        s.workload_version == 1 && s.id == "resource-transfer",
        "unsupported workload"
    );
    ensure!(
        s.layer == "live-applications"
            && s.adapter == "direct-rust-tcp"
            && s.topology == "two-process-loopback",
        "unsupported execution configuration"
    );
    ensure!(
        s.completion == "receiver-verified-and-sender-settled",
        "unsupported completion boundary"
    );
    ensure!(
        s.concurrency == 1,
        "only one outstanding Resource is supported"
    );
    ensure!(
        (1..=300).contains(&s.timeout_secs),
        "timeout must be 1..300 seconds"
    );
    ensure!(
        (1..=20).contains(&p.repetitions)
            && (1..=10000).contains(&p.operations)
            && p.warmup_operations <= 100,
        "invalid operation budget"
    );
    ensure!(
        !p.performance_claims,
        "qualified performance profiles are not implemented"
    );
    ensure!((1..=256).contains(&p.max_cases), "invalid case budget");
    ensure!(
        (1..=64 * 1024 * 1024).contains(&p.max_payload_bytes),
        "invalid payload budget"
    );
    ensure!(
        !s.payloads.is_empty() && !s.sizes.is_empty() && !s.compression.is_empty(),
        "empty scenario dimension"
    );
    ensure!(
        s.sizes.iter().all(|n| (1..=64 * 1024 * 1024).contains(n)),
        "invalid payload size"
    );
    let mut out = Vec::new();
    let mut ids = std::collections::BTreeSet::new();
    for rep in 0..p.repetitions {
        for &payload in &s.payloads {
            for &bytes in s.sizes.iter().filter(|&&n| n <= p.max_payload_bytes) {
                for &compression in &s.compression {
                    let id = format!(
                        "{}-{:?}-{bytes}-compress{compression}-r{rep}",
                        s.id, payload
                    )
                    .to_lowercase();
                    ensure!(ids.insert(id.clone()), "duplicate case: {id}");
                    out.push(Case {
                        id,
                        payload,
                        bytes,
                        compression,
                        seed: s.seed,
                        repetition: rep,
                        operations: p.operations,
                        warmup_operations: p.warmup_operations,
                        timeout_secs: s.timeout_secs,
                    });
                    ensure!(
                        out.len() <= p.max_cases,
                        "expanded matrix exceeds case budget"
                    );
                }
            }
        }
    }
    if out.is_empty() {
        bail!("profile excludes every payload size");
    }
    Ok(out)
}

// Version 1 payload vector: xorshift64, low byte after each complete step.
// Only application data is seeded; protocol keys use OsRng.
pub fn payload(c: &Case) -> Vec<u8> {
    let mut state = c.seed.max(1);
    (0..c.bytes)
        .map(|_| match c.payload {
            Payload::Repeated => 0x5a,
            Payload::Seeded => {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                state as u8
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    fn inputs() -> (Scenario, Profile) {
        (
            toml::from_str(include_str!(
                "../../../bench/scenarios/resource-transfer.toml"
            ))
            .unwrap(),
            toml::from_str(include_str!("../../../bench/profiles/smoke.toml")).unwrap(),
        )
    }
    #[test]
    fn bounded_matrix_and_duplicate_rejection() {
        let (mut s, mut p) = inputs();
        assert_eq!(expand(&s, &p).unwrap().len(), 4);
        p.max_cases = 3;
        assert!(expand(&s, &p).is_err());
        p.max_cases = 16;
        s.sizes.push(4096);
        assert!(expand(&s, &p).is_err());
    }
    #[test]
    fn unsupported_and_empty_configs_fail() {
        let (mut s, p) = inputs();
        s.concurrency = 8;
        assert!(expand(&s, &p).is_err());
        s.concurrency = 1;
        s.sizes.clear();
        assert!(expand(&s, &p).is_err());
    }
    #[test]
    fn unknown_fields_fail() {
        let text = format!(
            "{}\ntypo = 1\n",
            include_str!("../../../bench/profiles/smoke.toml")
        );
        assert!(toml::from_str::<Profile>(&text).is_err());
    }
    #[test]
    fn golden_payload() {
        let (s, p) = inputs();
        let mut c = expand(&s, &p).unwrap().remove(0);
        c.payload = Payload::Seeded;
        c.seed = 1;
        c.bytes = 8;
        assert_eq!(payload(&c), [65, 65, 41, 37, 101, 1, 113, 13]);
    }
}
