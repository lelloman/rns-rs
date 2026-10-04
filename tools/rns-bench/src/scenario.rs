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
    #[serde(default)]
    pub probes: Option<ProbeConfig>,
    #[serde(default)]
    pub background: Vec<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProbeConfig {
    pub count: usize,
    pub interval_us: u64,
    pub bulk_start_us: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Payload {
    Repeated,
    Seeded,
    #[serde(rename = "sha256-counter")]
    Sha256Counter,
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
    #[serde(default)]
    pub rate_bps: Option<u64>,
    pub id: String,
    pub payload: Payload,
    pub bytes: usize,
    pub compression: bool,
    pub seed: u64,
    pub repetition: usize,
    pub operations: usize,
    pub warmup_operations: usize,
    pub timeout_secs: u64,
    #[serde(default)]
    pub probes: Option<ProbeConfig>,
    #[serde(default = "default_background")]
    pub background: bool,
}
fn default_background() -> bool {
    true
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
        (s.workload_version == 2 && s.id == "resource-transfer")
            || (s.workload_version == 1 && s.id == "resource-mixed"),
        "unsupported workload"
    );
    ensure!(
        s.layer == "live-applications"
            && s.adapter == "direct-rust-tcp"
            && s.topology == "two-process-loopback",
        "unsupported execution configuration"
    );
    if let Some(q) = &s.probes {
        ensure!(
            s.id == "resource-mixed"
                && (16..=256).contains(&q.count)
                && (1000..=10000).contains(&q.interval_us)
                && q.bulk_start_us >= q.interval_us
                && q.bulk_start_us < q.interval_us * (q.count as u64 - 1),
            "invalid probe schedule"
        );
        ensure!(
            s.background == [false, true],
            "mixed suite requires baseline and loaded cases"
        );
        ensure!(
            q.count as u64 * q.interval_us < s.timeout_secs * 1_000_000,
            "probe schedule exceeds operation deadline"
        );
    } else {
        ensure!(
            s.id == "resource-transfer" && s.background.is_empty(),
            "invalid background configuration"
        );
    }
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
                let mut compression_order = s.compression.clone();
                let mut background_order = if s.probes.is_some() {
                    s.background.clone()
                } else {
                    vec![true]
                };
                if rep % 2 == 1 {
                    compression_order.reverse();
                    background_order.reverse();
                }
                for &compression in &compression_order {
                    for &background in &background_order {
                        let id = format!(
                            "{}-v{}-{:?}-{bytes}-compress{compression}-bulk{background}-r{rep}",
                            s.id, s.workload_version, payload
                        )
                        .to_lowercase();
                        ensure!(ids.insert(id.clone()), "duplicate case: {id}");
                        out.push(Case {
                            rate_bps: None,
                            id,
                            payload,
                            bytes,
                            compression,
                            seed: s.seed,
                            repetition: rep,
                            operations: p.operations,
                            warmup_operations: p.warmup_operations,
                            timeout_secs: s.timeout_secs,
                            probes: s.probes.clone(),
                            background,
                        });
                        ensure!(
                            out.len() <= p.max_cases,
                            "expanded matrix exceeds case budget"
                        );
                    }
                }
            }
        }
    }
    if out.is_empty() {
        bail!("profile excludes every payload size");
    }
    Ok(out)
}

/// Apply an explicit synthetic network variant without changing unshaped IDs.
pub fn apply_rate(cases: &mut [Case], rate_bps: Option<u64>) -> Result<()> {
    if let Some(rate) = rate_bps {
        ensure!(
            (64_000..=1_000_000_000).contains(&rate),
            "rate must be 64000..1000000000 bit/s per direction"
        );
        for c in cases.iter() {
            // Conservative budget for framing/escaping and protocol round trips.
            let seconds = if c.background {
                (c.bytes as u64 * 16).div_ceil(rate)
            } else {
                0
            };
            ensure!(
                seconds + 10 <= c.timeout_secs,
                "{}: rate needs a longer operation deadline (at least {} seconds)",
                c.id,
                seconds + 10
            );
        }
        for c in cases {
            c.rate_bps = Some(rate);
            c.id.push_str(&format!("-rate{rate}-pacer1"));
        }
    }
    Ok(())
}

// Version 1 payload vector: xorshift64, low byte after each complete step.
// Only application data is seeded; protocol keys use OsRng.
pub fn payload(c: &Case) -> Vec<u8> {
    if c.payload == Payload::Sha256Counter {
        let mut out = Vec::with_capacity(c.bytes);
        for i in 0..c.bytes.div_ceil(32) {
            let mut input = [0; 16];
            input[..8].copy_from_slice(&c.seed.to_le_bytes());
            input[8..].copy_from_slice(&(i as u64).to_le_bytes());
            out.extend_from_slice(&rns_crypto::sha256::sha256(&input));
        }
        out.truncate(c.bytes);
        return out;
    }
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
            Payload::Sha256Counter => unreachable!(),
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
        assert_eq!(expand(&s, &p).unwrap().len(), 6);
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
    fn rate_variants_preserve_baselines_and_reject_impossible_budgets() {
        let (s, p) = inputs();
        let mut cases = expand(&s, &p).unwrap();
        let baseline = cases.clone();
        apply_rate(&mut cases, None).unwrap();
        assert_eq!(cases, baseline);
        assert!(apply_rate(&mut cases, Some(0)).is_err());
        assert_eq!(cases, baseline);
        apply_rate(&mut cases, Some(64_000)).unwrap();
        assert!(cases
            .iter()
            .all(|c| c.rate_bps == Some(64_000) && c.id.ends_with("-rate64000-pacer1")));
        let mut large = baseline;
        large[0].bytes = 1024 * 1024;
        let before = large.clone();
        assert!(apply_rate(&mut large, Some(64_000)).is_err());
        assert_eq!(large, before);
        apply_rate(&mut large, Some(1_000_000)).unwrap();
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
        c.payload = Payload::Sha256Counter;
        c.seed = 87123;
        c.bytes = 32;
        assert_eq!(
            payload(&c)
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>(),
            "d24a43addb8dcc815df00ea91baa5ad4097bb5950619ee4aa82cd5a0075a2304"
        );
        c.bytes = 35;
        let extended = payload(&c);
        c.bytes = 33;
        assert_eq!(payload(&c), extended[..33]);
    }
    #[test]
    fn mixed_matrix_requires_baselines_and_valid_probe_schedule() {
        let mut s: Scenario =
            toml::from_str(include_str!("../../../bench/scenarios/resource-mixed.toml")).unwrap();
        let p: Profile =
            toml::from_str(include_str!("../../../bench/profiles/mixed-quick.toml")).unwrap();
        let cases = expand(&s, &p).unwrap();
        assert_eq!(cases.len(), 36);
        assert!(!cases[0].background && cases[12].background);
        s.probes.as_mut().unwrap().count = 10000;
        assert!(expand(&s, &p).is_err());
        s.probes.as_mut().unwrap().count = 128;
        s.background = vec![true];
        assert!(expand(&s, &p).is_err());
    }
}
