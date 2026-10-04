use crate::scenario::ProbeConfig;
use anyhow::{ensure, Result};
use serde::{Deserialize, Serialize};
use std::time::{Duration, Instant};

pub fn packet(id: u64) -> Vec<u8> {
    let mut data = vec![0x6d; 64];
    data[..8].copy_from_slice(b"RNSPROBE");
    data[8..16].copy_from_slice(&id.to_le_bytes());
    data
}
pub fn decode(data: &[u8]) -> Result<u64> {
    ensure!(
        data.len() == 64 && &data[..8] == b"RNSPROBE",
        "invalid probe frame"
    );
    let id = u64::from_le_bytes(data[8..16].try_into()?);
    ensure!(data == packet(id), "probe payload corruption");
    Ok(id)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Summary {
    pub rtt_ns: Vec<u64>,
    pub scheduled_latency_ns: Vec<u64>,
    pub send_lateness_ns: Vec<u64>,
    pub bulk_started_ns: Option<u64>,
    pub bulk_finished_ns: Option<u64>,
}

pub struct Train {
    pub round: u64,
    pub started: Instant,
    pub config: ProbeConfig,
    issued: usize,
    received: usize,
    submitted: Vec<Option<Instant>>,
    summary: Summary,
    pub resource_elapsed_ns: Option<u64>,
    pub bulk_started: bool,
}
fn ns(d: Duration) -> u64 {
    d.as_nanos().try_into().expect("duration fits u64")
}
impl Train {
    pub fn new(round: u64, config: ProbeConfig) -> Self {
        let n = config.count;
        Self {
            round,
            started: Instant::now(),
            config,
            issued: 0,
            received: 0,
            submitted: vec![None; n],
            summary: Summary {
                rtt_ns: vec![0; n],
                scheduled_latency_ns: vec![0; n],
                send_lateness_ns: vec![0; n],
                bulk_started_ns: None,
                bulk_finished_ns: None,
            },
            resource_elapsed_ns: None,
            bulk_started: false,
        }
    }
    pub fn next_due(&self) -> Option<Instant> {
        (self.issued < self.config.count).then(|| {
            self.started + Duration::from_micros(self.issued as u64 * self.config.interval_us)
        })
    }
    pub fn bulk_due(&self) -> Instant {
        self.started + Duration::from_micros(self.config.bulk_start_us)
    }
    pub fn next_id(&self) -> u64 {
        self.round * self.config.count as u64 + self.issued as u64
    }
    pub fn submitted(&mut self, when: Instant) -> Result<()> {
        ensure!(
            self.issued < self.config.count,
            "too many probe submissions"
        );
        let due = self.next_due().unwrap();
        ensure!(when >= due, "probe submitted early");
        self.submitted[self.issued] = Some(when);
        self.summary.send_lateness_ns[self.issued] = ns(when - due);
        self.issued += 1;
        Ok(())
    }
    pub fn receive(&mut self, id: u64, when: Instant) -> Result<()> {
        let i = id
            .checked_sub(self.round * self.config.count as u64)
            .ok_or_else(|| anyhow::anyhow!("stale probe"))? as usize;
        ensure!(i < self.config.count, "wrong probe round/index");
        let sent = self.submitted[i]
            .take()
            .ok_or_else(|| anyhow::anyhow!("duplicate or unsubmitted probe"))?;
        ensure!(when >= sent, "probe clock ordering");
        self.summary.rtt_ns[i] = ns(when - sent);
        self.summary.scheduled_latency_ns[i] =
            ns(when - (self.started + Duration::from_micros(i as u64 * self.config.interval_us)));
        self.received += 1;
        Ok(())
    }
    pub fn start_bulk(&mut self, at: Instant) {
        self.bulk_started = true;
        self.summary.bulk_started_ns = Some(ns(at - self.started));
    }
    pub fn end_bulk(&mut self, at: Instant, elapsed: u64) {
        self.summary.bulk_finished_ns = Some(ns(at - self.started));
        self.resource_elapsed_ns = Some(elapsed);
    }
    pub fn complete(&self, background: bool) -> bool {
        self.received == self.config.count && (!background || self.resource_elapsed_ns.is_some())
    }
    pub fn summary(self) -> Summary {
        self.summary
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn probes_validate_payload_duplicates_and_scheduled_latency() {
        let mut t = Train::new(
            2,
            ProbeConfig {
                count: 16,
                interval_us: 2000,
                bulk_start_us: 10000,
            },
        );
        let data = packet(t.next_id());
        assert_eq!(decode(&data).unwrap(), 32);
        let mut bad = data.clone();
        bad[63] ^= 1;
        assert!(decode(&bad).is_err());
        let sent = t.started + Duration::from_millis(5);
        t.submitted(sent).unwrap();
        t.receive(32, sent + Duration::from_millis(1)).unwrap();
        assert_eq!(t.summary.rtt_ns[0], 1_000_000);
        assert_eq!(t.summary.scheduled_latency_ns[0], 6_000_000);
        assert_eq!(t.summary.send_lateness_ns[0], 5_000_000);
        assert!(t.receive(32, sent + Duration::from_millis(2)).is_err());
        assert!(t.receive(33, sent + Duration::from_millis(2)).is_err());
        assert!(!t.complete(false));
    }
}
