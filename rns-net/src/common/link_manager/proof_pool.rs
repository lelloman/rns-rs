//! Verification of link packet proofs on worker threads.
//!
//! Checking a proof's Ed25519 signature is most of what a link message costs
//! its sender once the message is out. With threads to spare, the driver
//! hands each check to a small pool and goes on with the next event; the
//! verdicts come back through a mailbox the driver drains on every turn.
//! Without them (one CPU, or none configured) proofs are checked inline as
//! before.

use super::*;
use rns_crypto::ed25519::Ed25519PublicKey;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc, Mutex};

/// Proofs queued for the pool at most; past that they are checked inline.
const MAX_QUEUED: usize = 4096;

/// Proofs a worker checks together at most. Past about 16 a batch costs no
/// less per signature, and verdicts wait on the whole batch.
const MAX_BATCH: usize = 32;

/// How many threads verify link proofs. Threads start only in builds with the
/// `proof-pool` feature; other builds verify every proof inline.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ProofVerifyThreads {
    /// One thread when this process may run on more than one CPU, none on
    /// one. A single worker keeps up with a link at full rate; more add
    /// wake-ups and contention on the shared queue and cost throughput.
    #[default]
    Auto,
    /// Exactly this many; 0 checks every proof on the driver thread.
    Fixed(usize),
}

impl ProofVerifyThreads {
    /// Threads to start: none without the `proof-pool` feature.
    pub(super) fn count(self) -> usize {
        if !cfg!(feature = "proof-pool") {
            if matches!(self, ProofVerifyThreads::Fixed(n) if n > 0) {
                log::warn!("link proofs verified inline: built without the proof-pool feature");
            }
            return 0;
        }
        match self {
            ProofVerifyThreads::Fixed(n) => n,
            ProofVerifyThreads::Auto => {
                std::thread::available_parallelism().map_or(0, |n| usize::from(n.get() > 1))
            }
        }
    }
}

struct Job {
    link_id: LinkId,
    packet_hash: [u8; 32],
    signature: [u8; 64],
    key: Ed25519PublicKey,
}

pub(super) struct Verdict {
    pub(super) link_id: LinkId,
    pub(super) packet_hash: [u8; 32],
    pub(super) valid: bool,
}

pub(super) struct ProofPool {
    jobs: Option<mpsc::SyncSender<Job>>,
    verdicts: mpsc::Receiver<Verdict>,
    /// Set by a worker that sent the driver a wake event the driver has not
    /// yet answered by draining the mailbox.
    woken: Arc<AtomicBool>,
    workers: Vec<std::thread::JoinHandle<()>>,
}

impl ProofPool {
    pub(super) fn start(threads: usize, wake: crate::event::EventSender) -> std::io::Result<Self> {
        let (jobs, queue) = mpsc::sync_channel::<Job>(MAX_QUEUED);
        let queue = Arc::new(Mutex::new(queue));
        let (verdict_tx, verdicts) = mpsc::channel();
        let woken = Arc::new(AtomicBool::new(false));
        let mut workers = Vec::with_capacity(threads);
        for index in 0..threads {
            let queue = Arc::clone(&queue);
            let verdict_tx = verdict_tx.clone();
            let woken = Arc::clone(&woken);
            let wake = wake.clone();
            let worker = std::thread::Builder::new()
                .name(format!("rns-proof-{index}"))
                .spawn(move || loop {
                    // Wait for one proof, then take those already queued
                    // behind it: proofs come in bursts while a link has
                    // several packets in flight, and a batch is checked for
                    // about half the cost of checking each.
                    let mut batch = Vec::with_capacity(MAX_BATCH);
                    {
                        let queue = queue.lock().unwrap_or_else(|p| p.into_inner());
                        let Ok(job) = queue.recv() else {
                            return;
                        };
                        batch.push(job);
                        while batch.len() < MAX_BATCH {
                            match queue.try_recv() {
                                Ok(job) => batch.push(job),
                                Err(_) => break,
                            }
                        }
                    }
                    for (job, valid) in verify_jobs(&batch) {
                        let verdict = Verdict {
                            link_id: job.link_id,
                            packet_hash: job.packet_hash,
                            valid,
                        };
                        if verdict_tx.send(verdict).is_err() {
                            return;
                        }
                    }
                    // One wake stands for every verdict until the driver
                    // drains the mailbox.
                    if !woken.swap(true, Ordering::AcqRel) {
                        let _ = wake.try_send(crate::event::Event::LinkProofsVerified);
                    }
                });
            match worker {
                Ok(handle) => workers.push(handle),
                Err(error) if workers.is_empty() => return Err(error),
                // Fewer threads than asked for still verify.
                Err(_) => break,
            }
        }
        Ok(Self {
            jobs: Some(jobs),
            verdicts,
            woken,
            workers,
        })
    }

    /// Queue a proof's check. Returns false when the pool is full or gone,
    /// for the caller to check it inline.
    pub(super) fn submit(
        &self,
        link_id: LinkId,
        packet_hash: [u8; 32],
        signature: [u8; 64],
        key: Ed25519PublicKey,
    ) -> bool {
        let Some(jobs) = &self.jobs else {
            return false;
        };
        jobs.try_send(Job {
            link_id,
            packet_hash,
            signature,
            key,
        })
        .is_ok()
    }

    /// The verdicts ready so far.
    pub(super) fn drain(&self, out: &mut Vec<Verdict>) {
        // Cleared first: a verdict sent after the drain wakes the driver again.
        self.woken.store(false, Ordering::Release);
        out.extend(self.verdicts.try_iter());
    }
}

impl Drop for ProofPool {
    fn drop(&mut self) {
        // Closing the queue ends every worker once it is empty.
        self.jobs = None;
        for worker in self.workers.drain(..) {
            let _ = worker.join();
        }
    }
}

/// Check `jobs`, as one batch when there are several: each job with its
/// verdict. A batch that fails is checked again one proof at a time, to tell
/// which proofs failed.
fn verify_jobs(jobs: &[Job]) -> impl Iterator<Item = (&Job, bool)> {
    // Batches need rns-crypto's `ed25519-batch`, which `proof-pool` (the
    // only build that starts workers) turns on.
    #[cfg(feature = "proof-pool")]
    let batch_valid = jobs.len() > 1 && {
        let items: Vec<(&Ed25519PublicKey, &[u8; 64], &[u8])> = jobs
            .iter()
            .map(|job| (&job.key, &job.signature, &job.packet_hash[..]))
            .collect();
        rns_crypto::ed25519::verify_batch(&items)
    };
    #[cfg(not(feature = "proof-pool"))]
    let batch_valid = false;
    jobs.iter().map(move |job| {
        let valid = batch_valid || job.key.verify(&job.signature, &job.packet_hash);
        (job, valid)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use rns_crypto::ed25519::Ed25519PrivateKey;

    fn job(index: u8, valid: bool) -> Job {
        let key = Ed25519PrivateKey::from_bytes(&[index + 1; 32]);
        let packet_hash = [index; 32];
        let mut signature = key.sign(&packet_hash);
        if !valid {
            signature[0] ^= 1;
        }
        Job {
            link_id: [index; 16],
            packet_hash,
            signature,
            key: key.public_key(),
        }
    }

    #[test]
    fn verdicts_name_each_bad_proof_in_a_batch() {
        let jobs: Vec<Job> = (0..6).map(|i| job(i, i != 3)).collect();
        let verdicts: Vec<bool> = verify_jobs(&jobs).map(|(_, valid)| valid).collect();
        assert_eq!(verdicts, [true, true, true, false, true, true]);

        let jobs: Vec<Job> = (0..6).map(|i| job(i, true)).collect();
        assert!(verify_jobs(&jobs).all(|(_, valid)| valid));
        assert!(!verify_jobs(&[job(9, false)]).any(|(_, valid)| valid));
    }
}
