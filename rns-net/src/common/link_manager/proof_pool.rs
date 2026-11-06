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
/// Threads `auto` starts at most.
const AUTO_MAX_THREADS: usize = 4;

/// How many threads verify link proofs. Threads start only in builds with the
/// `proof-pool` feature; other builds verify every proof inline.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ProofVerifyThreads {
    /// One fewer than the CPUs this process may run on, at most four: none
    /// on a single CPU.
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
            ProofVerifyThreads::Auto => std::thread::available_parallelism()
                .map_or(0, |n| n.get().saturating_sub(1).min(AUTO_MAX_THREADS)),
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
                    let job = {
                        let queue = queue.lock().unwrap_or_else(|p| p.into_inner());
                        queue.recv()
                    };
                    let Ok(job) = job else {
                        return;
                    };
                    let valid = job.key.verify(&job.signature, &job.packet_hash);
                    let verdict = Verdict {
                        link_id: job.link_id,
                        packet_hash: job.packet_hash,
                        valid,
                    };
                    if verdict_tx.send(verdict).is_err() {
                        return;
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
