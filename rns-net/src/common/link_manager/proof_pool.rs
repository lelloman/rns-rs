//! Signing and verification of link packet proofs on worker threads.
//!
//! Signing a received link packet's proof, and checking a proof of a packet
//! sent, are most of what a link message costs once it is out. With threads
//! to spare, the driver hands each to a small pool and goes on with the
//! next event; the outcomes come back through a mailbox the driver drains on
//! every turn. Several workers sign and check proofs at the same time: with
//! many link packets in flight, signing them one after another on the
//! driver held every packet behind the ones received with it. Without
//! threads (one CPU, or none configured) proofs are signed and checked
//! inline as before.

use super::*;
use rns_crypto::ed25519::{Ed25519PrivateKey, Ed25519PublicKey};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc, Mutex};

/// Proofs queued for the pool at most; past that they are checked inline.
const MAX_QUEUED: usize = 4096;

/// Proof checks a worker takes together at most: those queued right behind
/// the one it waited for are checked as one Ed25519 batch, about half the
/// cost each from 8 on. Kept small so one worker does not take the work of
/// the others.
const MAX_BATCH: usize = 8;

/// How many threads verify and sign link proofs. Threads start only in builds with the
/// `proof-pool` feature; other builds verify every proof inline.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ProofVerifyThreads {
    /// Half the CPUs this process may run on, at least one and at most four.
    /// One thread pays off even on a single CPU: proofs queued behind each
    /// other are verified as one batch, which inline checking cannot do, and
    /// the driver keeps reading while proofs are signed. Signing scales
    /// with threads up to about four; past that, contention on the shared
    /// queue costs more than the extra threads add.
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
                std::thread::available_parallelism().map_or(1, |n| (n.get() / 2).clamp(1, 4))
            }
        }
    }
}

/// What a proof belongs to.
#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) enum Owner {
    /// A packet sent or received on this link.
    Link(LinkId),
    /// A single packet sent to or received for `destination`. For a check,
    /// `rtt` is the round trip measured when the proof arrived.
    Packet { destination: [u8; 16], rtt: f64 },
}

enum Job {
    /// Check a peer's proof of a packet `owner` sent.
    Verify {
        owner: Owner,
        packet_hash: [u8; 32],
        signature: [u8; 64],
        key: Ed25519PublicKey,
    },
    /// Sign the proof of a packet `owner` received.
    Sign {
        owner: Owner,
        packet_hash: [u8; 32],
        key: Ed25519PrivateKey,
    },
    /// Encrypt a deferred single packet's payload for `destination`.
    Encrypt(Box<Encryption>),
}

/// A deferred send's plaintext and what encrypting it takes.
pub(crate) use crate::common::event::DeferredSend as Encryption;

pub(crate) enum Outcome {
    Verified {
        owner: Owner,
        packet_hash: [u8; 32],
        valid: bool,
    },
    Signed {
        owner: Owner,
        packet_hash: [u8; 32],
        signature: [u8; 64],
    },
    /// A deferred send's encrypted payload, `None` when it failed.
    Encrypted {
        ticket: u64,
        destination: [u8; 16],
        payload: Option<Vec<u8>>,
    },
}

impl Job {
    fn run(self) -> Outcome {
        match self {
            Job::Verify {
                owner,
                packet_hash,
                signature,
                key,
            } => Outcome::Verified {
                owner,
                packet_hash,
                valid: key.verify(&signature, &packet_hash),
            },
            Job::Sign {
                owner,
                packet_hash,
                key,
            } => Outcome::Signed {
                owner,
                packet_hash,
                signature: key.sign(&packet_hash),
            },
            Job::Encrypt(encryption) => Outcome::Encrypted {
                ticket: encryption.ticket,
                destination: encryption.destination,
                payload: encryption.run(),
            },
        }
    }
}

pub(super) struct ProofPool {
    jobs: Option<mpsc::SyncSender<Job>>,
    outcomes: mpsc::Receiver<Outcome>,
    /// Set by a worker that sent the driver a wake event the driver has not
    /// yet answered by draining the mailbox.
    woken: Arc<AtomicBool>,
    workers: Vec<std::thread::JoinHandle<()>>,
}

impl ProofPool {
    pub(super) fn start(threads: usize, wake: crate::event::EventSender) -> std::io::Result<Self> {
        let (jobs, queue) = mpsc::sync_channel::<Job>(MAX_QUEUED);
        let queue = Arc::new(Mutex::new(queue));
        let (outcome_tx, outcomes) = mpsc::channel();
        let woken = Arc::new(AtomicBool::new(false));
        let mut workers = Vec::with_capacity(threads);
        for index in 0..threads {
            let queue = Arc::clone(&queue);
            let outcome_tx = outcome_tx.clone();
            let woken = Arc::clone(&woken);
            let wake = wake.clone();
            let worker = std::thread::Builder::new()
                .name(format!("rns-proof-{index}"))
                .spawn(move || loop {
                    // One job, and the proof checks queued right behind it.
                    let mut jobs = Vec::with_capacity(MAX_BATCH);
                    {
                        let queue = queue.lock().unwrap_or_else(|p| p.into_inner());
                        let Ok(job) = queue.recv() else {
                            return;
                        };
                        let checking = matches!(job, Job::Verify { .. });
                        jobs.push(job);
                        while checking && jobs.len() < MAX_BATCH {
                            match queue.try_recv() {
                                Ok(job) => {
                                    let check = matches!(job, Job::Verify { .. });
                                    jobs.push(job);
                                    if !check {
                                        break;
                                    }
                                }
                                Err(_) => break,
                            }
                        }
                    }
                    for outcome in run_jobs(jobs) {
                        if outcome_tx.send(outcome).is_err() {
                            return;
                        }
                    }
                    // One wake stands for every outcome until the driver
                    // drains the mailbox.
                    if !woken.swap(true, Ordering::AcqRel) {
                        let _ = wake.try_send(crate::event::Event::LinkProofsVerified);
                    }
                });
            match worker {
                Ok(handle) => workers.push(handle),
                Err(error) if workers.is_empty() => return Err(error),
                // Fewer threads than asked for still work.
                Err(_) => break,
            }
        }
        Ok(Self {
            jobs: Some(jobs),
            outcomes,
            woken,
            workers,
        })
    }

    fn submit(&self, job: Job) -> bool {
        self.jobs
            .as_ref()
            .is_some_and(|jobs| jobs.try_send(job).is_ok())
    }

    /// Queue a deferred send's encryption, or hand it back when the pool is
    /// full or gone, for the caller to encrypt it inline.
    pub(super) fn submit_encrypt(
        &self,
        encryption: Box<Encryption>,
    ) -> Result<(), Box<Encryption>> {
        let Some(jobs) = &self.jobs else {
            return Err(encryption);
        };
        jobs.try_send(Job::Encrypt(encryption))
            .map_err(|error| match error {
                mpsc::TrySendError::Full(Job::Encrypt(encryption))
                | mpsc::TrySendError::Disconnected(Job::Encrypt(encryption)) => encryption,
                _ => unreachable!("handed back the job it was given"),
            })
    }

    /// Queue a proof's check. Returns false when the pool is full or gone,
    /// for the caller to check it inline.
    pub(super) fn submit_verify(
        &self,
        owner: Owner,
        packet_hash: [u8; 32],
        signature: [u8; 64],
        key: Ed25519PublicKey,
    ) -> bool {
        self.submit(Job::Verify {
            owner,
            packet_hash,
            signature,
            key,
        })
    }

    /// Queue a proof's signature. Returns false when the pool is full or
    /// gone, for the caller to sign inline.
    pub(super) fn submit_sign(
        &self,
        owner: Owner,
        packet_hash: [u8; 32],
        key: Ed25519PrivateKey,
    ) -> bool {
        self.submit(Job::Sign {
            owner,
            packet_hash,
            key,
        })
    }

    /// The outcomes ready so far.
    pub(super) fn drain(&self, out: &mut Vec<Outcome>) {
        // Cleared first: an outcome sent after the drain wakes the driver again.
        self.woken.store(false, Ordering::Release);
        out.extend(self.outcomes.try_iter());
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

/// Run `jobs` in order, checking their proofs as one batch when there are
/// several. A batch that fails is checked again proof by proof, to tell
/// which proofs failed.
fn run_jobs(jobs: Vec<Job>) -> Vec<Outcome> {
    let checks = jobs
        .iter()
        .filter(|job| matches!(job, Job::Verify { .. }))
        .count();
    // Batches need rns-crypto's `ed25519-batch`, which `proof-pool` (the
    // only build that starts workers) turns on.
    #[cfg(feature = "proof-pool")]
    let batch_valid = checks > 1 && {
        let items: Vec<(&Ed25519PublicKey, &[u8; 64], &[u8])> = jobs
            .iter()
            .filter_map(|job| match job {
                Job::Verify {
                    packet_hash,
                    signature,
                    key,
                    ..
                } => Some((key, signature, &packet_hash[..])),
                Job::Sign { .. } | Job::Encrypt(_) => None,
            })
            .collect();
        rns_crypto::ed25519::verify_batch(&items)
    };
    #[cfg(not(feature = "proof-pool"))]
    let batch_valid = {
        let _ = checks;
        false
    };
    jobs.into_iter()
        .map(|job| match job {
            Job::Verify {
                owner, packet_hash, ..
            } if batch_valid => Outcome::Verified {
                owner,
                packet_hash,
                valid: true,
            },
            job => job.run(),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn check(index: u8, valid: bool) -> Job {
        let key = Ed25519PrivateKey::from_bytes(&[index + 1; 32]);
        let packet_hash = [index; 32];
        let mut signature = key.sign(&packet_hash);
        if !valid {
            signature[0] ^= 1;
        }
        Job::Verify {
            owner: Owner::Link([index; 16]),
            packet_hash,
            signature,
            key: key.public_key(),
        }
    }

    fn verdicts(jobs: Vec<Job>) -> Vec<bool> {
        run_jobs(jobs)
            .into_iter()
            .map(|outcome| match outcome {
                Outcome::Verified { valid, .. } => valid,
                Outcome::Signed { .. } | Outcome::Encrypted { .. } => true,
            })
            .collect()
    }

    #[test]
    fn verdicts_name_each_bad_proof_in_a_batch() {
        let jobs: Vec<Job> = (0..6).map(|i| check(i, i != 3)).collect();
        assert_eq!(verdicts(jobs), [true, true, true, false, true, true]);
        let jobs: Vec<Job> = (0..6).map(|i| check(i, true)).collect();
        assert!(verdicts(jobs).into_iter().all(|valid| valid));
        assert_eq!(verdicts(vec![check(9, false)]), [false]);
    }

    #[test]
    fn a_batch_keeps_order_and_signs_its_proofs() {
        let key = Ed25519PrivateKey::from_bytes(&[42; 32]);
        let jobs = vec![
            check(1, true),
            Job::Sign {
                owner: Owner::Link([2; 16]),
                packet_hash: [2; 32],
                key: Ed25519PrivateKey::from_bytes(&[42; 32]),
            },
            check(3, false),
        ];
        let outcomes = run_jobs(jobs);
        assert!(matches!(outcomes[0], Outcome::Verified { valid: true, .. }));
        match &outcomes[1] {
            Outcome::Signed {
                packet_hash,
                signature,
                ..
            } => assert!(key.public_key().verify(signature, packet_hash)),
            _ => panic!("expected a signature"),
        }
        assert!(matches!(
            outcomes[2],
            Outcome::Verified { valid: false, .. }
        ));
    }
}
