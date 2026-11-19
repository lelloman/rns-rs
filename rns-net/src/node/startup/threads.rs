//! The node's background threads: announce verification and transport
//! state persistence.

#![allow(unsafe_code, reason = "OS calls through libc")]

use super::*;

/// The thread that verifies announces, unless the compact engine verifies
/// them on its driver loop.
pub(super) fn spawn_announce_verifier(
    queue: &Arc<std::sync::Mutex<rns_core::transport::announce_verify_queue::AnnounceVerifyQueue>>,
    signal: &Arc<crate::driver::WorkSignal>,
    verify_tx: EventSender,
) -> io::Result<Option<JoinHandle<()>>> {
    let announce_verify_queue = Arc::clone(queue);
    let verify_shutdown_thread = Arc::clone(signal);
    let handle = if crate::engine::FOLD_WORK {
        None
    } else {
        Some(
            thread::Builder::new()
                .name("rns-verify".into())
                .spawn(move || {
                    #[cfg(target_family = "unix")]
                    {
                        // SAFETY: `nice` takes a plain integer and only lowers scheduling
                        // priority (per thread on Linux); no memory is involved.
                        unsafe {
                            libc::nice(5);
                        }
                    }

                    while !verify_shutdown_thread.stopped() {
                        let batch = {
                            let mut queue = crate::sync::lock_or_recover(
                                &announce_verify_queue,
                                "threads announce verify queue",
                            );
                            queue.take_pending(time::now())
                        };

                        if batch.is_empty() {
                            // Until the driver queues an announce.
                            verify_shutdown_thread.wait();
                            continue;
                        }

                        for (key, pending) in batch {
                            if verify_shutdown_thread.stopped() {
                                break;
                            }
                            let event = match crate::driver::check_pending_announce(&pending) {
                                crate::driver::AnnounceCheck::Valid {
                                    validated,
                                    sig_cache_key,
                                } => Event::AnnounceVerified {
                                    key,
                                    validated,
                                    sig_cache_key,
                                },
                                crate::driver::AnnounceCheck::Invalid { sig_cache_key } => {
                                    Event::AnnounceVerifyFailed { key, sig_cache_key }
                                }
                            };
                            if verify_tx.send(event).is_err() {
                                return;
                            }
                        }
                    }
                })?,
        )
    };
    Ok(handle)
}

/// The thread that persists the transport state every 12 hours, as
/// upstream's background persistence does, and the sender that stops it;
/// none when the compact engine persists on its driver loop. It writes at
/// low priority and reads engine state only through the driver's snapshot.
pub(super) fn spawn_transport_state_persister(
    transport_state_dir: Option<std::path::PathBuf>,
    persist_tx: EventSender,
) -> io::Result<Option<(JoinHandle<()>, std::sync::mpsc::Sender<()>)>> {
    let threads = if let Some(storage_dir) =
        transport_state_dir.filter(|_| !crate::engine::FOLD_TIMERS)
    {
        let (stop_tx, stop_rx) = std::sync::mpsc::channel();
        let handle = thread::Builder::new()
            .name("rns-persist".into())
            .spawn(move || {
                #[cfg(target_family = "unix")]
                // SAFETY: `nice` takes a plain integer and only lowers scheduling
                // priority (per thread on Linux); no memory is involved.
                unsafe {
                    libc::nice(5);
                }

                loop {
                    match stop_rx.recv_timeout(Duration::from_secs(12 * 60 * 60)) {
                        Ok(()) | Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
                        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
                    }
                    let (response_tx, response_rx) = std::sync::mpsc::channel();
                    if persist_tx
                        .send(Event::query(
                            QueryRequest::TransportStateSnapshot,
                            response_tx,
                        ))
                        .is_err()
                    {
                        break;
                    }
                    let Ok(QueryResponse::TransportStateSnapshot(snapshot)) = response_rx.recv()
                    else {
                        continue;
                    };
                    if let Err(err) = storage::save_transport_state(&snapshot, &storage_dir, true) {
                        log::warn!("failed to persist transport state: {}", err);
                    }
                }
            })?;
        Some((handle, stop_tx))
    } else {
        None
    };
    Ok(threads)
}
