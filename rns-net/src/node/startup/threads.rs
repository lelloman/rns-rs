//! The node's background threads: the timer, announce verification, the
//! driver and transport state persistence.

use super::*;

/// The thread that sends the driver its ticks, at the interval
/// `tick_interval_ms` holds, unless the driver keeps the tick itself
/// (compact engine).
pub(super) fn spawn_timer(tx: &EventSender, tick_interval_ms: &Arc<AtomicU64>) -> io::Result<()> {
    if !crate::engine::FOLD_TIMERS {
        let timer_tx = tx.clone();
        let timer_interval = Arc::clone(tick_interval_ms);
        thread::Builder::new()
            .name("rns-timer".into())
            .spawn(move || loop {
                let ms = timer_interval.load(Ordering::Relaxed);
                thread::sleep(Duration::from_millis(ms));
                if timer_tx.send(Event::Tick).is_err() {
                    break; // receiver dropped
                }
            })?;
    }
    Ok(())
}

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
                        crate::sys::nice(5);
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
                crate::sys::nice(5);

                loop {
                    match stop_rx.recv_timeout(Duration::from_secs(12 * 60 * 60)) {
                        Ok(()) | Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
                        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
                    }
                    let (response_tx, response_rx) = std::sync::mpsc::channel();
                    if persist_tx
                        .send(Event::query(
                            query::TransportStateSnapshot.into(),
                            response_tx,
                        ))
                        .is_err()
                    {
                        break;
                    }
                    let Some(snapshot) = response_rx
                        .recv()
                        .ok()
                        .and_then(query::TransportStateSnapshot::response)
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

/// The threads a node runs once started, and how to stop them.
pub(super) struct NodeThreads {
    pub(super) verify: Option<JoinHandle<()>>,
    pub(super) verify_shutdown: Arc<crate::driver::WorkSignal>,
    pub(super) driver: JoinHandle<()>,
    pub(super) persist: Option<JoinHandle<()>>,
    pub(super) persist_stop: Option<std::sync::mpsc::Sender<()>>,
}

/// Spawn the announce verifier, the driver and the transport state
/// persister, once startup has set the driver up.
pub(super) fn spawn_node_threads(
    mut driver: Driver,
    tx: &EventSender,
    transport_state_dir: Option<std::path::PathBuf>,
) -> io::Result<NodeThreads> {
    let verify_shutdown = Arc::clone(&driver.announce_verify.signal);
    let verify_handle =
        spawn_announce_verifier(&driver.announce_verify.queue, &verify_shutdown, tx.clone())?;

    // Spawn the driver after startup has registered local destinations and static interfaces.
    // Interface readers can enqueue frames before this point; the bounded event queue preserves
    // ordering and backpressures instead of dropping startup traffic.
    log::debug!("rns-net {} engine", crate::engine::ENGINE);
    // The compact engine persists transport state on the driver loop.
    if crate::engine::FOLD_TIMERS {
        driver.folded.persist_dir = transport_state_dir.clone();
    }
    let driver_handle = thread::Builder::new()
        .name("rns-driver".into())
        .spawn(move || {
            driver.run();
        })?;

    let (persist_handle, persist_stop) =
        spawn_transport_state_persister(transport_state_dir, tx.clone())?.unzip();
    Ok(NodeThreads {
        verify: verify_handle,
        verify_shutdown,
        driver: driver_handle,
        persist: persist_handle,
        persist_stop,
    })
}
