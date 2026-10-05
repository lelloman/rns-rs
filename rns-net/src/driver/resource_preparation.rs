//! Bounded, node-owned compression preparation. Protocol state stays on the driver.
use super::*;
use rns_core::buffer::types::{Compressor, DecompressError};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    mpsc,
};

const MAX_JOBS: usize = 8;
const MAX_BYTES: usize = 8 * 1024 * 1024;
const MIN_INPUT: usize = 16 * 1024;

struct Job {
    id: u64,
    data: Vec<u8>,
    metadata: Option<Vec<u8>>,
    cancelled: Arc<AtomicBool>,
}
struct Ready {
    id: u64,
    data: Vec<u8>,
    metadata: Option<Vec<u8>>,
    compressed: Result<Option<Box<[u8]>>, String>,
}
struct Pending {
    link: [u8; 16],
    generation: Arc<()>,
    cancelled: Arc<AtomicBool>,
    bytes: usize,
}

pub(super) struct Worker {
    tx: Option<mpsc::SyncSender<Job>>,
    rx: mpsc::Receiver<Ready>,
    handle: Option<std::thread::JoinHandle<()>>,
    stop: Arc<AtomicBool>,
    pending: HashMap<u64, Pending>,
    bytes: usize,
    next_id: u64,
}

impl Worker {
    fn new(wake: crate::event::EventSender) -> std::io::Result<Self> {
        Self::start(wake, |input| {
            crate::common::compressor::Bzip2Compressor.compress(input)
        })
    }

    fn start(
        wake: crate::event::EventSender,
        compress: impl Fn(&[u8]) -> Option<Vec<u8>> + Send + 'static,
    ) -> std::io::Result<Self> {
        let (tx, jobs) = mpsc::sync_channel::<Job>(MAX_JOBS);
        let (results, rx) = mpsc::sync_channel(MAX_JOBS);
        let stop = Arc::new(AtomicBool::new(false));
        let stopped = stop.clone();
        let handle = std::thread::Builder::new()
            .name("rns-resource-prepare".into())
            .spawn(move || {
                while let Ok(job) = jobs.recv() {
                    if stopped.load(Ordering::Acquire) {
                        break;
                    }
                    let compressed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        if job.cancelled.load(Ordering::Acquire) {
                            return None;
                        }
                        let input = job
                            .metadata
                            .as_ref()
                            .map(|m| rns_core::resource::parts::prepend_metadata(&job.data, m));
                        let input = input.as_deref().unwrap_or(&job.data);
                        compress(input)
                            .filter(|bytes| bytes.len() < input.len())
                            // Charge retained output by length, not an allocator growth heuristic.
                            .map(Vec::into_boxed_slice)
                    }))
                    .map_err(|_| "Resource compression worker panicked".to_string());
                    if stopped.load(Ordering::Acquire) {
                        break;
                    }
                    let ready = Ready {
                        id: job.id,
                        data: job.data,
                        metadata: job.metadata,
                        compressed,
                    };
                    // At most MAX_JOBS results exist, including work not yet completed.
                    // Never block here, including during shutdown or a full control queue.
                    if results.try_send(ready).is_err() {
                        break;
                    }
                    let _ = wake.try_send(Event::ResourcePreparationReady);
                }
            })?;
        Ok(Self {
            tx: Some(tx),
            rx,
            handle: Some(handle),
            stop,
            pending: HashMap::new(),
            bytes: 0,
            next_id: 0,
        })
    }

    pub(super) fn len(&self) -> usize {
        self.pending.len()
    }

    fn charge(data: &Vec<u8>, metadata: &Option<Vec<u8>>) -> Option<usize> {
        let logical = data
            .len()
            .checked_add(metadata.as_ref().map_or(0, |m| 3 + m.len()))?;
        if data.len() < MIN_INPUT || logical > rns_core::constants::RESOURCE_MAX_EFFICIENT_SIZE {
            return None;
        }
        // Raw owned capacity plus the largest retained compressed result. The single
        // running job also needs one metadata-prefixed input and native codec workspace.
        data.capacity()
            .checked_add(metadata.as_ref().map_or(0, Vec::capacity))?
            .checked_add(logical)
    }

    fn can_submit(&self, bytes: usize) -> bool {
        self.pending.len() < MAX_JOBS && bytes <= MAX_BYTES.saturating_sub(self.bytes)
    }

    fn submit(
        &mut self,
        link: [u8; 16],
        generation: Arc<()>,
        data: Vec<u8>,
        metadata: Option<Vec<u8>>,
        bytes: usize,
    ) -> Result<(), (Vec<u8>, Option<Vec<u8>>)> {
        if !self.can_submit(bytes) {
            return Err((data, metadata));
        }
        let id = self.next_id;
        let Some(next_id) = id.checked_add(1) else {
            return Err((data, metadata));
        };
        let cancelled = Arc::new(AtomicBool::new(false));
        let job = Job {
            id,
            data,
            metadata,
            cancelled: cancelled.clone(),
        };
        match self.tx.as_ref().unwrap().try_send(job) {
            Ok(()) => {
                self.next_id = next_id;
                self.pending.insert(
                    id,
                    Pending {
                        link,
                        generation,
                        cancelled,
                        bytes,
                    },
                );
                self.bytes += bytes;
                Ok(())
            }
            Err(mpsc::TrySendError::Full(job) | mpsc::TrySendError::Disconnected(job)) => {
                Err((job.data, job.metadata))
            }
        }
    }

    fn receive(&mut self, wait: bool) -> Option<(Pending, Ready)> {
        let result = if wait {
            self.rx.recv().map_err(|_| mpsc::TryRecvError::Disconnected)
        } else {
            self.rx.try_recv()
        };
        let ready = match result {
            Ok(ready) => ready,
            Err(mpsc::TryRecvError::Empty) => return None,
            Err(mpsc::TryRecvError::Disconnected) => {
                let id = *self.pending.keys().next()?;
                Ready {
                    id,
                    data: Vec::new(),
                    metadata: None,
                    compressed: Err("Resource compression worker stopped".into()),
                }
            }
        };
        let pending = self
            .pending
            .remove(&ready.id)
            .expect("worker returned unknown Resource job");
        self.bytes -= pending.bytes;
        Some((pending, ready))
    }
}

impl Drop for Worker {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        self.tx.take();
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

struct PreparedCompressor(std::cell::RefCell<Option<Vec<u8>>>);
impl Compressor for PreparedCompressor {
    fn compress(&self, _: &[u8]) -> Option<Vec<u8>> {
        self.0.borrow_mut().take()
    }
    fn decompress_bounded(&self, _: &[u8], _: usize) -> Result<Vec<u8>, DecompressError> {
        Err(DecompressError::InvalidData)
    }
}

impl Driver {
    pub(super) fn prepare_resource(
        &mut self,
        link: [u8; 16],
        mut data: Vec<u8>,
        mut metadata: Option<Vec<u8>>,
        auto_compress: bool,
    ) {
        if let Some((generation, bytes)) = auto_compress
            .then(|| {
                self.link_manager
                    .resource_generation(&link)
                    .zip(Worker::charge(&data, &metadata))
            })
            .flatten()
            .filter(|(_, bytes)| *bytes <= MAX_BYTES)
        {
            if self.resource_preparation.is_none() {
                match Worker::new(self.event_tx.clone()) {
                    Ok(worker) => self.resource_preparation = Some(worker),
                    Err(error) => log::warn!(
                        "Resource worker unavailable, using synchronous preparation: {}",
                        error
                    ),
                }
            }
            if let Some(worker) = self.resource_preparation.as_mut() {
                match worker.submit(link, generation, data, metadata, bytes) {
                    Ok(()) => return,
                    Err(input) => {
                        (data, metadata) = input;
                    }
                }
            }
        }
        // No new rejection policy: unsupported or saturated work uses the existing
        // synchronous path, after earlier buffered sends on this link are installed.
        self.finish_resource_preparations_for(&link);
        let actions = self.link_manager.send_resource_with_auto_compress(
            &link,
            &data,
            metadata.as_deref(),
            auto_compress,
            &mut self.rng,
        );
        self.dispatch_link_actions(actions);
    }

    fn finish_prepared_resource(&mut self, pending: Pending, ready: Ready) {
        let valid = self
            .link_manager
            .resource_generation(&pending.link)
            .is_some_and(|current| Arc::ptr_eq(&current, &pending.generation));
        if pending.cancelled.load(Ordering::Acquire) || !valid {
            self.callbacks.on_resource_failed(
                rns_core::types::LinkId(pending.link),
                "Link closed during Resource preparation".into(),
            );
            return;
        }
        match ready.compressed {
            Ok(compressed) => {
                let compressor = PreparedCompressor(std::cell::RefCell::new(
                    compressed.map(|bytes| bytes.into_vec()),
                ));
                let actions = self.link_manager.send_resource_with_compressor(
                    &pending.link,
                    &ready.data,
                    ready.metadata.as_deref(),
                    true,
                    &compressor,
                    &mut self.rng,
                );
                self.dispatch_link_actions(actions);
            }
            Err(error) => self
                .callbacks
                .on_resource_failed(rns_core::types::LinkId(pending.link), error),
        }
    }

    pub(super) fn poll_resource_preparations(&mut self) {
        if let Some(worker) = &mut self.resource_preparation {
            for pending in worker.pending.values() {
                if !self
                    .link_manager
                    .resource_generation(&pending.link)
                    .is_some_and(|current| Arc::ptr_eq(&current, &pending.generation))
                {
                    pending.cancelled.store(true, Ordering::Release);
                }
            }
        }
        while let Some((pending, ready)) = self
            .resource_preparation
            .as_mut()
            .and_then(|worker| worker.receive(false))
        {
            self.finish_prepared_resource(pending, ready);
        }
    }

    pub(super) fn finish_resource_preparations_for(&mut self, link: &[u8; 16]) {
        while self
            .resource_preparation
            .as_ref()
            .is_some_and(|worker| worker.pending.values().any(|pending| &pending.link == link))
        {
            if let Some((pending, ready)) = self
                .resource_preparation
                .as_mut()
                .and_then(|worker| worker.receive(true))
            {
                self.finish_prepared_resource(pending, ready);
            }
        }
    }

    pub(super) fn stop_resource_preparations(&mut self) {
        if let Some(worker) = self.resource_preparation.take() {
            for pending in worker.pending.values() {
                pending.cancelled.store(true, Ordering::Release);
                self.callbacks.on_resource_failed(
                    rns_core::types::LinkId(pending.link),
                    "Resource preparation cancelled by shutdown".into(),
                );
            }
            drop(worker); // Join the bounded current codec call; discard queued work/results.
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn submit(worker: &mut Worker, value: u8) {
        let data = vec![value; MIN_INPUT];
        let bytes = Worker::charge(&data, &None).unwrap();
        worker
            .submit([1; 16], Arc::new(()), data, None, bytes)
            .unwrap();
    }

    #[test]
    fn preparation_eligibility_includes_metadata_and_excludes_split_resources() {
        let data = vec![0; MIN_INPUT];
        let mut metadata =
            vec![0; rns_core::constants::RESOURCE_MAX_EFFICIENT_SIZE - MIN_INPUT - 3];
        assert!(Worker::charge(&data, &Some(metadata.clone())).is_some());
        metadata.push(0);
        assert!(Worker::charge(&data, &Some(metadata)).is_none());
        assert!(Worker::charge(&vec![0; MIN_INPUT - 1], &None).is_none());
        assert!(Worker::charge(
            &vec![0; rns_core::constants::RESOURCE_MAX_EFFICIENT_SIZE + 1],
            &None
        )
        .is_none());
    }

    #[test]
    fn preparation_limits_count_owned_capacity_and_keep_cancelled_jobs_charged() {
        let (wake, _rx) = crate::event::channel();
        let (release, gate) = mpsc::channel();
        let mut worker = Worker::start(wake, move |_| {
            gate.recv().unwrap();
            None
        })
        .unwrap();
        let mut large_capacity = Vec::with_capacity(MAX_BYTES / 2);
        large_capacity.resize(MIN_INPUT, 0);
        let bytes = Worker::charge(&large_capacity, &None).unwrap();
        worker
            .submit([1; 16], Arc::new(()), large_capacity, None, bytes)
            .unwrap();
        assert!(!worker.can_submit(bytes));
        worker
            .pending
            .values()
            .next()
            .unwrap()
            .cancelled
            .store(true, Ordering::Release);
        assert!(!worker.can_submit(bytes));
        release.send(()).unwrap();
        worker.receive(true).unwrap();
        assert_eq!(worker.bytes, 0);
        assert!(worker.can_submit(bytes));
    }

    #[test]
    fn preparation_fifo_and_completion_work_with_a_full_control_queue() {
        let (wake, rx) = crate::event::channel_with_capacity(1);
        wake.send(Event::Tick).unwrap();
        let mut worker = Worker::start(wake, |_| None).unwrap();
        for n in 0..MAX_JOBS {
            submit(&mut worker, n as u8);
        }
        assert_eq!(worker.len(), MAX_JOBS);
        assert!(!worker.can_submit(MIN_INPUT * 2));
        for n in 0..MAX_JOBS {
            let (_, ready) = worker.receive(true).unwrap();
            assert_eq!(ready.data[0], n as u8);
        }
        assert_eq!(worker.bytes, 0);
        assert!(matches!(rx.try_recv(), Ok(Event::Tick)));
        drop(worker); // No control-queue receiver needed to join the worker.
    }

    #[test]
    fn preparation_drop_joins_active_job_and_discards_queued_jobs() {
        let (wake, _rx) = crate::event::channel_with_capacity(1);
        wake.send(Event::Tick).unwrap();
        let (entered, started) = mpsc::channel();
        let (release, gate) = mpsc::channel();
        let count = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let calls = count.clone();
        let mut worker = Worker::start(wake, move |_| {
            calls.fetch_add(1, Ordering::Relaxed);
            entered.send(()).unwrap();
            gate.recv().unwrap();
            None
        })
        .unwrap();
        submit(&mut worker, 1);
        started.recv_timeout(Duration::from_secs(5)).unwrap();
        submit(&mut worker, 2);
        // Set shutdown before releasing the running codec, so queued work is skipped.
        worker.stop.store(true, Ordering::Release);
        release.send(()).unwrap();
        drop(worker);
        assert_eq!(count.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn preparation_panic_reports_failure_and_worker_continues() {
        let (wake, _rx) = crate::event::channel();
        let mut worker = Worker::start(wake, |input| {
            assert_ne!(input[0], 1);
            None
        })
        .unwrap();
        submit(&mut worker, 1);
        submit(&mut worker, 2);
        assert!(worker.receive(true).unwrap().1.compressed.is_err());
        assert!(worker.receive(true).unwrap().1.compressed.is_ok());
        assert_eq!(worker.bytes, 0);
    }

    #[derive(Default)]
    struct Monitor(Arc<Mutex<Vec<String>>>);
    impl Callbacks for Monitor {
        fn on_announce(&mut self, _: crate::common::destination::AnnouncedIdentity) {}
        fn on_path_updated(&mut self, _: crate::DestHash, _: u8) {}
        fn on_local_delivery(&mut self, _: crate::DestHash, _: Vec<u8>, _: crate::PacketHash) {}
        fn on_resource_failed(&mut self, _: rns_core::types::LinkId, error: String) {
            self.0.lock().unwrap().push(error);
        }
    }
    fn driver() -> (Driver, [u8; 16], Arc<Mutex<Vec<String>>>) {
        let (tx, rx) = crate::event::channel();
        let errors = Arc::new(Mutex::new(Vec::new()));
        let mut driver = Driver::new(
            super::super::tests::make_transport_config(false),
            rx,
            tx,
            Box::new(Monitor(errors.clone())),
        );
        let (manager, id) = super::super::tests::active_link_manager_with_route(InterfaceId(1));
        driver.link_manager = manager;
        (driver, id, errors)
    }

    #[test]
    fn preparation_fallback_preserves_resource_order_and_drain_tracks_pending() {
        let (mut driver, id, errors) = driver();
        driver.prepare_resource(id, vec![0; MIN_INPUT], None, true);
        assert_eq!(driver.resource_preparation.as_ref().unwrap().len(), 1);
        // A small/uncompressed synchronous send must not overtake the queued send.
        driver.prepare_resource(id, vec![7; 2000], None, false);
        let entries = driver.link_manager.resource_entries();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].total_parts, 1);
        assert!(entries[1].total_parts > 1);
        assert!(errors.lock().unwrap().is_empty());
    }

    #[test]
    fn preparation_saturated_driver_falls_back_after_earlier_sends() {
        let (mut driver, id, errors) = driver();
        // Refuse compression on the worker so its advertisements can be
        // distinguished from the real compressor used by the fallback.
        driver.resource_preparation =
            Some(Worker::start(driver.event_tx.clone(), |_| None).unwrap());
        for _ in 0..MAX_JOBS {
            driver.prepare_resource(id, vec![0; MIN_INPUT], None, true);
        }
        assert_eq!(
            driver.resource_preparation.as_ref().unwrap().len(),
            MAX_JOBS
        );
        driver.prepare_resource(id, vec![0; MIN_INPUT], None, true);
        let entries = driver.link_manager.resource_entries();
        assert_eq!(entries.len(), MAX_JOBS + 1);
        assert!(entries[..MAX_JOBS]
            .iter()
            .all(|entry| entry.total_parts > 1));
        assert_eq!(entries[MAX_JOBS].total_parts, 1);
        assert_eq!(driver.resource_preparation.as_ref().unwrap().bytes, 0);
        assert!(errors.lock().unwrap().is_empty());
    }

    #[test]
    fn preparation_teardown_discards_ready_result_and_releases_budget() {
        let (mut driver, id, errors) = driver();
        driver.prepare_resource(id, vec![0; MIN_INPUT], Some(vec![2, 3]), true);
        driver.link_manager.teardown_link(&id);
        driver.finish_resource_preparations_for(&id);
        assert!(driver.link_manager.resource_entries().is_empty());
        assert_eq!(errors.lock().unwrap().len(), 1);
        assert_eq!(driver.resource_preparation.as_ref().unwrap().bytes, 0);
    }

    #[test]
    fn preparation_cancellation_during_codec_skips_queued_job() {
        let (mut driver, id, errors) = driver();
        let (entered, started) = mpsc::channel();
        let (release, gate) = mpsc::channel();
        let count = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let calls = count.clone();
        driver.resource_preparation = Some(
            Worker::start(driver.event_tx.clone(), move |input| {
                calls.fetch_add(1, Ordering::Relaxed);
                entered.send(()).unwrap();
                gate.recv().unwrap();
                crate::common::compressor::Bzip2Compressor.compress(input)
            })
            .unwrap(),
        );
        driver.prepare_resource(id, vec![0; MIN_INPUT], None, true);
        started.recv_timeout(Duration::from_secs(5)).unwrap();
        driver.prepare_resource(id, vec![1; MIN_INPUT], None, true);
        driver.link_manager.teardown_link(&id);
        driver.poll_resource_preparations();
        assert_eq!(driver.resource_preparation.as_ref().unwrap().len(), 2);
        assert!(driver.resource_preparation.as_ref().unwrap().bytes > 0);
        release.send(()).unwrap();
        driver.finish_resource_preparations_for(&id);
        assert_eq!(count.load(Ordering::Relaxed), 1);
        assert_eq!(errors.lock().unwrap().len(), 2);
        assert!(driver.link_manager.resource_entries().is_empty());
        assert_eq!(driver.resource_preparation.as_ref().unwrap().bytes, 0);
    }

    #[test]
    fn preparation_rejects_result_with_wrong_link_generation() {
        let (mut driver, id, errors) = driver();
        driver.prepare_resource(id, vec![0; MIN_INPUT], None, true);
        let (mut pending, ready) = driver
            .resource_preparation
            .as_mut()
            .unwrap()
            .receive(true)
            .unwrap();
        pending.generation = Arc::new(());
        driver.finish_prepared_resource(pending, ready);
        assert!(driver.link_manager.resource_entries().is_empty());
        assert_eq!(errors.lock().unwrap().len(), 1);
    }

    #[test]
    fn preparation_drain_finishes_accepted_work_and_shutdown_cancels_pending() {
        let (mut driver, id, errors) = driver();
        driver.prepare_resource(id, vec![0; MIN_INPUT], None, true);
        driver.begin_drain(Duration::from_secs(10));
        assert!(driver
            .drain_status()
            .detail
            .unwrap()
            .contains("1 resource transfer"));
        driver.finish_resource_preparations_for(&id);
        assert_eq!(driver.link_manager.resource_transfer_count(), 1);
        assert!(errors.lock().unwrap().is_empty());
        let (mut other, id, errors) = self::driver();
        other.prepare_resource(id, vec![0; MIN_INPUT], None, true);
        other.stop_resource_preparations();
        assert!(other.resource_preparation.is_none());
        assert!(other.link_manager.resource_entries().is_empty());
        assert_eq!(errors.lock().unwrap().len(), 1);
    }
}
