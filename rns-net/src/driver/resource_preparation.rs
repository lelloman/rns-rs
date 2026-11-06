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
    app_flag: bool,
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
        app_flag: bool,
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
                        app_flag,
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

/// bzip2 level of the compact engine's folded compression, which runs on the
/// driver loop one bzip2 block at a time (`compact-threads-work` keeps the
/// worker thread instead, at the codec's default level 6).
///
/// bzip2 sorts each block in a single call, so one block is the smallest
/// slice a compression can be cut into, and the driver handles no packet
/// while it runs. Level 1 means 100 kB blocks: about 10 ms of work each on a
/// desktop core, and several times that on a small device. Level 6 would
/// mean 600 kB blocks and stalls six times as long. The output is ordinary
/// bzip2, which any node decompresses; on the data measured it was between
/// 11% smaller (JSON) and 16% larger (source text) than level 6's, at about
/// the same total CPU time.
const FOLDED_COMPRESSION_LEVEL: u32 = 1;

/// Input fed to the folded compressor per slice: one level-1 block.
const FOLDED_BLOCK_BYTES: usize = 100_000;

/// A compression the compact engine's driver runs in slices.
pub(crate) struct FoldedCompression {
    id: u64,
    pending: Pending,
    data: Vec<u8>,
    metadata: Option<Vec<u8>>,
    /// The metadata-prefixed input, when there is metadata.
    prefixed: Option<Vec<u8>>,
    consumed: usize,
    encoder: bzip2::Compress,
    output: Vec<u8>,
}

impl FoldedCompression {
    fn new(id: u64, pending: Pending, data: Vec<u8>, metadata: Option<Vec<u8>>) -> Self {
        let prefixed = metadata
            .as_ref()
            .map(|m| rns_core::resource::parts::prepend_metadata(&data, m));
        FoldedCompression {
            id,
            pending,
            data,
            metadata,
            prefixed,
            consumed: 0,
            encoder: bzip2::Compress::new(bzip2::Compression::new(FOLDED_COMPRESSION_LEVEL), 30),
            output: Vec::new(),
        }
    }

    fn input(&self) -> &[u8] {
        self.prefixed.as_deref().unwrap_or(&self.data)
    }

    /// Compress the next block. Returns the finished result once the input
    /// is consumed and the stream closed, or at once when cancelled.
    fn step(&mut self) -> Option<(Pending, Ready)> {
        let compressed = if self.pending.cancelled.load(Ordering::Acquire) {
            Ok(None)
        } else {
            match self.compress_block() {
                Ok(false) => return None,
                Ok(true) => {
                    let input_len = self.input().len();
                    let output = core::mem::take(&mut self.output);
                    // Kept only when it saves space, as the worker does.
                    Ok((output.len() < input_len).then(|| output.into_boxed_slice()))
                }
                Err(error) => Err(format!("Resource compression failed: {error}")),
            }
        };
        Some((
            Pending {
                link: self.pending.link,
                generation: Arc::clone(&self.pending.generation),
                cancelled: Arc::clone(&self.pending.cancelled),
                bytes: self.pending.bytes,
                app_flag: self.pending.app_flag,
            },
            Ready {
                id: self.id,
                data: core::mem::take(&mut self.data),
                metadata: self.metadata.take(),
                compressed,
            },
        ))
    }

    /// Feed one block of input (and, with the last one, close the stream).
    /// Returns whether the stream is complete.
    fn compress_block(&mut self) -> Result<bool, bzip2::Error> {
        let input_len = self.input().len();
        let end = (self.consumed + FOLDED_BLOCK_BYTES).min(input_len);
        let action = if end == input_len {
            bzip2::Action::Finish
        } else {
            bzip2::Action::Run
        };
        loop {
            if self.output.capacity() - self.output.len() < 16 * 1024 {
                self.output.reserve(64 * 1024);
            }
            let before = self.encoder.total_in();
            let input = self.prefixed.as_deref().unwrap_or(&self.data);
            let status =
                self.encoder
                    .compress_vec(&input[self.consumed..end], &mut self.output, action)?;
            self.consumed += (self.encoder.total_in() - before) as usize;
            match (action, status) {
                (bzip2::Action::Finish, bzip2::Status::StreamEnd) => return Ok(true),
                (bzip2::Action::Run, _) if self.consumed == end => return Ok(false),
                _ => {}
            }
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
    #[cfg(test)]
    pub(super) fn prepare_resource(
        &mut self,
        link: [u8; 16],
        data: Vec<u8>,
        metadata: Option<Vec<u8>>,
        auto_compress: bool,
    ) {
        self.prepare_resource_with_options(
            link,
            data,
            metadata,
            crate::resource::ResourceSendOptions {
                auto_compress,
                ..Default::default()
            },
        );
    }

    pub(super) fn prepare_resource_with_options(
        &mut self,
        link: [u8; 16],
        mut data: Vec<u8>,
        mut metadata: Option<Vec<u8>>,
        options: crate::resource::ResourceSendOptions,
    ) {
        if let Some((generation, bytes)) = options
            .auto_compress
            .then(|| {
                self.link_manager
                    .resource_generation(&link)
                    .zip(Worker::charge(&data, &metadata))
            })
            .flatten()
            .filter(|(_, bytes)| *bytes <= MAX_BYTES)
        {
            let folded_room = crate::engine::FOLD_WORK
                && self.folded.compressions.len() < MAX_JOBS
                && bytes
                    <= MAX_BYTES.saturating_sub(
                        self.folded
                            .compressions
                            .iter()
                            .map(|job| job.pending.bytes)
                            .sum(),
                    );
            if folded_room {
                // Compressed on the driver loop, one block per idle turn,
                // within the worker's budget; past it, the synchronous path
                // below runs after this link's queued compressions.
                let id = self.folded.next_compression_id;
                self.folded.next_compression_id = id.wrapping_add(1);
                let pending = Pending {
                    link,
                    generation,
                    cancelled: Arc::new(AtomicBool::new(false)),
                    bytes,
                    app_flag: options.app_flag,
                };
                self.folded
                    .compressions
                    .push_back(FoldedCompression::new(id, pending, data, metadata));
                return;
            }
            if !crate::engine::FOLD_WORK && self.resource_preparation.is_none() {
                match Worker::new(self.event_tx.clone()) {
                    Ok(worker) => self.resource_preparation = Some(worker),
                    Err(error) => log::warn!(
                        "Resource worker unavailable, using synchronous preparation: {}",
                        error
                    ),
                }
            }
            if let Some(worker) = self.resource_preparation.as_mut() {
                match worker.submit(link, generation, data, metadata, bytes, options.app_flag) {
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
        let actions = self.link_manager.send_resource_with_options(
            &link,
            &data,
            metadata.as_deref(),
            options,
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
                    crate::resource::ResourceSendOptions {
                        auto_compress: true,
                        app_flag: pending.app_flag,
                    },
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

    /// Run one slice of the oldest folded compression, completing it when
    /// it is done.
    pub(super) fn step_folded_compression(&mut self) {
        let Some(job) = self.folded.compressions.front_mut() else {
            return;
        };
        if !self
            .link_manager
            .resource_generation(&job.pending.link)
            .is_some_and(|current| Arc::ptr_eq(&current, &job.pending.generation))
        {
            job.pending.cancelled.store(true, Ordering::Release);
        }
        if let Some((pending, ready)) = job.step() {
            self.folded.compressions.pop_front();
            self.finish_prepared_resource(pending, ready);
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
        // Folded compressions run in order, so finishing this link's means
        // finishing every one queued before them too.
        while self
            .folded
            .compressions
            .iter()
            .any(|job| &job.pending.link == link)
        {
            self.step_folded_compression();
        }
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
        for job in core::mem::take(&mut self.folded.compressions) {
            self.callbacks.on_resource_failed(
                rns_core::types::LinkId(job.pending.link),
                "Resource preparation cancelled by shutdown".into(),
            );
        }
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

    fn folded(data: Vec<u8>, metadata: Option<Vec<u8>>) -> FoldedCompression {
        let pending = Pending {
            link: [1; 16],
            generation: Arc::new(()),
            cancelled: Arc::new(AtomicBool::new(false)),
            bytes: data.len(),
            app_flag: false,
        };
        FoldedCompression::new(0, pending, data, metadata)
    }

    #[test]
    fn folded_compression_round_trips_one_block_per_slice() {
        let text: Vec<u8> = (0..rns_core::constants::RESOURCE_MAX_EFFICIENT_SIZE)
            .map(|i| b"compact engines fold work into the loop "[i % 40] ^ (i / 997) as u8)
            .collect();
        for (len, metadata) in [
            (MIN_INPUT, None),
            (250_000, Some(b"meta".to_vec())),
            (300_000, None),
            (text.len(), None),
        ] {
            let data = text[..len].to_vec();
            let mut job = folded(data.clone(), metadata.clone());
            let mut slices = 0;
            let (pending, ready) = loop {
                let before = job.consumed;
                slices += 1;
                if let Some(done) = job.step() {
                    break done;
                }
                assert!(job.consumed - before <= FOLDED_BLOCK_BYTES);
            };
            let input = metadata
                .as_ref()
                .map(|m| rns_core::resource::parts::prepend_metadata(&data, m))
                .unwrap_or_else(|| data.clone());
            assert_eq!(
                slices,
                input.len().div_ceil(FOLDED_BLOCK_BYTES),
                "len {len}"
            );
            assert_eq!(ready.data, data);
            assert_eq!(ready.metadata, metadata);
            assert_eq!(pending.link, [1; 16]);
            let compressed = ready.compressed.unwrap().expect("compressible input");
            let restored = crate::common::compressor::Bzip2Compressor
                .decompress_bounded(&compressed, usize::MAX)
                .unwrap();
            assert_eq!(restored, input, "len {len}");
        }
    }

    #[test]
    fn folded_compression_stops_when_cancelled() {
        let mut job = folded(vec![7; 300_000], None);
        assert!(job.step().is_none());
        job.pending.cancelled.store(true, Ordering::Release);
        let (_, ready) = job.step().expect("a cancelled job ends at once");
        assert_eq!(ready.compressed, Ok(None));
    }

    fn submit(worker: &mut Worker, value: u8) {
        let data = vec![value; MIN_INPUT];
        let bytes = Worker::charge(&data, &None).unwrap();
        worker
            .submit([1; 16], Arc::new(()), data, None, bytes, false)
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
            .submit([1; 16], Arc::new(()), large_capacity, None, bytes, false)
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

    #[cfg(not(any(feature = "engine-parallel", feature = "compact-threads-work")))]
    #[test]
    fn folded_preparation_keeps_resource_order_on_the_link() {
        let (mut driver, id, errors) = driver();
        driver.prepare_resource(id, vec![0; MIN_INPUT], None, true);
        assert!(driver.resource_preparation.is_none(), "no worker thread");
        assert_eq!(driver.folded.compressions.len(), 1);
        // A synchronous send must not overtake the queued compression.
        driver.prepare_resource(id, vec![7; 2000], None, false);
        assert!(driver.folded.compressions.is_empty());
        let entries = driver.link_manager.resource_entries();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].total_parts, 1);
        assert!(entries[1].total_parts > 1);
        assert!(errors.lock().unwrap().is_empty());
    }

    #[cfg(not(any(feature = "engine-parallel", feature = "compact-threads-work")))]
    #[test]
    fn folded_preparation_keeps_the_worker_budget() {
        let (mut driver, id, errors) = driver();
        for _ in 0..MAX_JOBS {
            driver.prepare_resource(id, vec![0; MIN_INPUT], None, true);
        }
        assert_eq!(driver.folded.compressions.len(), MAX_JOBS);
        // Past the budget the send runs synchronously, after the queued ones.
        driver.prepare_resource(id, vec![0; MIN_INPUT], None, true);
        assert!(driver.folded.compressions.is_empty());
        let entries = driver.link_manager.resource_entries();
        assert_eq!(entries.len(), MAX_JOBS + 1);
        assert!(entries.iter().all(|entry| entry.total_parts == 1));
        assert!(errors.lock().unwrap().is_empty());
    }

    #[cfg(not(any(feature = "engine-parallel", feature = "compact-threads-work")))]
    #[test]
    fn folded_preparation_fails_when_the_link_is_torn_down() {
        let (mut driver, id, errors) = driver();
        driver.prepare_resource(id, vec![0; MIN_INPUT], Some(vec![2, 3]), true);
        driver.link_manager.teardown_link(&id);
        driver.finish_resource_preparations_for(&id);
        assert!(driver.link_manager.resource_entries().is_empty());
        assert_eq!(errors.lock().unwrap().len(), 1);
    }

    #[cfg(not(any(feature = "engine-parallel", feature = "compact-threads-work")))]
    #[test]
    fn folded_preparation_fails_pending_work_at_shutdown() {
        let (mut driver, id, errors) = driver();
        driver.prepare_resource(id, vec![0; MIN_INPUT], None, true);
        driver.stop_resource_preparations();
        assert!(driver.folded.compressions.is_empty());
        assert_eq!(
            errors.lock().unwrap().as_slice(),
            ["Resource preparation cancelled by shutdown"]
        );
    }

    #[cfg(any(feature = "engine-parallel", feature = "compact-threads-work"))]
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

    #[cfg(any(feature = "engine-parallel", feature = "compact-threads-work"))]
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

    #[cfg(any(feature = "engine-parallel", feature = "compact-threads-work"))]
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

    #[cfg(any(feature = "engine-parallel", feature = "compact-threads-work"))]
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

    #[cfg(any(feature = "engine-parallel", feature = "compact-threads-work"))]
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

    #[cfg(any(feature = "engine-parallel", feature = "compact-threads-work"))]
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
