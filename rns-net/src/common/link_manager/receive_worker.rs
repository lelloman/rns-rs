//! Bounded verification of authenticated, single-segment application Resources.
use super::*;
use rns_core::resource::{AssemblyId, AssemblyResult, ResourceAssembly};
use std::collections::BTreeMap;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    mpsc, Arc,
};

const MAX_JOBS: usize = 4;
const MAX_BYTES: usize = 256 * 1024 * 1024;
const MIN_DATA: u64 = 16 * 1024;

struct Job {
    id: u64,
    assembly: ResourceAssembly,
    cancelled: Arc<AtomicBool>,
}
struct Ready {
    id: u64,
    result: Result<Option<AssemblyResult>, ()>,
}
struct Pending {
    link: LinkId,
    generation: Arc<()>,
    assembly: AssemblyId,
    cancelled: Arc<AtomicBool>,
    bytes: usize,
}

pub(super) struct Worker {
    tx: Option<mpsc::SyncSender<Job>>,
    rx: mpsc::Receiver<Ready>,
    handle: Option<std::thread::JoinHandle<()>>,
    stop: Arc<AtomicBool>,
    pending: BTreeMap<u64, Pending>,
    bytes: usize,
    next: u64,
    disconnected: bool,
}
struct WakeOnExit(crate::event::EventSender);
impl Drop for WakeOnExit {
    fn drop(&mut self) {
        let _ = self.0.try_send(crate::event::Event::ResourceAssemblyReady);
    }
}
impl Worker {
    pub(super) fn len(&self) -> usize {
        self.pending.len()
    }
    fn new(wake: crate::event::EventSender) -> std::io::Result<Self> {
        Self::start(wake, |job| job.run(&Bzip2Compressor))
    }
    fn start(
        wake: crate::event::EventSender,
        run: impl Fn(ResourceAssembly) -> AssemblyResult + Send + 'static,
    ) -> std::io::Result<Self> {
        let (tx, jobs) = mpsc::sync_channel::<Job>(MAX_JOBS);
        let (results, rx) = mpsc::sync_channel(MAX_JOBS);
        let stop = Arc::new(AtomicBool::new(false));
        let stopped = stop.clone();
        let handle = std::thread::Builder::new()
            .name("rns-resource-receive".into())
            .spawn(move || {
                // Also wake on an unexpected thread exit. A full control queue is safe:
                // the driver polls this mailbox before receiving its next event.
                let _exit = WakeOnExit(wake.clone());
                while let Ok(job) = jobs.recv() {
                    if stopped.load(Ordering::Acquire) {
                        break;
                    }
                    let result = if job.cancelled.load(Ordering::Acquire) {
                        Ok(None)
                    } else {
                        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| run(job.assembly)))
                            .map(Some)
                            .map_err(|_| ())
                    };
                    if stopped.load(Ordering::Acquire) {
                        break;
                    }
                    // Admission includes completed, unconsumed jobs, so this never
                    // needs to block (including during joined shutdown).
                    if results.try_send(Ready { id: job.id, result }).is_err() {
                        break;
                    }
                    let _ = wake.try_send(crate::event::Event::ResourceAssemblyReady);
                }
            })?;
        Ok(Self {
            tx: Some(tx),
            rx,
            handle: Some(handle),
            stop,
            pending: BTreeMap::new(),
            bytes: 0,
            next: 0,
            disconnected: false,
        })
    }
    fn charge(assembly: &ResourceAssembly) -> Option<usize> {
        // Bzip2Compressor's growable output plus metadata extraction can retain
        // more than the logical output length. Hash/proof verification also uses
        // a temporary input copy. Reserve three output bounds,
        // actual owned input capacity, and fixed job/identity/mailbox overhead.
        // Native decoder workspace, allocator overhead and the thread stack are
        // additional. This is NOT a whole-node RSS limit. Default 64MiB output
        // bounds permit one job; advertised size never reduces that reservation.
        assembly
            .max_output_size()
            .checked_mul(3)?
            .checked_add(assembly.input_capacity())?
            .checked_add(4096)
    }
    fn can_submit(&self, bytes: usize) -> bool {
        !self.disconnected
            && self.next < u64::MAX
            && self.pending.len() < MAX_JOBS
            && bytes <= MAX_BYTES.saturating_sub(self.bytes)
    }
    pub(super) fn submit(
        &mut self,
        link: LinkId,
        generation: Arc<()>,
        assembly: ResourceAssembly,
    ) -> Result<(), ResourceAssembly> {
        let Some(bytes) = Self::charge(&assembly).filter(|bytes| self.can_submit(*bytes)) else {
            return Err(assembly);
        };
        let id = self.next;
        let cancelled = Arc::new(AtomicBool::new(false));
        let pending = Pending {
            link,
            generation,
            assembly: assembly.id().clone(),
            cancelled: cancelled.clone(),
            bytes,
        };
        match self.tx.as_ref().expect("live worker sender").try_send(Job {
            id,
            assembly,
            cancelled,
        }) {
            Ok(()) => {
                self.next += 1;
                self.pending.insert(id, pending);
                self.bytes += bytes;
                Ok(())
            }
            Err(mpsc::TrySendError::Full(job)) => Err(job.assembly),
            Err(mpsc::TrySendError::Disconnected(job)) => {
                self.disconnected = true;
                Err(job.assembly)
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
                self.disconnected = true;
                // Convert lost work into local failures in submission order.
                Ready {
                    id: *self.pending.keys().next()?,
                    result: Err(()),
                }
            }
        };
        let pending = self.pending.remove(&ready.id).expect("known receive job");
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
impl LinkManager {
    pub(crate) fn set_receive_worker_wake(&mut self, wake: crate::event::EventSender) {
        self.receive_worker_wake = Some(wake);
    }
    pub(super) fn ensure_receive_worker(&mut self) {
        self.ensure_receive_worker_with(Worker::new);
    }
    fn ensure_receive_worker_with(
        &mut self,
        start: impl FnOnce(crate::event::EventSender) -> std::io::Result<Worker>,
    ) {
        if self.receive_worker.is_none() {
            if let Some(wake) = &self.receive_worker_wake {
                match start(wake.clone()) {
                    Ok(worker) => self.receive_worker = Some(worker),
                    Err(error) => log::warn!(
                        "Resource receive worker unavailable, using synchronous assembly: {}",
                        error
                    ),
                }
            }
        }
    }
    pub(crate) fn stop_receive_worker(&mut self) {
        self.receive_worker.take();
        self.receive_worker_wake = None;
    }
    fn receive_is_valid(&self, pending: &Pending) -> bool {
        self.links.get(&pending.link).is_some_and(|link| {
            link.engine.state() == LinkState::Active
                && Arc::ptr_eq(&link.resource_generation, &pending.generation)
                && link
                    .incoming_resources
                    .iter()
                    .any(|r| r.assembly_id() == Some(&pending.assembly))
        })
    }
    fn finish_receive(
        &mut self,
        pending: Pending,
        ready: Ready,
        rng: &mut dyn Rng,
    ) -> Vec<LinkManagerAction> {
        if pending.cancelled.load(Ordering::Acquire) || !self.receive_is_valid(&pending) {
            return Vec::new();
        }
        let receiver = self
            .links
            .get_mut(&pending.link)
            .unwrap()
            .incoming_resources
            .iter_mut()
            .find(|r| r.assembly_id() == Some(&pending.assembly))
            .unwrap();
        let actions = match ready.result {
            Ok(Some(result)) => receiver.complete_assembly(result),
            Ok(None) | Err(()) => receiver.fail_assembly(&pending.assembly),
        };
        self.process_resource_actions(&pending.link, actions, rng)
    }
    pub(crate) fn poll_receive_worker(&mut self, rng: &mut dyn Rng) -> Vec<LinkManagerAction> {
        let Some(worker) = &self.receive_worker else {
            return Vec::new();
        };
        for pending in worker.pending.values() {
            if !self.receive_is_valid(pending) {
                pending.cancelled.store(true, Ordering::Release);
            }
        }
        let mut actions = Vec::new();
        while let Some((pending, ready)) =
            self.receive_worker.as_mut().and_then(|w| w.receive(false))
        {
            actions.extend(self.finish_receive(pending, ready, rng));
        }
        if self
            .receive_worker
            .as_ref()
            .is_some_and(|w| w.disconnected && w.pending.is_empty())
        {
            self.receive_worker.take(); // Joined before a later lazy restart.
        }
        actions
    }
    pub(super) fn wait_receive_for(
        &mut self,
        link: &LinkId,
        rng: &mut dyn Rng,
    ) -> Vec<LinkManagerAction> {
        let mut actions = self.poll_receive_worker(rng);
        // Preserve completion order with unsupported/saturated synchronous work.
        // This can block the driver under same-link overload; there is no new
        // rejection policy, nor a fabricated assembly timeout.
        while self
            .receive_worker
            .as_ref()
            .is_some_and(|w| w.pending.values().any(|p| &p.link == link))
        {
            if let Some((pending, ready)) =
                self.receive_worker.as_mut().and_then(|w| w.receive(true))
            {
                actions.extend(self.finish_receive(pending, ready, rng));
            }
        }
        actions
    }
    pub(super) fn receive_offload_eligible(
        link: &ManagedLink,
        receiver: &ResourceReceiver,
    ) -> bool {
        receiver.flags.compressed
            && !receiver.flags.split
            && !receiver.flags.is_request
            && !receiver.flags.is_response
            && receiver.data_size >= MIN_DATA
            && receiver.data_size <= constants::RESOURCE_MAX_EFFICIENT_SIZE as u64
            && matches!(
                link.resource_receive_mode,
                ResourceReceiveMode::Memory { .. }
            )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rns_core::resource::{ResourceError, ResourceStatus};
    use std::time::Duration;

    fn fixture(limit: usize) -> (ResourceReceiver, ResourceAssembly) {
        let mut rng = rns_crypto::OsRng;
        let mut sender = ResourceSender::new(
            &vec![42; 32768],
            Some(b"metadata"),
            constants::RESOURCE_SDU,
            &|x| x.to_vec(),
            &Bzip2Compressor,
            &mut rng,
            1000.,
            true,
            false,
            None,
            1,
            1,
            None,
            0.5,
            6.,
        )
        .unwrap();
        let mut receiver = ResourceReceiver::from_advertisement(
            &sender.get_advertisement(0),
            constants::RESOURCE_SDU,
            0.5,
            1000.,
            None,
            None,
        )
        .unwrap();
        receiver.max_decompressed_size = limit;
        for action in receiver.accept(1001.) {
            if let ResourceAction::SendRequest(request) = action {
                for action in sender.handle_request(&request, 1002.) {
                    if let ResourceAction::SendPart(part) = action {
                        receiver.receive_part(&part, 1003.);
                    }
                }
            }
        }
        let job = receiver
            .prepare_assembly(&|data| {
                let mut owned = Vec::with_capacity(4096);
                owned.extend_from_slice(data);
                Ok(owned)
            })
            .unwrap();
        (receiver, job)
    }
    fn submit(worker: &mut Worker) {
        let (_, job) = fixture(65536);
        assert!(worker.submit([1; 16], Arc::new(()), job).is_ok());
    }
    #[test]
    fn receive_worker_admission_accounts_capacity_bounds_and_retained_completions() {
        let (wake, _rx) = crate::event::channel();
        let mut worker = Worker::new(wake).unwrap();
        assert!(worker.can_submit(MAX_BYTES));
        assert!(!worker.can_submit(MAX_BYTES + 1));
        let (_, job) = fixture(constants::RESOURCE_AUTO_COMPRESS_MAX_SIZE);
        let charge = Worker::charge(&job).unwrap();
        assert_eq!(
            charge,
            3 * constants::RESOURCE_AUTO_COMPRESS_MAX_SIZE + 4096 + 4096
        );
        assert!(worker.submit([1; 16], Arc::new(()), job).is_ok());
        assert_eq!(worker.bytes, charge);
        assert!(!worker.can_submit(charge));
        let (_, retry) = fixture(constants::RESOURCE_AUTO_COMPRESS_MAX_SIZE);
        let id = retry.id().clone();
        let retry = worker.submit([2; 16], Arc::new(()), retry).err().unwrap();
        assert_eq!(retry.id(), &id);
        worker.pending[&0].cancelled.store(true, Ordering::Release);
        assert_eq!(worker.bytes, charge);
        worker.receive(true).unwrap();
        assert_eq!(worker.bytes, 0);
        let (_, overflow) = fixture(usize::MAX);
        assert!(Worker::charge(&overflow).is_none());
        worker.next = u64::MAX;
        assert!(!worker.can_submit(1));
    }
    #[test]
    fn receive_worker_fifo_full_wake_queue_and_queued_cancellation() {
        let (wake, rx) = crate::event::channel_with_capacity(1);
        wake.send(crate::event::Event::Tick).unwrap();
        let (release, gate) = mpsc::channel();
        let (entered, started) = mpsc::channel();
        let mut worker = Worker::start(wake, move |job| {
            entered.send(()).unwrap();
            gate.recv().unwrap();
            job.run(&Bzip2Compressor)
        })
        .unwrap();
        submit(&mut worker);
        started.recv_timeout(Duration::from_secs(2)).unwrap();
        for _ in 1..MAX_JOBS {
            submit(&mut worker);
        }
        worker.pending[&1].cancelled.store(true, Ordering::Release);
        assert_eq!(worker.len(), MAX_JOBS);
        assert!(!worker.can_submit(1));
        release.send(()).unwrap();
        for id in 0..MAX_JOBS as u64 {
            if id > 1 {
                started.recv_timeout(Duration::from_secs(2)).unwrap();
                release.send(()).unwrap();
            }
            let (_, ready) = worker.receive(true).unwrap();
            assert_eq!(ready.id, id);
            if id == 1 {
                assert!(matches!(ready.result, Ok(None)));
            }
        }
        assert_eq!(worker.bytes, 0);
        assert!(matches!(rx.try_recv(), Ok(crate::event::Event::Tick)));
    }
    #[test]
    fn receive_worker_drop_joins_active_codec_and_discards_queue() {
        let (wake, _rx) = crate::event::channel();
        let (release, gate) = mpsc::channel();
        let (entered, started) = mpsc::channel();
        let mut worker = Worker::start(wake, move |job| {
            entered.send(()).unwrap();
            gate.recv().unwrap();
            job.run(&Bzip2Compressor)
        })
        .unwrap();
        submit(&mut worker);
        submit(&mut worker);
        started.recv_timeout(Duration::from_secs(2)).unwrap();
        let stopped = worker.stop.clone();
        let join = std::thread::spawn(move || drop(worker));
        while !stopped.load(Ordering::Acquire) {
            std::thread::yield_now();
        }
        assert!(!join.is_finished());
        release.send(()).unwrap();
        join.join().unwrap();
        assert!(started.try_recv().is_err());
    }
    #[test]
    fn receive_worker_panic_is_local_failure_and_next_job_runs() {
        let (wake, _rx) = crate::event::channel();
        let calls = std::sync::atomic::AtomicUsize::new(0);
        let mut worker = Worker::start(wake, move |job| {
            if calls.fetch_add(1, Ordering::SeqCst) == 0 {
                panic!("injected");
            }
            job.run(&Bzip2Compressor)
        })
        .unwrap();
        submit(&mut worker);
        submit(&mut worker);
        assert!(worker.receive(true).unwrap().1.result.is_err());
        assert!(matches!(
            worker.receive(true).unwrap().1.result,
            Ok(Some(_))
        ));
    }
    fn disconnected_worker() -> Worker {
        let (tx, jobs) = mpsc::sync_channel(MAX_JOBS);
        drop(jobs);
        let (results, rx) = mpsc::sync_channel(MAX_JOBS);
        drop(results);
        Worker {
            tx: Some(tx),
            rx,
            handle: None,
            stop: Arc::new(AtomicBool::new(false)),
            pending: BTreeMap::new(),
            bytes: 0,
            next: 0,
            disconnected: false,
        }
    }
    #[test]
    fn receive_worker_disconnection_returns_input_and_failed_jobs_in_order() {
        let mut worker = disconnected_worker();
        let (_, job) = fixture(65536);
        let id = job.id().clone();
        assert_eq!(
            worker
                .submit([1; 16], Arc::new(()), job)
                .err()
                .unwrap()
                .id(),
            &id
        );
        assert!(!worker.can_submit(1));
        for n in [2, 0, 1] {
            let (_, job) = fixture(65536);
            worker.pending.insert(
                n,
                Pending {
                    link: [1; 16],
                    generation: Arc::new(()),
                    assembly: job.id().clone(),
                    cancelled: Arc::new(AtomicBool::new(false)),
                    bytes: 10,
                },
            );
            worker.bytes += 10;
        }
        for n in 0..3 {
            let (_, ready) = worker.receive(false).unwrap();
            assert_eq!(ready.id, n);
            assert!(ready.result.is_err());
        }
        assert!(worker.receive(false).is_none());
        assert_eq!(worker.bytes, 0);
    }
    #[test]
    fn receive_worker_lazy_start_failure_and_recovery() {
        let mut manager = LinkManager::new();
        manager
            .ensure_receive_worker_with(|_| panic!("unconfigured manager must stay synchronous"));
        let (wake, _rx) = crate::event::channel();
        manager.set_receive_worker_wake(wake);
        assert!(manager.receive_worker.is_none());
        manager
            .ensure_receive_worker_with(|_| Err(std::io::Error::other("injected start failure")));
        assert!(manager.receive_worker.is_none());
        manager.receive_worker = Some(disconnected_worker());
        assert!(manager
            .poll_receive_worker(&mut rns_crypto::OsRng)
            .is_empty());
        assert!(manager.receive_worker.is_none());
        manager.ensure_receive_worker();
        assert!(manager.receive_worker.is_some());
        manager.stop_receive_worker();
        assert!(manager.receive_worker.is_none());
    }
    #[test]
    fn receive_worker_generation_cancellation_shutdown_and_transfer_accounting() {
        for mode in [
            "success",
            "generation",
            "cancel",
            "cancel_all",
            "teardown",
            "resource",
            "lost",
        ] {
            let (_, mut manager, link) = super::super::tests::setup_active_link();
            let (wake, _rx) = crate::event::channel();
            let (release, gate) = mpsc::channel();
            let (entered, started) = mpsc::channel();
            manager.receive_worker = Some(
                Worker::start(wake, move |job| {
                    entered.send(()).unwrap();
                    gate.recv().unwrap();
                    job.run(&Bzip2Compressor)
                })
                .unwrap(),
            );
            let (receiver, job) = fixture(65536);
            assert!(manager
                .receive_worker
                .as_mut()
                .unwrap()
                .submit(link, manager.links[&link].resource_generation.clone(), job)
                .is_ok());
            manager
                .links
                .get_mut(&link)
                .unwrap()
                .incoming_resources
                .push(receiver);
            started.recv_timeout(Duration::from_secs(2)).unwrap();
            let mut rng = rns_crypto::OsRng;
            assert_eq!(manager.resource_transfer_count(), 1);
            manager.tick(&mut rng);
            assert_eq!(manager.resource_transfer_count(), 1);
            match mode {
                "generation" => {
                    manager.links.get_mut(&link).unwrap().resource_generation = Arc::new(())
                }
                "cancel" => {
                    manager.handle_resource_icl(&link);
                }
                "cancel_all" => {
                    manager.cancel_all_resources(&mut rng);
                }
                "teardown" => {
                    manager.teardown_link(&link);
                }
                "resource" => {
                    let (replacement, _) = fixture(65536);
                    manager.links.get_mut(&link).unwrap().incoming_resources[0] = replacement;
                }
                _ => {}
            }
            assert!(manager.poll_receive_worker(&mut rng).is_empty());
            assert!(manager.receive_worker.as_ref().unwrap().bytes > 0);
            release.send(()).unwrap();
            let (pending, mut ready) = manager
                .receive_worker
                .as_mut()
                .unwrap()
                .receive(true)
                .unwrap();
            if mode == "lost" {
                ready.result = Err(());
            }
            let actions = manager.finish_receive(pending, ready, &mut rng);
            assert_eq!(
                actions
                    .iter()
                    .filter(|a| matches!(a, LinkManagerAction::ResourceReceived { .. }))
                    .count(),
                usize::from(mode == "success")
            );
            if mode == "lost" {
                assert!(actions
                    .iter()
                    .any(|a| matches!(a, LinkManagerAction::ResourceFailed { .. })));
                assert_eq!(manager.link_state(&link), Some(LinkState::Active));
            }
            assert_eq!(manager.receive_worker.as_ref().unwrap().bytes, 0);
        }
    }
    #[test]
    fn receive_worker_driver_drain_deadline_and_shutdown_join_before_returning() {
        struct Monitor;
        impl crate::Callbacks for Monitor {
            fn on_announce(&mut self, _: crate::common::destination::AnnouncedIdentity) {}
            fn on_path_updated(&mut self, _: crate::DestHash, _: u8) {}
            fn on_local_delivery(&mut self, _: crate::DestHash, _: Vec<u8>, _: crate::PacketHash) {}
        }
        for shutdown in [false, true] {
            let (_, manager, link) = super::super::tests::setup_active_link();
            let (wake, rx) = crate::event::channel();
            let mut driver = crate::driver::Driver::new(
                crate::driver::tests::make_transport_config(false),
                rx,
                wake.clone(),
                Box::new(Monitor),
            );
            driver.link_manager = manager;
            let (release, gate) = mpsc::channel();
            let (entered, started) = mpsc::channel();
            let mut worker = Worker::start(wake, move |job| {
                entered.send(()).unwrap();
                gate.recv().unwrap();
                job.run(&Bzip2Compressor)
            })
            .unwrap();
            let stop = worker.stop.clone();
            let (receiver, job) = fixture(65536);
            assert!(worker
                .submit(
                    link,
                    driver.link_manager.links[&link].resource_generation.clone(),
                    job
                )
                .is_ok());
            driver
                .link_manager
                .links
                .get_mut(&link)
                .unwrap()
                .incoming_resources
                .push(receiver);
            driver.link_manager.receive_worker = Some(worker);
            started.recv_timeout(Duration::from_secs(2)).unwrap();
            driver.begin_drain(Duration::from_secs(10));
            assert!(!driver.drain_status().drain_complete);
            assert!(driver
                .drain_status()
                .detail
                .unwrap()
                .contains("1 resource transfer"));
            if !shutdown {
                driver.begin_drain(Duration::ZERO);
            }
            let (finished, done) = mpsc::channel();
            let join = std::thread::spawn(move || {
                if shutdown {
                    driver.graceful_shutdown();
                } else {
                    driver.enforce_drain_deadline();
                }
                assert!(driver.link_manager.receive_worker.is_none());
                assert_eq!(driver.link_manager.resource_transfer_count(), 0);
                assert!(driver.drain_status().drain_complete);
                finished.send(()).unwrap();
            });
            let deadline = std::time::Instant::now() + Duration::from_secs(2);
            while !stop.load(Ordering::Acquire) && std::time::Instant::now() < deadline {
                std::thread::yield_now();
            }
            assert!(stop.load(Ordering::Acquire));
            assert!(matches!(done.try_recv(), Err(mpsc::TryRecvError::Empty)));
            release.send(()).unwrap();
            done.recv_timeout(Duration::from_secs(2)).unwrap();
            join.join().unwrap();
        }
    }

    fn deliver(
        manager: &mut LinkManager,
        actions: Vec<LinkManagerAction>,
    ) -> Vec<LinkManagerAction> {
        let mut out = Vec::new();
        for action in actions {
            if let LinkManagerAction::SendPacket { raw, .. } = action {
                let packet = RawPacket::unpack(&raw).unwrap();
                out.extend(manager.handle_local_delivery(
                    packet.destination_hash,
                    &raw,
                    packet.packet_hash,
                    rns_core::transport::types::InterfaceId(0),
                    &mut rns_crypto::OsRng,
                ));
            }
        }
        out
    }
    fn resource_parts(
        sender: &mut LinkManager,
        receiver: &mut LinkManager,
        link: &LinkId,
        byte: u8,
        compressed: bool,
    ) -> Vec<LinkManagerAction> {
        let data = vec![byte; if compressed { 32768 } else { 32 }];
        let adv = sender.send_resource_with_auto_compress(
            link,
            &data,
            None,
            compressed,
            &mut rns_crypto::OsRng,
        );
        let requests = deliver(receiver, adv);
        deliver(sender, requests)
    }
    #[test]
    fn receive_worker_same_link_barrier_preserves_supported_and_fallback_order() {
        for compressed in [false, true] {
            let (mut sender, mut receiver, link) = super::super::tests::setup_active_link();
            receiver.set_resource_strategy(&link, ResourceStrategy::AcceptAll);
            let (wake, _rx) = crate::event::channel();
            let (release, gate) = mpsc::channel();
            let (entered, started) = mpsc::channel();
            let count = std::sync::atomic::AtomicUsize::new(0);
            receiver.receive_worker = Some(
                Worker::start(wake, move |job| {
                    if count.fetch_add(1, Ordering::SeqCst) == 0 {
                        entered.send(()).unwrap();
                        gate.recv().unwrap();
                    }
                    job.run(&Bzip2Compressor)
                })
                .unwrap(),
            );
            let parts = resource_parts(&mut sender, &mut receiver, &link, 1, true);
            let initial = deliver(&mut receiver, parts);
            assert!(!initial
                .iter()
                .any(|a| matches!(a, LinkManagerAction::ResourceReceived { .. })));
            started.recv_timeout(Duration::from_secs(2)).unwrap();
            let parts = resource_parts(&mut sender, &mut receiver, &link, 2, compressed);
            let (finished, result) = mpsc::channel();
            let thread = std::thread::spawn(move || {
                let mut actions = deliver(&mut receiver, parts);
                actions.extend(receiver.wait_receive_for(&link, &mut rns_crypto::OsRng));
                let data: Vec<_> = actions
                    .into_iter()
                    .filter_map(|a| match a {
                        LinkManagerAction::ResourceReceived { data, .. } => Some(data[0]),
                        _ => None,
                    })
                    .collect();
                finished.send(data).unwrap();
            });
            assert!(matches!(
                result.recv_timeout(Duration::from_millis(30)),
                Err(mpsc::RecvTimeoutError::Timeout)
            ));
            release.send(()).unwrap();
            assert_eq!(
                result.recv_timeout(Duration::from_secs(2)).unwrap(),
                vec![1, 2]
            );
            thread.join().unwrap();
        }
    }
    #[test]
    fn receive_worker_pending_application_delivery_survives_request_response_conversion() {
        for response in [false, true] {
            let (mut sender, mut receiver, link) = super::super::tests::setup_active_link();
            receiver.set_resource_strategy(&link, ResourceStrategy::AcceptAll);
            let called = Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let observed = called.clone();
            receiver.register_request_handler("/worker", None, move |_, _, _, _| {
                observed.fetch_add(1, Ordering::SeqCst);
                None
            });
            let (wake, _rx) = crate::event::channel();
            let (release, gate) = mpsc::channel();
            let (entered, started) = mpsc::channel();
            receiver.receive_worker = Some(
                Worker::start(wake, move |job| {
                    entered.send(()).unwrap();
                    gate.recv().unwrap();
                    job.run(&Bzip2Compressor)
                })
                .unwrap(),
            );
            let parts = resource_parts(&mut sender, &mut receiver, &link, 1, true);
            deliver(&mut receiver, parts);
            started.recv_timeout(Duration::from_secs(2)).unwrap();
            let data = rns_core::msgpack::pack(&rns_core::msgpack::Value::Bin(vec![2; 32768]));
            let adv = if response {
                receiver
                    .links
                    .get_mut(&link)
                    .unwrap()
                    .pending_requests
                    .insert(
                        [7; 16],
                        PendingRequest {
                            deadline: None,
                            max_response_size: None,
                        },
                    );
                sender.send_response_resource(
                    &link,
                    &[7; 16],
                    &data,
                    None,
                    true,
                    &mut rns_crypto::OsRng,
                )
            } else {
                sender.send_request(&link, "/worker", &data, &mut rns_crypto::OsRng)
            };
            let requests = deliver(&mut receiver, adv);
            let parts = deliver(&mut sender, requests);
            let (finished, result) = mpsc::channel();
            let join = std::thread::spawn(move || {
                finished.send(deliver(&mut receiver, parts)).unwrap();
            });
            assert!(matches!(
                result.recv_timeout(Duration::from_millis(30)),
                Err(mpsc::RecvTimeoutError::Timeout)
            ));
            release.send(()).unwrap();
            let actions = result.recv_timeout(Duration::from_secs(2)).unwrap();
            join.join().unwrap();
            let application: Vec<_> = actions
                .iter()
                .filter_map(|a| match a {
                    LinkManagerAction::ResourceReceived { data, .. } => Some(data),
                    _ => None,
                })
                .collect();
            assert_eq!(application.len(), 1);
            assert_eq!(application[0], &vec![1; 32768]);
            if response {
                assert!(actions.iter().any(|a| matches!(a, LinkManagerAction::ResponseReceived { data: received, .. } if received == &data)));
            } else {
                assert_eq!(called.load(Ordering::SeqCst), 1);
            }
        }
    }

    #[test]
    fn receive_worker_other_link_saturation_assembles_synchronously_without_dropping() {
        let (mut sender, mut receiver, link) = super::super::tests::setup_active_link();
        receiver.set_resource_strategy(&link, ResourceStrategy::AcceptAll);
        let (wake, _rx) = crate::event::channel();
        let (release, gate) = mpsc::channel();
        let (entered, started) = mpsc::channel();
        let mut worker = Worker::start(wake, move |job| {
            entered.send(()).unwrap();
            gate.recv().unwrap();
            job.run(&Bzip2Compressor)
        })
        .unwrap();
        let (_, job) = fixture(constants::RESOURCE_AUTO_COMPRESS_MAX_SIZE);
        assert!(worker.submit([99; 16], Arc::new(()), job).is_ok());
        started.recv_timeout(Duration::from_secs(2)).unwrap();
        let charged = worker.bytes;
        receiver.receive_worker = Some(worker);
        let parts = resource_parts(&mut sender, &mut receiver, &link, 3, true);
        let actions = deliver(&mut receiver, parts);
        assert!(actions.iter().any(|a| matches!(a, LinkManagerAction::ResourceReceived { data, .. } if data==&vec![3;32768])));
        assert_eq!(receiver.receive_worker.as_ref().unwrap().bytes, charged);
        release.send(()).unwrap();
        assert!(receiver
            .wait_receive_for(&[99; 16], &mut rns_crypto::OsRng)
            .is_empty());
        assert_eq!(receiver.receive_worker.as_ref().unwrap().bytes, 0);
    }

    #[test]
    fn receive_worker_eligibility_and_corrupt_completion() {
        let (_, mut manager, link) = super::super::tests::setup_active_link();
        let (mut receiver, job) = fixture(16);
        assert!(LinkManager::receive_offload_eligible(
            &manager.links[&link],
            &receiver
        ));
        receiver.flags.is_request = true;
        assert!(!LinkManager::receive_offload_eligible(
            &manager.links[&link],
            &receiver
        ));
        receiver.flags.is_request = false;
        receiver.flags.split = true;
        assert!(!LinkManager::receive_offload_eligible(
            &manager.links[&link],
            &receiver
        ));
        receiver.flags.split = false;
        receiver.flags.is_response = true;
        assert!(!LinkManager::receive_offload_eligible(
            &manager.links[&link],
            &receiver
        ));
        receiver.flags.is_response = false;
        receiver.flags.compressed = false;
        assert!(!LinkManager::receive_offload_eligible(
            &manager.links[&link],
            &receiver
        ));
        receiver.flags.compressed = true;
        receiver.data_size = MIN_DATA - 1;
        assert!(!LinkManager::receive_offload_eligible(
            &manager.links[&link],
            &receiver
        ));
        receiver.data_size = constants::RESOURCE_MAX_EFFICIENT_SIZE as u64 + 1;
        assert!(!LinkManager::receive_offload_eligible(
            &manager.links[&link],
            &receiver
        ));
        let actions = receiver.complete_assembly(job.run(&Bzip2Compressor));
        assert!(actions
            .iter()
            .any(|a| matches!(a, ResourceAction::Failed(ResourceError::TooLarge))));
        assert_eq!(receiver.status, ResourceStatus::Corrupt);
        let actions = manager.process_resource_actions(&link, actions, &mut rns_crypto::OsRng);
        assert!(!actions.iter().any(|a| matches!(
            a,
            LinkManagerAction::ResourceReceived { .. }
                | LinkManagerAction::ResourceCompleted { .. }
        )));
        assert_eq!(manager.link_state(&link), Some(LinkState::Closed));
    }
}
