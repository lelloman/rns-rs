//! One worker per adopted host interface, started and stopped as they
//! come and go.

use super::*;

#[cfg_attr(not(test), allow(dead_code))]
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(super) struct AutoWorkerKey {
    pub(super) ifname: String,
    pub(super) if_index: u32,
    pub(super) link_local_addr: String,
}

#[allow(dead_code)]
impl AutoWorkerKey {
    pub(super) fn from_local_interface(local: &LocalInterface) -> Self {
        Self {
            ifname: local.name.clone(),
            if_index: local.index,
            link_local_addr: local.link_local_addr.clone(),
        }
    }
}

#[cfg_attr(not(test), allow(dead_code))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum WorkerReconcileAction {
    Add(AutoWorkerKey),
    Remove(AutoWorkerKey),
}

#[cfg_attr(not(test), allow(dead_code))]
pub(super) fn reconcile_worker_keys(
    active: impl IntoIterator<Item = AutoWorkerKey>,
    desired: impl IntoIterator<Item = AutoWorkerKey>,
) -> Vec<WorkerReconcileAction> {
    let active = active.into_iter().collect::<HashSet<_>>();
    let desired = desired.into_iter().collect::<HashSet<_>>();
    let mut actions = Vec::new();

    for key in active.difference(&desired) {
        actions.push(WorkerReconcileAction::Remove(key.clone()));
    }
    for key in desired.difference(&active) {
        actions.push(WorkerReconcileAction::Add(key.clone()));
    }

    actions.sort_by(|a, b| format!("{a:?}").cmp(&format!("{b:?}")));
    actions
}

pub(super) struct RunningAutoWorker {
    pub(super) running: Arc<AtomicBool>,
}

impl RunningAutoWorker {
    pub(super) fn stop(&self) {
        self.running.store(false, Ordering::Relaxed);
    }
}

pub(super) enum AutoWorkerEntry {
    Running(RunningAutoWorker),
    Pending,
}

impl AutoWorkerEntry {
    pub(super) fn stop(&self) {
        if let AutoWorkerEntry::Running(worker) = self {
            worker.stop();
        }
    }
}

pub(super) fn reconcile_auto_workers<F>(
    workers: &mut HashMap<AutoWorkerKey, AutoWorkerEntry>,
    desired: Vec<AutoWorkerKey>,
    mut start_worker: F,
) where
    F: FnMut(&AutoWorkerKey) -> io::Result<RunningAutoWorker>,
{
    let mut desired_keys = desired.into_iter().collect::<HashSet<_>>();
    let active_keys = workers.keys().cloned().collect::<Vec<_>>();

    for key in active_keys {
        if !desired_keys.contains(&key) {
            if let Some(worker) = workers.remove(&key) {
                worker.stop();
            }
        }
    }

    let mut desired = desired_keys.drain().collect::<Vec<_>>();
    desired.sort_by(|a, b| a.ifname.cmp(&b.ifname).then(a.if_index.cmp(&b.if_index)));

    for key in desired {
        if matches!(workers.get(&key), Some(AutoWorkerEntry::Running(_))) {
            continue;
        }

        let entry = match start_worker(&key) {
            Ok(worker) => AutoWorkerEntry::Running(worker),
            Err(e) => {
                log::warn!(
                    "AutoInterface worker {} failed to start on {}%{}: {}",
                    key.ifname,
                    key.link_local_addr,
                    key.if_index,
                    e
                );
                AutoWorkerEntry::Pending
            }
        };
        workers.insert(key, entry);
    }
}

impl AutoWorkerContext {
    pub(super) fn discovery_handler(&self, key: &AutoWorkerKey) -> DiscoveryHandler {
        DiscoveryHandler {
            group_id: self.group_id.clone(),
            shared: self.shared.clone(),
            name: self.name.clone(),
            ifname: key.ifname.clone(),
            if_index: key.if_index,
            data_port: self.data_port,
            configured_bitrate: self.configured_bitrate,
            ingress_control: self.ingress_control,
            runtime: self.runtime.clone(),
            dynamic_template: self.dynamic_template.clone(),
            underlay_mark: self.underlay_mark,
            inline: crate::engine::FOLD_IO,
        }
    }
}

#[derive(Clone)]
pub(super) struct AutoWorkerContext {
    pub(super) group_id: Vec<u8>,
    pub(super) mcast_ip: Ipv6Addr,
    pub(super) discovery_port: u16,
    pub(super) unicast_discovery_port: u16,
    pub(super) data_port: u16,
    pub(super) name: String,
    pub(super) configured_bitrate: u64,
    pub(super) ingress_control: rns_core::transport::types::IngressControlConfig,
    pub(super) runtime: Arc<Mutex<AutoRuntime>>,
    pub(super) shared: Arc<Mutex<SharedState>>,
    pub(super) tx: EventSender,
    pub(super) dynamic_template: Option<crate::interface::DynamicInterfaceTemplate>,
    pub(super) underlay_mark: Option<u32>,
}

pub(super) fn auto_supervisor_loop(
    allowed_interfaces: Vec<String>,
    ignored_interfaces: Vec<String>,
    context: AutoWorkerContext,
    running: Arc<AtomicBool>,
    name: &str,
) {
    let mut workers: HashMap<AutoWorkerKey, AutoWorkerEntry> = HashMap::new();

    while running.load(Ordering::Relaxed) {
        let interfaces = enumerate_interfaces(&allowed_interfaces, &ignored_interfaces);
        let desired = interfaces
            .iter()
            .map(AutoWorkerKey::from_local_interface)
            .collect::<Vec<_>>();

        {
            let mut state = lock_or_recover(&context.shared, "auto shared state");
            state.link_local_addresses = desired
                .iter()
                .map(|key| PeerKey {
                    link_local_addr: key.link_local_addr.clone(),
                    if_index: key.if_index,
                })
                .collect();
        }

        let removed_workers = reconcile_worker_keys(workers.keys().cloned(), desired.clone())
            .into_iter()
            .filter_map(|action| match action {
                WorkerReconcileAction::Remove(key) => Some(key),
                WorkerReconcileAction::Add(_) => None,
            })
            .collect::<Vec<_>>();
        for key in &removed_workers {
            remove_peers_for_worker(&context.shared, &context.tx, key);
        }

        if desired.is_empty() && workers.is_empty() {
            log::warn!("[{}] No suitable IPv6 link-local interfaces found", name);
        }

        reconcile_auto_workers(&mut workers, desired, |key| {
            start_auto_worker(key, &context)
        });

        thread::sleep(Duration::from_secs_f64(AUTO_RESCAN_INTERVAL));
    }

    for (key, worker) in workers {
        remove_peers_for_worker(&context.shared, &context.tx, &key);
        worker.stop();
    }
}

pub(super) fn start_auto_worker(
    key: &AutoWorkerKey,
    context: &AutoWorkerContext,
) -> io::Result<RunningAutoWorker> {
    let underlay_mark = context.underlay_mark;
    let mcast_socket = create_multicast_recv_socket(
        &context.mcast_ip,
        context.discovery_port,
        key.if_index,
        context.underlay_mark,
    )?;
    let unicast_socket = create_unicast_recv_socket(
        &key.link_local_addr,
        context.unicast_discovery_port,
        key.if_index,
        context.underlay_mark,
    )?;
    let data_socket = create_data_recv_socket(
        &key.link_local_addr,
        context.data_port,
        key.if_index,
        context.underlay_mark,
    )?;

    let worker_running = Arc::new(AtomicBool::new(true));

    {
        let group_id = context.group_id.clone();
        let link_local = key.link_local_addr.clone();
        let running = worker_running.clone();
        let name = context.name.clone();
        let runtime = context.runtime.clone();
        let mcast_ip = context.mcast_ip;
        let discovery_port = context.discovery_port;
        let if_index = key.if_index;
        thread::Builder::new()
            .name(format!("auto-disc-tx-{}", key.ifname))
            .spawn(move || {
                discovery_sender_loop(DiscoverySenderContext {
                    group_id,
                    link_local_addr: link_local,
                    mcast_ip,
                    discovery_port,
                    if_index,
                    runtime,
                    running,
                    name,
                    underlay_mark,
                });
            })?;
    }

    let handler = context.discovery_handler(key);
    for (socket, thread_name) in [
        (mcast_socket, format!("auto-disc-rx-{}", key.ifname)),
        (unicast_socket, format!("auto-udisc-rx-{}", key.ifname)),
    ] {
        let handler = handler.clone();
        let tx = context.tx.clone();
        let running = worker_running.clone();
        thread::Builder::new()
            .name(thread_name)
            .spawn(move || discovery_receiver_loop(socket, handler, tx, running))?;
    }

    {
        let shared = context.shared.clone();
        let tx = context.tx.clone();
        let running = worker_running.clone();
        let name = context.name.clone();
        let if_index = key.if_index;
        thread::Builder::new()
            .name(format!("auto-data-rx-{}", key.ifname))
            .spawn(move || {
                data_receiver_loop(data_socket, shared, tx, &running, &name, if_index);
            })?;
    }

    log::info!(
        "[{}] AutoInterface worker online on {} {}%{}",
        context.name,
        key.ifname,
        key.link_local_addr,
        key.if_index
    );

    Ok(RunningAutoWorker {
        running: worker_running,
    })
}
