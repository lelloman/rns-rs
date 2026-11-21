//! Creating a link manager and its settings.

use super::*;

impl LinkManager {
    /// Create a new empty link manager.
    pub fn new() -> Self {
        LinkManager {
            decrypt_feeder: None,
            decrypt_feeder_failed: false,
            segment_builder: None,
            segment_builder_failed: false,
            receive_worker: None,
            receive_worker_wake: None,
            folded_assemblies: std::collections::VecDeque::new(),
            proof_verify_threads: ProofVerifyThreads::Fixed(0),
            proof_pool: None,
            proof_pool_settled: false,
            proof_outcomes: Vec::new(),
            packet_proof_outcomes: Vec::new(),
            links: Default::default(),
            link_destinations: Default::default(),
            request_handlers: Vec::new(),
            deferred_request_handlers: Vec::new(),
            management_paths: Vec::new(),
            link_mtu_discovery: true,
            link_request_costs: Default::default(),
            resource_scratch: Vec::new(),
            resource_part_scratch: Vec::new(),
            local_link_rxb: 0,
            local_link_sent: 0,
            local_link_resent: 0,
            plaintext_scratch: Vec::new(),
            stream_prebuilds: Vec::new(),
            receive_decrypts: std::collections::VecDeque::new(),
        }
    }

    /// Share the per-destination link request costs with the node.
    pub(crate) fn set_link_request_costs(&mut self, costs: crate::stamps::LinkRequestCosts) {
        self.link_request_costs = costs;
    }

    /// The per-destination link request costs this manager enforces.
    pub(crate) fn link_request_costs(&self) -> &crate::stamps::LinkRequestCosts {
        &self.link_request_costs
    }

    /// How many threads verify link proofs (see [`ProofVerifyThreads`]).
    pub(crate) fn set_proof_verify_threads(&mut self, threads: ProofVerifyThreads) {
        self.proof_verify_threads = threads;
        self.proof_pool = None;
        self.proof_pool_settled = false;
    }

    pub(crate) fn set_link_mtu_discovery(&mut self, enabled: bool) {
        self.link_mtu_discovery = enabled;
    }

    /// Register a path hash as a management path.
    /// Management requests are returned as ManagementRequest actions
    /// for the driver to handle (since they need access to engine state).
    pub fn register_management_path(&mut self, path_hash: [u8; 16]) {
        if !self.management_paths.contains(&path_hash) {
            self.management_paths.push(path_hash);
        }
    }
}
