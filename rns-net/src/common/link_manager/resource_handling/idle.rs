//! Work done while the link is idle: decrypting received parts ahead.

use super::*;

impl LinkManager {
    /// Whether [`Self::run_idle_work`] has anything to do.
    pub fn has_idle_work(&self) -> bool {
        !self.stream_prebuilds.is_empty()
            || !self.folded_assemblies.is_empty()
            || !self.receive_decrypts.is_empty()
    }

    /// Do one piece of work that can wait until no event is waiting; the
    /// driver calls this only then. Preparing a stream's next segment goes
    /// first: the peer waits for it.
    pub fn run_idle_work(&mut self, rng: &mut dyn Rng) -> Vec<LinkManagerAction> {
        if let Some(prebuild) = self.stream_prebuilds.pop() {
            return self.prepare_next_stream_segment(prebuild, rng);
        }
        if self.has_folded_assembly() {
            return self.step_folded_assembly(rng);
        }
        self.decrypt_received_part_ahead();
        Vec::new()
    }

    /// Decrypt held parts of an incoming resource, so that its assembly has
    /// less left to do once the last part arrives. One job does at least
    /// one part and about [`IDLE_DECRYPT_BYTES`]: the driver polls its
    /// sources between jobs, and small parts would make that poll the
    /// larger cost.
    pub(super) fn decrypt_received_part_ahead(&mut self) {
        let Some((link_id, resource_hash)) = self.receive_decrypts.pop_front() else {
            return;
        };
        let Some(link) = self.links.get_mut(&link_id) else {
            return;
        };
        let engine = &link.engine;
        let Some(receiver) = link
            .incoming_resources
            .iter_mut()
            .find(|r| r.resource_hash[..] == resource_hash[..])
        else {
            return;
        };
        if receiver.decrypt_held_parts(
            || engine.decrypt_stream(constants::RESOURCE_RANDOM_HASH_SIZE),
            IDLE_DECRYPT_BYTES,
        ) {
            self.receive_decrypts.push_back((link_id, resource_hash));
        }
    }
}
