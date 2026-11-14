//! Blackhole list changes: persistence and path removal, as upstream's
//! `Transport.blackhole_identity`, `unblackhole_identity`, `persist_blackhole`,
//! `reload_blackhole` and `remove_blackholed_paths` do them.

use super::*;

impl Driver {
    /// Blackhole an identity on this node. Returns `false` when it already
    /// is blackholed, which leaves the entry unchanged. A new entry is
    /// persisted and the paths to its destinations are dropped.
    pub(crate) fn blackhole_identity_local(
        &mut self,
        identity_hash: [u8; 16],
        duration_hours: Option<f64>,
        reason: Option<String>,
    ) -> bool {
        let added =
            self.engine
                .blackhole_identity(identity_hash, time::now(), duration_hours, reason);
        if added {
            log::info!("Blackholed identity {}", hex16(&identity_hash));
            self.persist_blackhole();
            self.remove_blackholed_paths();
        }
        added
    }

    /// Lift the blackhole for an identity. Returns `false` when it was not
    /// blackholed.
    pub(crate) fn unblackhole_identity_local(&mut self, identity_hash: &[u8; 16]) -> bool {
        let removed = self.engine.unblackhole_identity(identity_hash);
        if removed {
            log::info!("Lifted blackhole for identity {}", hex16(identity_hash));
            self.persist_blackhole();
        }
        removed
    }

    /// Write this node's own entries to `storage/blackhole/local`.
    pub(crate) fn persist_blackhole(&self) {
        let Some(dir) = self.blackhole_dir.as_ref() else {
            return;
        };
        if let Err(error) = crate::blackhole_store::save_local(
            dir,
            self.engine.blackholed_entries(),
            self.engine.identity_hash(),
        ) {
            log::error!("Error while persisting blackhole list: {error}");
        }
    }

    /// Load the persisted blackhole lists from `dir` and use it from now on.
    pub(crate) fn load_blackhole(&mut self, dir: std::path::PathBuf) {
        let now = time::now();
        let sources = self.blackhole_sources.clone();
        let mut loaded = 0usize;
        for (identity_hash, entry) in crate::blackhole_store::load(&dir, &sources, now) {
            if self.engine.insert_blackhole_entry(identity_hash, entry) {
                loaded += 1;
            }
        }
        if loaded > 0 {
            log::info!("Loaded {loaded} blackholed identities");
        }
        self.blackhole_dir = Some(dir);
        self.remove_blackholed_paths();
    }

    /// Drop the paths to destinations whose announced identity is
    /// blackholed (`Transport.remove_blackholed_paths`).
    pub(crate) fn remove_blackholed_paths(&mut self) {
        let now = time::now();
        let drop: Vec<[u8; 16]> = self
            .engine
            .path_table_entries()
            .map(|(dest_hash, _)| *dest_hash)
            .filter(|dest_hash| {
                self.known_destinations.get(dest_hash).is_some_and(|known| {
                    self.engine
                        .is_blackholed(&known.announced.identity_hash.0, now)
                })
            })
            .collect();
        for dest_hash in &drop {
            self.engine.drop_path(dest_hash);
        }
        if !drop.is_empty() {
            let s = if drop.len() == 1 { "" } else { "s" };
            log::info!(
                "Removed {} destination{s} associated with blackholed identities from path table",
                drop.len()
            );
        }

        // Upstream 350b7e26: connections from blackholed transport nodes are
        // torn down.
        let detach: Vec<(InterfaceId, [u8; 16])> = self
            .interfaces
            .keys()
            .filter_map(|id| Some((*id, self.engine.remote_transport(id)?)))
            .filter(|(_, remote)| self.engine.is_blackholed(remote, now))
            .collect();
        for (id, remote) in detach {
            log::info!(
                "Tearing down interface {} from blackholed transport node {}",
                id.0,
                hex16(&remote)
            );
            self.teardown_interface(id);
        }
    }
}

fn hex16(hash: &[u8; 16]) -> String {
    hash.iter().map(|b| format!("{b:02x}")).collect()
}
