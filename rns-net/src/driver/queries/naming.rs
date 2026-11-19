//! How interfaces are named in status output.

use super::*;

impl Driver {
    /// Upstream's `str(interface)` for an interface entry.
    pub(crate) fn interface_display_name(&self, entry: &InterfaceEntry) -> String {
        if let Some(display_name) = self.interface_display_names.get(&entry.info.id) {
            return display_name.clone();
        }
        // The shared instance's clients on its Unix socket, which its
        // listener spawns unnamed: upstream names them after the socket.
        // (On TCP the listener names them after their port.)
        if entry.info.is_local_client && entry.dynamic {
            if let Some(ListenerStat {
                clients: ListenerClients::Local(endpoint),
                ..
            }) = self.shared_instance_listener()
            {
                return crate::interface::display::local_client(endpoint);
            }
        }
        crate::interface::display::typed(
            crate::rpc::upstream_interface_type(&entry.interface_type),
            &entry.info.name,
        )
    }

    /// Name a client the shared instance accepted on its abstract Unix
    /// socket, before it is added, as upstream does: `{clients}@\0rns/{instance}`,
    /// after the number of clients the instance serves (on TCP the
    /// listener names its clients after their port).
    pub(crate) fn name_local_client(&mut self, id: InterfaceId) {
        if self.interface_short_names.contains_key(&id) {
            return;
        }
        let Some(ListenerStat {
            clients:
                ListenerClients::Local(crate::interface::display::LocalEndpoint::Unix(instance)),
            ..
        }) = self.shared_instance_listener()
        else {
            return;
        };
        let clients = self
            .interfaces
            .values()
            .filter(|entry| entry.info.is_local_client && entry.dynamic && entry.info.id != id)
            .count();
        let short_name = format!("{clients}@\0rns/{instance}");
        self.interface_short_names.insert(id, short_name);
    }

    /// The display name of the listener that spawned an interface.
    pub(super) fn parent_display_name(&self, entry: &InterfaceEntry) -> Option<String> {
        let parent_id = match self.dynamic_interface_parents.get(&entry.info.id) {
            Some(parent_id) => *parent_id,
            // The shared instance's clients have no registered parent.
            None if entry.info.is_local_client && entry.dynamic => {
                return self
                    .shared_instance_listener()
                    .map(|listener| listener.display_name.clone());
            }
            // Subinterfaces are configured, not spawned.
            None => {
                return self
                    .listener_stats
                    .iter()
                    .find(|listener| {
                        matches!(&listener.clients, ListenerClients::Subinterfaces(ids) if ids.contains(&entry.info.id))
                    })
                    .map(|listener| listener.display_name.clone());
            }
        };
        if let Some(listener) = self
            .listener_stats
            .iter()
            .find(|listener| listener.id == parent_id)
        {
            return Some(listener.display_name.clone());
        }
        if let Some(display_name) = self.interface_display_names.get(&parent_id) {
            return Some(display_name.clone());
        }
        self.interfaces
            .get(&parent_id)
            .map(|parent| self.interface_display_name(parent))
    }

    /// Whether `entry` is a subinterface of an RNodeMultiInterface whose
    /// device is not connected and configured: upstream creates the
    /// subinterfaces once it configured the device, and removes them when
    /// the connection fails, so it does not list them meanwhile.
    pub(super) fn subinterface_without_device(&self, entry: &InterfaceEntry) -> bool {
        !entry.online
            && self.listener_stats.iter().any(|listener| {
                matches!(&listener.clients, ListenerClients::Subinterfaces(ids) if ids.contains(&entry.info.id))
            })
    }
}
