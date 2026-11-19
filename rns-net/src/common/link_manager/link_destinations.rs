//! Link destinations and their request handlers.

use super::*;

impl LinkManager {
    /// Register a destination that can accept incoming links.
    pub fn register_link_destination(
        &mut self,
        dest_hash: [u8; 16],
        sig_prv: Ed25519PrivateKey,
        sig_pub_bytes: [u8; 32],
        resource_strategy: ResourceStrategy,
    ) {
        self.link_destinations.insert(
            dest_hash,
            LinkDestination {
                sig_prv,
                sig_pub_bytes,
                resource_strategy,
                max_request_size: None,
                resource_receive_mode: ResourceReceiveMode::default(),
                answers_requests: true,
            },
        );
    }

    /// Register a destination that accepts incoming links but has no
    /// request handlers of its own, as upstream's management destinations
    /// without any: links to it are established, and requests on them and
    /// resources offered over them are left unanswered.
    pub fn register_link_destination_without_requests(
        &mut self,
        dest_hash: [u8; 16],
        sig_prv: Ed25519PrivateKey,
        sig_pub_bytes: [u8; 32],
    ) {
        self.register_link_destination(
            dest_hash,
            sig_prv,
            sig_pub_bytes,
            ResourceStrategy::AcceptNone,
        );
        if let Some(destination) = self.link_destinations.get_mut(&dest_hash) {
            destination.answers_requests = false;
        }
    }

    /// Whether requests on `link_id` may reach the request handlers: not on
    /// a link to a destination registered without requests.
    pub(in crate::common) fn link_answers_requests(&self, link_id: &LinkId) -> bool {
        self.links.get(link_id).is_none_or(|link| {
            self.link_destinations
                .get(&link.dest_hash)
                .is_none_or(|destination| destination.answers_requests)
        })
    }

    /// Configure the maximum request size for this destination.
    ///
    /// The new limit also applies to responder links that are already active.
    /// Returns false when the destination is not registered.
    pub fn set_link_destination_max_request_size(
        &mut self,
        dest_hash: &[u8; 16],
        max_request_size: Option<usize>,
    ) -> bool {
        let Some(destination) = self.link_destinations.get_mut(dest_hash) else {
            return false;
        };
        destination.max_request_size = max_request_size;
        for link in self.links.values_mut() {
            if link.dest_hash == *dest_hash && link.dest_sig_pub_bytes.is_none() {
                link.max_request_size = max_request_size;
            }
        }
        true
    }

    /// Set how links to this destination deliver independent Resources
    /// from the moment they are established, before the application could
    /// call [`LinkManager::set_resource_receive_mode`] on the link: a
    /// Resource advertised right after the link comes up would otherwise
    /// be received in memory. Links already established keep their mode.
    ///
    /// Returns false when the destination is not registered.
    pub fn set_link_destination_resource_receive_mode(
        &mut self,
        dest_hash: &[u8; 16],
        mode: ResourceReceiveMode,
    ) -> bool {
        let Some(destination) = self.link_destinations.get_mut(dest_hash) else {
            return false;
        };
        destination.resource_receive_mode = mode;
        true
    }

    /// Deregister a link destination.
    pub fn deregister_link_destination(&mut self, dest_hash: &[u8; 16]) {
        self.link_destinations.remove(dest_hash);
    }

    /// Register a request handler for a given path.
    ///
    /// `path`: the request path string (e.g. "/status")
    /// `allowed_list`: None = allow all, Some(list) = restrict to these identity hashes
    /// `handler`: called with (link_id, path, request_data, remote_identity) -> Option<response>
    pub fn register_request_handler<F>(
        &mut self,
        path: &str,
        allowed_list: Option<Vec<[u8; 16]>>,
        handler: F,
    ) where
        F: Fn(LinkId, &str, &[u8], Option<&([u8; 16], [u8; 64])>) -> Option<Vec<u8>>
            + Send
            + 'static,
    {
        let path_hash = compute_path_hash(path);
        self.request_handlers.push(RequestHandlerEntry {
            path: path.to_string(),
            path_hash,
            allowed_list,
            handler: Box::new(move |link_id, p, data, remote| {
                handler(link_id, p, data, remote).map(RequestResponse::Bytes)
            }),
        });
    }

    /// Register a request handler that can return resource responses with metadata.
    pub fn register_request_handler_response<F>(
        &mut self,
        path: &str,
        allowed_list: Option<Vec<[u8; 16]>>,
        handler: F,
    ) where
        F: Fn(LinkId, &str, &[u8], Option<&([u8; 16], [u8; 64])>) -> Option<RequestResponse>
            + Send
            + 'static,
    {
        let path_hash = compute_path_hash(path);
        self.request_handlers.push(RequestHandlerEntry {
            path: path.to_string(),
            path_hash,
            allowed_list,
            handler: Box::new(handler),
        });
    }

    /// Register a request handler that produces its response asynchronously.
    pub fn register_deferred_request_handler<F>(
        &mut self,
        path: &str,
        allowed_list: Option<Vec<[u8; 16]>>,
        handler: F,
    ) where
        F: Fn(LinkId, &str, [u8; 16], &[u8], Option<&([u8; 16], [u8; 64])>) + Send + 'static,
    {
        self.deferred_request_handlers
            .push(DeferredRequestHandlerEntry {
                path: path.to_string(),
                path_hash: compute_path_hash(path),
                allowed_list,
                handler: Box::new(handler),
            });
    }

    /// Check if a destination hash is a known link_id managed by this manager.
    pub fn is_link_destination(&self, dest_hash: &[u8; 16]) -> bool {
        self.links.contains_key(dest_hash) || self.link_destinations.contains_key(dest_hash)
    }
}
