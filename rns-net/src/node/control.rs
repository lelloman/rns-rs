//! Interfaces, state snapshots and draining of a running node.

use super::*;

impl RnsNode {
    /// Query the driver for state information.
    pub fn query(&self, request: QueryRequest) -> Result<QueryResponse, SendError> {
        let (resp_tx, resp_rx) = std::sync::mpsc::channel();
        self.tx
            .send(Event::query(request, resp_tx))
            .map_err(|_| SendError)?;
        resp_rx.recv().map_err(|_| SendError)
    }

    /// Attach a named interface from the current on-disk configuration.
    pub fn attach_interface(&self, name: &str) -> Result<Option<bool>, SendError> {
        self.manage_interface(crate::event::InterfaceManagementOperation::Attach, name)
    }

    /// Detach a named interface and its spawned children.
    pub fn detach_interface(&self, name: &str) -> Result<Option<bool>, SendError> {
        self.manage_interface(crate::event::InterfaceManagementOperation::Detach, name)
    }

    /// Detach and attach a named interface using the current on-disk configuration.
    pub fn reload_interface(&self, name: &str) -> Result<Option<bool>, SendError> {
        self.manage_interface(crate::event::InterfaceManagementOperation::Reload, name)
    }

    pub(super) fn manage_interface(
        &self,
        operation: crate::event::InterfaceManagementOperation,
        name: &str,
    ) -> Result<Option<bool>, SendError> {
        match self.query(QueryRequest::ManageInterface {
            operation,
            name: name.to_string(),
        })? {
            QueryResponse::InterfaceManagement(result) => Ok(result),
            _ => Err(SendError),
        }
    }

    /// The state of Direct Link: node-wide counters and each link with
    /// Direct Link activity, with its current path (direct or the original
    /// one), the direct path's candidate, MTU and RTT, and its upgrade
    /// attempts and failures.
    pub fn direct_links(&self) -> Result<crate::event::DirectLinkStatus, SendError> {
        match self.query(QueryRequest::DirectLinks)? {
            QueryResponse::DirectLinks(status) => Ok(status),
            _ => Err(SendError),
        }
    }

    /// Snapshot active Link metadata, including the negotiated direct-data MDU.
    pub fn links(&self) -> Result<Vec<crate::event::LinkInfoEntry>, SendError> {
        match self.query(QueryRequest::Links)? {
            QueryResponse::Links(links) => Ok(links),
            _ => Err(SendError),
        }
    }

    /// Snapshot one Link, including local send backlog, or None if unknown.
    pub fn query_link(
        &self,
        link_id: [u8; 16],
    ) -> Result<Option<crate::event::LinkInfoEntry>, SendError> {
        Ok(self
            .links()?
            .into_iter()
            .find(|link| link.link_id == link_id))
    }

    /// The link and interface statistics the driver last published, read
    /// without a driver round trip.
    ///
    /// Unlike [`query`](Self::query), [`links`](Self::links) and
    /// [`query_link`](Self::query_link), which queue behind every earlier
    /// control event and answer exactly at that point, this returns at once
    /// even while the driver works through a long backlog or is blocked, for
    /// example in a callback. The price is freshness and ordering: the driver
    /// republishes on every tick (`global.tick_interval_ms`, 1 s by default)
    /// and as soon as a link or interface changes state, so the snapshot may
    /// lag by up to one tick, plus however long the driver has been blocked,
    /// and it is not a barrier: events sent before the call, sends included,
    /// may not be reflected yet. Before the first publish the snapshot is
    /// empty with `sequence == 0`.
    pub fn state_snapshot(&self) -> Arc<crate::state_snapshot::StateSnapshot> {
        self.tx.state_snapshot().load()
    }

    /// Links as of the last published [`state_snapshot`](Self::state_snapshot).
    ///
    /// May lag by up to one tick and is not ordered after earlier events; use
    /// [`links`](Self::links) for an exact, ordered answer.
    pub fn snapshot_links(&self) -> Vec<crate::event::LinkInfoEntry> {
        self.state_snapshot().links.clone()
    }

    /// One link as of the last published
    /// [`state_snapshot`](Self::state_snapshot), or None if it was not known
    /// then.
    ///
    /// May lag by up to one tick and is not ordered after earlier events; use
    /// [`query_link`](Self::query_link) for an exact, ordered answer.
    pub fn snapshot_link(&self, link_id: [u8; 16]) -> Option<crate::event::LinkInfoEntry> {
        self.state_snapshot().link(&link_id).cloned()
    }

    /// Interface statistics as of the last published
    /// [`state_snapshot`](Self::state_snapshot).
    ///
    /// May lag by up to one tick and is not ordered after earlier events; use
    /// `query(QueryRequest::InterfaceStats)` for an exact, ordered answer.
    pub fn snapshot_interfaces(&self) -> crate::event::InterfaceStatsResponse {
        self.state_snapshot().interfaces.clone()
    }

    /// Return the slowest positive bitrate among currently registered interfaces.
    ///
    /// Returns `Ok(None)` when no registered interface advertises a usable
    /// bitrate.
    pub fn lowest_interface_bitrate(&self) -> Result<Option<u64>, SendError> {
        match self.query(QueryRequest::LowestInterfaceBitrate)? {
            QueryResponse::LowestInterfaceBitrate(bitrate) => Ok(bitrate),
            _ => Err(SendError),
        }
    }

    /// Return the adaptive medium path timeout advertised by the transport engine.
    ///
    /// The estimate covers a full MTU round trip on the slowest registered
    /// positive-bitrate interface plus the per-hop allowance, or is zero when
    /// no usable bitrate is known.
    pub fn medium_path_timeout(&self) -> Result<f64, SendError> {
        match self.query(QueryRequest::MediumPathTimeout)? {
            QueryResponse::MediumPathTimeout(timeout) => Ok(timeout),
            _ => Err(SendError),
        }
    }

    /// The names this node knows destination types by: upstream's
    /// `Transport.destination_type_map` and `flagged_type_map`, from the
    /// `[filter]` section, the type files and the types applications asked
    /// for.
    pub fn destination_type_names(
        &self,
    ) -> Result<crate::destination_types::DestinationTypeNames, SendError> {
        match self.query(QueryRequest::DestinationTypeNames)? {
            QueryResponse::DestinationTypeNames(names) => Ok(names),
            _ => Err(SendError),
        }
    }

    /// Enter drain mode and stop admitting new work.
    pub fn begin_drain(&self, timeout: Duration) -> Result<(), SendError> {
        // Draining is one-way. Refuse new work from this call on, before the
        // driver has processed the event.
        self.accepting_work.store(false, Ordering::Release);
        self.tx
            .send(Event::BeginDrain { timeout })
            .map_err(|_| SendError)
    }

    /// Query current drain/lifecycle status.
    pub fn drain_status(&self) -> Result<crate::event::DrainStatus, SendError> {
        match self.query(QueryRequest::DrainStatus)? {
            QueryResponse::DrainStatus(status) => Ok(status),
            _ => Err(SendError),
        }
    }

    pub(super) fn reject_new_work_if_draining(&self) -> Result<(), SendError> {
        // A flag the driver clears when draining starts, not a driver query:
        // this runs on every send.
        if self.accepting_work.load(Ordering::Acquire) {
            Ok(())
        } else {
            Err(SendError)
        }
    }

    /// Send a raw outbound packet.
    pub fn send_raw(
        &self,
        raw: Vec<u8>,
        dest_type: u8,
        attached_interface: Option<rns_core::transport::types::InterfaceId>,
    ) -> Result<(), SendError> {
        self.tx
            .send(Event::SendOutbound {
                raw,
                dest_type,
                attached_interface,
            })
            .map_err(|_| SendError)
    }
}
