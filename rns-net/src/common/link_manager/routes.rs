//! Where a link's packets go: route hints and direct paths.

use super::*;

impl LinkManager {
    /// Return best-known routing hint for link packets.
    pub fn get_link_route_hint(&self, link_id: &LinkId) -> Option<LinkRouteHint> {
        self.links.get(link_id).and_then(|link| {
            link.route_interface.map(|interface| LinkRouteHint {
                interface,
                transport_id: link.route_transport_id,
                mtu: link.engine.mtu(),
            })
        })
    }

    /// Set the best-known outbound route for a link. While the link runs
    /// over a direct path, this updates the route it falls back to.
    pub fn set_link_route_hint(
        &mut self,
        link_id: &LinkId,
        interface: rns_core::transport::types::InterfaceId,
        transport_id: Option<[u8; 16]>,
    ) -> bool {
        let Some(link) = self.links.get_mut(link_id) else {
            return false;
        };
        if let Some(direct) = link.direct_route.as_mut() {
            direct.fallback_interface = Some(interface);
            direct.fallback_transport_id = transport_id;
            return true;
        }
        link.route_interface = Some(interface);
        link.route_transport_id = transport_id;
        true
    }

    /// Route the link over a Direct Link interface, remembering its current
    /// route and MTU to fall back to. The link MTU becomes `mtu`, the
    /// direct interface's, but never more than the peer accepts there:
    /// `peer_max_packet` when it advertised one, otherwise the link's
    /// current MTU, which is then never raised. Its RTT and keepalive
    /// timing are left as measured on the original path, so they stay
    /// valid after a fallback.
    pub fn attach_direct_route(
        &mut self,
        link_id: &LinkId,
        interface: rns_core::transport::types::InterfaceId,
        mtu: u32,
        peer_max_packet: Option<u32>,
    ) -> bool {
        let Some(link) = self.links.get_mut(link_id) else {
            return false;
        };
        let mut direct = match link.direct_route.take() {
            // A newer upgrade: the original route is still the fallback.
            Some(previous) => DirectRoute {
                interface,
                ..previous
            },
            None => DirectRoute {
                interface,
                fallback_interface: link.route_interface,
                fallback_transport_id: link.route_transport_id,
                fallback_mtu: link.engine.mtu(),
                ceiling: 0,
                resource_mtu: 0,
            },
        };
        // Every node accepts packets of the base MTU.
        direct.ceiling =
            peer_max_packet.map_or(direct.fallback_mtu, |max| max.max(constants::MTU as u32));
        let mtu = mtu.min(direct.ceiling);
        direct.resource_mtu = mtu.min(direct.fallback_mtu);
        link.engine.set_mtu(mtu);
        link.direct_route = Some(direct);
        link.direct_peer = true;
        link.route_interface = Some(interface);
        link.route_transport_id = None;
        if let Some(channel) = link.channel.as_mut() {
            channel.set_hold_on_exhaustion(true);
        }
        true
    }

    /// The path MTU of the link's direct interface is known: use it, but
    /// never above what the peer accepts there (see
    /// [`LinkManager::attach_direct_route`]). Returns the MTU now in use,
    /// or `None` if the link does not run over `interface`.
    pub fn set_direct_mtu(
        &mut self,
        link_id: &LinkId,
        interface: rns_core::transport::types::InterfaceId,
        mtu: u32,
    ) -> Option<u32> {
        let link = self.links.get_mut(link_id)?;
        let direct = link.direct_route.as_ref()?;
        if direct.interface != interface {
            return None;
        }
        let mtu = mtu.min(direct.ceiling);
        link.engine.set_mtu(mtu);
        Some(mtu)
    }

    /// Return the link to the route and MTU it had before its direct path.
    /// Returns the direct interface it stops using, and the channel's
    /// outstanding messages resent on the original route: they may have
    /// been lost with the direct path, and the retries spent there say
    /// nothing about the original one, so each gets its full set again.
    pub fn detach_direct_route(
        &mut self,
        link_id: &LinkId,
        rng: &mut dyn Rng,
    ) -> Option<(
        rns_core::transport::types::InterfaceId,
        Vec<LinkManagerAction>,
    )> {
        let interface = self.restore_original_route(link_id)?;
        let resends = self
            .links
            .get_mut(link_id)
            .and_then(|link| link.channel.as_mut())
            .map(|channel| channel.resend_outstanding(time::now()))
            .unwrap_or_default();
        Some((
            interface,
            self.process_channel_actions(link_id, resends, rng),
        ))
    }

    /// The route and MTU part of [`LinkManager::detach_direct_route`].
    pub(super) fn restore_original_route(
        &mut self,
        link_id: &LinkId,
    ) -> Option<rns_core::transport::types::InterfaceId> {
        let link = self.links.get_mut(link_id)?;
        let direct = link.direct_route.take()?;
        link.route_interface = direct.fallback_interface;
        link.route_transport_id = direct.fallback_transport_id;
        link.engine.set_mtu(direct.fallback_mtu);
        if let Some(channel) = link.channel.as_mut() {
            channel.set_hold_on_exhaustion(false);
        }
        Some(direct.interface)
    }

    /// Whether this side initiated the link (`None` for an unknown link).
    pub fn is_link_initiator(&self, link_id: &LinkId) -> Option<bool> {
        self.links
            .get(link_id)
            .map(|link| link.engine.is_initiator())
    }

    /// The Direct Link interface the link runs over, if any.
    pub fn direct_route_interface(
        &self,
        link_id: &LinkId,
    ) -> Option<rns_core::transport::types::InterfaceId> {
        self.links
            .get(link_id)
            .and_then(|link| link.direct_route.as_ref())
            .map(|direct| direct.interface)
    }

    /// Whether a link packet arriving on `interface` is on one of the
    /// link's routes: its current one, or, while it runs over a direct
    /// path, the original route it falls back to (the peer may already have
    /// fallen back). A link without a known route accepts any interface.
    pub fn link_route_accepts(
        &self,
        link_id: &LinkId,
        interface: rns_core::transport::types::InterfaceId,
    ) -> bool {
        let Some(link) = self.links.get(link_id) else {
            return true;
        };
        match link.route_interface {
            None => true,
            Some(route) if route == interface => true,
            Some(_) => link
                .direct_route
                .as_ref()
                .is_some_and(|direct| direct.fallback_interface == Some(interface)),
        }
    }
}
