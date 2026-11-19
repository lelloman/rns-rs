//! How an event prints in debug output.

use super::*;

impl<W: Send> fmt::Debug for Event<W> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Event::Frame {
                interface_id,
                data,
                rssi,
                snr,
            } => f
                .debug_struct("Frame")
                .field("interface_id", interface_id)
                .field("data_len", &data.len())
                .field("rssi", rssi)
                .field("snr", snr)
                .finish(),
            Event::AnnounceVerified { key, .. } => f
                .debug_struct("AnnounceVerified")
                .field("destination_hash", &key.destination_hash)
                .field("received_from", &key.received_from)
                .finish(),
            Event::AnnounceVerifyFailed { key, .. } => f
                .debug_struct("AnnounceVerifyFailed")
                .field("destination_hash", &key.destination_hash)
                .field("received_from", &key.received_from)
                .finish(),
            Event::InterfaceUp(id, writer, info) => f
                .debug_tuple("InterfaceUp")
                .field(id)
                .field(&writer.is_some())
                .field(&info.is_some())
                .finish(),
            Event::DynamicInterfaceUp {
                id, registration, ..
            } => f
                .debug_struct("DynamicInterfaceUp")
                .field("id", id)
                .field("type", &registration.interface_type)
                .field("parent_id", &registration.parent_id)
                .finish(),
            Event::InterfaceNames {
                id,
                display_name,
                short_name,
            } => f
                .debug_struct("InterfaceNames")
                .field("id", id)
                .field("display_name", display_name)
                .field("short_name", short_name)
                .finish(),
            Event::InterfaceTelemetry {
                interface_id,
                telemetry,
            } => f
                .debug_struct("InterfaceTelemetry")
                .field("interface_id", interface_id)
                .field("telemetry", telemetry)
                .finish(),
            Event::InterfaceDown(id) => f.debug_tuple("InterfaceDown").field(id).finish(),
            Event::Tick => write!(f, "Tick"),
            Event::BeginDrain { timeout } => f
                .debug_struct("BeginDrain")
                .field("timeout", timeout)
                .finish(),
            Event::Shutdown => write!(f, "Shutdown"),
            Event::DeliverDecrypted { dest_hash, .. } => f
                .debug_struct("DeliverDecrypted")
                .field("dest_hash", dest_hash)
                .finish(),
            Event::SendDeferred(encryption) => f
                .debug_struct("SendDeferred")
                .field("ticket", &encryption.ticket)
                .field("data_len", &encryption.data.len())
                .finish(),
            Event::SendOutbound { raw, dest_type, .. }
            | Event::SendOutboundTracked { raw, dest_type, .. } => f
                .debug_struct("SendOutbound")
                .field("raw_len", &raw.len())
                .field("dest_type", dest_type)
                .finish(),
            Event::RegisterDestination {
                dest_hash,
                dest_type,
            } => f
                .debug_struct("RegisterDestination")
                .field("dest_hash", dest_hash)
                .field("dest_type", dest_type)
                .finish(),
            Event::StoreSharedAnnounce {
                dest_hash,
                name_hash,
                app_data,
                ..
            } => f
                .debug_struct("StoreSharedAnnounce")
                .field("dest_hash", dest_hash)
                .field("name_hash", name_hash)
                .field("app_data_len", &app_data.as_ref().map(|d| d.len()))
                .finish(),
            Event::RegisterPathResponder { destination, .. } => f
                .debug_struct("RegisterPathResponder")
                .field("dest_hash", &destination.hash.0)
                .finish(),
            Event::AnnounceRegisteredDestination { dest_hash } => f
                .debug_struct("AnnounceRegisteredDestination")
                .field("dest_hash", dest_hash)
                .finish(),
            Event::DeregisterDestination { dest_hash } => f
                .debug_struct("DeregisterDestination")
                .field("dest_hash", dest_hash)
                .finish(),
            Event::DeregisterLinkDestination { dest_hash } => f
                .debug_struct("DeregisterLinkDestination")
                .field("dest_hash", dest_hash)
                .finish(),
            Event::Query(req, _) => f.debug_tuple("Query").field(req).finish(),
            Event::RegisterLinkDestination { dest_hash, .. } => f
                .debug_struct("RegisterLinkDestination")
                .field("dest_hash", dest_hash)
                .finish(),
            Event::RegisterRequestHandler { path, .. } => f
                .debug_struct("RegisterRequestHandler")
                .field("path", path)
                .finish(),
            Event::RegisterRequestHandlerResponse { path, .. } => f
                .debug_struct("RegisterRequestHandlerResponse")
                .field("path", path)
                .finish(),
            Event::RegisterDeferredRequestHandler { path, .. } => f
                .debug_struct("RegisterDeferredRequestHandler")
                .field("path", path)
                .finish(),
            Event::CreateLink { dest_hash, .. } => f
                .debug_struct("CreateLink")
                .field("dest_hash", dest_hash)
                .finish(),
            Event::CompleteStampedLink(keys) => f
                .debug_struct("CompleteStampedLink")
                .field("dest_hash", &keys.dest_hash)
                .field("stamp_value", &keys.stamp_value)
                .finish(),
            Event::SendRequest { link_id, path, .. } => f
                .debug_struct("SendRequest")
                .field("link_id", link_id)
                .field("path", path)
                .finish(),
            Event::SendDeferredResponse {
                link_id,
                request_id,
                data,
            } => f
                .debug_struct("SendDeferredResponse")
                .field("link_id", link_id)
                .field("request_id", request_id)
                .field("data_len", &data.len())
                .finish(),
            Event::IdentifyOnLink { link_id, .. } => f
                .debug_struct("IdentifyOnLink")
                .field("link_id", link_id)
                .finish(),
            Event::TeardownLink { link_id } => f
                .debug_struct("TeardownLink")
                .field("link_id", link_id)
                .finish(),
            Event::ResourcePreparationReady => f.write_str("ResourcePreparationReady"),
            Event::ResourceAssemblyReady => f.write_str("ResourceAssemblyReady"),
            Event::LinkProofsVerified => f.write_str("LinkProofsVerified"),
            Event::SendResource { link_id, data, .. } => f
                .debug_struct("SendResource")
                .field("link_id", link_id)
                .field("data_len", &data.len())
                .finish(),
            Event::SendResourceStream {
                link_id,
                transfer_id,
                declared_length,
                ..
            } => f
                .debug_struct("SendResourceStream")
                .field("link_id", link_id)
                .field("transfer_id", transfer_id)
                .field("declared_length", declared_length)
                .finish(),
            Event::SetResourceStrategy { link_id, strategy } => f
                .debug_struct("SetResourceStrategy")
                .field("link_id", link_id)
                .field("strategy", strategy)
                .finish(),
            Event::SetResourceReceiveMode { link_id, mode } => f
                .debug_struct("SetResourceReceiveMode")
                .field("link_id", link_id)
                .field("mode", mode)
                .finish(),
            Event::SetLinkDestinationResourceReceiveMode { dest_hash, mode } => f
                .debug_struct("SetLinkDestinationResourceReceiveMode")
                .field("dest_hash", dest_hash)
                .field("mode", mode)
                .finish(),
            Event::AcceptResource {
                link_id, accept, ..
            } => f
                .debug_struct("AcceptResource")
                .field("link_id", link_id)
                .field("accept", accept)
                .finish(),
            Event::SendChannelMessage {
                link_id,
                msgtype,
                payload,
                ..
            } => f
                .debug_struct("SendChannelMessage")
                .field("link_id", link_id)
                .field("msgtype", msgtype)
                .field("payload_len", &payload.len())
                .finish(),
            Event::LinkWriterReady => f.write_str("LinkWriterReady"),
            Event::SendOnLink {
                link_id,
                data,
                context,
                ..
            }
            | Event::SendLinkTracked {
                link_id,
                data,
                context,
                ..
            } => f
                .debug_struct("SendOnLink")
                .field("link_id", link_id)
                .field("data_len", &data.len())
                .field("context", context)
                .finish(),
            Event::RequestPath { dest_hash } => f
                .debug_struct("RequestPath")
                .field("dest_hash", dest_hash)
                .finish(),
            Event::SendStampedPathRequest(request) => f
                .debug_struct("SendStampedPathRequest")
                .field("dest_hash", &request.destination_hash)
                .field("target", &request.target)
                .finish(),
            Event::DestinationStampReady { dest_hash } => f
                .debug_struct("DestinationStampReady")
                .field("dest_hash", dest_hash)
                .finish(),
            Event::RegisterProofStrategy {
                dest_hash,
                strategy,
                ..
            } => f
                .debug_struct("RegisterProofStrategy")
                .field("dest_hash", dest_hash)
                .field("strategy", strategy)
                .finish(),
            Event::BlackholeDirectPath { link_id } => f
                .debug_struct("BlackholeDirectPath")
                .field("link_id", link_id)
                .finish(),
            Event::ProposeDirectConnect { link_id } => f
                .debug_struct("ProposeDirectConnect")
                .field("link_id", link_id)
                .finish(),
            Event::SetDirectConnectPolicy { .. } => {
                write!(f, "SetDirectConnectPolicy")
            }
            Event::HolePunchProbeResult {
                link_id,
                session_id,
                observed_addr,
                probe_server,
                ..
            } => f
                .debug_struct("HolePunchProbeResult")
                .field("link_id", link_id)
                .field("session_id", session_id)
                .field("observed_addr", observed_addr)
                .field("probe_server", probe_server)
                .finish(),
            Event::HolePunchProbeFailed {
                link_id,
                session_id,
            } => f
                .debug_struct("HolePunchProbeFailed")
                .field("link_id", link_id)
                .field("session_id", session_id)
                .finish(),
            Event::DirectPathMtu { interface_id, mtu } => f
                .debug_struct("DirectPathMtu")
                .field("interface_id", interface_id)
                .field("mtu", mtu)
                .finish(),
            Event::InterfaceConfigChanged(id) => {
                f.debug_tuple("InterfaceConfigChanged").field(id).finish()
            }
            Event::BackbonePeerConnected {
                server_interface_id,
                peer_interface_id,
                peer_ip,
                peer_port,
            } => f
                .debug_struct("BackbonePeerConnected")
                .field("server_interface_id", server_interface_id)
                .field("peer_interface_id", peer_interface_id)
                .field("peer_ip", peer_ip)
                .field("peer_port", peer_port)
                .finish(),
            Event::BackbonePeerDisconnected {
                server_interface_id,
                peer_interface_id,
                peer_ip,
                peer_port,
                connected_for,
                had_received_data,
            } => f
                .debug_struct("BackbonePeerDisconnected")
                .field("server_interface_id", server_interface_id)
                .field("peer_interface_id", peer_interface_id)
                .field("peer_ip", peer_ip)
                .field("peer_port", peer_port)
                .field("connected_for", connected_for)
                .field("had_received_data", had_received_data)
                .finish(),
            Event::BackbonePeerIdleTimeout {
                server_interface_id,
                peer_interface_id,
                peer_ip,
                peer_port,
                connected_for,
            } => f
                .debug_struct("BackbonePeerIdleTimeout")
                .field("server_interface_id", server_interface_id)
                .field("peer_interface_id", peer_interface_id)
                .field("peer_ip", peer_ip)
                .field("peer_port", peer_port)
                .field("connected_for", connected_for)
                .finish(),
            Event::BackbonePeerWriteStall {
                server_interface_id,
                peer_interface_id,
                peer_ip,
                peer_port,
                connected_for,
            } => f
                .debug_struct("BackbonePeerWriteStall")
                .field("server_interface_id", server_interface_id)
                .field("peer_interface_id", peer_interface_id)
                .field("peer_ip", peer_ip)
                .field("peer_port", peer_port)
                .field("connected_for", connected_for)
                .finish(),
            Event::BackbonePeerPenalty {
                server_interface_id,
                peer_ip,
                penalty_level,
                blacklist_for,
            } => f
                .debug_struct("BackbonePeerPenalty")
                .field("server_interface_id", server_interface_id)
                .field("peer_ip", peer_ip)
                .field("penalty_level", penalty_level)
                .field("blacklist_for", blacklist_for)
                .finish(),
            Event::LoadHook {
                name,
                attach_point,
                priority,
                ..
            } => f
                .debug_struct("LoadHook")
                .field("name", name)
                .field("attach_point", attach_point)
                .field("priority", priority)
                .finish(),
            Event::LoadHookFile {
                name,
                path,
                hook_type,
                attach_point,
                priority,
                ..
            } => f
                .debug_struct("LoadHookFile")
                .field("name", name)
                .field("path", path)
                .field("hook_type", hook_type)
                .field("attach_point", attach_point)
                .field("priority", priority)
                .finish(),
            Event::LoadBuiltinHook {
                name,
                builtin_id,
                attach_point,
                priority,
                ..
            } => f
                .debug_struct("LoadBuiltinHook")
                .field("name", name)
                .field("builtin_id", builtin_id)
                .field("attach_point", attach_point)
                .field("priority", priority)
                .finish(),
            Event::UnloadHook {
                name, attach_point, ..
            } => f
                .debug_struct("UnloadHook")
                .field("name", name)
                .field("attach_point", attach_point)
                .finish(),
            Event::ReloadHook {
                name, attach_point, ..
            } => f
                .debug_struct("ReloadHook")
                .field("name", name)
                .field("attach_point", attach_point)
                .finish(),
            Event::ReloadHookFile {
                name,
                attach_point,
                path,
                hook_type,
                ..
            } => f
                .debug_struct("ReloadHookFile")
                .field("name", name)
                .field("attach_point", attach_point)
                .field("path", path)
                .field("hook_type", hook_type)
                .finish(),
            Event::ReloadBuiltinHook {
                name,
                attach_point,
                builtin_id,
                ..
            } => f
                .debug_struct("ReloadBuiltinHook")
                .field("name", name)
                .field("attach_point", attach_point)
                .field("builtin_id", builtin_id)
                .finish(),
            Event::SetHookEnabled {
                name,
                attach_point,
                enabled,
                ..
            } => f
                .debug_struct("SetHookEnabled")
                .field("name", name)
                .field("attach_point", attach_point)
                .field("enabled", enabled)
                .finish(),
            Event::SetHookPriority {
                name,
                attach_point,
                priority,
                ..
            } => f
                .debug_struct("SetHookPriority")
                .field("name", name)
                .field("attach_point", attach_point)
                .field("priority", priority)
                .finish(),
            Event::ListHooks { .. } => write!(f, "ListHooks"),
        }
    }
}
