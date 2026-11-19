//! Carrying out what the transport engine and the link manager decide:
//! sending, delivering, proving and following direct paths.

mod actions;
mod delivery;
mod direct;
mod link_actions;
mod link_sends;
mod proofs;
mod send;
mod writers;

use super::*;

/// Maximum nesting depth for re-dispatching actions injected by hooks.
#[cfg(feature = "hooks")]
const MAX_HOOK_INJECTION_DEPTH: usize = 4;

fn is_outbound_path_request(raw: &[u8], path_request_dest: &[u8; 16]) -> bool {
    crate::packet_header::PacketHeader::unpack(raw).is_some_and(|packet| {
        packet.destination_hash == path_request_dest
            && packet.flags.destination_type == rns_core::constants::DESTINATION_PLAIN
            && packet.flags.packet_type == rns_core::constants::PACKET_TYPE_DATA
    })
}

/// The hash of a delivered packet. The engine leaves a link resource part
/// unhashed, so hash it here for the consumers that read the hash.
fn delivered_packet_hash(raw: &[u8], packet_hash: [u8; 32]) -> [u8; 32] {
    if RawPacket::is_unhashed_link_resource_wire(raw) {
        if let Ok(packet) = RawPacket::unpack(raw) {
            return packet.packet_hash;
        }
    }
    packet_hash
}

use crate::common::link_manager::one_cpu;

#[cfg(test)]
mod classification_tests {
    use super::*;

    #[test]
    fn outbound_path_request_matches_full_unpack() {
        let destination = [0x53; 16];
        for flags in 0..=u8::MAX {
            for hops in [
                0,
                rns_core::constants::PATHFINDER_M - 1,
                rns_core::constants::PATHFINDER_M,
                255,
            ] {
                for matching in [false, true] {
                    let mut raw = [0x31; 80];
                    raw[0] = flags;
                    raw[1] = hops;
                    let start = if flags & 0x40 == 0 { 2 } else { 18 };
                    if matching {
                        raw[start..start + 16].copy_from_slice(&destination);
                    }
                    for len in (0..=40).chain([80]) {
                        let raw = &raw[..len];
                        let expected = RawPacket::unpack(raw).is_ok_and(|packet| {
                            packet.destination_hash == destination
                                && packet.flags.destination_type
                                    == rns_core::constants::DESTINATION_PLAIN
                                && packet.flags.packet_type == rns_core::constants::PACKET_TYPE_DATA
                        });
                        assert_eq!(
                            is_outbound_path_request(raw, &destination),
                            expected,
                            "flags={flags} hops={hops} len={len} matching={matching}"
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn delivered_resource_parts_are_hashed_on_demand() {
        let packet = |context| {
            RawPacket::pack(
                rns_core::packet::PacketFlags {
                    header_type: rns_core::constants::HEADER_1,
                    context_flag: rns_core::constants::FLAG_UNSET,
                    transport_type: rns_core::constants::TRANSPORT_BROADCAST,
                    destination_type: rns_core::constants::DESTINATION_LINK,
                    packet_type: rns_core::constants::PACKET_TYPE_DATA,
                },
                0,
                &[0x42; 16],
                None,
                context,
                b"payload",
            )
            .unwrap()
        };
        let part = packet(rns_core::constants::CONTEXT_RESOURCE);
        assert_eq!(delivered_packet_hash(&part.raw, [0; 32]), part.packet_hash);
        // Any other packet keeps the hash the engine computed.
        let channel = packet(rns_core::constants::CONTEXT_CHANNEL);
        assert_eq!(delivered_packet_hash(&channel.raw, [7; 32]), [7; 32]);
    }
}

#[cfg(all(test, feature = "rns-hooks-builtin"))]
mod hook_injection_tests {
    use super::*;
    use crate::interface::Writer;
    use rns_core::transport::types::InterfaceInfo;
    use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    struct NoopCallbacks;

    impl Callbacks for NoopCallbacks {
        fn on_announce(&mut self, _: crate::common::destination::AnnouncedIdentity) {}
        fn on_path_updated(&mut self, _: rns_core::types::DestHash, _: u8) {}
        fn on_local_delivery(
            &mut self,
            _: rns_core::types::DestHash,
            _: Vec<u8>,
            _: rns_core::types::PacketHash,
        ) {
        }
    }

    struct RecordingWriter(Arc<Mutex<Vec<Vec<u8>>>>);

    impl Writer for RecordingWriter {
        fn send_frame(&mut self, data: &[u8]) -> std::io::Result<()> {
            self.0.lock().unwrap().push(data.to_vec());
            Ok(())
        }
    }

    fn interface_info(id: u64) -> InterfaceInfo {
        InterfaceInfo {
            stamp_costs: Default::default(),
            id: InterfaceId(id),
            name: format!("test-{}", id),
            mode: rns_core::constants::MODE_FULL,
            gravity: 0,
            recursive_prs: false,
            announces_from_internal: true,
            announces_to_internal: None,
            out_capable: true,
            in_capable: true,
            bitrate: None,
            airtime_profile: None,
            announce_rate_target: None,
            announce_rate_grace: 0,
            announce_rate_penalty: 0.0,
            announce_cap: rns_core::constants::ANNOUNCE_CAP,
            is_local_client: false,
            wants_tunnel: false,
            hop_limiter: None,
            tunnel_id: None,
            mtu: rns_core::constants::MTU as u32,
            mtu_upgradable: false,
            ia_freq: 0.0,
            ip_freq: 0.0,
            op_freq: 0.0,
            op_samples: 0,
            started: 0.0,
            ingress_control: rns_core::transport::types::IngressControlConfig::disabled(),
        }
    }

    fn driver_with_interface(id: u64) -> (Driver, Arc<Mutex<Vec<Vec<u8>>>>) {
        let (tx, rx) = crate::event::channel();
        let mut driver = Driver::new(
            super::super::tests::make_transport_config(false),
            rx,
            tx,
            Box::new(NoopCallbacks),
        );
        driver.set_tick_interval_handle(Arc::new(AtomicU64::new(1000)));
        let sent = Arc::new(Mutex::new(Vec::new()));
        driver.interfaces.insert(
            InterfaceId(id),
            InterfaceEntry {
                id: InterfaceId(id),
                info: interface_info(id),
                writer: Box::new(RecordingWriter(sent.clone())),
                async_writer_metrics: None,
                enabled: true,
                online: true,
                dynamic: false,
                ifac: None,
                stats: InterfaceStats::default(),
                interface_type: String::new(),
                send_retry_at: None,
                send_retry_backoff: Duration::ZERO,
            },
        );
        (driver, sent)
    }

    static HOOK_ID_COUNTER: AtomicUsize = AtomicUsize::new(0);

    fn attach_builtin(
        driver: &mut Driver,
        point: HookPoint,
        hook: impl rns_hooks::BuiltinHook,
    ) -> String {
        let id = format!(
            "test.dispatch.hook_injection.{}.{}",
            std::process::id(),
            HOOK_ID_COUNTER.fetch_add(1, Ordering::SeqCst)
        );
        rns_hooks::register_builtin_hook(id.clone(), hook).unwrap();
        let program = driver
            .hook_manager
            .as_ref()
            .expect("hook manager")
            .load_builtin(id.clone(), id.as_str(), 0)
            .unwrap();
        driver.hook_slots[point as usize].attach(program);
        id
    }

    #[test]
    fn send_hook_injecting_a_send_runs_once_and_sends_the_injected_frame() {
        let (mut driver, sent) = driver_with_interface(1);
        let calls = Arc::new(AtomicUsize::new(0));
        let hook_calls = calls.clone();
        attach_builtin(
            &mut driver,
            HookPoint::SendOnInterface,
            move |_call: rns_hooks::BuiltinHookCall<'_>, host: &mut rns_hooks::BuiltinHookHost| {
                hook_calls.fetch_add(1, Ordering::SeqCst);
                host.inject_action(rns_hooks::ActionWire::SendOnInterface {
                    interface: 1,
                    raw: vec![0x00, 0x00, 0x42],
                });
                Ok(rns_hooks::HookResult::continue_result())
            },
        );

        driver.dispatch_all(vec![TransportAction::SendOnInterface {
            interface: InterfaceId(1),
            raw: vec![0x00, 0x00, 0x01].into(),
        }]);

        assert_eq!(calls.load(Ordering::SeqCst), 1);
        let sent = sent.lock().unwrap();
        assert_eq!(
            sent.as_slice(),
            &[vec![0x00, 0x00, 0x01], vec![0x00, 0x00, 0x42]]
        );
    }

    #[test]
    fn self_injecting_path_updated_hook_stops_at_nesting_limit() {
        let (mut driver, _sent) = driver_with_interface(1);
        let calls = Arc::new(AtomicUsize::new(0));
        let hook_calls = calls.clone();
        attach_builtin(
            &mut driver,
            HookPoint::PathUpdated,
            move |_call: rns_hooks::BuiltinHookCall<'_>, host: &mut rns_hooks::BuiltinHookHost| {
                hook_calls.fetch_add(1, Ordering::SeqCst);
                host.inject_action(rns_hooks::ActionWire::PathUpdated {
                    destination_hash: [0x11; 16],
                    hops: 1,
                    next_hop: [0x22; 16],
                    interface: 1,
                });
                Ok(rns_hooks::HookResult::continue_result())
            },
        );

        driver.dispatch_all(vec![TransportAction::PathUpdated {
            destination_hash: [0x11; 16],
            hops: 1,
            next_hop: [0x22; 16],
            interface: InterfaceId(1),
        }]);

        assert_eq!(calls.load(Ordering::SeqCst), MAX_HOOK_INJECTION_DEPTH + 1);
    }
}
