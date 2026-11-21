//! The driver answers every query with the response its type pairs it with.

use super::*;
use crate::event::{
    query, InterfaceManagementOperation, KnownDestinationEntry, Query, RuntimeConfigValue,
};

/// Both of the driver's query entry points answer `query` as its type says.
fn assert_answers<Q: Query + Clone + std::fmt::Debug>(driver: &mut Driver, query: Q) {
    let read = driver.handle_query(query.clone().into());
    assert!(Q::response(read).is_some(), "handle_query: {query:?}");
    let mutate = driver.handle_query_mut(query.clone().into());
    assert!(Q::response(mutate).is_some(), "handle_query_mut: {query:?}");
}

#[test]
fn every_query_is_answered_with_its_own_response() {
    let mut driver = crate::driver::tests::new_test_driver();
    let d = &mut driver;
    let hash = [0x11; 16];
    let packet_hash = [0x22; 32];
    let peer_ip = std::net::IpAddr::from([127, 0, 0, 1]);
    for operation in [
        InterfaceManagementOperation::Attach,
        InterfaceManagementOperation::Detach,
        InterfaceManagementOperation::Reload,
    ] {
        assert_answers(
            d,
            query::ManageInterface {
                operation,
                name: "missing".into(),
            },
        );
    }
    assert_answers(d, query::InterfaceStats);
    assert_answers(d, query::PathTable { max_hops: Some(2) });
    assert_answers(d, query::RateTable);
    assert_answers(d, query::LowestInterfaceBitrate);
    assert_answers(d, query::MediumPathTimeout);
    assert_answers(d, query::FirstHopTimeout { dest_hash: hash });
    assert_answers(d, query::NextHop { dest_hash: hash });
    assert_answers(d, query::NextHopIfName { dest_hash: hash });
    assert_answers(d, query::LinkCount);
    assert_answers(d, query::ActiveLinkCount);
    assert_answers(d, query::LinkDistribution);
    assert_answers(d, query::DropPath { dest_hash: hash });
    assert_answers(
        d,
        query::DropAllVia {
            transport_hash: hash,
        },
    );
    assert_answers(d, query::DropAnnounceQueues);
    assert_answers(d, query::TransportIdentity);
    assert_answers(d, query::TransportStateSnapshot);
    assert_answers(d, query::GetBlackholed);
    assert_answers(
        d,
        query::BlackholeIdentity {
            identity_hash: hash,
            duration_hours: Some(1.0),
            reason: None,
        },
    );
    assert_answers(
        d,
        query::UnblackholeIdentity {
            identity_hash: hash,
        },
    );
    assert_answers(
        d,
        query::WantsDestinationType {
            full_name: "app.aspect".into(),
            requester: vec![1],
        },
    );
    assert_answers(
        d,
        query::UnwantsDestinationType {
            full_name: "app.aspect".into(),
            requester: vec![1],
        },
    );
    assert_answers(d, query::UnwantsAllDestinationTypes { requester: vec![1] });
    assert_answers(d, query::SetRequiredDestinationsOnly { enabled: false });
    assert_answers(d, query::HasPath { dest_hash: hash });
    assert_answers(d, query::PacketSignal { packet_hash });
    assert_answers(d, query::HopsTo { dest_hash: hash });
    assert_answers(d, query::RecallIdentity { dest_hash: hash });
    assert_answers(d, query::RecallDestinationStamp { dest_hash: hash });
    assert_answers(d, query::KnownDestinations);
    assert_answers(d, query::KnownDestinationChanges);
    assert_answers(
        d,
        query::RecordKnownDestinationFlush {
            stored: vec![(hash, 1)],
            removed: Vec::new(),
            seed: false,
        },
    );
    assert_answers(d, query::LocalDestinations);
    assert_answers(d, query::Links);
    assert_answers(d, query::DirectLinks);
    assert_answers(d, query::Resources);
    assert_answers(
        d,
        query::InjectPath {
            dest_hash: hash,
            next_hop: hash,
            hops: 1,
            expires: 0.0,
            interface_name: "missing".into(),
            packet_hash,
        },
    );
    assert_answers(
        d,
        query::InjectIdentity {
            dest_hash: hash,
            identity_hash: hash,
            public_key: [0x33; 64],
            app_data: None,
            hops: 1,
            received_at: 0.0,
        },
    );
    assert_answers(
        d,
        query::RestoreKnownDestination(KnownDestinationEntry {
            dest_hash: hash,
            identity_hash: hash,
            public_key: [0x33; 64],
            packet_hash: None,
            app_data: None,
            hops: 1,
            received_at: 0.0,
            receiving_interface: InterfaceId(0),
            was_used: false,
            last_used_at: None,
            retained: false,
            stamp: None,
            stamp_value: rns_core::stamp::StampValue::ZERO,
            lr_cost: None,
        }),
    );
    assert_answers(d, query::RetainKnownDestination { dest_hash: hash });
    assert_answers(
        d,
        query::RetainIdentity {
            identity_hash: hash,
        },
    );
    assert_answers(d, query::UnretainKnownDestination { dest_hash: hash });
    assert_answers(d, query::MarkKnownDestinationUsed { dest_hash: hash });
    assert_answers(
        d,
        query::DiscoveredInterfaces {
            only_available: false,
            only_transport: false,
        },
    );
    assert_answers(
        d,
        query::SendProbe {
            dest_hash: hash,
            payload_size: 16,
        },
    );
    assert_answers(d, query::CheckProof { packet_hash });
    assert_answers(d, query::ListRuntimeConfig);
    assert_answers(
        d,
        query::GetRuntimeConfig {
            key: "missing".into(),
        },
    );
    assert_answers(
        d,
        query::SetRuntimeConfig {
            key: "missing".into(),
            value: RuntimeConfigValue::Bool(true),
        },
    );
    assert_answers(
        d,
        query::ResetRuntimeConfig {
            key: "missing".into(),
        },
    );
    assert_answers(
        d,
        query::BackbonePeerState {
            interface_name: None,
        },
    );
    assert_answers(d, query::BackboneInterfaces);
    assert_answers(d, query::ProviderBridgeStats);
    assert_answers(d, query::DrainStatus);
    assert_answers(
        d,
        query::ClearBackbonePeerState {
            interface_name: "missing".into(),
            peer_ip,
        },
    );
    assert_answers(
        d,
        query::BlacklistBackbonePeer {
            interface_name: "missing".into(),
            peer_ip,
            duration: Duration::from_secs(1),
            reason: "test".into(),
            penalty_level: 1,
        },
    );
}
