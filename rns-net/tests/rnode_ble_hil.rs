//! Hardware test: an RNode over BLE (`port = ble://...`).
//!
//! Needs a host with a BlueZ adapter and an RNode with Bluetooth on and
//! bonded to it. Ignored by default and skipped unless `RNS_RNODE_BLE_PORT`
//! names the device:
//!
//! ```text
//! RNS_RNODE_BLE_PORT='ble://RNode 7012' \
//!     cargo test -p rns-net --features iface-rnode-ble --test rnode_ble_hil -- --ignored --nocapture
//! ```
//!
//! The node brings the interface up on 868 MHz (override with
//! `RNS_RNODE_BLE_FREQUENCY`), announces over it and checks that the bytes
//! went out and that the interface stays up past several keepalives
//! (`RNS_RNODE_BLE_SECONDS`, 45 by default). Nothing needs to receive the
//! radio's transmissions.

use std::time::{Duration, Instant};

use rns_crypto::identity::Identity;
use rns_crypto::OsRng;
use rns_net::{
    AnnouncedIdentity, Callbacks, DestHash, Destination, IdentityHash, PacketHash, QueryRequest,
    QueryResponse, RnsNode,
};

struct Quiet;

impl Callbacks for Quiet {
    fn on_announce(&mut self, _: AnnouncedIdentity) {}
    fn on_path_updated(&mut self, _: DestHash, _: u8) {}
    fn on_local_delivery(&mut self, _: DestHash, _: Vec<u8>, _: PacketHash) {}
}

/// Whether the RNode interface is up, and the bytes it has sent.
fn rnode_status(node: &RnsNode) -> Option<(bool, u64)> {
    let QueryResponse::InterfaceStats(stats) = node.query(QueryRequest::InterfaceStats).ok()?
    else {
        return None;
    };
    stats
        .interfaces
        .iter()
        .find(|iface| iface.name == "BLE RNode")
        .map(|iface| (iface.status, iface.txb))
}

#[test]
#[ignore = "needs an RNode bonded over BLE; set RNS_RNODE_BLE_PORT"]
fn rnode_over_ble_comes_up_and_transmits() {
    let Ok(port) = std::env::var("RNS_RNODE_BLE_PORT") else {
        eprintln!("RNS_RNODE_BLE_PORT is not set; skipping");
        return;
    };
    let frequency = std::env::var("RNS_RNODE_BLE_FREQUENCY")
        .ok()
        .and_then(|value| value.parse::<u32>().ok())
        .unwrap_or(868_000_000);
    let hold = Duration::from_secs(
        std::env::var("RNS_RNODE_BLE_SECONDS")
            .ok()
            .and_then(|value| value.parse().ok())
            .unwrap_or(45),
    );

    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("config"),
        format!(
            "[reticulum]\n  share_instance = No\n  enable_transport = No\n\n\
             [interfaces]\n  [[BLE RNode]]\n    type = RNodeInterface\n    enabled = yes\n\
             \x20   port = {port}\n    frequency = {frequency}\n    bandwidth = 125000\n\
             \x20   txpower = 2\n    spreadingfactor = 8\n    codingrate = 5\n"
        ),
    )
    .unwrap();
    let node = RnsNode::from_config(Some(dir.path()), Box::new(Quiet)).unwrap();

    // Finding, connecting and configuring the device takes seconds.
    let deadline = Instant::now() + Duration::from_secs(60);
    let sent_before = loop {
        match rnode_status(&node) {
            Some((true, txb)) => break txb,
            _ if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(500)),
            other => panic!("the RNode interface did not come up: {other:?}"),
        }
    };

    let identity = Identity::new(&mut OsRng);
    let destination = Destination::single_in(
        "rns_hil",
        &["ble", "announce"],
        IdentityHash(*identity.hash()),
    );
    node.register_destination_with_proof(&destination, None)
        .unwrap();
    node.announce_queued(&destination, &identity, Some(b"over BLE"))
        .unwrap();

    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        match rnode_status(&node) {
            Some((true, txb)) if txb > sent_before => break,
            _ if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(250)),
            other => panic!("the announce was not sent: {other:?}"),
        }
    }

    // Keepalives hold the connection open.
    let until = Instant::now() + hold;
    while Instant::now() < until {
        assert_eq!(
            rnode_status(&node).map(|(up, _)| up),
            Some(true),
            "the RNode interface went down"
        );
        std::thread::sleep(Duration::from_secs(1));
    }
    node.shutdown();
}
