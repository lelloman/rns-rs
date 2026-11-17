use super::super::engine_fixtures::{config, engine};
use super::*;

fn entry(timestamp: f64, len: usize) -> AnnounceEntry {
    AnnounceEntry {
        timestamp,
        retransmit_timeout: timestamp,
        retries: 0,
        received_from: [0xAA; 16],
        hops: 2,
        packet_raw: vec![0x01; len],
        packet_data: vec![0x02; 2 * len],
        destination_hash: [0; 16],
        context_flag: 0,
        local_rebroadcasts: 0,
        block_rebroadcasts: false,
        attached_interface: None,
    }
}

fn capped_engine(max_bytes: usize) -> TransportEngine {
    let mut config = config(true);
    config.announce_table_max_bytes = max_bytes;
    TransportEngine::new(config)
}

#[test]
fn announce_entry_size_counts_the_entry_and_both_buffers() {
    let entry = entry(1000.0, 10);
    assert_eq!(
        TransportEngine::announce_entry_size_bytes(&entry),
        size_of::<AnnounceEntry>() + entry.packet_raw.capacity() + entry.packet_data.capacity()
    );
    assert_eq!(
        TransportEngine::announce_entry_size_bytes(&entry),
        size_of::<AnnounceEntry>() + 30
    );
}

#[test]
fn culling_expired_announces_counts_both_tables() {
    let mut engine = engine(true);
    let ttl = engine.config.announce_table_ttl_secs;
    for (table, expired) in [(false, [1, 5]), (true, [3, 6])] {
        let entries = if table {
            &mut engine.held_announces
        } else {
            &mut engine.announce_table
        };
        for (i, destination) in expired.into_iter().enumerate() {
            entries.insert([destination; 16], entry(1000.0 - i as f64, 4));
        }
    }
    engine
        .announce_table
        .insert([2; 16], entry(1000.0 + ttl, 4));
    engine
        .held_announces
        .insert([4; 16], entry(1000.0 + ttl, 4));
    assert_eq!(engine.cull_expired_announce_entries(1000.5 + ttl), 4);
    assert!(engine.announce_table.contains_key(&[2; 16]));
    assert!(engine.held_announces.contains_key(&[4; 16]));
}

/// The retention cap holds announces up to exactly its size, and an
/// announce larger than the cap is refused without displacing others.
#[test]
fn retention_cap_admits_up_to_its_size() {
    let size = TransportEngine::announce_entry_size_bytes(&entry(1000.0, 8));
    let mut engine = capped_engine(2 * size);
    assert!(engine.insert_announce_entry([1; 16], entry(1000.0, 8), 1000.0));
    assert!(engine.insert_held_announce([2; 16], entry(1000.0, 8), 1000.0));
    assert!(engine.announce_table.contains_key(&[1; 16]));

    let exact = size + 16 * 3;
    let mut engine = capped_engine(exact);
    assert!(engine.insert_announce_entry([1; 16], entry(1000.0, 24), 1000.0));
    let mut engine = capped_engine(exact);
    assert!(engine.insert_held_announce([1; 16], entry(1000.0, 24), 1000.0));

    let mut engine = capped_engine(exact);
    assert!(engine.insert_announce_entry([1; 16], entry(999.0, 4), 1000.0));
    assert!(!engine.insert_announce_entry([2; 16], entry(1000.0, 25), 1000.0));
    assert!(!engine.insert_held_announce([3; 16], entry(1000.0, 25), 1000.0));
    assert!(engine.announce_table.contains_key(&[1; 16]));
}
