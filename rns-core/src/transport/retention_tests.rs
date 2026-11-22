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
        packet_hash: [0; 32],
        blocked_interfaces: Default::default(),
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
            &mut engine.announces.held
        } else {
            &mut engine.announces.table
        };
        for (i, destination) in expired.into_iter().enumerate() {
            entries.insert([destination; 16], entry(1000.0 - i as f64, 4));
        }
    }
    engine
        .announces
        .table
        .insert([2; 16], entry(1000.0 + ttl, 4));
    engine
        .announces
        .held
        .insert([4; 16], entry(1000.0 + ttl, 4));
    assert_eq!(engine.cull_expired_announce_entries(1000.5 + ttl), 4);
    assert!(engine.announces.table.contains_key(&[2; 16]));
    assert!(engine.announces.held.contains_key(&[4; 16]));
}

/// The retention cap holds announces up to exactly its size, and an
/// announce larger than the cap is refused without displacing others.
#[test]
fn retention_cap_admits_up_to_its_size() {
    let size = TransportEngine::announce_entry_size_bytes(&entry(1000.0, 8));
    let mut engine = capped_engine(2 * size);
    assert!(engine.insert_announce_entry([1; 16], entry(1000.0, 8), 1000.0));
    assert!(engine.insert_held_announce([2; 16], entry(1000.0, 8), 1000.0));
    assert!(engine.announces.table.contains_key(&[1; 16]));

    let exact = size + 16 * 3;
    let mut engine = capped_engine(exact);
    assert!(engine.insert_announce_entry([1; 16], entry(1000.0, 24), 1000.0));
    let mut engine = capped_engine(exact);
    assert!(engine.insert_held_announce([1; 16], entry(1000.0, 24), 1000.0));

    let mut engine = capped_engine(exact);
    assert!(engine.insert_announce_entry([1; 16], entry(999.0, 4), 1000.0));
    assert!(!engine.insert_announce_entry([2; 16], entry(1000.0, 25), 1000.0));
    assert!(!engine.insert_held_announce([3; 16], entry(1000.0, 25), 1000.0));
    assert!(engine.announces.table.contains_key(&[1; 16]));
}

fn numbered_dest(i: u32) -> [u8; 16] {
    let mut dest = [0u8; 16];
    dest.copy_from_slice(&crate::hash::full_hash(&i.to_be_bytes())[..16]);
    dest
}

fn assert_retained_bytes_consistent(engine: &TransportEngine) {
    assert!(engine.announces.table.retained_bytes_consistent());
    assert!(engine.announces.held.retained_bytes_consistent());
    let sum: usize = engine
        .announces
        .table
        .values()
        .chain(engine.announces.held.values())
        .map(TransportEngine::announce_entry_size_bytes)
        .sum();
    assert_eq!(engine.announce_retained_bytes_total(), sum);
}

/// The running retained-bytes total follows every kind of change: insert,
/// replacement, in-place update, removal, the periodic job, cap eviction
/// and clearing.
#[test]
fn announce_retained_bytes_total_tracks_every_change() {
    let size = TransportEngine::announce_entry_size_bytes(&entry(1000.0, 8));
    let mut engine = capped_engine(6 * size);
    assert!(engine.insert_announce_entry([1; 16], entry(1000.0, 8), 1000.0));
    assert!(engine.insert_held_announce([1; 16], entry(1000.0, 4), 1000.0));
    assert_retained_bytes_consistent(&engine);
    // Replacement with a different size.
    assert!(engine.insert_announce_entry([1; 16], entry(1000.5, 3), 1000.5));
    assert_retained_bytes_consistent(&engine);
    // In-place growth.
    engine.announces.table.update(&[1; 16], |e| {
        e.blocked_interfaces.insert(InterfaceId(7));
        e.packet_data.reserve(64);
    });
    assert_retained_bytes_consistent(&engine);
    assert!(engine.announces.table.remove(&[1; 16]).is_some());
    assert_retained_bytes_consistent(&engine);
    // Over the cap: eviction.
    for i in 0..10u8 {
        engine.insert_announce_entry([0x10 + i; 16], entry(1001.0 + f64::from(i), 8), 1001.0);
        assert_retained_bytes_consistent(&engine);
    }
    assert!(engine.announce_retained_bytes_total() <= 6 * size);
    // The periodic job: retransmission, held promotion and expiry.
    let mut rng = rns_crypto::FixedRng::new(&[0x42; 32]);
    let _ = engine.tick(1012.0, &mut rng);
    assert_retained_bytes_consistent(&engine);
    let ttl = engine.config.announce_table_ttl_secs;
    let _ = engine.tick(1020.0 + ttl, &mut rng);
    assert_retained_bytes_consistent(&engine);
    assert_eq!(engine.announce_retained_bytes_total(), 0);
    assert!(engine.insert_held_announce([2; 16], entry(1100.0, 8), 1100.0));
    engine.drop_announce_queues();
    assert_eq!(engine.announce_retained_bytes_total(), 0);
    assert_retained_bytes_consistent(&engine);
}

/// Inserting leaves expired entries to the periodic announce job instead
/// of culling both tables on every insert; an entry already expired is
/// still not retained, and an expired pending send is not preserved.
#[test]
fn announce_insert_leaves_expiry_to_the_periodic_job() {
    let mut engine = engine(true);
    let ttl = engine.config.announce_table_ttl_secs;
    assert!(engine.insert_announce_entry([1; 16], entry(1000.0, 8), 1000.0));
    assert!(engine.insert_held_announce([2; 16], entry(1000.0, 8), 1000.0));
    let later = 1001.0 + ttl;
    assert!(engine.insert_announce_entry([3; 16], entry(later, 8), later));
    assert!(engine.announces.table.contains_key(&[1; 16]));
    assert!(engine.announces.held.contains_key(&[2; 16]));
    assert!(!engine.insert_announce_entry([4; 16], entry(1000.0, 8), later));
    assert!(!engine.insert_held_announce([4; 16], entry(1000.0, 8), later));

    let mut fresh = entry(later, 8);
    fresh.retransmit_timeout = later + 0.5;
    assert!(engine.insert_announce_entry([1; 16], fresh, later));
    assert_eq!(
        engine.announces.table[&[1; 16]].retransmit_timeout,
        later + 0.5
    );

    let mut rng = rns_crypto::FixedRng::new(&[0x42; 32]);
    let _ = engine.tick(later, &mut rng);
    assert!(!engine.announces.held.contains_key(&[2; 16]));
    assert!(engine.announces.table.contains_key(&[3; 16]));
}

/// A flood at the retention cap stays under it and evicts in batches, so
/// most inserts past the cap do not cull and sort the tables again.
#[test]
fn announce_retention_cap_holds_under_flood_and_evicts_in_batches() {
    let size = TransportEngine::announce_entry_size_bytes(&entry(1000.0, 8));
    let max_bytes = 256 * size;
    let mut engine = capped_engine(max_bytes);
    let mut cap_events = 0usize;
    for i in 0..4000u32 {
        let now = 1000.0 + f64::from(i) * 0.001;
        if engine.announce_retained_bytes_total() + size > max_bytes {
            cap_events += 1;
        }
        assert!(engine.insert_announce_entry(numbered_dest(i), entry(now, 8), now));
        assert!(engine.announce_retained_bytes_total() <= max_bytes);
    }
    // The oldest went first, the newest stayed.
    assert!(!engine.announces.table.contains_key(&numbered_dest(0)));
    assert!(engine.announces.table.contains_key(&numbered_dest(3998)));
    assert!(cap_events * 4 <= 4000 - 256);
    assert_retained_bytes_consistent(&engine);
}
