pub(crate) mod callbacks;
pub(crate) mod compressor;
pub mod config;
pub(crate) mod destination;
pub(crate) mod discovery;
pub(crate) mod event;
/// Per-interface statistics: traffic counters, announce and path request
/// rate samples, and RNode radio reports.
pub(crate) mod interface_stats;
pub(crate) mod link_manager;
pub(crate) mod management;
pub mod time;
pub(crate) mod tunnel_extension;

/// Hash map for hot per-packet lookups keyed by link ids and hashes. std's
/// SipHash dominated these lookups; foldhash is several times cheaper and
/// still seeded randomly per process, so remotely chosen keys (link ids are
/// hashes of peer-supplied requests) cannot be ground into collisions
/// offline.
pub(crate) type FastHashMap<K, V> = std::collections::HashMap<K, V, foldhash::fast::RandomState>;
/// Set counterpart of [`FastHashMap`].
pub(crate) type FastHashSet<T> = std::collections::HashSet<T, foldhash::fast::RandomState>;
