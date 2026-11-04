pub mod callbacks;
pub mod compressor;
pub mod config;
pub mod destination;
pub mod discovery;
pub mod event;
pub mod interface_stats;
pub mod link_manager;
pub mod management;
pub mod time;

/// Hash map for hot per-packet lookups keyed by link ids and hashes. std's
/// SipHash dominated these lookups; foldhash is several times cheaper and
/// still seeded randomly per process, so remotely chosen keys (link ids are
/// hashes of peer-supplied requests) cannot be ground into collisions
/// offline.
pub(crate) type FastHashMap<K, V> = std::collections::HashMap<K, V, foldhash::fast::RandomState>;
/// Set counterpart of [`FastHashMap`].
pub(crate) type FastHashSet<T> = std::collections::HashSet<T, foldhash::fast::RandomState>;
