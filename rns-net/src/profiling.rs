//! Lightweight live profiling compatible with Reticulum's profiler results.
//!
//! Create a guard with [`profile`] or [`profile_with_parent`]. A capture is
//! registered immediately and completed when the guard is dropped, which makes
//! nested and reentrant calls independently visible without reporting partial
//! durations. Results are process-global and bounded per tag so the daemon can
//! expose them indefinitely over local and remote status APIs.

use std::collections::{BTreeMap, HashSet, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};
use std::thread::ThreadId;
use std::time::Instant;

use rns_core::msgpack::Value;

use crate::pickle::PickleValue;

/// Default maximum retained samples for each tag across all threads.
pub const MAX_CAPTURES: usize = 10_000;

#[derive(Debug, Clone, Copy)]
struct Capture {
    id: u64,
    started: f64,
    ended: Option<f64>,
    thread_id: ThreadId,
}

impl Capture {
    fn duration(self) -> Option<f64> {
        self.ended.map(|ended| ended - self.started)
    }
}

#[derive(Debug)]
struct TagCaptures {
    parent: Option<String>,
    max_captures: usize,
    captures: VecDeque<Capture>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ProfilingStats {
    pub count: usize,
    pub mean: f64,
    pub median: f64,
    pub min: f64,
    pub max: f64,
    pub stdev: Option<f64>,
    pub sum: f64,
    pub threads: Option<usize>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ProfilingResult {
    pub name: String,
    pub parent: Option<String>,
    pub stats_all: ProfilingStats,
    pub stats_1m: Option<ProfilingStats>,
    pub stats_5m: Option<ProfilingStats>,
    pub stats_30m: Option<ProfilingStats>,
    pub stats_60m: Option<ProfilingStats>,
}

static EPOCH: OnceLock<Instant> = OnceLock::new();
static NEXT_CAPTURE_ID: AtomicU64 = AtomicU64::new(1);
static CAPTURES: OnceLock<Mutex<BTreeMap<String, TagCaptures>>> = OnceLock::new();

fn elapsed_now() -> f64 {
    EPOCH.get_or_init(Instant::now).elapsed().as_secs_f64()
}

fn captures() -> &'static Mutex<BTreeMap<String, TagCaptures>> {
    CAPTURES.get_or_init(|| Mutex::new(BTreeMap::new()))
}

/// A timing sample that is completed when the guard is dropped.
#[must_use = "the guard must be retained for the duration being profiled"]
pub struct ProfileGuard {
    tag: String,
    capture_id: Option<u64>,
}

impl Drop for ProfileGuard {
    fn drop(&mut self) {
        if let Some(capture_id) = self.capture_id {
            complete_capture(&self.tag, capture_id, elapsed_now());
        }
    }
}

fn begin_capture(
    tag: &str,
    parent: Option<&str>,
    max_captures: usize,
    started: f64,
    thread_id: ThreadId,
) -> Option<u64> {
    if max_captures == 0 {
        return None;
    }
    let capture_id = NEXT_CAPTURE_ID.fetch_add(1, Ordering::Relaxed);
    let mut registry = captures()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let entry = registry
        .entry(tag.to_owned())
        .or_insert_with(|| TagCaptures {
            parent: parent.map(str::to_owned),
            max_captures,
            captures: VecDeque::with_capacity(max_captures.min(1024)),
        });
    if entry.parent.is_none() {
        entry.parent = parent.map(str::to_owned);
    }
    while entry.captures.len() >= entry.max_captures {
        entry.captures.pop_front();
    }
    entry.captures.push_back(Capture {
        id: capture_id,
        started,
        ended: None,
        thread_id,
    });
    Some(capture_id)
}

fn complete_capture(tag: &str, capture_id: u64, ended: f64) {
    let mut registry = captures()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let Some(entry) = registry.get_mut(tag) else {
        return;
    };
    if let Some(capture) = entry
        .captures
        .iter_mut()
        .find(|capture| capture.id == capture_id)
    {
        capture.ended = Some(ended);
    }
}

fn start_profile(tag: String, parent: Option<String>, max_captures: usize) -> ProfileGuard {
    let capture_id = begin_capture(
        &tag,
        parent.as_deref(),
        max_captures,
        elapsed_now(),
        std::thread::current().id(),
    );
    ProfileGuard { tag, capture_id }
}

/// Start profiling a top-level tag with the default retention limit.
pub fn profile(tag: impl Into<String>) -> ProfileGuard {
    start_profile(tag.into(), None, MAX_CAPTURES)
}

/// Start profiling a top-level tag with a custom per-tag retention limit.
pub fn profile_with_limit(tag: impl Into<String>, max_captures: usize) -> ProfileGuard {
    start_profile(tag.into(), None, max_captures)
}

/// Start profiling a tag nested under `parent` in formatted results.
pub fn profile_with_parent(tag: impl Into<String>, parent: impl Into<String>) -> ProfileGuard {
    start_profile(tag.into(), Some(parent.into()), MAX_CAPTURES)
}

/// Start nested profiling with a custom per-tag retention limit.
pub fn profile_with_parent_and_limit(
    tag: impl Into<String>,
    parent: impl Into<String>,
    max_captures: usize,
) -> ProfileGuard {
    start_profile(tag.into(), Some(parent.into()), max_captures)
}

/// Run a function or closure under a profiling tag and return its result.
///
/// This is the Rust counterpart to Reticulum's profiling decorator. Rust does
/// not expose a stable runtime qualified function name, so the tag is explicit.
/// The guard is also dropped during unwinding, preserving completed timing for
/// functions that panic when the panic is caught by their caller.
pub fn profile_function<T>(tag: impl Into<String>, function: impl FnOnce() -> T) -> T {
    let _profile = profile(tag);
    function()
}

/// Run a function or closure under a profiling tag with a custom retention
/// limit and return its result.
pub fn profile_function_with_limit<T>(
    tag: impl Into<String>,
    max_captures: usize,
    function: impl FnOnce() -> T,
) -> T {
    let _profile = profile_with_limit(tag, max_captures);
    function()
}

/// Return whether at least one timing sample has completed.
pub fn ran() -> bool {
    captures()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .values()
        .any(|entry| entry.captures.iter().any(|capture| capture.ended.is_some()))
}

fn calculate_stats(captures: &[Capture], include_threads: bool) -> Option<ProfilingStats> {
    let completed: Vec<(f64, ThreadId)> = captures
        .iter()
        .filter_map(|capture| {
            capture
                .duration()
                .map(|duration| (duration, capture.thread_id))
        })
        .collect();
    if completed.is_empty() {
        return None;
    }
    let mut durations: Vec<f64> = completed.iter().map(|(duration, _)| *duration).collect();
    durations.sort_by(f64::total_cmp);
    let count = durations.len();
    let sum = durations.iter().sum::<f64>();
    let mean = sum / count as f64;
    let median = if count.is_multiple_of(2) {
        (durations[count / 2 - 1] + durations[count / 2]) / 2.0
    } else {
        durations[count / 2]
    };
    let stdev = (count > 1).then(|| {
        let variance = durations
            .iter()
            .map(|duration| (duration - mean).powi(2))
            .sum::<f64>()
            / (count - 1) as f64;
        variance.sqrt()
    });
    let threads = include_threads.then(|| {
        completed
            .iter()
            .map(|(_, thread_id)| *thread_id)
            .collect::<HashSet<_>>()
            .len()
    });
    Some(ProfilingStats {
        count,
        mean,
        median,
        min: durations[0],
        max: durations[count - 1],
        stdev,
        sum,
        threads,
    })
}

fn window_stats(
    captures: &[Capture],
    now: f64,
    youngest_age: f64,
    oldest_age: f64,
) -> Option<ProfilingStats> {
    let window: Vec<Capture> = captures
        .iter()
        .copied()
        .filter(|capture| {
            let age = now - capture.started;
            age >= youngest_age && age < oldest_age
        })
        .collect();
    calculate_stats(&window, false)
}

/// Return a stable, tag-sorted snapshot of all retained completed samples.
pub fn results() -> BTreeMap<String, ProfilingResult> {
    let now = elapsed_now();
    captures()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .iter()
        .filter_map(|(tag, entry)| {
            let mut tag_captures: Vec<Capture> = entry.captures.iter().copied().collect();
            tag_captures.sort_by(|left, right| left.started.total_cmp(&right.started));
            let stats_all = calculate_stats(&tag_captures, true)?;
            Some((
                tag.clone(),
                ProfilingResult {
                    name: tag.clone(),
                    parent: entry.parent.clone(),
                    stats_all,
                    stats_1m: window_stats(&tag_captures, now, 0.0, 60.0),
                    stats_5m: window_stats(&tag_captures, now, 60.0, 5.0 * 60.0),
                    stats_30m: window_stats(&tag_captures, now, 5.0 * 60.0, 30.0 * 60.0),
                    stats_60m: window_stats(&tag_captures, now, 30.0 * 60.0, 60.0 * 60.0),
                },
            ))
        })
        .collect()
}

fn pickle_key(key: &str) -> PickleValue {
    PickleValue::String(key.into())
}

fn stats_to_pickle(stats: Option<&ProfilingStats>) -> PickleValue {
    let Some(stats) = stats else {
        return PickleValue::None;
    };
    PickleValue::Dict(vec![
        (pickle_key("count"), PickleValue::Int(stats.count as i64)),
        (pickle_key("mean"), PickleValue::Float(stats.mean)),
        (pickle_key("median"), PickleValue::Float(stats.median)),
        (pickle_key("min"), PickleValue::Float(stats.min)),
        (pickle_key("max"), PickleValue::Float(stats.max)),
        (
            pickle_key("stdev"),
            stats.stdev.map_or(PickleValue::None, PickleValue::Float),
        ),
        (pickle_key("sum"), PickleValue::Float(stats.sum)),
        (
            pickle_key("threads"),
            stats.threads.map_or(PickleValue::None, |threads| {
                PickleValue::Int(threads as i64)
            }),
        ),
    ])
}

fn result_to_pickle(result: &ProfilingResult) -> PickleValue {
    PickleValue::Dict(vec![
        (pickle_key("name"), PickleValue::String(result.name.clone())),
        (
            pickle_key("super"),
            result.parent.as_ref().map_or(PickleValue::None, |parent| {
                PickleValue::String(parent.clone())
            }),
        ),
        (
            pickle_key("stats_all"),
            stats_to_pickle(Some(&result.stats_all)),
        ),
        (
            pickle_key("stats_1m"),
            stats_to_pickle(result.stats_1m.as_ref()),
        ),
        (
            pickle_key("stats_5m"),
            stats_to_pickle(result.stats_5m.as_ref()),
        ),
        (
            pickle_key("stats_30m"),
            stats_to_pickle(result.stats_30m.as_ref()),
        ),
        (
            pickle_key("stats_60m"),
            stats_to_pickle(result.stats_60m.as_ref()),
        ),
    ])
}

/// Snapshot results in the dictionary shape used by Python's local RPC.
pub fn results_pickle() -> Option<PickleValue> {
    let results = results();
    (!results.is_empty()).then(|| {
        PickleValue::Dict(
            results
                .iter()
                .map(|(tag, result)| (PickleValue::String(tag.clone()), result_to_pickle(result)))
                .collect(),
        )
    })
}

fn stats_to_msgpack(stats: Option<&ProfilingStats>) -> Value {
    let Some(stats) = stats else {
        return Value::Nil;
    };
    Value::Map(vec![
        (Value::Str("count".into()), Value::UInt(stats.count as u64)),
        (Value::Str("mean".into()), Value::Float(stats.mean)),
        (Value::Str("median".into()), Value::Float(stats.median)),
        (Value::Str("min".into()), Value::Float(stats.min)),
        (Value::Str("max".into()), Value::Float(stats.max)),
        (
            Value::Str("stdev".into()),
            stats.stdev.map_or(Value::Nil, Value::Float),
        ),
        (Value::Str("sum".into()), Value::Float(stats.sum)),
        (
            Value::Str("threads".into()),
            stats
                .threads
                .map_or(Value::Nil, |threads| Value::UInt(threads as u64)),
        ),
    ])
}

fn result_to_msgpack(result: &ProfilingResult) -> Value {
    Value::Map(vec![
        (Value::Str("name".into()), Value::Str(result.name.clone())),
        (
            Value::Str("super".into()),
            result
                .parent
                .as_ref()
                .map_or(Value::Nil, |parent| Value::Str(parent.clone())),
        ),
        (
            Value::Str("stats_all".into()),
            stats_to_msgpack(Some(&result.stats_all)),
        ),
        (
            Value::Str("stats_1m".into()),
            stats_to_msgpack(result.stats_1m.as_ref()),
        ),
        (
            Value::Str("stats_5m".into()),
            stats_to_msgpack(result.stats_5m.as_ref()),
        ),
        (
            Value::Str("stats_30m".into()),
            stats_to_msgpack(result.stats_30m.as_ref()),
        ),
        (
            Value::Str("stats_60m".into()),
            stats_to_msgpack(result.stats_60m.as_ref()),
        ),
    ])
}

/// Snapshot results in the dictionary shape used by remote management.
pub fn results_msgpack() -> Value {
    let results = results();
    if results.is_empty() {
        Value::Nil
    } else {
        Value::Map(
            results
                .iter()
                .map(|(tag, result)| (Value::Str(tag.clone()), result_to_msgpack(result)))
                .collect(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(tag: &str, started: f64, duration: f64, limit: usize) {
        let id = begin_capture(tag, None, limit, started, std::thread::current().id()).unwrap();
        complete_capture(tag, id, started + duration);
    }

    #[test]
    fn retention_limit_is_shared_across_threads() {
        let tag = "entry113.shared-limit";
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
        let handles: Vec<_> = (0..2)
            .map(|thread_index| {
                let barrier = barrier.clone();
                std::thread::spawn(move || {
                    for sample in 0..3 {
                        barrier.wait();
                        record(
                            tag,
                            elapsed_now(),
                            (thread_index * 10 + sample + 1) as f64,
                            3,
                        );
                        barrier.wait();
                    }
                })
            })
            .collect();
        for handle in handles {
            handle.join().unwrap();
        }

        let result = &results()[tag];
        assert_eq!(result.stats_all.count, 3);
        assert_eq!(result.stats_all.threads, Some(2));
    }

    #[test]
    fn reentrant_guards_complete_independent_captures() {
        let outer = profile("entry113.reentrant");
        let inner = profile("entry113.reentrant");
        drop(inner);
        assert_eq!(results()["entry113.reentrant"].stats_all.count, 1);
        drop(outer);
        assert_eq!(results()["entry113.reentrant"].stats_all.count, 2);
    }

    #[test]
    fn live_windows_are_non_overlapping() {
        let tag = "entry113.windows";
        let now = elapsed_now();
        record(tag, now - 30.0, 0.001, 10);
        record(tag, now - 120.0, 0.002, 10);
        record(tag, now - 600.0, 0.003, 10);
        record(tag, now - 2_400.0, 0.004, 10);

        let result = &results()[tag];
        assert_eq!(result.stats_all.count, 4);
        assert!((result.stats_all.sum - 0.010).abs() < 1e-9);
        assert_eq!(result.stats_1m.as_ref().unwrap().count, 1);
        assert!((result.stats_1m.as_ref().unwrap().sum - 0.001).abs() < 1e-9);
        assert!((result.stats_5m.as_ref().unwrap().sum - 0.002).abs() < 1e-9);
        assert!((result.stats_30m.as_ref().unwrap().sum - 0.003).abs() < 1e-9);
        assert!((result.stats_60m.as_ref().unwrap().sum - 0.004).abs() < 1e-9);
    }

    #[test]
    fn rpc_shape_moves_counts_into_statistics() {
        record("entry113.shape", elapsed_now(), 0.005, 10);
        let pickle = results_pickle().unwrap();
        let entry = pickle.get("entry113.shape").unwrap();
        assert!(entry.get("count").is_none());
        assert!(entry.get("threads").is_none());
        let all = entry.get("stats_all").unwrap();
        assert_eq!(all.get("count").and_then(PickleValue::as_int), Some(1));
        assert_eq!(all.get("threads").and_then(PickleValue::as_int), Some(1));
        let sum = all.get("sum").and_then(PickleValue::as_float).unwrap();
        assert!((sum - 0.005).abs() < 1e-9);
    }

    #[test]
    fn function_adapter_preserves_result_and_records_unwind() {
        assert_eq!(profile_function("entry113.function", || 42), 42);
        let unwind = std::panic::catch_unwind(|| {
            profile_function("entry113.unwind", || panic!("profiled failure"));
        });
        assert!(unwind.is_err());
        assert_eq!(results()["entry113.unwind"].stats_all.count, 1);
    }

    #[test]
    fn merged_live_profiling_pipeline_retains_final_schema() {
        profile_function("entry114.merge", || ());
        let Value::Map(tags) = results_msgpack() else {
            panic!("merged profiler results must be a MessagePack map");
        };
        let Value::Map(entry) = tags
            .iter()
            .find(|(key, _)| *key == Value::Str("entry114.merge".into()))
            .map(|(_, value)| value)
            .unwrap()
        else {
            panic!("merged profiler entry must be a map");
        };
        for key in [
            "name",
            "super",
            "stats_all",
            "stats_1m",
            "stats_5m",
            "stats_30m",
            "stats_60m",
        ] {
            assert!(entry
                .iter()
                .any(|(candidate, _)| *candidate == Value::Str(key.into())));
        }
    }
}
