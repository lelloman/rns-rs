//! Lightweight live profiling compatible with Reticulum's profiler results.
//!
//! Create a guard with [`profile`] or [`profile_with_parent`]. Dropping the
//! guard records the elapsed wall-clock duration under its tag. Results are
//! process-global so the daemon can expose bounded, live statistics over local
//! and remote status APIs while it runs indefinitely.

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::sync::{Mutex, OnceLock};
use std::thread::ThreadId;
use std::time::Instant;

use rns_core::msgpack::Value;

use crate::pickle::PickleValue;

/// Default maximum retained samples for each tag and thread.
pub const MAX_CAPTURES: usize = 10_000;

#[derive(Debug, Clone, Copy)]
struct Capture {
    started: f64,
    duration: f64,
}

#[derive(Debug, Default)]
struct TagCaptures {
    parent: Option<String>,
    threads: HashMap<ThreadId, VecDeque<Capture>>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ProfilingStats {
    pub mean: f64,
    pub median: f64,
    pub min: f64,
    pub max: f64,
    pub stdev: Option<f64>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ProfilingResult {
    pub name: String,
    pub parent: Option<String>,
    pub count: usize,
    pub threads: usize,
    pub stats_all: ProfilingStats,
    pub stats_1m: Option<ProfilingStats>,
    pub stats_5m: Option<ProfilingStats>,
    pub stats_30m: Option<ProfilingStats>,
    pub stats_60m: Option<ProfilingStats>,
}

static EPOCH: OnceLock<Instant> = OnceLock::new();
static CAPTURES: OnceLock<Mutex<BTreeMap<String, TagCaptures>>> = OnceLock::new();

fn elapsed_now() -> f64 {
    EPOCH.get_or_init(Instant::now).elapsed().as_secs_f64()
}

fn captures() -> &'static Mutex<BTreeMap<String, TagCaptures>> {
    CAPTURES.get_or_init(|| Mutex::new(BTreeMap::new()))
}

/// A timing sample that is recorded when the guard is dropped.
#[must_use = "the guard must be retained for the duration being profiled"]
pub struct ProfileGuard {
    tag: String,
    parent: Option<String>,
    started_at: f64,
    started: Instant,
    max_captures: usize,
}

impl Drop for ProfileGuard {
    fn drop(&mut self) {
        record_duration(
            &self.tag,
            self.parent.as_deref(),
            self.started_at,
            self.started.elapsed().as_secs_f64(),
            self.max_captures,
            std::thread::current().id(),
        );
    }
}

fn start_profile(tag: String, parent: Option<String>, max_captures: usize) -> ProfileGuard {
    ProfileGuard {
        tag,
        parent,
        started_at: elapsed_now(),
        started: Instant::now(),
        max_captures,
    }
}

/// Start profiling a top-level tag with the default retention limit.
pub fn profile(tag: impl Into<String>) -> ProfileGuard {
    start_profile(tag.into(), None, MAX_CAPTURES)
}

/// Start profiling a top-level tag with a custom per-thread retention limit.
pub fn profile_with_limit(tag: impl Into<String>, max_captures: usize) -> ProfileGuard {
    start_profile(tag.into(), None, max_captures)
}

/// Start profiling a tag nested under `parent` in formatted results.
pub fn profile_with_parent(tag: impl Into<String>, parent: impl Into<String>) -> ProfileGuard {
    start_profile(tag.into(), Some(parent.into()), MAX_CAPTURES)
}

/// Start nested profiling with a custom per-thread retention limit.
pub fn profile_with_parent_and_limit(
    tag: impl Into<String>,
    parent: impl Into<String>,
    max_captures: usize,
) -> ProfileGuard {
    start_profile(tag.into(), Some(parent.into()), max_captures)
}

fn record_duration(
    tag: &str,
    parent: Option<&str>,
    started: f64,
    duration: f64,
    max_captures: usize,
    thread_id: ThreadId,
) {
    let mut registry = captures()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let entry = registry.entry(tag.to_owned()).or_default();
    if entry.parent.is_none() {
        entry.parent = parent.map(str::to_owned);
    }
    let thread = entry.threads.entry(thread_id).or_default();
    if max_captures == 0 {
        thread.clear();
        return;
    }
    while thread.len() >= max_captures {
        thread.pop_front();
    }
    thread.push_back(Capture { started, duration });
}

/// Return whether at least one timing sample has completed.
pub fn ran() -> bool {
    captures()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .values()
        .any(|entry| entry.threads.values().any(|thread| !thread.is_empty()))
}

fn calculate_stats(captures: &[Capture]) -> Option<ProfilingStats> {
    if captures.is_empty() {
        return None;
    }
    let mut durations: Vec<f64> = captures.iter().map(|capture| capture.duration).collect();
    durations.sort_by(f64::total_cmp);
    let count = durations.len();
    let mean = durations.iter().sum::<f64>() / count as f64;
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
    Some(ProfilingStats {
        mean,
        median,
        min: durations[0],
        max: durations[count - 1],
        stdev,
    })
}

fn recent_stats(captures: &[Capture], now: f64, age: f64) -> Option<ProfilingStats> {
    let recent: Vec<Capture> = captures
        .iter()
        .copied()
        .filter(|capture| capture.started >= now - age)
        .collect();
    (recent.len() > 1)
        .then(|| calculate_stats(&recent))
        .flatten()
}

/// Return a stable, tag-sorted snapshot of all retained samples.
pub fn results() -> BTreeMap<String, ProfilingResult> {
    let now = elapsed_now();
    captures()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .iter()
        .filter_map(|(tag, entry)| {
            let mut tag_captures: Vec<Capture> = entry
                .threads
                .values()
                .flat_map(|thread| thread.iter().copied())
                .collect();
            tag_captures.sort_by(|left, right| left.started.total_cmp(&right.started));
            let stats_all = calculate_stats(&tag_captures)?;
            Some((
                tag.clone(),
                ProfilingResult {
                    name: tag.clone(),
                    parent: entry.parent.clone(),
                    count: tag_captures.len(),
                    threads: entry
                        .threads
                        .values()
                        .filter(|thread| !thread.is_empty())
                        .count(),
                    stats_all,
                    stats_1m: recent_stats(&tag_captures, now, 60.0),
                    stats_5m: recent_stats(&tag_captures, now, 5.0 * 60.0),
                    stats_30m: recent_stats(&tag_captures, now, 30.0 * 60.0),
                    stats_60m: recent_stats(&tag_captures, now, 60.0 * 60.0),
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
        (pickle_key("mean"), PickleValue::Float(stats.mean)),
        (pickle_key("median"), PickleValue::Float(stats.median)),
        (pickle_key("min"), PickleValue::Float(stats.min)),
        (pickle_key("max"), PickleValue::Float(stats.max)),
        (
            pickle_key("stdev"),
            stats.stdev.map_or(PickleValue::None, PickleValue::Float),
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
        (pickle_key("count"), PickleValue::Int(result.count as i64)),
        (
            pickle_key("threads"),
            PickleValue::Int(result.threads as i64),
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
        (Value::Str("mean".into()), Value::Float(stats.mean)),
        (Value::Str("median".into()), Value::Float(stats.median)),
        (Value::Str("min".into()), Value::Float(stats.min)),
        (Value::Str("max".into()), Value::Float(stats.max)),
        (
            Value::Str("stdev".into()),
            stats.stdev.map_or(Value::Nil, Value::Float),
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
        (Value::Str("count".into()), Value::UInt(result.count as u64)),
        (
            Value::Str("threads".into()),
            Value::UInt(result.threads as u64),
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
        record_duration(
            tag,
            None,
            started,
            duration,
            limit,
            std::thread::current().id(),
        );
    }

    #[test]
    fn bounded_timestamped_captures_support_live_windows() {
        let now = elapsed_now();
        record("entry111.bounded", now - 70.0, 0.001, 3);
        record("entry111.bounded", now - 50.0, 0.003, 3);
        record("entry111.bounded", now - 10.0, 0.005, 3);
        record("entry111.bounded", now, 0.007, 3);

        let result = &results()["entry111.bounded"];
        assert_eq!(result.count, 3);
        assert_eq!(result.threads, 1);
        assert_eq!(result.stats_all.min, 0.003);
        assert_eq!(result.stats_all.max, 0.007);
        assert_eq!(result.stats_1m.as_ref().unwrap().mean, 0.005);
        assert_eq!(result.stats_5m.as_ref().unwrap().mean, 0.005);
        assert!(result.stats_30m.is_some());
        assert!(result.stats_60m.is_some());

        let pickle = results_pickle().unwrap();
        let entry = pickle.get("entry111.bounded").unwrap();
        assert_eq!(entry.get("threads").and_then(PickleValue::as_int), Some(1));
        assert_eq!(
            entry
                .get("stats_all")
                .and_then(|stats| stats.get("max"))
                .and_then(PickleValue::as_float),
            Some(0.007)
        );
    }

    #[test]
    fn retention_limit_applies_independently_per_thread() {
        let handles: Vec<_> = (0..2)
            .map(|thread_index| {
                std::thread::spawn(move || {
                    for sample in 0..3 {
                        record_duration(
                            "entry111.threads",
                            None,
                            elapsed_now(),
                            (thread_index * 10 + sample) as f64,
                            2,
                            std::thread::current().id(),
                        );
                    }
                })
            })
            .collect();
        for handle in handles {
            handle.join().unwrap();
        }

        let result = &results()["entry111.threads"];
        assert_eq!(result.count, 4);
        assert_eq!(result.threads, 2);
        assert_eq!(result.stats_all.min, 1.0);
        assert_eq!(result.stats_all.max, 12.0);
    }

    #[test]
    fn guard_records_elapsed_time() {
        {
            let _sample = profile("entry111.guard");
        }
        assert!(results()["entry111.guard"].stats_all.mean >= 0.0);
    }
}
