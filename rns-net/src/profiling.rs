//! Lightweight live profiling compatible with Reticulum's profiler results.
//!
//! Create a guard with [`profile`] or [`profile_with_parent`]. Dropping the
//! guard records the elapsed wall-clock duration under its tag. Results are
//! process-global so the daemon can expose them over local and remote status
//! APIs while it is running.

use std::collections::BTreeMap;
use std::sync::{Mutex, OnceLock};
use std::time::Instant;

use rns_core::msgpack::Value;

use crate::pickle::PickleValue;

#[derive(Debug, Default)]
struct TagCaptures {
    parent: Option<String>,
    durations: Vec<f64>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ProfilingResult {
    pub name: String,
    pub parent: Option<String>,
    pub count: usize,
    pub mean: f64,
    pub median: f64,
    pub stdev: Option<f64>,
}

static CAPTURES: OnceLock<Mutex<BTreeMap<String, TagCaptures>>> = OnceLock::new();

fn captures() -> &'static Mutex<BTreeMap<String, TagCaptures>> {
    CAPTURES.get_or_init(|| Mutex::new(BTreeMap::new()))
}

/// A timing sample that is recorded when the guard is dropped.
#[must_use = "the guard must be retained for the duration being profiled"]
pub struct ProfileGuard {
    tag: String,
    parent: Option<String>,
    started: Instant,
}

impl Drop for ProfileGuard {
    fn drop(&mut self) {
        record_duration(
            &self.tag,
            self.parent.as_deref(),
            self.started.elapsed().as_secs_f64(),
        );
    }
}

/// Start profiling a top-level tag.
pub fn profile(tag: impl Into<String>) -> ProfileGuard {
    ProfileGuard {
        tag: tag.into(),
        parent: None,
        started: Instant::now(),
    }
}

/// Start profiling a tag nested under `parent` in formatted results.
pub fn profile_with_parent(tag: impl Into<String>, parent: impl Into<String>) -> ProfileGuard {
    ProfileGuard {
        tag: tag.into(),
        parent: Some(parent.into()),
        started: Instant::now(),
    }
}

fn record_duration(tag: &str, parent: Option<&str>, duration: f64) {
    let mut registry = captures()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let entry = registry.entry(tag.to_owned()).or_default();
    if entry.parent.is_none() {
        entry.parent = parent.map(str::to_owned);
    }
    entry.durations.push(duration);
}

/// Return whether at least one timing sample has completed.
pub fn ran() -> bool {
    captures()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .values()
        .any(|entry| !entry.durations.is_empty())
}

/// Return a stable, tag-sorted snapshot of all completed samples.
pub fn results() -> BTreeMap<String, ProfilingResult> {
    captures()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .iter()
        .filter_map(|(tag, entry)| {
            let mut durations = entry.durations.clone();
            if durations.is_empty() {
                return None;
            }
            durations.sort_by(f64::total_cmp);
            let count = durations.len();
            let mean = durations.iter().sum::<f64>() / count as f64;
            let median = if count % 2 == 0 {
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
            Some((
                tag.clone(),
                ProfilingResult {
                    name: tag.clone(),
                    parent: entry.parent.clone(),
                    count,
                    mean,
                    median,
                    stdev,
                },
            ))
        })
        .collect()
}

fn pickle_key(key: &str) -> PickleValue {
    PickleValue::String(key.into())
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
        (pickle_key("mean"), PickleValue::Float(result.mean)),
        (pickle_key("median"), PickleValue::Float(result.median)),
        (
            pickle_key("stdev"),
            result.stdev.map_or(PickleValue::None, PickleValue::Float),
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
        (Value::Str("mean".into()), Value::Float(result.mean)),
        (Value::Str("median".into()), Value::Float(result.median)),
        (
            Value::Str("stdev".into()),
            result.stdev.map_or(Value::Nil, Value::Float),
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

    #[test]
    fn completed_guards_produce_sorted_rpc_results() {
        record_duration("entry110.child", Some("entry110.parent"), 0.003);
        record_duration("entry110.parent", None, 0.001);
        record_duration("entry110.parent", None, 0.005);

        let results = results();
        let parent = &results["entry110.parent"];
        assert_eq!(parent.count, 2);
        assert_eq!(parent.mean, 0.003);
        assert_eq!(parent.median, 0.003);
        assert!((parent.stdev.unwrap() - 0.00282842712474619).abs() < 1e-15);
        assert_eq!(
            results["entry110.child"].parent.as_deref(),
            Some("entry110.parent")
        );

        let PickleValue::Dict(tags) = results_pickle().unwrap() else {
            panic!("profiling results must be a dictionary");
        };
        let names: Vec<&str> = tags.iter().filter_map(|(key, _)| key.as_str()).collect();
        assert!(names.windows(2).all(|pair| pair[0] <= pair[1]));
    }

    #[test]
    fn guard_records_elapsed_time() {
        {
            let _sample = profile("entry110.guard");
        }
        assert!(results()["entry110.guard"].mean >= 0.0);
    }
}
