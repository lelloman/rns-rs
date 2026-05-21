use std::collections::BTreeMap;
use std::fs;
use std::time::{SystemTime, UNIX_EPOCH};

use rns_core::msgpack::{self, Value};

use crate::acl::{Access, Operation};
use crate::config::ServerConfig;
use crate::util::validate_repo_name;
use crate::Result;

#[derive(Debug, Clone, Copy)]
enum Counter {
    View,
    Fetch,
    Push,
    Download,
    ReleaseDownload,
}

#[derive(Debug, Clone, Default)]
struct StatsData {
    pages: PageStats,
    groups: BTreeMap<String, GroupStats>,
}

#[derive(Debug, Clone, Default)]
struct PageStats {
    front: BTreeMap<String, u64>,
}

#[derive(Debug, Clone, Default)]
struct GroupStats {
    view: BTreeMap<String, u64>,
    repositories: BTreeMap<String, RepositoryCounters>,
}

#[derive(Debug, Clone, Default)]
struct RepositoryCounters {
    view: BTreeMap<String, u64>,
    fetch: BTreeMap<String, u64>,
    push: BTreeMap<String, u64>,
    download: BTreeMap<String, u64>,
    release_download: BTreeMap<String, u64>,
}

#[derive(Debug, Clone)]
pub(crate) struct RepositoryStats {
    pub(crate) repository: String,
    pub(crate) date_range: String,
    pub(crate) timeline_labels: [String; 2],
    pub(crate) views: CounterStats,
    pub(crate) fetches: CounterStats,
    pub(crate) pushes: CounterStats,
    pub(crate) downloads_combined: CounterStats,
    pub(crate) activity_score: u64,
    pub(crate) activity_level: ActivityLevel,
    pub(crate) actual_days: usize,
}

#[derive(Debug, Clone)]
pub(crate) struct CounterStats {
    pub(crate) daily: Vec<u64>,
    pub(crate) total: u64,
    pub(crate) peak: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ActivityLevel {
    Inactive,
    Low,
    Moderate,
    High,
}

impl ActivityLevel {
    pub(crate) fn label(self) -> &'static str {
        match self {
            ActivityLevel::Inactive => "No activity",
            ActivityLevel::Low => "Low activity",
            ActivityLevel::Moderate => "Moderate activity",
            ActivityLevel::High => "High activity",
        }
    }

    pub(crate) fn color(self) -> &'static str {
        match self {
            ActivityLevel::Inactive => "`F666",
            ActivityLevel::Low => "`F66d",
            ActivityLevel::Moderate => "`Faa0",
            ActivityLevel::High => "`F0a0",
        }
    }
}

pub(crate) fn record_front_view(config: &ServerConfig, remote: Option<&[u8; 16]>) {
    if !should_record(config, remote) {
        return;
    }
    let _ = update(config, |stats| {
        increment(&mut stats.pages.front, today());
    });
}

pub(crate) fn record_group_view(config: &ServerConfig, group: &str, remote: Option<&[u8; 16]>) {
    if !should_record(config, remote) || group.is_empty() {
        return;
    }
    let _ = update(config, |stats| {
        let group = stats.groups.entry(group.to_string()).or_default();
        increment(&mut group.view, today());
    });
}

pub(crate) fn record_repository_view(
    config: &ServerConfig,
    group: &str,
    repo: &str,
    remote: Option<&[u8; 16]>,
) {
    record_repository_counter(config, group, repo, remote, Counter::View);
}

pub(crate) fn record_fetch(config: &ServerConfig, repository: &str, remote: Option<&[u8; 16]>) {
    if let Some((group, repo)) = split_repository(repository) {
        record_repository_counter(config, group, repo, remote, Counter::Fetch);
    }
}

pub(crate) fn record_push(config: &ServerConfig, repository: &str, remote: Option<&[u8; 16]>) {
    if let Some((group, repo)) = split_repository(repository) {
        record_repository_counter(config, group, repo, remote, Counter::Push);
    }
}

pub(crate) fn record_download(config: &ServerConfig, repository: &str, remote: Option<&[u8; 16]>) {
    if let Some((group, repo)) = split_repository(repository) {
        record_repository_counter(config, group, repo, remote, Counter::Download);
    }
}

pub(crate) fn record_release_download(
    config: &ServerConfig,
    repository: &str,
    remote: Option<&[u8; 16]>,
) {
    if let Some((group, repo)) = split_repository(repository) {
        record_repository_counter(config, group, repo, remote, Counter::ReleaseDownload);
    }
}

pub(crate) fn repository_stats(
    config: &ServerConfig,
    access: &Access,
    remote: Option<&[u8; 16]>,
    group: &str,
    repo: &str,
    lookback_days: usize,
) -> Result<Option<RepositoryStats>> {
    let repository = format!("{group}/{repo}");
    if !access.allows(Operation::Stats, &repository, remote)? {
        return Ok(None);
    }

    let data = load(config);
    Ok(Some(aggregate_repository_stats(
        &data,
        group,
        repo,
        lookback_days,
        current_day_index(),
    )))
}

fn record_repository_counter(
    config: &ServerConfig,
    group: &str,
    repo: &str,
    remote: Option<&[u8; 16]>,
    counter: Counter,
) {
    if !should_record_counter(config, remote, counter) || group.is_empty() || repo.is_empty() {
        return;
    }
    let repository = format!("{group}/{repo}");
    if validate_repo_name(&repository).is_err() {
        return;
    }
    let _ = update(config, |stats| {
        let group = stats.groups.entry(group.to_string()).or_default();
        let repo = group.repositories.entry(repo.to_string()).or_default();
        let day = today();
        match counter {
            Counter::View => increment(&mut repo.view, day),
            Counter::Fetch => increment(&mut repo.fetch, day),
            Counter::Push => increment(&mut repo.push, day),
            Counter::Download => increment(&mut repo.download, day),
            Counter::ReleaseDownload => increment(&mut repo.release_download, day),
        }
    });
}

fn aggregate_repository_stats(
    data: &StatsData,
    group: &str,
    repo: &str,
    lookback_days: usize,
    today_index: i64,
) -> RepositoryStats {
    let lookback_days = lookback_days.max(1);
    let days: Vec<String> = (0..lookback_days)
        .map(|offset| format_day(today_index - (lookback_days - offset - 1) as i64))
        .collect();
    let day_labels: Vec<String> = (0..lookback_days)
        .map(|offset| format_day_label(today_index - (lookback_days - offset - 1) as i64))
        .collect();
    let counters = data
        .groups
        .get(group)
        .and_then(|group| group.repositories.get(repo))
        .cloned()
        .unwrap_or_default();

    let views = summarize_counter(&counters.view, &days);
    let fetches = summarize_counter(&counters.fetch, &days);
    let pushes = summarize_counter(&counters.push, &days);
    let downloads = summarize_counter(&counters.download, &days);
    let release_downloads = summarize_counter(&counters.release_download, &days);
    let downloads_combined = combine_counter_stats(&downloads, &release_downloads);
    let total_score = (views.total + downloads.total + release_downloads.total) as f64 * 0.2
        + fetches.total as f64 * 2.0
        + pushes.total as f64 * 5.0;
    let activity_score = total_score as u64;
    let actual_days = actual_days(&counters, today_index, lookback_days);
    let daily_score = if actual_days > 0 {
        total_score / actual_days as f64
    } else {
        0.0
    };
    let activity_level = if daily_score == 0.0 {
        ActivityLevel::Inactive
    } else if daily_score < 3.0 {
        ActivityLevel::Low
    } else if daily_score < 10.0 {
        ActivityLevel::Moderate
    } else {
        ActivityLevel::High
    };

    RepositoryStats {
        repository: repo.to_string(),
        date_range: format!("{} - {}", day_labels[0], day_labels[lookback_days - 1]),
        timeline_labels: [format!("{lookback_days} days ago"), "Today".to_string()],
        views,
        fetches,
        pushes,
        downloads_combined,
        activity_score,
        activity_level,
        actual_days,
    }
}

fn summarize_counter(counter: &BTreeMap<String, u64>, days: &[String]) -> CounterStats {
    let mut stats = CounterStats {
        daily: Vec::with_capacity(days.len()),
        total: 0,
        peak: 0,
    };
    for day in days {
        let count = *counter.get(day).unwrap_or(&0);
        stats.daily.push(count);
        stats.total += count;
        stats.peak = stats.peak.max(count);
    }
    stats
}

fn combine_counter_stats(first: &CounterStats, second: &CounterStats) -> CounterStats {
    let mut stats = CounterStats {
        daily: Vec::with_capacity(first.daily.len().max(second.daily.len())),
        total: first.total + second.total,
        peak: 0,
    };
    let len = first.daily.len().max(second.daily.len());
    for index in 0..len {
        let count = first.daily.get(index).copied().unwrap_or(0)
            + second.daily.get(index).copied().unwrap_or(0);
        stats.peak = stats.peak.max(count);
        stats.daily.push(count);
    }
    stats
}

fn actual_days(counters: &RepositoryCounters, today_index: i64, lookback_days: usize) -> usize {
    let earliest = counters
        .view
        .iter()
        .chain(counters.fetch.iter())
        .chain(counters.push.iter())
        .chain(counters.download.iter())
        .chain(counters.release_download.iter())
        .filter(|(_, count)| **count > 0)
        .filter_map(|(day, _)| parse_day(day))
        .min();
    let Some(earliest) = earliest else {
        return lookback_days;
    };
    ((today_index - earliest + 1).max(1) as usize).min(lookback_days)
}

fn should_record(config: &ServerConfig, remote: Option<&[u8; 16]>) -> bool {
    should_record_counter(config, remote, Counter::View)
}

fn should_record_counter(
    config: &ServerConfig,
    remote: Option<&[u8; 16]>,
    counter: Counter,
) -> bool {
    config.record_stats
        && !remote.is_some_and(|remote| {
            config
                .stats_ignore_identities
                .iter()
                .any(|ignored| ignored == remote)
                || (matches!(counter, Counter::Push)
                    && config
                        .stats_push_ignore_identities
                        .iter()
                        .any(|ignored| ignored == remote))
        })
}

fn update(config: &ServerConfig, update: impl FnOnce(&mut StatsData)) -> Result<()> {
    let mut data = load(config);
    update(&mut data);
    persist(config, &data)
}

fn load(config: &ServerConfig) -> StatsData {
    let path = config.dir.join("stats");
    let Ok(bytes) = fs::read(path) else {
        return StatsData::default();
    };
    let Ok(value) = msgpack::unpack_exact(&bytes) else {
        return StatsData::default();
    };
    StatsData::from_value(&value)
}

fn persist(config: &ServerConfig, data: &StatsData) -> Result<()> {
    fs::create_dir_all(&config.dir)?;
    let path = config.dir.join("stats");
    let tmp_path = config.dir.join("stats.tmp");
    fs::write(&tmp_path, msgpack::pack(&data.to_value()))?;
    fs::rename(tmp_path, path)?;
    Ok(())
}

fn increment(counter: &mut BTreeMap<String, u64>, day: String) {
    *counter.entry(day).or_insert(0) += 1;
}

fn split_repository(repository: &str) -> Option<(&str, &str)> {
    let (group, repo) = repository.split_once('/')?;
    if group.is_empty() || repo.is_empty() || repo.contains('/') {
        None
    } else {
        Some((group, repo))
    }
}

impl StatsData {
    fn from_value(value: &Value) -> Self {
        let pages = value
            .map_get("pages")
            .and_then(|pages| pages.map_get("front"))
            .map(date_counter_from_value)
            .unwrap_or_default();
        let groups = value
            .map_get("groups")
            .and_then(Value::as_map)
            .map(|groups| {
                groups
                    .iter()
                    .filter_map(|(key, value)| {
                        Some((key.as_str()?.to_string(), GroupStats::from_value(value)))
                    })
                    .collect()
            })
            .unwrap_or_default();
        Self {
            pages: PageStats { front: pages },
            groups,
        }
    }

    fn to_value(&self) -> Value {
        Value::Map(vec![
            (
                Value::Str("pages".to_string()),
                Value::Map(vec![(
                    Value::Str("front".to_string()),
                    date_counter_to_value(&self.pages.front),
                )]),
            ),
            (
                Value::Str("groups".to_string()),
                Value::Map(
                    self.groups
                        .iter()
                        .map(|(name, group)| (Value::Str(name.clone()), group.to_value()))
                        .collect(),
                ),
            ),
        ])
    }
}

impl GroupStats {
    fn from_value(value: &Value) -> Self {
        let view = value
            .map_get("view")
            .map(date_counter_from_value)
            .unwrap_or_default();
        let repositories = value
            .map_get("repositories")
            .and_then(Value::as_map)
            .map(|repos| {
                repos
                    .iter()
                    .filter_map(|(key, value)| {
                        Some((
                            key.as_str()?.to_string(),
                            RepositoryCounters::from_value(value),
                        ))
                    })
                    .collect()
            })
            .unwrap_or_default();
        Self { view, repositories }
    }

    fn to_value(&self) -> Value {
        Value::Map(vec![
            (
                Value::Str("view".to_string()),
                date_counter_to_value(&self.view),
            ),
            (
                Value::Str("repositories".to_string()),
                Value::Map(
                    self.repositories
                        .iter()
                        .map(|(name, repo)| (Value::Str(name.clone()), repo.to_value()))
                        .collect(),
                ),
            ),
        ])
    }
}

impl RepositoryCounters {
    fn from_value(value: &Value) -> Self {
        Self {
            view: value
                .map_get("view")
                .map(date_counter_from_value)
                .unwrap_or_default(),
            fetch: value
                .map_get("fetch")
                .map(date_counter_from_value)
                .unwrap_or_default(),
            push: value
                .map_get("push")
                .map(date_counter_from_value)
                .unwrap_or_default(),
            download: value
                .map_get("download")
                .map(date_counter_from_value)
                .unwrap_or_default(),
            release_download: value
                .map_get("release_download")
                .map(date_counter_from_value)
                .unwrap_or_default(),
        }
    }

    fn to_value(&self) -> Value {
        Value::Map(vec![
            (
                Value::Str("view".to_string()),
                date_counter_to_value(&self.view),
            ),
            (
                Value::Str("fetch".to_string()),
                date_counter_to_value(&self.fetch),
            ),
            (
                Value::Str("push".to_string()),
                date_counter_to_value(&self.push),
            ),
            (
                Value::Str("download".to_string()),
                date_counter_to_value(&self.download),
            ),
            (
                Value::Str("release_download".to_string()),
                date_counter_to_value(&self.release_download),
            ),
        ])
    }
}

fn date_counter_from_value(value: &Value) -> BTreeMap<String, u64> {
    value
        .as_map()
        .into_iter()
        .flat_map(|entries| entries.iter())
        .filter_map(|(key, value)| Some((key.as_str()?.to_string(), value.as_integer()? as u64)))
        .collect()
}

fn date_counter_to_value(counter: &BTreeMap<String, u64>) -> Value {
    Value::Map(
        counter
            .iter()
            .map(|(day, count)| (Value::Str(day.clone()), Value::UInt(*count)))
            .collect(),
    )
}

fn today() -> String {
    format_day(current_day_index())
}

fn current_day_index() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| (duration.as_secs() / 86_400) as i64)
        .unwrap_or(0)
}

fn format_day(day_index: i64) -> String {
    let (year, month, day) = civil_from_days(day_index);
    format!("{year:04}-{month:02}-{day:02}")
}

fn format_day_label(day_index: i64) -> String {
    let (_, month, day) = civil_from_days(day_index);
    let name = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ][month as usize - 1];
    format!("{name} {day:02}")
}

fn parse_day(day: &str) -> Option<i64> {
    let mut parts = day.split('-');
    let year = parts.next()?.parse::<i32>().ok()?;
    let month = parts.next()?.parse::<u32>().ok()?;
    let day = parts.next()?.parse::<u32>().ok()?;
    if parts.next().is_some() {
        return None;
    }
    days_from_civil(year, month, day)
}

fn civil_from_days(days: i64) -> (i32, u32, u32) {
    let days = days + 719_468;
    let era = if days >= 0 { days } else { days - 146_096 } / 146_097;
    let day_of_era = days - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let mut year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_part = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_part + 2) / 5 + 1;
    let month = month_part + if month_part < 10 { 3 } else { -9 };
    year += if month <= 2 { 1 } else { 0 };
    (year as i32, month as u32, day as u32)
}

fn days_from_civil(year: i32, month: u32, day: u32) -> Option<i64> {
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }
    let mut year = year as i64;
    let month = month as i64;
    let day = day as i64;
    year -= if month <= 2 { 1 } else { 0 };
    let era = if year >= 0 { year } else { year - 399 } / 400;
    let year_of_era = year - era * 400;
    let month_part = month + if month > 2 { -3 } else { 9 };
    let day_of_year = (153 * month_part + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    Some(era * 146_097 + day_of_era - 719_468)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn date_conversion_round_trips_known_days() {
        for (day_index, expected) in [(0, "1970-01-01"), (20_000, "2024-10-04")] {
            assert_eq!(format_day(day_index), expected);
            assert_eq!(parse_day(expected), Some(day_index));
        }
    }

    #[test]
    fn aggregation_scores_activity_and_peaks() {
        let today = 20_000;
        let today_str = format_day(today);
        let mut data = StatsData::default();
        let repo = data
            .groups
            .entry("public".into())
            .or_default()
            .repositories
            .entry("alpha".into())
            .or_default();
        repo.view.insert(today_str.clone(), 5);
        repo.fetch.insert(today_str.clone(), 2);
        repo.push.insert(today_str, 1);

        let stats = aggregate_repository_stats(&data, "public", "alpha", 90, today);
        assert_eq!(stats.views.total, 5);
        assert_eq!(stats.views.peak, 5);
        assert_eq!(stats.fetches.total, 2);
        assert_eq!(stats.pushes.total, 1);
        assert_eq!(stats.activity_score, 10);
        assert_eq!(stats.actual_days, 1);
        assert_eq!(stats.activity_level, ActivityLevel::High);
    }

    #[test]
    fn msgpack_round_trip_preserves_nested_counters() {
        let mut data = StatsData::default();
        data.pages.front.insert("2026-05-05".into(), 1);
        data.groups
            .entry("public".into())
            .or_default()
            .repositories
            .entry("alpha".into())
            .or_default()
            .fetch
            .insert("2026-05-05".into(), 2);

        let value = data.to_value();
        let decoded = StatsData::from_value(&value);
        assert_eq!(decoded.pages.front["2026-05-05"], 1);
        assert_eq!(
            decoded.groups["public"].repositories["alpha"].fetch["2026-05-05"],
            2
        );
    }

    #[test]
    fn persist_keeps_existing_stats_when_temp_write_fails() {
        let tmp = tempfile::tempdir().unwrap();
        let config = test_config(tmp.path());
        fs::create_dir_all(&config.dir).unwrap();
        let stats_path = config.dir.join("stats");
        fs::write(&stats_path, b"old stats").unwrap();
        fs::create_dir(config.dir.join("stats.tmp")).unwrap();

        let mut data = StatsData::default();
        data.pages.front.insert("2026-05-05".into(), 1);

        let err = persist(&config, &data).unwrap_err();

        assert!(
            err.to_string().contains("Is a directory") || err.to_string().contains("os error"),
            "unexpected error: {err}"
        );
        assert_eq!(fs::read(&stats_path).unwrap(), b"old stats");
    }

    fn test_config(root: &std::path::Path) -> ServerConfig {
        ServerConfig {
            dir: root.to_path_buf(),
            reticulum_dir: None,
            repositories_dir: root.join("repositories"),
            identity_path: root.join("repositories_identity"),
            client_identity_path: root.join("client_identity"),
            node_name: "Anonymous Git Node".into(),
            announce_interval_secs: 300,
            serve_nomadnet: false,
            templates_dir: root.join("templates"),
            unicode_icons: false,
            record_stats: true,
            stats_ignore_identities: Vec::new(),
            stats_push_ignore_identities: Vec::new(),
            blocked_identities: Vec::new(),
            identity_aliases: std::collections::BTreeMap::new(),
            allow_read: vec!["all".into()],
            allow_write: vec!["all".into()],
            allow_create: vec!["all".into()],
            allow_stats: vec!["all".into()],
            allow_release: vec!["none".into()],
            allow_interact: vec!["none".into()],
            allow_propose: vec!["none".into()],
            allow_admin: vec!["none".into()],
            log_level: crate::logging::DEFAULT_LOG_LEVEL,
        }
    }
}
