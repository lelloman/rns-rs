use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use rusqlite::{params, Connection, OpenFlags};
use serde_json::{json, Value};

use crate::http::{parse_query, HttpRequest, HttpResponse};
use crate::state::SharedState;

const DEFAULT_WINDOW_SECONDS: i64 = 24 * 60 * 60;
const MAX_WINDOW_SECONDS: i64 = 30 * 24 * 60 * 60;
const DEFAULT_LIMIT: usize = 10;
const MAX_LIMIT: usize = 100;

pub fn handle_summary(req: &HttpRequest, state: &SharedState) -> HttpResponse {
    let params = parse_query(&req.query);
    let query = match StatsQuery::from_params(&params) {
        Ok(query) => query,
        Err(err) => return HttpResponse::bad_request(&err),
    };
    with_db(state, |db_path, conn| {
        let announce_total: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM seen_announces WHERE seen_at_ms >= ?1 AND seen_at_ms < ?2",
                params![query.start_ms, query.end_ms],
                |row| row.get(0),
            )
            .map_err(db_error)?;
        let unique_destinations: i64 = conn
            .query_row(
                "SELECT COUNT(DISTINCT hex(destination_hash))
                 FROM seen_announces WHERE seen_at_ms >= ?1 AND seen_at_ms < ?2",
                params![query.start_ms, query.end_ms],
                |row| row.get(0),
            )
            .map_err(db_error)?;
        let unique_identities: i64 = conn
            .query_row(
                "SELECT COUNT(DISTINCT hex(identity_hash))
                 FROM seen_announces WHERE seen_at_ms >= ?1 AND seen_at_ms < ?2",
                params![query.start_ms, query.end_ms],
                |row| row.get(0),
            )
            .map_err(db_error)?;
        let unique_names: i64 = conn
            .query_row(
                "SELECT COUNT(DISTINCT hex(name_hash))
                 FROM seen_announces WHERE seen_at_ms >= ?1 AND seen_at_ms < ?2",
                params![query.start_ms, query.end_ms],
                |row| row.get(0),
            )
            .map_err(db_error)?;
        let unique_interfaces: i64 = conn
            .query_row(
                "SELECT COUNT(DISTINCT interface_id)
                 FROM seen_announces
                 WHERE seen_at_ms >= ?1 AND seen_at_ms < ?2 AND interface_id IS NOT NULL",
                params![query.start_ms, query.end_ms],
                |row| row.get(0),
            )
            .map_err(db_error)?;
        let first_seen_ms: Option<i64> = conn
            .query_row(
                "SELECT MIN(seen_at_ms) FROM seen_announces WHERE seen_at_ms >= ?1 AND seen_at_ms < ?2",
                params![query.start_ms, query.end_ms],
                |row| row.get(0),
            )
            .map_err(db_error)?;
        let last_seen_ms: Option<i64> = conn
            .query_row(
                "SELECT MAX(seen_at_ms) FROM seen_announces WHERE seen_at_ms >= ?1 AND seen_at_ms < ?2",
                params![query.start_ms, query.end_ms],
                |row| row.get(0),
            )
            .map_err(db_error)?;
        let latest_process_sample = latest_process_sample(conn)?;
        let provider_dropped_events: i64 = conn
            .query_row(
                "SELECT COALESCE(SUM(dropped_events), 0)
                 FROM provider_drop_samples WHERE ts_ms >= ?1 AND ts_ms < ?2",
                params![query.start_ms, query.end_ms],
                |row| row.get(0),
            )
            .map_err(db_error)?;

        let mut rx_packets = 0i64;
        let mut tx_packets = 0i64;
        let mut rx_bytes = 0i64;
        let mut tx_bytes = 0i64;
        let mut latest_packet_update_ms = None;
        let mut stmt = conn
            .prepare(
                "SELECT direction,
                        COALESCE(SUM(packets), 0),
                        COALESCE(SUM(bytes), 0),
                        MAX(updated_at_ms)
                 FROM packet_counters
                 GROUP BY direction",
            )
            .map_err(db_error)?;
        let mut rows = stmt.query([]).map_err(db_error)?;
        while let Some(row) = rows.next().map_err(db_error)? {
            let direction: String = row.get(0).map_err(db_error)?;
            let packets: i64 = row.get(1).map_err(db_error)?;
            let bytes: i64 = row.get(2).map_err(db_error)?;
            let updated_at_ms: Option<i64> = row.get(3).map_err(db_error)?;
            if direction == "in" {
                rx_packets = packets;
                rx_bytes = bytes;
            } else if direction == "out" {
                tx_packets = packets;
                tx_bytes = bytes;
            }
            latest_packet_update_ms = latest_packet_update_ms.max(updated_at_ms);
        }
        let active_counters_in_window: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM packet_counters WHERE updated_at_ms >= ?1 AND updated_at_ms < ?2",
                params![query.start_ms, query.end_ms],
                |row| row.get(0),
            )
            .map_err(db_error)?;

        Ok(HttpResponse::ok(json!({
            "db_path": db_path.display().to_string(),
            "generated_at_ms": query.end_ms,
            "window": query.window_json(),
            "announces": {
                "total": announce_total,
                "unique_destinations": unique_destinations,
                "unique_identities": unique_identities,
                "unique_names": unique_names,
                "unique_interfaces": unique_interfaces,
                "first_seen_ms": first_seen_ms,
                "last_seen_ms": last_seen_ms,
            },
            "packets": {
                "scope": "lifetime_counters_snapshot",
                "rx_packets": rx_packets,
                "tx_packets": tx_packets,
                "rx_bytes": rx_bytes,
                "tx_bytes": tx_bytes,
                "active_counters_in_window": active_counters_in_window,
                "latest_updated_at_ms": latest_packet_update_ms,
            },
            "system": {
                "provider_dropped_events": provider_dropped_events,
                "latest_process_sample": latest_process_sample,
            }
        })))
    })
}

pub fn handle_announces(req: &HttpRequest, state: &SharedState) -> HttpResponse {
    let params = parse_query(&req.query);
    let query = match StatsQuery::from_params(&params) {
        Ok(query) => query,
        Err(err) => return HttpResponse::bad_request(&err),
    };
    with_db(state, |db_path, conn| {
        let mut buckets = zero_count_buckets(&query);
        let mut stmt = conn
            .prepare(
                "SELECT (seen_at_ms / ?1) * ?1 AS bucket_start_ms,
                        COUNT(*) AS announce_count,
                        COUNT(DISTINCT hex(destination_hash)) AS unique_destinations,
                        COUNT(DISTINCT hex(identity_hash)) AS unique_identities
                 FROM seen_announces
                 WHERE seen_at_ms >= ?2 AND seen_at_ms < ?3
                 GROUP BY bucket_start_ms
                 ORDER BY bucket_start_ms",
            )
            .map_err(db_error)?;
        let mut rows = stmt
            .query(params![query.bucket_ms, query.start_ms, query.end_ms])
            .map_err(db_error)?;
        while let Some(row) = rows.next().map_err(db_error)? {
            let bucket_start_ms: i64 = row.get(0).map_err(db_error)?;
            if let Some(bucket) = buckets.get_mut(&bucket_start_ms) {
                bucket["announce_count"] = Value::from(row.get::<_, i64>(1).map_err(db_error)?);
                bucket["unique_destinations"] =
                    Value::from(row.get::<_, i64>(2).map_err(db_error)?);
                bucket["unique_identities"] = Value::from(row.get::<_, i64>(3).map_err(db_error)?);
            }
        }

        let series: Vec<Value> = buckets.into_values().collect();
        let average = if series.is_empty() {
            0.0
        } else {
            series
                .iter()
                .map(|bucket| bucket["announce_count"].as_i64().unwrap_or(0) as f64)
                .sum::<f64>()
                / series.len() as f64
        };
        let burst_buckets: Vec<Value> = series
            .iter()
            .filter(|bucket| {
                let count = bucket["announce_count"].as_i64().unwrap_or(0) as f64;
                average > 0.0 && count > average * 2.0
            })
            .cloned()
            .collect();

        Ok(HttpResponse::ok(json!({
            "db_path": db_path.display().to_string(),
            "window": query.window_json(),
            "bucket_seconds": query.bucket_ms / 1000,
            "series": series,
            "anomalies": {
                "average_announce_count_per_bucket": average,
                "burst_buckets": burst_buckets,
            }
        })))
    })
}

pub fn handle_interfaces(req: &HttpRequest, state: &SharedState) -> HttpResponse {
    let params = parse_query(&req.query);
    let query = match StatsQuery::from_params(&params) {
        Ok(query) => query,
        Err(err) => return HttpResponse::bad_request(&err),
    };
    let limit = parse_limit(&params);
    with_db(state, |db_path, conn| {
        let mut stmt = conn
            .prepare(
                "SELECT interface_id,
                        COUNT(*) AS announce_count,
                        COUNT(DISTINCT hex(destination_hash)) AS unique_destinations,
                        COUNT(DISTINCT hex(identity_hash)) AS unique_identities,
                        MIN(hops) AS min_hops,
                        MAX(hops) AS max_hops,
                        MAX(seen_at_ms) AS last_seen_ms
                 FROM seen_announces
                 WHERE seen_at_ms >= ?1 AND seen_at_ms < ?2
                 GROUP BY interface_id
                 ORDER BY announce_count DESC, last_seen_ms DESC
                 LIMIT ?3",
            )
            .map_err(db_error)?;
        let entries = collect_rows(
            stmt.query(params![query.start_ms, query.end_ms, limit as i64])
                .map_err(db_error)?,
            |row| {
                Ok(json!({
                    "interface_id": row.get::<_, Option<i64>>(0).map_err(db_error)?,
                    "announce_count": row.get::<_, i64>(1).map_err(db_error)?,
                    "unique_destinations": row.get::<_, i64>(2).map_err(db_error)?,
                    "unique_identities": row.get::<_, i64>(3).map_err(db_error)?,
                    "min_hops": row.get::<_, i64>(4).map_err(db_error)?,
                    "max_hops": row.get::<_, i64>(5).map_err(db_error)?,
                    "last_seen_ms": row.get::<_, i64>(6).map_err(db_error)?,
                }))
            },
        )?;
        Ok(HttpResponse::ok(json!({
            "db_path": db_path.display().to_string(),
            "window": query.window_json(),
            "limit": limit,
            "interfaces": entries,
        })))
    })
}

pub fn handle_destinations(req: &HttpRequest, state: &SharedState) -> HttpResponse {
    let params = parse_query(&req.query);
    let query = match StatsQuery::from_params(&params) {
        Ok(query) => query,
        Err(err) => return HttpResponse::bad_request(&err),
    };
    let limit = parse_limit(&params);
    with_db(state, |db_path, conn| {
        let mut stmt = conn
            .prepare(
                "SELECT hex(a.destination_hash) AS destination_hash,
                        hex(MAX(a.identity_hash)) AS identity_hash,
                        hex(MAX(a.name_hash)) AS name_hash,
                        COUNT(*) AS announce_count,
                        MIN(a.seen_at_ms) AS first_seen_ms,
                        MAX(a.seen_at_ms) AS last_seen_ms,
                        MIN(a.hops) AS min_hops,
                        MAX(a.hops) AS max_hops,
                        d.announce_count AS lifetime_announce_count,
                        d.last_interface_id AS last_interface_id
                 FROM seen_announces a
                 LEFT JOIN seen_destinations d ON d.destination_hash = a.destination_hash
                 WHERE a.seen_at_ms >= ?1 AND a.seen_at_ms < ?2
                 GROUP BY a.destination_hash
                 ORDER BY announce_count DESC, last_seen_ms DESC
                 LIMIT ?3",
            )
            .map_err(db_error)?;
        let entries = collect_rows(
            stmt.query(params![query.start_ms, query.end_ms, limit as i64])
                .map_err(db_error)?,
            |row| {
                Ok(json!({
                    "destination_hash": row.get::<_, String>(0).map_err(db_error)?.to_lowercase(),
                    "identity_hash": row.get::<_, String>(1).map_err(db_error)?.to_lowercase(),
                    "name_hash": row.get::<_, String>(2).map_err(db_error)?.to_lowercase(),
                    "announce_count": row.get::<_, i64>(3).map_err(db_error)?,
                    "first_seen_ms": row.get::<_, i64>(4).map_err(db_error)?,
                    "last_seen_ms": row.get::<_, i64>(5).map_err(db_error)?,
                    "min_hops": row.get::<_, i64>(6).map_err(db_error)?,
                    "max_hops": row.get::<_, i64>(7).map_err(db_error)?,
                    "lifetime_announce_count": row.get::<_, Option<i64>>(8).map_err(db_error)?,
                    "last_interface_id": row.get::<_, Option<i64>>(9).map_err(db_error)?,
                }))
            },
        )?;
        Ok(HttpResponse::ok(json!({
            "db_path": db_path.display().to_string(),
            "window": query.window_json(),
            "limit": limit,
            "destinations": entries,
        })))
    })
}

pub fn handle_packets(req: &HttpRequest, state: &SharedState) -> HttpResponse {
    let params = parse_query(&req.query);
    let query = match StatsQuery::from_params(&params) {
        Ok(query) => query,
        Err(err) => return HttpResponse::bad_request(&err),
    };
    let limit = parse_limit(&params);
    with_db(state, |db_path, conn| {
        let mut stmt = conn
            .prepare(
                "SELECT interface_key, interface_id, direction, packet_type, packets, bytes, updated_at_ms
                 FROM packet_counters
                 WHERE updated_at_ms >= ?1 AND updated_at_ms < ?2
                 ORDER BY packets DESC, bytes DESC
                 LIMIT ?3",
            )
            .map_err(db_error)?;
        let counters = collect_rows(
            stmt.query(params![query.start_ms, query.end_ms, limit as i64])
                .map_err(db_error)?,
            |row| {
                Ok(json!({
                    "interface_key": row.get::<_, String>(0).map_err(db_error)?,
                    "interface_id": row.get::<_, Option<i64>>(1).map_err(db_error)?,
                    "direction": row.get::<_, String>(2).map_err(db_error)?,
                    "packet_type": row.get::<_, String>(3).map_err(db_error)?,
                    "packets": row.get::<_, i64>(4).map_err(db_error)?,
                    "bytes": row.get::<_, i64>(5).map_err(db_error)?,
                    "updated_at_ms": row.get::<_, i64>(6).map_err(db_error)?,
                }))
            },
        )?;
        Ok(HttpResponse::ok(json!({
            "db_path": db_path.display().to_string(),
            "window": query.window_json(),
            "limit": limit,
            "scope": "lifetime_counters_filtered_by_recent_activity",
            "counters": counters,
        })))
    })
}

pub fn handle_system(req: &HttpRequest, state: &SharedState) -> HttpResponse {
    let params = parse_query(&req.query);
    let query = match StatsQuery::from_params(&params) {
        Ok(query) => query,
        Err(err) => return HttpResponse::bad_request(&err),
    };
    with_db(state, |db_path, conn| {
        let mut buckets = zero_system_buckets(&query);
        let mut process_stmt = conn
            .prepare(
                "SELECT (ts_ms / ?1) * ?1 AS bucket_start_ms,
                        AVG(rss_bytes), MAX(rss_bytes),
                        AVG(threads), MAX(threads),
                        AVG(fds), MAX(fds)
                 FROM process_samples
                 WHERE ts_ms >= ?2 AND ts_ms < ?3
                 GROUP BY bucket_start_ms
                 ORDER BY bucket_start_ms",
            )
            .map_err(db_error)?;
        let mut process_rows = process_stmt
            .query(params![query.bucket_ms, query.start_ms, query.end_ms])
            .map_err(db_error)?;
        while let Some(row) = process_rows.next().map_err(db_error)? {
            let bucket_start_ms: i64 = row.get(0).map_err(db_error)?;
            if let Some(bucket) = buckets.get_mut(&bucket_start_ms) {
                bucket["avg_rss_bytes"] =
                    json_number_from_f64(row.get::<_, f64>(1).map_err(db_error)?);
                bucket["max_rss_bytes"] = Value::from(row.get::<_, i64>(2).map_err(db_error)?);
                bucket["avg_threads"] =
                    json_number_from_f64(row.get::<_, f64>(3).map_err(db_error)?);
                bucket["max_threads"] = Value::from(row.get::<_, i64>(4).map_err(db_error)?);
                bucket["avg_fds"] = json_number_from_f64(row.get::<_, f64>(5).map_err(db_error)?);
                bucket["max_fds"] = Value::from(row.get::<_, i64>(6).map_err(db_error)?);
            }
        }
        let mut drop_stmt = conn
            .prepare(
                "SELECT (ts_ms / ?1) * ?1 AS bucket_start_ms,
                        COALESCE(SUM(dropped_events), 0)
                 FROM provider_drop_samples
                 WHERE ts_ms >= ?2 AND ts_ms < ?3
                 GROUP BY bucket_start_ms
                 ORDER BY bucket_start_ms",
            )
            .map_err(db_error)?;
        let mut drop_rows = drop_stmt
            .query(params![query.bucket_ms, query.start_ms, query.end_ms])
            .map_err(db_error)?;
        while let Some(row) = drop_rows.next().map_err(db_error)? {
            let bucket_start_ms: i64 = row.get(0).map_err(db_error)?;
            if let Some(bucket) = buckets.get_mut(&bucket_start_ms) {
                bucket["provider_dropped_events"] =
                    Value::from(row.get::<_, i64>(1).map_err(db_error)?);
            }
        }
        let latest_process_sample = latest_process_sample(conn)?;
        let nonzero_drop_buckets: Vec<Value> = buckets
            .values()
            .filter(|bucket| bucket["provider_dropped_events"].as_i64().unwrap_or(0) > 0)
            .cloned()
            .collect();
        Ok(HttpResponse::ok(json!({
            "db_path": db_path.display().to_string(),
            "window": query.window_json(),
            "bucket_seconds": query.bucket_ms / 1000,
            "latest_process_sample": latest_process_sample,
            "series": buckets.into_values().collect::<Vec<_>>(),
            "anomalies": {
                "provider_drop_buckets": nonzero_drop_buckets,
            }
        })))
    })
}

fn with_db<F>(state: &SharedState, f: F) -> HttpResponse
where
    F: FnOnce(PathBuf, &Connection) -> Result<HttpResponse, String>,
{
    let db_path = match stats_db_path(state) {
        Ok(path) => path,
        Err(err) => return HttpResponse::internal_error(&err),
    };
    let conn = match open_readonly(&db_path) {
        Ok(conn) => conn,
        Err(err) => return HttpResponse::internal_error(&err),
    };
    match f(db_path, &conn) {
        Ok(response) => response,
        Err(err) => HttpResponse::internal_error(&err),
    }
}

fn stats_db_path(state: &SharedState) -> Result<PathBuf, String> {
    let state = state.read().unwrap();
    let config = state
        .server_config
        .as_ref()
        .ok_or_else(|| "Server config is unavailable".to_string())?;
    if config.stats_db_path.trim().is_empty() {
        return Err("Stats DB path is not configured".into());
    }
    Ok(PathBuf::from(&config.stats_db_path))
}

fn open_readonly(path: &PathBuf) -> Result<Connection, String> {
    if !path.exists() {
        return Err(format!("Stats database does not exist: {}", path.display()));
    }
    let conn = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(db_error)?;
    conn.busy_timeout(std::time::Duration::from_secs(2))
        .map_err(db_error)?;
    Ok(conn)
}

fn latest_process_sample(conn: &Connection) -> Result<Value, String> {
    let mut stmt = conn
        .prepare(
            "SELECT ts_ms, pid, rss_bytes, cpu_user_ms, cpu_system_ms, threads, fds
             FROM process_samples ORDER BY ts_ms DESC LIMIT 1",
        )
        .map_err(db_error)?;
    let mut rows = stmt.query([]).map_err(db_error)?;
    let Some(row) = rows.next().map_err(db_error)? else {
        return Ok(Value::Null);
    };
    Ok(json!({
        "ts_ms": row.get::<_, i64>(0).map_err(db_error)?,
        "pid": row.get::<_, i64>(1).map_err(db_error)?,
        "rss_bytes": row.get::<_, i64>(2).map_err(db_error)?,
        "cpu_user_ms": row.get::<_, i64>(3).map_err(db_error)?,
        "cpu_system_ms": row.get::<_, i64>(4).map_err(db_error)?,
        "threads": row.get::<_, i64>(5).map_err(db_error)?,
        "fds": row.get::<_, i64>(6).map_err(db_error)?,
    }))
}

fn collect_rows<F>(mut rows: rusqlite::Rows<'_>, mut map: F) -> Result<Vec<Value>, String>
where
    F: FnMut(&rusqlite::Row<'_>) -> Result<Value, String>,
{
    let mut values = Vec::new();
    while let Some(row) = rows.next().map_err(db_error)? {
        values.push(map(row)?);
    }
    Ok(values)
}

fn parse_limit(params: &std::collections::HashMap<String, String>) -> usize {
    params
        .get("limit")
        .and_then(|value| value.parse::<usize>().ok())
        .map(|value| value.clamp(1, MAX_LIMIT))
        .unwrap_or(DEFAULT_LIMIT)
}

fn db_error(err: rusqlite::Error) -> String {
    format!("stats query failed: {}", err)
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}

fn json_number_from_f64(value: f64) -> Value {
    serde_json::Number::from_f64(value)
        .map(Value::Number)
        .unwrap_or(Value::Null)
}

fn zero_count_buckets(query: &StatsQuery) -> BTreeMap<i64, Value> {
    let mut buckets = BTreeMap::new();
    let mut bucket_start = query.aligned_start_ms();
    while bucket_start < query.end_ms {
        buckets.insert(
            bucket_start,
            json!({
                "bucket_start_ms": bucket_start,
                "bucket_end_ms": (bucket_start + query.bucket_ms).min(query.end_ms),
                "announce_count": 0,
                "unique_destinations": 0,
                "unique_identities": 0,
            }),
        );
        bucket_start += query.bucket_ms;
    }
    buckets
}

fn zero_system_buckets(query: &StatsQuery) -> BTreeMap<i64, Value> {
    let mut buckets = BTreeMap::new();
    let mut bucket_start = query.aligned_start_ms();
    while bucket_start < query.end_ms {
        buckets.insert(
            bucket_start,
            json!({
                "bucket_start_ms": bucket_start,
                "bucket_end_ms": (bucket_start + query.bucket_ms).min(query.end_ms),
                "avg_rss_bytes": Value::Null,
                "max_rss_bytes": Value::Null,
                "avg_threads": Value::Null,
                "max_threads": Value::Null,
                "avg_fds": Value::Null,
                "max_fds": Value::Null,
                "provider_dropped_events": 0,
            }),
        );
        bucket_start += query.bucket_ms;
    }
    buckets
}

struct StatsQuery {
    start_ms: i64,
    end_ms: i64,
    bucket_ms: i64,
    window_seconds: i64,
}

impl StatsQuery {
    fn from_params(params: &std::collections::HashMap<String, String>) -> Result<Self, String> {
        let end_ms = now_ms();
        let window_seconds = params
            .get("window")
            .map(|value| parse_duration_seconds(value))
            .transpose()?
            .unwrap_or(DEFAULT_WINDOW_SECONDS)
            .clamp(60, MAX_WINDOW_SECONDS);
        let bucket_seconds = params
            .get("bucket")
            .map(|value| parse_duration_seconds(value))
            .transpose()?
            .unwrap_or_else(|| default_bucket_seconds(window_seconds))
            .clamp(60, window_seconds.max(60));
        Ok(Self {
            start_ms: end_ms - window_seconds * 1000,
            end_ms,
            bucket_ms: bucket_seconds * 1000,
            window_seconds,
        })
    }

    fn aligned_start_ms(&self) -> i64 {
        (self.start_ms / self.bucket_ms) * self.bucket_ms
    }

    fn window_json(&self) -> Value {
        json!({
            "start_ms": self.start_ms,
            "end_ms": self.end_ms,
            "seconds": self.window_seconds,
        })
    }
}

fn default_bucket_seconds(window_seconds: i64) -> i64 {
    if window_seconds <= 3600 {
        60
    } else if window_seconds <= 24 * 3600 {
        3600
    } else if window_seconds <= 7 * 24 * 3600 {
        6 * 3600
    } else {
        24 * 3600
    }
}

fn parse_duration_seconds(raw: &str) -> Result<i64, String> {
    let raw = raw.trim();
    if raw.is_empty() {
        return Err("duration cannot be empty".into());
    }
    if let Ok(seconds) = raw.parse::<i64>() {
        if seconds <= 0 {
            return Err("duration must be greater than 0".into());
        }
        return Ok(seconds);
    }
    let (digits, multiplier) = match raw.chars().last().unwrap() {
        's' => (&raw[..raw.len() - 1], 1),
        'm' => (&raw[..raw.len() - 1], 60),
        'h' => (&raw[..raw.len() - 1], 60 * 60),
        'd' => (&raw[..raw.len() - 1], 24 * 60 * 60),
        'w' => (&raw[..raw.len() - 1], 7 * 24 * 60 * 60),
        _ => return Err(format!("invalid duration '{}'", raw)),
    };
    let value = digits
        .parse::<i64>()
        .map_err(|_| format!("invalid duration '{}'", raw))?;
    if value <= 0 {
        return Err("duration must be greater than 0".into());
    }
    Ok(value * multiplier)
}
