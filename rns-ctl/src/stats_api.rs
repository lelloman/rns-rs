use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use rusqlite::{params, Connection, OpenFlags};
use serde_json::{json, Value};

use crate::http::{parse_query, HttpRequest, HttpResponse};
use crate::state::{read_state, SharedState};

const DEFAULT_WINDOW_SECONDS: i64 = 24 * 60 * 60;
const MAX_WINDOW_SECONDS: i64 = 30 * 24 * 60 * 60;
const DEFAULT_LIMIT: usize = 10;
const MAX_LIMIT: usize = 100;

pub(crate) fn handle_summary(req: &HttpRequest, state: &SharedState) -> HttpResponse {
    let params = parse_query(&req.query);
    let query = match StatsQuery::from_params(&params) {
        Ok(query) => query,
        Err(err) => return HttpResponse::bad_request(&err.to_string()),
    };
    with_db(state, |db_path, conn| {
        let announce_total: i64 = conn.query_row(
            "SELECT COUNT(*) FROM seen_announces WHERE seen_at_ms >= ?1 AND seen_at_ms < ?2",
            params![query.start_ms, query.end_ms],
            |row| row.get(0),
        )?;
        let unique_destinations: i64 = conn.query_row(
            "SELECT COUNT(DISTINCT hex(destination_hash))
                 FROM seen_announces WHERE seen_at_ms >= ?1 AND seen_at_ms < ?2",
            params![query.start_ms, query.end_ms],
            |row| row.get(0),
        )?;
        let unique_identities: i64 = conn.query_row(
            "SELECT COUNT(DISTINCT hex(identity_hash))
                 FROM seen_announces WHERE seen_at_ms >= ?1 AND seen_at_ms < ?2",
            params![query.start_ms, query.end_ms],
            |row| row.get(0),
        )?;
        let unique_names: i64 = conn.query_row(
            "SELECT COUNT(DISTINCT hex(name_hash))
                 FROM seen_announces WHERE seen_at_ms >= ?1 AND seen_at_ms < ?2",
            params![query.start_ms, query.end_ms],
            |row| row.get(0),
        )?;
        let unique_interfaces: i64 = conn.query_row(
            "SELECT COUNT(DISTINCT interface_id)
                 FROM seen_announces
                 WHERE seen_at_ms >= ?1 AND seen_at_ms < ?2 AND interface_id IS NOT NULL",
            params![query.start_ms, query.end_ms],
            |row| row.get(0),
        )?;
        let first_seen_ms: Option<i64> = conn.query_row(
            "SELECT MIN(seen_at_ms) FROM seen_announces WHERE seen_at_ms >= ?1 AND seen_at_ms < ?2",
            params![query.start_ms, query.end_ms],
            |row| row.get(0),
        )?;
        let last_seen_ms: Option<i64> = conn.query_row(
            "SELECT MAX(seen_at_ms) FROM seen_announces WHERE seen_at_ms >= ?1 AND seen_at_ms < ?2",
            params![query.start_ms, query.end_ms],
            |row| row.get(0),
        )?;
        let latest_process_sample = latest_process_sample(conn)?;
        let provider_dropped_events: i64 = conn.query_row(
            "SELECT COALESCE(SUM(dropped_events), 0)
                 FROM provider_drop_samples WHERE ts_ms >= ?1 AND ts_ms < ?2",
            params![query.start_ms, query.end_ms],
            |row| row.get(0),
        )?;

        let mut rx_packets = 0i64;
        let mut tx_packets = 0i64;
        let mut rx_bytes = 0i64;
        let mut tx_bytes = 0i64;
        let mut latest_packet_update_ms = None;
        let mut stmt = conn.prepare(
            "SELECT direction,
                        COALESCE(SUM(packets), 0),
                        COALESCE(SUM(bytes), 0),
                        MAX(updated_at_ms)
                 FROM packet_counters
                 GROUP BY direction",
        )?;
        let mut rows = stmt.query([])?;
        while let Some(row) = rows.next()? {
            let direction: String = row.get(0)?;
            let packets: i64 = row.get(1)?;
            let bytes: i64 = row.get(2)?;
            let updated_at_ms: Option<i64> = row.get(3)?;
            if direction == "in" {
                rx_packets = packets;
                rx_bytes = bytes;
            } else if direction == "out" {
                tx_packets = packets;
                tx_bytes = bytes;
            }
            latest_packet_update_ms = latest_packet_update_ms.max(updated_at_ms);
        }
        let active_counters_in_window: i64 = conn.query_row(
            "SELECT COUNT(*) FROM packet_counters WHERE updated_at_ms >= ?1 AND updated_at_ms < ?2",
            params![query.start_ms, query.end_ms],
            |row| row.get(0),
        )?;

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

pub(crate) fn handle_announces(req: &HttpRequest, state: &SharedState) -> HttpResponse {
    let params = parse_query(&req.query);
    let query = match StatsQuery::from_params(&params) {
        Ok(query) => query,
        Err(err) => return HttpResponse::bad_request(&err.to_string()),
    };
    with_db(state, |db_path, conn| {
        let mut buckets = zero_count_buckets(&query);
        let mut stmt = conn.prepare(
            "SELECT (seen_at_ms / ?1) * ?1 AS bucket_start_ms,
                        COUNT(*) AS announce_count,
                        COUNT(DISTINCT hex(destination_hash)) AS unique_destinations,
                        COUNT(DISTINCT hex(identity_hash)) AS unique_identities
                 FROM seen_announces
                 WHERE seen_at_ms >= ?2 AND seen_at_ms < ?3
                 GROUP BY bucket_start_ms
                 ORDER BY bucket_start_ms",
        )?;
        let mut rows = stmt.query(params![query.bucket_ms, query.start_ms, query.end_ms])?;
        while let Some(row) = rows.next()? {
            let bucket_start_ms: i64 = row.get(0)?;
            if let Some(bucket) = buckets.get_mut(&bucket_start_ms) {
                bucket["announce_count"] = Value::from(row.get::<_, i64>(1)?);
                bucket["unique_destinations"] = Value::from(row.get::<_, i64>(2)?);
                bucket["unique_identities"] = Value::from(row.get::<_, i64>(3)?);
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

pub(crate) fn handle_interfaces(req: &HttpRequest, state: &SharedState) -> HttpResponse {
    let params = parse_query(&req.query);
    let query = match StatsQuery::from_params(&params) {
        Ok(query) => query,
        Err(err) => return HttpResponse::bad_request(&err.to_string()),
    };
    let limit = parse_limit(&params);
    with_db(state, |db_path, conn| {
        let mut stmt = conn.prepare(
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
        )?;
        let entries = collect_rows(
            stmt.query(params![query.start_ms, query.end_ms, limit as i64])?,
            |row| {
                Ok(json!({
                    "interface_id": row.get::<_, Option<i64>>(0)?,
                    "announce_count": row.get::<_, i64>(1)?,
                    "unique_destinations": row.get::<_, i64>(2)?,
                    "unique_identities": row.get::<_, i64>(3)?,
                    "min_hops": row.get::<_, i64>(4)?,
                    "max_hops": row.get::<_, i64>(5)?,
                    "last_seen_ms": row.get::<_, i64>(6)?,
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

pub(crate) fn handle_destinations(req: &HttpRequest, state: &SharedState) -> HttpResponse {
    let params = parse_query(&req.query);
    let query = match StatsQuery::from_params(&params) {
        Ok(query) => query,
        Err(err) => return HttpResponse::bad_request(&err.to_string()),
    };
    let limit = parse_limit(&params);
    with_db(state, |db_path, conn| {
        let mut stmt = conn.prepare(
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
        )?;
        let entries = collect_rows(
            stmt.query(params![query.start_ms, query.end_ms, limit as i64])?,
            |row| {
                Ok(json!({
                    "destination_hash": row.get::<_, String>(0)?.to_lowercase(),
                    "identity_hash": row.get::<_, String>(1)?.to_lowercase(),
                    "name_hash": row.get::<_, String>(2)?.to_lowercase(),
                    "announce_count": row.get::<_, i64>(3)?,
                    "first_seen_ms": row.get::<_, i64>(4)?,
                    "last_seen_ms": row.get::<_, i64>(5)?,
                    "min_hops": row.get::<_, i64>(6)?,
                    "max_hops": row.get::<_, i64>(7)?,
                    "lifetime_announce_count": row.get::<_, Option<i64>>(8)?,
                    "last_interface_id": row.get::<_, Option<i64>>(9)?,
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

pub(crate) fn handle_packets(req: &HttpRequest, state: &SharedState) -> HttpResponse {
    let params = parse_query(&req.query);
    let query = match StatsQuery::from_params(&params) {
        Ok(query) => query,
        Err(err) => return HttpResponse::bad_request(&err.to_string()),
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
            )?;
        let counters = collect_rows(
            stmt.query(params![query.start_ms, query.end_ms, limit as i64])?,
            |row| {
                Ok(json!({
                    "interface_key": row.get::<_, String>(0)?,
                    "interface_id": row.get::<_, Option<i64>>(1)?,
                    "direction": row.get::<_, String>(2)?,
                    "packet_type": row.get::<_, String>(3)?,
                    "packets": row.get::<_, i64>(4)?,
                    "bytes": row.get::<_, i64>(5)?,
                    "updated_at_ms": row.get::<_, i64>(6)?,
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

pub(crate) fn handle_packet_series(req: &HttpRequest, state: &SharedState) -> HttpResponse {
    let params = parse_query(&req.query);
    let query = match StatsQuery::from_params(&params) {
        Ok(query) => query,
        Err(err) => return HttpResponse::bad_request(&err.to_string()),
    };
    with_db(state, |db_path, conn| {
        if !has_table(conn, "packet_samples")? {
            let mut series: Vec<Value> = zero_packet_buckets(&query).into_values().collect();
            finalize_packet_series(&mut series);
            return Ok(HttpResponse::ok(json!({
                "db_path": db_path.display().to_string(),
                "window": query.window_json(),
                "bucket_seconds": query.bucket_ms / 1000,
                "series": series,
                "anomalies": {
                    "average_packets_per_bucket": 0.0,
                    "busy_buckets": [],
                }
            })));
        }
        let mut buckets = zero_packet_buckets(&query);
        let mut stmt = conn.prepare(
            "SELECT (ts_ms / ?1) * ?1 AS bucket_start_ms,
                        direction,
                        COALESCE(SUM(packets), 0),
                        COALESCE(SUM(bytes), 0),
                        COUNT(DISTINCT interface_key || ':' || packet_type)
                 FROM packet_samples
                 WHERE ts_ms >= ?2 AND ts_ms < ?3
                 GROUP BY bucket_start_ms, direction
                 ORDER BY bucket_start_ms",
        )?;
        let mut rows = stmt.query(params![query.bucket_ms, query.start_ms, query.end_ms])?;
        while let Some(row) = rows.next()? {
            let bucket_start_ms: i64 = row.get(0)?;
            let direction: String = row.get(1)?;
            if let Some(bucket) = buckets.get_mut(&bucket_start_ms) {
                let packets = row.get::<_, i64>(2)?;
                let bytes = row.get::<_, i64>(3)?;
                let active_keys = row.get::<_, i64>(4)?;
                if direction == "rx" {
                    bucket["rx_packets"] = Value::from(packets);
                    bucket["rx_bytes"] = Value::from(bytes);
                } else if direction == "tx" {
                    bucket["tx_packets"] = Value::from(packets);
                    bucket["tx_bytes"] = Value::from(bytes);
                }
                let current_active = bucket["active_keys"].as_i64().unwrap_or(0);
                bucket["active_keys"] = Value::from(current_active + active_keys);
            }
        }

        let mut series: Vec<Value> = buckets.into_values().collect();
        finalize_packet_series(&mut series);
        let average = if series.is_empty() {
            0.0
        } else {
            series
                .iter()
                .map(|bucket| bucket["total_packets"].as_i64().unwrap_or(0) as f64)
                .sum::<f64>()
                / series.len() as f64
        };
        let busy_buckets: Vec<Value> = series
            .iter()
            .filter(|bucket| {
                let total = bucket["total_packets"].as_i64().unwrap_or(0) as f64;
                average > 0.0 && total > average * 2.0
            })
            .cloned()
            .collect();

        Ok(HttpResponse::ok(json!({
            "db_path": db_path.display().to_string(),
            "window": query.window_json(),
            "bucket_seconds": query.bucket_ms / 1000,
            "series": series,
            "anomalies": {
                "average_packets_per_bucket": average,
                "busy_buckets": busy_buckets,
            }
        })))
    })
}

pub(crate) fn handle_links(req: &HttpRequest, state: &SharedState) -> HttpResponse {
    let params = parse_query(&req.query);
    let query = match StatsQuery::from_params(&params) {
        Ok(query) => query,
        Err(err) => return HttpResponse::bad_request(&err.to_string()),
    };
    let limit = parse_limit(&params);
    with_db(state, |db_path, conn| {
        if !has_table(conn, "link_event_samples")? {
            return Ok(HttpResponse::ok(json!({
                "db_path": db_path.display().to_string(),
                "window": query.window_json(),
                "bucket_seconds": query.bucket_ms / 1000,
                "series": zero_link_buckets(&query).into_values().collect::<Vec<_>>(),
                "interfaces": [],
                "anomalies": {
                    "close_buckets": [],
                }
            })));
        }
        let mut buckets = zero_link_buckets(&query);
        let mut stmt = conn.prepare(
            "SELECT (ts_ms / ?1) * ?1 AS bucket_start_ms,
                        event_type,
                        COUNT(*),
                        COUNT(DISTINCT hex(link_id))
                 FROM link_event_samples
                 WHERE ts_ms >= ?2 AND ts_ms < ?3
                 GROUP BY bucket_start_ms, event_type
                 ORDER BY bucket_start_ms",
        )?;
        let mut rows = stmt.query(params![query.bucket_ms, query.start_ms, query.end_ms])?;
        while let Some(row) = rows.next()? {
            let bucket_start_ms: i64 = row.get(0)?;
            let event_type: String = row.get(1)?;
            if let Some(bucket) = buckets.get_mut(&bucket_start_ms) {
                let count = row.get::<_, i64>(2)?;
                let unique_links = row.get::<_, i64>(3)?;
                match event_type.as_str() {
                    "requested" => bucket["requested"] = Value::from(count),
                    "established" => bucket["established"] = Value::from(count),
                    "closed" => bucket["closed"] = Value::from(count),
                    _ => {}
                }
                let current_unique = bucket["unique_links"].as_i64().unwrap_or(0);
                bucket["unique_links"] = Value::from(current_unique.max(unique_links));
            }
        }

        let series: Vec<Value> = buckets.into_values().collect();
        let close_buckets: Vec<Value> = series
            .iter()
            .filter(|bucket| bucket["closed"].as_i64().unwrap_or(0) > 0)
            .cloned()
            .collect();
        let mut iface_stmt = conn
            .prepare(
                "SELECT interface_id,
                        SUM(CASE WHEN event_type = 'requested' THEN 1 ELSE 0 END) AS requested_count,
                        SUM(CASE WHEN event_type = 'established' THEN 1 ELSE 0 END) AS established_count,
                        SUM(CASE WHEN event_type = 'closed' THEN 1 ELSE 0 END) AS closed_count,
                        COUNT(DISTINCT hex(link_id)) AS unique_links,
                        MAX(ts_ms) AS last_seen_ms
                 FROM link_event_samples
                 WHERE ts_ms >= ?1 AND ts_ms < ?2
                 GROUP BY interface_id
                 ORDER BY established_count DESC, requested_count DESC, closed_count DESC, last_seen_ms DESC
                 LIMIT ?3",
            )?;
        let interfaces = collect_rows(
            iface_stmt.query(params![query.start_ms, query.end_ms, limit as i64])?,
            |row| {
                Ok(json!({
                    "interface_id": row.get::<_, Option<i64>>(0)?,
                    "requested_count": row.get::<_, i64>(1)?,
                    "established_count": row.get::<_, i64>(2)?,
                    "closed_count": row.get::<_, i64>(3)?,
                    "unique_links": row.get::<_, i64>(4)?,
                    "last_seen_ms": row.get::<_, i64>(5)?,
                }))
            },
        )?;

        Ok(HttpResponse::ok(json!({
            "db_path": db_path.display().to_string(),
            "window": query.window_json(),
            "bucket_seconds": query.bucket_ms / 1000,
            "series": series,
            "interfaces": interfaces,
            "anomalies": {
                "close_buckets": close_buckets,
            }
        })))
    })
}

pub(crate) fn handle_system(req: &HttpRequest, state: &SharedState) -> HttpResponse {
    let params = parse_query(&req.query);
    let query = match StatsQuery::from_params(&params) {
        Ok(query) => query,
        Err(err) => return HttpResponse::bad_request(&err.to_string()),
    };
    with_db(state, |db_path, conn| {
        let mut buckets = zero_system_buckets(&query);
        let mut process_stmt = conn.prepare(
            "SELECT (ts_ms / ?1) * ?1 AS bucket_start_ms,
                        AVG(rss_bytes), MAX(rss_bytes),
                        AVG(threads), MAX(threads),
                        AVG(fds), MAX(fds)
                 FROM process_samples
                 WHERE ts_ms >= ?2 AND ts_ms < ?3
                 GROUP BY bucket_start_ms
                 ORDER BY bucket_start_ms",
        )?;
        let mut process_rows =
            process_stmt.query(params![query.bucket_ms, query.start_ms, query.end_ms])?;
        while let Some(row) = process_rows.next()? {
            let bucket_start_ms: i64 = row.get(0)?;
            if let Some(bucket) = buckets.get_mut(&bucket_start_ms) {
                bucket["avg_rss_bytes"] = json_number_from_f64(row.get::<_, f64>(1)?);
                bucket["max_rss_bytes"] = Value::from(row.get::<_, i64>(2)?);
                bucket["avg_threads"] = json_number_from_f64(row.get::<_, f64>(3)?);
                bucket["max_threads"] = Value::from(row.get::<_, i64>(4)?);
                bucket["avg_fds"] = json_number_from_f64(row.get::<_, f64>(5)?);
                bucket["max_fds"] = Value::from(row.get::<_, i64>(6)?);
            }
        }
        let mut drop_stmt = conn.prepare(
            "SELECT (ts_ms / ?1) * ?1 AS bucket_start_ms,
                        COALESCE(SUM(dropped_events), 0)
                 FROM provider_drop_samples
                 WHERE ts_ms >= ?2 AND ts_ms < ?3
                 GROUP BY bucket_start_ms
                 ORDER BY bucket_start_ms",
        )?;
        let mut drop_rows =
            drop_stmt.query(params![query.bucket_ms, query.start_ms, query.end_ms])?;
        while let Some(row) = drop_rows.next()? {
            let bucket_start_ms: i64 = row.get(0)?;
            if let Some(bucket) = buckets.get_mut(&bucket_start_ms) {
                bucket["provider_dropped_events"] = Value::from(row.get::<_, i64>(1)?);
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
    F: FnOnce(PathBuf, &Connection) -> Result<HttpResponse, StatsDbError>,
{
    let db_path = match stats_db_path(state) {
        Ok(path) => path,
        Err(err) => return HttpResponse::internal_error(&err.to_string()),
    };
    let conn = match open_readonly(&db_path) {
        Ok(conn) => conn,
        Err(err) => return HttpResponse::internal_error(&err.to_string()),
    };
    match f(db_path, &conn) {
        Ok(response) => response,
        Err(err) => HttpResponse::internal_error(&err.to_string()),
    }
}

fn stats_db_path(state: &SharedState) -> Result<PathBuf, StatsDbError> {
    let state = read_state(state);
    let config = state
        .server_config
        .as_ref()
        .ok_or(StatsDbError::ConfigUnavailable)?;
    if config.stats_db_path.trim().is_empty() {
        return Err(StatsDbError::PathNotConfigured);
    }
    Ok(PathBuf::from(&config.stats_db_path))
}

fn open_readonly(path: &PathBuf) -> Result<Connection, StatsDbError> {
    if !path.exists() {
        return Err(StatsDbError::Missing(path.clone()));
    }
    let conn = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )?;
    conn.busy_timeout(std::time::Duration::from_secs(2))?;
    Ok(conn)
}

fn latest_process_sample(conn: &Connection) -> Result<Value, StatsDbError> {
    let mut stmt = conn.prepare(
        "SELECT ts_ms, pid, rss_bytes, cpu_user_ms, cpu_system_ms, threads, fds
             FROM process_samples ORDER BY ts_ms DESC LIMIT 1",
    )?;
    let mut rows = stmt.query([])?;
    let Some(row) = rows.next()? else {
        return Ok(Value::Null);
    };
    Ok(json!({
        "ts_ms": row.get::<_, i64>(0)?,
        "pid": row.get::<_, i64>(1)?,
        "rss_bytes": row.get::<_, i64>(2)?,
        "cpu_user_ms": row.get::<_, i64>(3)?,
        "cpu_system_ms": row.get::<_, i64>(4)?,
        "threads": row.get::<_, i64>(5)?,
        "fds": row.get::<_, i64>(6)?,
    }))
}

fn collect_rows<F>(mut rows: rusqlite::Rows<'_>, mut map: F) -> Result<Vec<Value>, StatsDbError>
where
    F: FnMut(&rusqlite::Row<'_>) -> Result<Value, StatsDbError>,
{
    let mut values = Vec::new();
    while let Some(row) = rows.next()? {
        values.push(map(row)?);
    }
    Ok(values)
}

fn has_table(conn: &Connection, table_name: &str) -> Result<bool, StatsDbError> {
    conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?1)",
        params![table_name],
        |row| row.get::<_, i64>(0),
    )
    .map(|value| value != 0)
    .map_err(StatsDbError::Query)
}

fn parse_limit(params: &std::collections::HashMap<String, String>) -> usize {
    params
        .get("limit")
        .and_then(|value| value.parse::<usize>().ok())
        .map(|value| value.clamp(1, MAX_LIMIT))
        .unwrap_or(DEFAULT_LIMIT)
}

/// Why a stats endpoint could not answer from the stats database; its
/// text is the `error` of the 500 response.
#[derive(Debug)]
enum StatsDbError {
    ConfigUnavailable,
    PathNotConfigured,
    Missing(PathBuf),
    Query(rusqlite::Error),
}

impl std::fmt::Display for StatsDbError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StatsDbError::ConfigUnavailable => f.write_str("Server config is unavailable"),
            StatsDbError::PathNotConfigured => f.write_str("Stats DB path is not configured"),
            StatsDbError::Missing(path) => {
                write!(f, "Stats database does not exist: {}", path.display())
            }
            StatsDbError::Query(err) => write!(f, "stats query failed: {}", err),
        }
    }
}

impl std::error::Error for StatsDbError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            StatsDbError::Query(err) => Some(err),
            _ => None,
        }
    }
}

impl From<rusqlite::Error> for StatsDbError {
    fn from(err: rusqlite::Error) -> Self {
        StatsDbError::Query(err)
    }
}

/// Why a `window` or `bucket` query parameter is not a duration; its text
/// is the `error` of the 400 response.
#[derive(Debug, PartialEq, Eq)]
enum DurationError {
    Empty,
    NotPositive,
    Invalid(String),
}

impl std::fmt::Display for DurationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DurationError::Empty => f.write_str("duration cannot be empty"),
            DurationError::NotPositive => f.write_str("duration must be greater than 0"),
            DurationError::Invalid(raw) => write!(f, "invalid duration '{}'", raw),
        }
    }
}

impl std::error::Error for DurationError {}

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

fn zero_packet_buckets(query: &StatsQuery) -> BTreeMap<i64, Value> {
    let mut buckets = BTreeMap::new();
    let mut bucket_start = query.aligned_start_ms();
    while bucket_start < query.end_ms {
        buckets.insert(
            bucket_start,
            json!({
                "bucket_start_ms": bucket_start,
                "bucket_end_ms": (bucket_start + query.bucket_ms).min(query.end_ms),
                "rx_packets": 0,
                "tx_packets": 0,
                "rx_bytes": 0,
                "tx_bytes": 0,
                "active_keys": 0,
            }),
        );
        bucket_start += query.bucket_ms;
    }
    buckets
}

fn zero_link_buckets(query: &StatsQuery) -> BTreeMap<i64, Value> {
    let mut buckets = BTreeMap::new();
    let mut bucket_start = query.aligned_start_ms();
    while bucket_start < query.end_ms {
        buckets.insert(
            bucket_start,
            json!({
                "bucket_start_ms": bucket_start,
                "bucket_end_ms": (bucket_start + query.bucket_ms).min(query.end_ms),
                "requested": 0,
                "established": 0,
                "closed": 0,
                "unique_links": 0,
            }),
        );
        bucket_start += query.bucket_ms;
    }
    buckets
}

fn finalize_packet_series(series: &mut [Value]) {
    for bucket in series {
        let total_packets =
            bucket["rx_packets"].as_i64().unwrap_or(0) + bucket["tx_packets"].as_i64().unwrap_or(0);
        let total_bytes =
            bucket["rx_bytes"].as_i64().unwrap_or(0) + bucket["tx_bytes"].as_i64().unwrap_or(0);
        bucket["total_packets"] = Value::from(total_packets);
        bucket["total_bytes"] = Value::from(total_bytes);
    }
}

struct StatsQuery {
    start_ms: i64,
    end_ms: i64,
    bucket_ms: i64,
    window_seconds: i64,
}

impl StatsQuery {
    fn from_params(
        params: &std::collections::HashMap<String, String>,
    ) -> Result<Self, DurationError> {
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

fn parse_duration_seconds(raw: &str) -> Result<i64, DurationError> {
    let raw = raw.trim();
    if raw.is_empty() {
        return Err(DurationError::Empty);
    }
    if let Ok(seconds) = raw.parse::<i64>() {
        if seconds <= 0 {
            return Err(DurationError::NotPositive);
        }
        return Ok(seconds);
    }
    let Some(last) = raw.chars().last() else {
        return Err(DurationError::Empty);
    };
    let (digits, multiplier) = match last {
        's' => (&raw[..raw.len() - 1], 1),
        'm' => (&raw[..raw.len() - 1], 60),
        'h' => (&raw[..raw.len() - 1], 60 * 60),
        'd' => (&raw[..raw.len() - 1], 24 * 60 * 60),
        'w' => (&raw[..raw.len() - 1], 7 * 24 * 60 * 60),
        _ => return Err(DurationError::Invalid(raw.to_string())),
    };
    let value = digits
        .parse::<i64>()
        .map_err(|_| DurationError::Invalid(raw.to_string()))?;
    if value <= 0 {
        return Err(DurationError::NotPositive);
    }
    Ok(value * multiplier)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_messages_are_the_response_text() {
        let duration = |raw| parse_duration_seconds(raw).unwrap_err().to_string();
        assert_eq!(duration(" "), "duration cannot be empty");
        assert_eq!(duration("0"), "duration must be greater than 0");
        assert_eq!(duration("0h"), "duration must be greater than 0");
        assert_eq!(duration("5x"), "invalid duration '5x'");
        assert_eq!(duration("xh"), "invalid duration 'xh'");
        assert_eq!(parse_duration_seconds("2h"), Ok(7200));

        assert_eq!(
            StatsDbError::ConfigUnavailable.to_string(),
            "Server config is unavailable"
        );
        assert_eq!(
            StatsDbError::PathNotConfigured.to_string(),
            "Stats DB path is not configured"
        );
        assert_eq!(
            open_readonly(&PathBuf::from("/nonexistent/stats.db"))
                .unwrap_err()
                .to_string(),
            "Stats database does not exist: /nonexistent/stats.db"
        );
        assert_eq!(
            StatsDbError::from(rusqlite::Error::InvalidQuery).to_string(),
            format!("stats query failed: {}", rusqlite::Error::InvalidQuery)
        );
    }
}
