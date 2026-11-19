//! The processes rns-ctl supervises: listing, logs, events and control.

use super::*;

pub(super) fn handle_processes(state: &SharedState) -> HttpResponse {
    let s = read_state(state);
    let mut processes: Vec<&crate::state::ManagedProcessState> = s.processes.values().collect();
    processes.sort_by(|a, b| a.name.cmp(&b.name));
    HttpResponse::ok(json!({
        "processes": processes
            .into_iter()
            .map(|p| json!({
                "name": p.name,
                "status": p.status,
                "ready": p.ready,
                "ready_state": p.ready_state,
                "pid": p.pid,
                "last_exit_code": p.last_exit_code,
                "restart_count": p.restart_count,
                "drain_ack_count": p.drain_ack_count,
                "forced_kill_count": p.forced_kill_count,
                "last_error": p.last_error,
                "status_detail": p.status_detail,
                "durable_log_path": p.durable_log_path,
                "last_log_age_seconds": p.last_log_age_seconds(),
                "recent_log_lines": p.recent_log_lines,
                "uptime_seconds": p.uptime_seconds(),
                "last_transition_seconds": p.last_transition_seconds(),
            }))
            .collect::<Vec<Value>>(),
    }))
}

pub(super) fn handle_process_events(state: &SharedState) -> HttpResponse {
    let s = read_state(state);
    let events: Vec<Value> = s
        .process_events
        .iter()
        .rev()
        .take(20)
        .map(|event| {
            json!({
                "process": event.process,
                "event": event.event,
                "detail": event.detail,
                "age_seconds": event.recorded_at.elapsed().as_secs_f64(),
            })
        })
        .collect();
    HttpResponse::ok(json!({ "events": events }))
}

pub(super) fn handle_process_logs(
    path: &str,
    req: &HttpRequest,
    state: &SharedState,
) -> HttpResponse {
    let Some(name) = path
        .strip_prefix("/api/processes/")
        .and_then(|rest| rest.strip_suffix("/logs"))
    else {
        return HttpResponse::bad_request("Invalid process logs path");
    };

    let limit = parse_query(&req.query)
        .get("limit")
        .and_then(|value| value.parse::<usize>().ok())
        .map(|value| value.min(500))
        .unwrap_or(200);

    let s = read_state(state);
    let Some(logs) = s.process_logs.get(name) else {
        return HttpResponse::not_found();
    };

    let lines: Vec<Value> = logs
        .iter()
        .rev()
        .take(limit)
        .map(|entry| {
            json!({
                "process": entry.process,
                "stream": entry.stream,
                "line": entry.line,
                "age_seconds": entry.recorded_at.elapsed().as_secs_f64(),
            })
        })
        .collect();

    HttpResponse::ok(json!({
        "process": name,
        "durable_log_path": s.processes.get(name).and_then(|p| p.durable_log_path.clone()),
        "last_log_age_seconds": s.processes.get(name).and_then(|p| p.last_log_age_seconds()),
        "recent_log_lines": s.processes.get(name).map(|p| p.recent_log_lines).unwrap_or(0),
        "lines": lines,
    }))
}

pub(super) fn handle_process_control(
    path: &str,
    state: &SharedState,
    action: &str,
) -> HttpResponse {
    let Some(name) = path.strip_prefix("/api/processes/").and_then(|rest| {
        rest.strip_suffix("/restart")
            .or_else(|| rest.strip_suffix("/start"))
            .or_else(|| rest.strip_suffix("/stop"))
    }) else {
        return HttpResponse::bad_request("Invalid process control path");
    };

    let tx = {
        let s = read_state(state);
        s.control_tx.clone()
    };

    match tx {
        Some(tx) => {
            let process_name = name.to_string();
            let command = match action {
                "restart" => crate::state::ProcessControlCommand::Restart(process_name.clone()),
                "start" => crate::state::ProcessControlCommand::Start(process_name.clone()),
                "stop" => crate::state::ProcessControlCommand::Stop(process_name.clone()),
                _ => return HttpResponse::bad_request("Unknown process action"),
            };
            match tx.send(command) {
                Ok(()) => HttpResponse::ok(json!({
                    "ok": true,
                    "queued": true,
                    "action": action,
                    "process": process_name,
                })),
                Err(_) => HttpResponse::internal_error("Process control channel is unavailable"),
            }
        }
        None => HttpResponse::internal_error("Process control is not enabled"),
    }
}
