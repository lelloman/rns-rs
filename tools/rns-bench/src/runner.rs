use crate::{
    protocol::{self, Command, Message, Metrics},
    scenario::{Case, Profile, Scenario},
};
use anyhow::{bail, ensure, Context, Result};
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, File},
    io::{BufReader, Write},
    path::{Path, PathBuf},
    process::{Child, ChildStdin, Stdio},
    sync::mpsc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

static CANCELLED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

fn cancelled() -> bool {
    CANCELLED.load(std::sync::atomic::Ordering::Relaxed)
}

fn digest(bytes: &[u8]) -> String {
    rns_crypto::sha256::sha256(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}
fn output(root: &Path, cmd: &str, args: &[&str]) -> Result<Vec<u8>> {
    let result = std::process::Command::new(cmd)
        .args(args)
        .current_dir(root)
        .output()?;
    ensure!(
        result.status.success(),
        "{cmd} failed: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    Ok(result.stdout)
}

pub fn environment(root: &Path) -> Result<serde_json::Value> {
    let git = |args: &[&str]| output(root, "git", args);
    let diff = git(&["diff", "HEAD", "--binary"])?;
    let untracked = git(&["ls-files", "--others", "--exclude-standard", "-z"])?;
    let mut source_files = std::collections::BTreeMap::new();
    for name in untracked.split(|b| *b == 0).filter(|s| !s.is_empty()) {
        let name = std::str::from_utf8(name)?;
        // Local planning notes are not build inputs. Hash other untracked source.
        if name.starts_with("LOCAL-") && name.ends_with(".txt") {
            continue;
        }
        source_files.insert(name.to_string(), digest(&fs::read(root.join(name))?));
    }
    Ok(serde_json::json!({
        "schema_version":1,"source_sha":String::from_utf8(git(&["rev-parse","HEAD"])?)?.trim(),
        "tracked_diff_sha256":digest(&diff),"dirty":!diff.is_empty()||!source_files.is_empty(),
        "untracked_source":source_files,"lockfile_sha256":digest(&fs::read(root.join("Cargo.lock"))?),
        "rustc":String::from_utf8(output(root,"rustc",&["-Vv"])?)?,
        "executable_sha256":digest(&fs::read(std::env::current_exe()?)?),
        "os":std::env::consts::OS,"arch":std::env::consts::ARCH,
        "logical_cpus":std::thread::available_parallelism().ok().map(|n|n.get()),
        "cpuinfo":fs::read_to_string("/proc/cpuinfo").ok(),
        "loadavg":fs::read_to_string("/proc/loadavg").ok(),
        "debug_assertions":cfg!(debug_assertions),"network":"unshaped-loopback-tcp",
        "metrics_backend":"getrusage and Linux /proc; RSS snapshots, not sampled measurement peak",
        "qualification":"exploratory; uncontrolled host load; no saturation claim"
    }))
}

pub(crate) fn atomic_json(path: &Path, value: &impl Serialize) -> Result<()> {
    let temp = path.with_extension("json.tmp");
    let mut f = File::create(&temp)?;
    serde_json::to_writer_pretty(&mut f, value)?;
    f.write_all(b"\n")?;
    f.sync_all()?;
    fs::rename(temp, path)?;
    Ok(())
}

struct Participant {
    child: Child,
    input: ChildStdin,
    rx: mpsc::Receiver<Result<Message>>,
    timeout: Duration,
}
impl Participant {
    fn spawn(
        executable: &Path,
        role: &str,
        port: u16,
        case: &Path,
        dir: &Path,
        timeout: u64,
    ) -> Result<Self> {
        let log = File::create(dir.join(format!("{role}.events.jsonl")))?;
        let child = std::process::Command::new(executable)
            .args(["participant", role, &port.to_string()])
            .arg(case)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(File::create(dir.join(format!("{role}.stderr.log")))?)
            .spawn()?;
        Self::attach(child, log, Duration::from_secs(timeout))
    }
    fn attach(mut child: Child, mut log: File, timeout: Duration) -> Result<Self> {
        let input = child.stdin.take().context("missing stdin")?;
        let stdout = child.stdout.take().context("missing stdout")?;
        let (tx, rx) = mpsc::sync_channel(32);
        std::thread::spawn(move || {
            let mut reader = BufReader::new(stdout);
            loop {
                let next = protocol::read_line(&mut reader).and_then(|line| {
                    let line = line.context("participant exited before expected event")?;
                    log.write_all(line.as_bytes())?;
                    serde_json::from_str(&line).map_err(Into::into)
                });
                let end = next.is_err();
                if tx.send(next).is_err() || end {
                    break;
                }
            }
        });
        Ok(Self {
            child,
            input,
            rx,
            timeout,
        })
    }
    fn send(&mut self, c: Command) -> Result<()> {
        protocol::write_json(&mut self.input, &c)
    }
    fn receive(&self) -> Result<Message> {
        self.receive_until(Instant::now() + self.timeout)
    }
    fn receive_until(&self, until: Instant) -> Result<Message> {
        let m = loop {
            ensure!(!cancelled(), "run interrupted");
            let remaining = until.saturating_duration_since(Instant::now());
            ensure!(!remaining.is_zero(), "participant event deadline exceeded");
            match self
                .rx
                .recv_timeout(remaining.min(Duration::from_millis(100)))
            {
                Ok(m) => break m?,
                Err(mpsc::RecvTimeoutError::Timeout) => continue,
                Err(e) => return Err(e.into()),
            }
        };
        if let Message::Error { message } = m {
            bail!("participant failed: {message}");
        }
        Ok(m)
    }
    fn snapshot(&mut self) -> Result<(Metrics, u64, u64, u64)> {
        self.send(Command::Snapshot)?;
        match self.receive()? {
            Message::Snapshot {
                metrics,
                received,
                completed,
                probes_received,
            } => Ok((metrics, received, completed, probes_received)),
            other => bail!("expected snapshot, got {other:?}"),
        }
    }
    fn stop(&mut self) -> Result<()> {
        self.send(Command::Stop)?;
        ensure!(
            matches!(self.receive()?, Message::Stopped),
            "missing shutdown acknowledgement"
        );
        let until = Instant::now() + self.timeout;
        loop {
            if let Some(s) = self.child.try_wait()? {
                ensure!(s.success(), "participant exited unsuccessfully");
                return Ok(());
            }
            ensure!(Instant::now() < until, "shutdown timed out");
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}
impl Drop for Participant {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct CaseResult {
    schema_version: u32,
    case: Case,
    status: String,
    error: Option<String>,
    elapsed_seconds: Option<f64>,
    verified_bytes: u64,
    latency_ns: Vec<u64>,
    #[serde(default)]
    probe_rounds: Vec<crate::probes::Summary>,
    #[serde(default)]
    resource_latency_ns: Vec<u64>,
    sender_before: Option<Metrics>,
    sender_after: Option<Metrics>,
    receiver_before: Option<Metrics>,
    receiver_after: Option<Metrics>,
    process_ready_seconds: Option<[f64; 2]>,
}

struct RoundOutcome {
    elapsed_ns: u64,
    probes: Option<crate::probes::Summary>,
    resource_elapsed_ns: Option<u64>,
}

fn transfer(
    sender: &mut Participant,
    receiver: &mut Participant,
    c: &Case,
    id: u64,
) -> Result<RoundOutcome> {
    let deadline = Instant::now() + Duration::from_secs(c.timeout_secs);
    sender.send(Command::Transfer { id })?;
    if c.background {
        match receiver.receive_until(deadline)? {
            Message::Received { id: n, bytes } => ensure!(
                n == id && bytes == c.bytes,
                "wrong delivered operation/length"
            ),
            other => bail!("expected verified delivery, got {other:?}"),
        }
    }
    match sender.receive_until(deadline)? {
        Message::Completed {
            id: n,
            elapsed_ns,
            probes,
            resource_elapsed_ns,
        } => {
            ensure!(n == id && elapsed_ns > 0, "wrong completion");
            ensure!(
                resource_elapsed_ns.is_some() == c.background,
                "incorrect Resource completion boundary"
            );
            match (&c.probes, &probes) {
                (Some(q), Some(p)) => validate_probes(q, p, c.background)?,
                (None, None) => {}
                _ => bail!("missing/unexpected probe result"),
            }
            Ok(RoundOutcome {
                elapsed_ns,
                probes,
                resource_elapsed_ns,
            })
        }
        other => bail!("expected settlement, got {other:?}"),
    }
}

fn validate_probes(
    q: &crate::scenario::ProbeConfig,
    p: &crate::probes::Summary,
    background: bool,
) -> Result<()> {
    ensure!(
        p.rtt_ns.len() == q.count
            && p.scheduled_latency_ns.len() == q.count
            && p.send_lateness_ns.len() == q.count,
        "probe count mismatch"
    );
    ensure!(
        p.rtt_ns
            .iter()
            .zip(&p.send_lateness_ns)
            .zip(&p.scheduled_latency_ns)
            .all(|((&r, &l), &s)| r > 0 && r.checked_add(l) == Some(s)),
        "invalid probe timings"
    );
    ensure!(
        p.bulk_started_ns.is_some() == background && p.bulk_finished_ns.is_some() == background,
        "missing/unexpected background interval"
    );
    if background {
        ensure!(
            p.bulk_finished_ns > p.bulk_started_ns,
            "invalid background interval"
        );
        ensure!(
            p.send_lateness_ns.iter().enumerate().any(|(i, late)| {
                let submitted = i as u64 * q.interval_us * 1000 + late;
                submitted >= p.bulk_started_ns.unwrap() && submitted <= p.bulk_finished_ns.unwrap()
            }),
            "no probe was submitted during the Resource interval"
        );
    }
    Ok(())
}

fn execute(executable: &Path, dir: &Path, c: &Case, r: &mut CaseResult) -> Result<()> {
    let casefile = dir.join("case.json");
    atomic_json(&casefile, c)?;
    // Bind-to-zero allocates a candidate. A bind race fails this case; never reuse
    // an unrelated listener or retry away a failed measurement.
    let reserved = std::net::TcpListener::bind("127.0.0.1:0")?;
    let port = reserved.local_addr()?.port();
    drop(reserved);
    let start = Instant::now();
    let mut receiver =
        Participant::spawn(executable, "receiver", port, &casefile, dir, c.timeout_secs)?;
    let (destination, signing_key) = match receiver.receive()? {
        Message::Ready {
            version: 1,
            destination,
            signing_key,
        } => (destination, signing_key),
        m => bail!("invalid receiver readiness: {m:?}"),
    };
    let receiver_ready = start.elapsed().as_secs_f64();
    let start = Instant::now();
    let mut sender =
        Participant::spawn(executable, "sender", port, &casefile, dir, c.timeout_secs)?;
    ensure!(
        matches!(sender.receive()?, Message::Ready { version: 1, .. }),
        "invalid sender readiness"
    );
    ensure!(
        matches!(sender.receive()?, Message::Connected),
        "sender interface not connected"
    );
    ensure!(
        matches!(receiver.receive()?, Message::Connected),
        "receiver has not accepted the TCP connection"
    );
    r.process_ready_seconds = Some([start.elapsed().as_secs_f64(), receiver_ready]);
    sender.send(Command::Connect {
        destination,
        signing_key,
    })?;
    receiver.send(Command::Announce)?;
    ensure!(
        matches!(sender.receive()?, Message::Linked),
        "sender link not established"
    );
    ensure!(
        matches!(receiver.receive()?, Message::Linked),
        "receiver link not established"
    );
    if c.probes.is_some() {
        sender.send(Command::ConnectProbes)?;
        ensure!(
            matches!(sender.receive()?, Message::ProbeLinked),
            "sender probe link not ready"
        );
        ensure!(
            matches!(receiver.receive()?, Message::ProbeLinked),
            "receiver probe link not ready"
        );
    }
    for id in 0..c.warmup_operations {
        transfer(&mut sender, &mut receiver, c, id as u64)?;
    }
    let resource_warmups = if c.background {
        c.warmup_operations as u64
    } else {
        0
    };
    let probe_warmups = c
        .probes
        .as_ref()
        .map_or(0, |p| p.count * c.warmup_operations) as u64;
    let (metrics, _, complete, probes) = sender.snapshot()?;
    ensure!(
        complete == resource_warmups && probes == probe_warmups,
        "warmup completion mismatch"
    );
    r.sender_before = Some(metrics);
    let (metrics, received, _, probes) = receiver.snapshot()?;
    ensure!(
        received == resource_warmups && probes == probe_warmups,
        "warmup delivery mismatch"
    );
    r.receiver_before = Some(metrics);
    let start = Instant::now();
    for n in 0..c.operations {
        let latency = transfer(
            &mut sender,
            &mut receiver,
            c,
            (c.warmup_operations + n) as u64,
        )?;
        r.latency_ns.push(latency.elapsed_ns);
        if let Some(p) = latency.probes {
            r.probe_rounds.push(p);
        }
        if let Some(ns) = latency.resource_elapsed_ns {
            r.resource_latency_ns.push(ns);
            r.verified_bytes += c.bytes as u64;
        }
    }
    r.elapsed_seconds = Some(start.elapsed().as_secs_f64());
    let rounds = (c.operations + c.warmup_operations) as u64;
    let expected = if c.background { rounds } else { 0 };
    let expected_probes = c.probes.as_ref().map_or(0, |p| p.count as u64 * rounds);
    let (metrics, received, completed, probes) = sender.snapshot()?;
    ensure!(
        received == 0 && completed == expected && probes == expected_probes,
        "sender ledger mismatch"
    );
    r.sender_after = Some(metrics);
    let (metrics, received, completed, probes) = receiver.snapshot()?;
    ensure!(
        received == expected && completed == expected && probes == expected_probes,
        "receiver ledger mismatch"
    );
    r.receiver_after = Some(metrics);
    sender.stop()?;
    receiver.stop()?;
    Ok(())
}

pub fn run(
    root: &Path,
    s: Scenario,
    p: Profile,
    cases: Vec<Case>,
    requested: Option<PathBuf>,
) -> Result<()> {
    ctrlc::set_handler(|| CANCELLED.store(true, std::sync::atomic::Ordering::Relaxed))?;
    ensure!(
        !cfg!(debug_assertions),
        "measurement requires a release build; use scripts/bench"
    );
    let dir = requested.unwrap_or_else(|| {
        root.join("target/bench-results").join(format!(
            "{}-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
            std::process::id()
        ))
    });
    if let Some(parent) = dir.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::create_dir(&dir).context("output directory must not already exist")?;
    let dir = dir.canonicalize()?;
    atomic_json(
        &dir.join("status.json"),
        &serde_json::json!({"schema_version":1,"status":"interrupted","expected_cases":cases.len()}),
    )?;
    let env = environment(root)?;
    // Every case uses the same executable even if a developer rebuilds meanwhile.
    let executable = dir.join("participant.bin");
    fs::copy(std::env::current_exe()?, &executable)?;
    let measurement = if s.probes.is_some() {
        "fixed-rate 64-byte echoes on a separate link; RTT is submission to verified callback; scheduled latency includes submission lateness; bulk Resource starts after configured lead-in; round ends after all echoes and Resource settlement; batch goodput includes the fixed probe schedule and is not Resource capacity"
    } else {
        "sequential controller-driven closed-loop; goodput includes control gaps, cloning and drain; sender latency includes receiver validation, application ack and proof settlement; CPU snapshots bracket whole measured batch"
    };
    atomic_json(
        &dir.join("manifest.json"),
        &serde_json::json!({"schema_version":1,"scenario":s,"profile":p,"cases":cases,"environment":env,"measurement":measurement}),
    )?;
    println!("Artifacts: {}", dir.display());
    let mut failures = 0;
    for c in cases {
        if cancelled() {
            break;
        }
        println!("Running {}", c.id);
        let case_dir = dir.join(&c.id);
        fs::create_dir(&case_dir)?;
        let mut r = CaseResult {
            schema_version: 1,
            case: c.clone(),
            status: "interrupted".into(),
            error: None,
            elapsed_seconds: None,
            verified_bytes: 0,
            latency_ns: vec![],
            probe_rounds: vec![],
            resource_latency_ns: vec![],
            sender_before: None,
            sender_after: None,
            receiver_before: None,
            receiver_after: None,
            process_ready_seconds: None,
        };
        atomic_json(&case_dir.join("result.json"), &r)?;
        match execute(&executable, &case_dir, &c, &mut r) {
            Ok(()) => r.status = "valid".into(),
            Err(e) => {
                failures += 1;
                r.status = if cancelled() { "interrupted" } else { "failed" }.into();
                r.error = Some(format!("{e:#}"));
                eprintln!("{}: {e:#}", c.id);
            }
        }
        atomic_json(&case_dir.join("result.json"), &r)?;
    }
    atomic_json(
        &dir.join("status.json"),
        &serde_json::json!({"schema_version":1,"status":if cancelled() {"interrupted"} else if failures==0 {"complete"} else {"failed"},"failed_cases":failures}),
    )?;
    report(&dir)?;
    ensure!(
        failures == 0 && !cancelled(),
        "{failures} benchmark cases failed; see {}",
        dir.display()
    );
    Ok(())
}

pub fn report(dir: &Path) -> Result<()> {
    let manifest: serde_json::Value =
        serde_json::from_slice(&fs::read(dir.join("manifest.json"))?)?;
    ensure!(
        manifest["schema_version"] == 1,
        "unsupported manifest version"
    );
    let cases: Vec<Case> = serde_json::from_value(manifest["cases"].clone())?;
    let status: serde_json::Value = serde_json::from_slice(&fs::read(dir.join("status.json"))?)?;
    ensure!(!cases.is_empty(), "empty run matrix");
    let mut results = Vec::new();
    let mut ids = std::collections::BTreeSet::new();
    for c in &cases {
        ensure!(
            c.id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-') && ids.insert(&c.id),
            "invalid/duplicate case ID"
        );
        let path = dir.join(&c.id).join("result.json");
        let result = if path.exists() {
            Some(serde_json::from_slice::<CaseResult>(&fs::read(path)?)?)
        } else {
            None
        };
        results.push(result);
    }
    let complete = status["status"] == "complete"
        && results
            .iter()
            .all(|r| r.as_ref().is_some_and(|r| r.status == "valid"));
    let effective = if complete {
        "complete"
    } else {
        "incomplete or failed"
    };
    let mut text=format!("rns-rs benchmark report\nStatus: {effective} (recorded: {})\nExploratory measurements; not a saturation or release qualification result.\nGoodput includes controller gaps and drain. Latency includes application acknowledgement.\nRSS high-water marks are full-process peaks, not measurement-window peaks.\n\n",status["status"]);
    for (c, result) in cases.into_iter().zip(results) {
        let Some(r) = result else {
            text.push_str(&format!("{}: MISSING\n", c.id));
            continue;
        };
        ensure!(
            r.schema_version == 1 && r.case == c,
            "result does not match manifest"
        );
        text.push_str(&format!("{}: {}", c.id, r.status));
        if r.status == "valid" {
            ensure!(
                c.operations > 0
                    && r.error.is_none()
                    && r.verified_bytes
                        == if c.background {
                            c.bytes as u64 * c.operations as u64
                        } else {
                            0
                        }
                    && r.latency_ns.len() == c.operations
                    && r.latency_ns.iter().all(|n| *n > 0),
                "invalid successful result accounting"
            );
            let elapsed = r.elapsed_seconds.context("missing elapsed time")?;
            ensure!(elapsed > 0.0 && elapsed.is_finite(), "invalid elapsed time");
            let mut samples = r.latency_ns;
            samples.sort_unstable();
            text.push_str(&format!("; verified={} B; elapsed={elapsed:.6} s; goodput={:.2} B/s; latency n={} median={:.3} ms",r.verified_bytes,r.verified_bytes as f64/elapsed,samples.len(),samples[samples.len()/2] as f64/1e6));
            if let Some(q) = &c.probes {
                ensure!(
                    r.probe_rounds.len() == c.operations
                        && r.resource_latency_ns.len()
                            == if c.background { c.operations } else { 0 },
                    "mixed round accounting mismatch"
                );
                for p in &r.probe_rounds {
                    validate_probes(q, p, c.background)?;
                }
                let quantile = |mut ns: Vec<u64>, percent: usize| {
                    ns.sort_unstable();
                    ns[(ns.len() * percent).div_ceil(100).saturating_sub(1)] as f64 / 1e6
                };
                let rtts: Vec<_> = r
                    .probe_rounds
                    .iter()
                    .flat_map(|p| p.rtt_ns.iter().copied())
                    .collect();
                let scheduled: Vec<_> = r
                    .probe_rounds
                    .iter()
                    .flat_map(|p| p.scheduled_latency_ns.iter().copied())
                    .collect();
                let lag: Vec<_> = r
                    .probe_rounds
                    .iter()
                    .flat_map(|p| p.send_lateness_ns.iter().copied())
                    .collect();
                text.push_str(" (whole probe round, not Resource latency)");
                text.push_str(&format!("\n  verified echoes={}; RTT p50={:.3} p95={:.3} ms; scheduled p95={:.3} ms; sender-lateness max={:.3} ms",rtts.len(),quantile(rtts.clone(),50),quantile(rtts.clone(),95),quantile(scheduled.clone(),95),quantile(lag,100)));
                if rtts.len() >= 100 {
                    text.push_str(&format!(
                        "; RTT p99={:.3} ms; scheduled p99={:.3} ms",
                        quantile(rtts, 99),
                        quantile(scheduled, 99)
                    ));
                }
                if !r.resource_latency_ns.is_empty() {
                    text.push_str(&format!(
                        "\n  Resource completion median={:.3} ms",
                        quantile(r.resource_latency_ns, 50)
                    ));
                }
            } else {
                ensure!(r.probe_rounds.is_empty(), "unexpected probe samples");
            }
            if samples.len() >= 100 {
                text.push_str(&format!(
                    "; p99={:.3} ms",
                    samples[(samples.len() * 99).div_ceil(100) - 1] as f64 / 1e6
                ));
            }
            for (role, before, after) in [
                ("sender", r.sender_before, r.sender_after),
                ("receiver", r.receiver_before, r.receiver_after),
            ] {
                let (b, a) = (
                    before.context("missing before metrics")?,
                    after.context("missing after metrics")?,
                );
                text.push_str(&format!(
                    "\n  {role}: CPU={:.6} s; RSS-after={:?} B; lifetime-peak-RSS={:?} B",
                    a.user_cpu_seconds + a.system_cpu_seconds
                        - b.user_cpu_seconds
                        - b.system_cpu_seconds,
                    a.current_rss_bytes,
                    a.lifetime_peak_rss_bytes
                ));
            }
        }
        if let Some(error) = r.error {
            text.push_str(&format!("; {error}"));
        }
        text.push('\n');
    }
    let temporary = dir.join("report.txt.tmp");
    fs::write(&temporary, &text)?;
    fs::rename(temporary, dir.join("report.txt"))?;
    print!("{text}");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn mixed_accounting_rejects_missing_echoes_and_missing_overlap() {
        let q = crate::scenario::ProbeConfig {
            count: 16,
            interval_us: 2000,
            bulk_start_us: 10000,
        };
        let mut p = crate::probes::Summary {
            rtt_ns: vec![1000; 16],
            scheduled_latency_ns: vec![1100; 16],
            send_lateness_ns: vec![100; 16],
            bulk_started_ns: Some(10_000_000),
            bulk_finished_ns: Some(20_000_000),
        };
        validate_probes(&q, &p, true).unwrap();
        p.rtt_ns.pop();
        assert!(validate_probes(&q, &p, true).is_err());
        p.rtt_ns.push(1000);
        p.scheduled_latency_ns[0] = 1;
        assert!(validate_probes(&q, &p, true).is_err());
        p.scheduled_latency_ns[0] = 1100;
        p.bulk_finished_ns = Some(1_000_000);
        assert!(validate_probes(&q, &p, true).is_err());
        p.bulk_started_ns = Some(90_000_000);
        p.bulk_finished_ns = Some(100_000_000);
        assert!(validate_probes(&q, &p, true).is_err());
    }

    fn fake(text: &str) -> (tempfile::TempDir, Participant) {
        let dir = tempfile::tempdir().unwrap();
        let child = std::process::Command::new("sh")
            .args(["-c", "printf '%s\\n' \"$1\"", "fake-participant", text])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let p = Participant::attach(
            child,
            File::create(dir.path().join("events")).unwrap(),
            Duration::from_secs(2),
        )
        .unwrap();
        (dir, p)
    }
    #[test]
    fn malformed_error_and_early_exit_fail() {
        let (_dir, p) = fake("not json");
        assert!(p.receive().is_err());
        let (_dir, p) = fake(r#"{"type":"error","message":"injected corruption"}"#);
        assert!(p
            .receive()
            .unwrap_err()
            .to_string()
            .contains("injected corruption"));
        let (_dir, p) = fake(r#"{"type":"connected"}"#);
        assert!(matches!(p.receive().unwrap(), Message::Connected));
        assert!(p.receive().is_err());
    }
    #[test]
    fn silent_child_times_out_and_is_reaped() {
        let dir = tempfile::tempdir().unwrap();
        let child = std::process::Command::new("sleep")
            .arg("30")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let pid = child.id();
        let p = Participant::attach(
            child,
            File::create(dir.path().join("events")).unwrap(),
            Duration::from_millis(30),
        )
        .unwrap();
        assert!(p.receive().unwrap_err().to_string().contains("deadline"));
        drop(p);
        #[cfg(target_os = "linux")]
        assert!(!Path::new(&format!("/proc/{pid}")).exists());
    }
    #[test]
    fn report_never_hides_missing_or_failed_cases() {
        let dir = tempfile::tempdir().unwrap();
        let c = Case {
            id: "test-case".into(),
            payload: crate::scenario::Payload::Repeated,
            bytes: 4096,
            compression: false,
            seed: 1,
            repetition: 0,
            operations: 2,
            warmup_operations: 1,
            timeout_secs: 1,
            probes: None,
            background: true,
        };
        atomic_json(
            &dir.path().join("manifest.json"),
            &serde_json::json!({"schema_version":1,"cases":[c]}),
        )
        .unwrap();
        atomic_json(
            &dir.path().join("status.json"),
            &serde_json::json!({"status":"complete"}),
        )
        .unwrap();
        report(dir.path()).unwrap();
        let text = fs::read_to_string(dir.path().join("report.txt")).unwrap();
        assert!(text.contains("incomplete or failed") && text.contains("MISSING"));
        fs::create_dir(dir.path().join(&c.id)).unwrap();
        let mut r = CaseResult {
            schema_version: 1,
            case: c.clone(),
            status: "failed".into(),
            error: Some("injected timeout".into()),
            elapsed_seconds: None,
            verified_bytes: 0,
            latency_ns: vec![],
            probe_rounds: vec![],
            resource_latency_ns: vec![],
            sender_before: None,
            sender_after: None,
            receiver_before: None,
            receiver_after: None,
            process_ready_seconds: None,
        };
        let path = dir.path().join(&c.id).join("result.json");
        atomic_json(&path, &r).unwrap();
        report(dir.path()).unwrap();
        let text = fs::read_to_string(dir.path().join("report.txt")).unwrap();
        assert!(text.contains("injected timeout") && !text.contains("goodput="));
        r.status = "valid".into();
        r.error = None;
        atomic_json(&path, &r).unwrap();
        assert!(report(dir.path()).is_err());
    }
}
