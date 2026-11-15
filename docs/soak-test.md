# Mixed-Mesh Soak Test

`scripts/mixed_mesh_soak.py` runs a long-lived localhost mesh of Rust and
upstream Python `rnsd` transport nodes and keeps it busy with announces,
links, probes and resource transfers. It looks for the problems short
integration tests miss: operations that stall, memory or file descriptor
growth, path table churn and transfers that fail or deliver the wrong bytes.

## What it starts

* Transport nodes, interleaved Rust and Python (`--rust-nodes`,
  `--python-nodes`, two of each by default), each with a TCP server, connected
  as a `ring` (default), `line` or `star` (`--topology`). Every node has its
  own config directory, a unique instance name and free ports, and answers
  probes (`respond_to_probes`).
* On every node: a Rust and a Python `rncp` listener (no auth, fetch allowed
  from a jail of fixed files, periodic announces), a Rust and a Python `rnx`
  listener (unless `--no-rnx`), and an announcer client that announces
  `--announcers` destinations every `--announce-interval` seconds.

## Workload

`--workers` loops each pick an operation, run it with the client utility of a
random implementation on a random node against a target on another node, and
pause for a random time around `--op-interval`:

| Operation | What it checks |
|-----------|----------------|
| `send` | `rncp` of a fresh random file (1 B to `--max-size`, some compressible) to a listener; the received file's SHA-256 must match |
| `fetch` | `rncp -f` of one of the listener's jail files; SHA-256 must match |
| `probe` | `rnprobe rnstransport.probe` of a remote transport node; a valid reply is required |
| `rnx` | `rnx` runs `/bin/echo <marker>` on a remote listener; the marker must come back |

An operation that does not finish within `--op-timeout` plus its size divided
by `--min-rate` is killed and counted as a stall. Failing operations keep
their directory under `ops/` with the utility's output.

## Sampling

Every `--sample-interval` seconds the harness records, for every long-running
process, RSS, open file descriptors and threads (from `/proc`), and for every
node the path table as reported by that node's own `rnpath -t -j`: size,
entries added, removed and changed since the last sample, and which announced
destinations are missing.

## Output

The work directory (`--workdir`, a new temporary directory by default) holds:

| File | Content |
|------|---------|
| `ops.jsonl` | One record per operation: kind, implementations and nodes, size, status (`ok`, `fail`, `stall`, `error`), latency, failure cause |
| `samples.jsonl` | Process and path table samples |
| `events.jsonl` | Topology, process exits, path table query errors |
| `summary.json` | The final summary |
| `logs/` | Output of every daemon and client program |
| `nodes/` | Config directories, identities, listener save and jail directories |

The printed summary gives counts, failure rates and p50/p95/max latencies per
operation kind and per client/target implementation pair, failure causes,
RSS start/end/max and slope per process, path table statistics, error
markers found in the logs, and a list of anomalies: stalls, failure rates
above `--max-failure-rate` (per kind from 10 operations, per implementation
pair from 20), RSS growing faster than `--rss-slope-threshold`
MB/h over at least `--rss-min-window` seconds (ignoring the first fifth of the
run), growing descriptor counts, announced destinations missing from a path
table for a whole announce interval, processes that exited, and panics or
Python tracebacks. The exit status is non-zero when there are anomalies.

## Running it

```bash
export RETICULUM_UPSTREAM_DIR=~/Reticulum   # the default
scripts/mixed_mesh_soak.py --duration 10m   # a quick check
scripts/mixed_mesh_soak.py --duration 24h --workdir /var/tmp/rns-soak \
    --seed 1 --progress-interval 1800
```

The script builds the release binaries first (`--no-build` skips that). It
prints a progress line every `--progress-interval` seconds. Ctrl-C or SIGTERM
stops the workload, kills every child by its recorded process group and
prints the summary of what ran. Children's PIDs are kept in `pids.json`; a
later run in the same work directory kills any that survived a hard kill of
the harness.

## Known upstream behaviour

These follow from upstream's behaviour, which rns-rs keeps or does not
control, and are not rns-rs defects:

* Several clients of the same node requesting a path to a destination the node
  already knows, at the same moment, are batched into one in-flight request,
  and one client can miss the answer. Its `rnprobe` or `rncp` then reports
  "Path request timed out".
* A client destination that announces within the same second as it registers
  with the shared instance has its announce rejected as not newer than the
  registration's path response, so it is not rebroadcast until the next
  announce. The announcer waits two seconds before its first announce.
* Upstream clients started at the same moment on one config directory can
  race creating its storage directories, so the harness starts clients one at
  a time.
* An upstream `rncp --fetch` from an upstream `rncp` listener occasionally
  gets no response to its fetch request and gives up after the request
  timeout (about 11 seconds on localhost), reporting "Fetch request failed due
  to an unknown error". In 2026-11 runs this hit a few percent of those
  fetches whether the transport nodes in between were Rust or upstream, and
  no other client/listener pairing. It shows up as `fail: missing received
  file` on `fetch python->python`.
