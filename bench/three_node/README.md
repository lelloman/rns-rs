# Three-Node Benchmark Harness

This benchmark starts 3 plain `rns-ctl http` nodes on one machine:

- `middle`: transport-enabled TCP server
- `edge-a`: TCP client to `middle`
- `edge-b`: TCP client to `middle`

It runs a sequence of waves intended to isolate different bottlenecks:

- `convergence`
- `raw_small`
- `raw_large`
- `raw_burst`
- `proof_heavy`
- `link_setup`
- `resource_large`
- `link_data`
- `mixed`

## Usage

Build `rns-ctl` once:

```bash
cargo build --release --bin rns-ctl
```

Run the full benchmark:

```bash
python3 bench/three_node/run_benchmark.py --keep-artifacts
```

Run a smaller smoke pass:

```bash
python3 bench/three_node/run_benchmark.py \
  --waves convergence,raw_small \
  --duration-secs 2 \
  --raw-rate 5 \
  --keep-artifacts
```

Write reports explicitly:

```bash
python3 bench/three_node/run_benchmark.py \
  --output-json /tmp/three-node.json \
  --output-md /tmp/three-node.md \
  --keep-artifacts
```

## Notes

- The harness uses one raw destination pair for baseline traffic and creates the
  proof-heavy destination pair lazily when the `proof_heavy` wave runs.
- Large payload correctness should be tested with `resource_large`. Single-packet
  sends are bounded by the protocol packet limits, not the TCP interface MTU.
- `--profile middle` attaches `perf stat` to the middle node for profiled waves
  if `perf` is available locally.
- `--keep-artifacts` preserves configs, node logs, and perf outputs under the
  run directory for inspection.
