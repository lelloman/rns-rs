# Relay benchmark

A self-contained rns-rs workload: sender → transport relay → receiver. Each
worker runs in a separate process. Both endpoints connect to the relay's loopback
TCP listener; there is no direct endpoint connection. Resource bytes, digests,
proofs and application acknowledgements are verified. The mixed suite also
checks small-message echoes on a second link while a Resource is active.

## Run locally

From the repository root:

```sh
./scripts/bench plan --relay --profile smoke
./scripts/bench run --relay --profile smoke --output .local/relay-smoke
./scripts/bench run --relay --profile quick --output .local/relay-quick
./scripts/bench run --relay --suite resource-mixed --profile mixed-quick --output .local/relay-mixed
```

Output directories must be new. Start with smoke to check functionality; use
quick profiles for exploratory measurement and repeat alternating baseline and
candidate runs on a quiet host.

## Docker and saved versions

```sh
./scripts/bench-relay-docker --profile smoke --output .local/relay-docker-smoke
```

The wrapper snapshots the source, builds with a pinned Rust base image, prints
an image tag and immutable image ID, and retains results on the host. Keep that
image to rerun exactly the same build:

```sh
./scripts/bench-relay-docker --no-build --image SAVED_TAG --profile quick --output .local/relay-saved
./scripts/bench-relay-docker --no-build --image SAVED_TAG --suite resource-mixed --profile mixed-quick --output .local/relay-saved-mixed
```

Building from another checkout produces a distinct default tag. Images contain
the source snapshot, tracked patch and source record. Results retain manifests,
case ledgers, worker logs, executable copies/hashes and Docker image/run metadata.
The untracked local performance note is excluded from snapshots.

The container has no external network, a read-only root and a writable results
mount. Its default four-CPU quota and 2 GiB memory limit are shared by the
controller and all three workers. Adjust with `--cpus`, `--memory`, and optionally
`--cpuset`. CPU affinity does not reserve cores or eliminate host interference.

## Keep endpoints fixed when changing the relay

Build a compatible `rns-bench` executable from the candidate revision, then:

```sh
./scripts/bench run --relay-executable /absolute/path/to/candidate/rns-bench --profile quick --output .local/relay-candidate
./scripts/bench-relay-docker --no-build --image SAVED_TAG --relay-binary /absolute/path/to/candidate/rns-bench --profile quick --output .local/relay-docker-candidate
```

The candidate must implement the benchmark relay worker protocol; `rnsd` is not
such a worker. Docker candidates must run on the image's Linux ABI. Endpoints
remain the runner's frozen executable. The relay is frozen separately and hashed;
retain its source revision, diff, features, allocator and build provenance too.
The endpoint manifest cannot infer those from an alternate executable.

## Measurement scope

Relay user/system CPU snapshots bracket the measured batch after warmup. RSS is
a process snapshot; peak RSS covers the entire process lifetime. Endpoint metrics
are separate. Goodput includes controller gaps and drain, and Resource latency
includes acknowledgement. Failures remain in the results and make the run fail.

The standard workers use the System allocator. The relay enables transport with
fresh state, ingress control disabled, no persistence, discovery workers or hooks.
This is not the complete daemon configuration or its allocator measurement.

This v1 relay topology is a new baseline: do not splice its numbers into older
measurements with different workload contracts. It covers sequential Resource
transfers and a mixed second link, not saturation, many simultaneous bulk links,
loss, stalled peers or release qualification. Smoke timings are too short for
performance conclusions. Record host load and repeat longer profiles before
claiming an improvement.
