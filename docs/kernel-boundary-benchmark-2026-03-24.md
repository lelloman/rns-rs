# Kernel Boundary Benchmark Notes (2026-03-24)

## Goal

Figure out whether moving some transport/networking code into the Linux kernel would likely buy meaningful performance, specifically by understanding how much work on the middle transport node is spent crossing the kernel/userspace boundary versus running RNS protocol or crypto logic in userspace.

This is not a saturation benchmark. It is a boundary-cost investigation.

## Current Harness

The local benchmark harness lives in [`bench/three_node/run_benchmark.py`](/home/lelloman/lelloprojects/rns-rs/bench/three_node/run_benchmark.py).

Current topology:

- `middle`: transport-enabled `TCPServerInterface`
- `edge-a`: `TCPClientInterface` connected to `middle`
- `edge-b`: `TCPClientInterface` connected to `middle`

The harness can now:

- run selected waves
- pre-establish links before steady-state waves
- isolate `mixed` by restarting nodes first
- attach profilers only to selected waves
- use either `perf stat` or `perf record/report`
- attempt `strace -c -f` on the middle node

Relevant commit for profiling-mode additions:

- `b4ee273` `Add steady-state profiling modes to benchmark harness`

## Correctness Status Before Profiling

These issues were fixed before the kernel-boundary investigation:

- benchmark misuse of oversized single-packet sends
- false-success channel send reporting
- channel window/ACK progress bug
- benchmark contamination across waves, especially before `mixed`

Key commits:

- `1c3c30e` `Add three-node benchmark harness and fix channel send errors`
- `9489548` `Remove benchmark bytecode artifact`
- `0c160c2` `Fix channel window progress and add link diagnostics`
- `f13b9af` `Isolate mixed benchmark wave with fresh node state`

Known-good full benchmark report:

- [`/tmp/rns-three-node-full-restartmixed.md`](/tmp/rns-three-node-full-restartmixed.md)
- [`/tmp/rns-three-node-full-restartmixed.json`](/tmp/rns-three-node-full-restartmixed.json)

## Local Environment Notes

`perf` was initially blocked by:

- `kernel.perf_event_paranoid = 4`

That was fixed locally with:

```bash
sudo sysctl -w kernel.perf_event_paranoid=-1
```

Two remaining host restrictions still matter:

- `kernel.kptr_restrict = 1` or equivalent restricted state
  - result: `perf report` cannot resolve kernel symbols cleanly
- `kernel.yama.ptrace_scope = 1`
  - result: `strace -p <pid>` from the harness fails because the tracer is not the parent of the target process

Observed value:

```bash
sysctl kernel.yama.ptrace_scope
# kernel.yama.ptrace_scope = 1
```

## Profiling Commands Run

### 1. Steady-State Link Data, `perf record`

This profiles only `link_data`, while running `link_setup` first to create the links:

```bash
python3 bench/three_node/run_benchmark.py \
  --waves link_setup,link_data \
  --profile middle \
  --profile-kind perf \
  --perf-mode record \
  --profile-waves link_data \
  --output-json /tmp/rns-kernel-boundary-linkdata-perfrecord.json \
  --output-md /tmp/rns-kernel-boundary-linkdata-perfrecord.md \
  --keep-artifacts
```

Artifacts:

- [`/tmp/rns-kernel-boundary-linkdata-perfrecord.md`](/tmp/rns-kernel-boundary-linkdata-perfrecord.md)
- [`/tmp/rns-kernel-boundary-linkdata-perfrecord.json`](/tmp/rns-kernel-boundary-linkdata-perfrecord.json)
- [`/tmp/rns-three-node-bench-cxgq31pt/perf-link_data.txt`](/tmp/rns-three-node-bench-cxgq31pt/perf-link_data.txt)
- [`/tmp/rns-three-node-bench-cxgq31pt/perf-link_data.data`](/tmp/rns-three-node-bench-cxgq31pt/perf-link_data.data)

Wave result:

- `edge_a_channel_send_ok = 90`
- `edge_b_channel_send_ok = 90`
- `edge_a_channel_not_ready = 0`
- `edge_b_channel_not_ready = 0`
- `edge_a_pending_channel_packets = 0`
- `edge_b_pending_channel_packets = 0`
- middle `cpu_percent ~= 0.67`

Main perf finding:

- steady-state `link_data` on the middle node is dominated by the TCP read/ingest path
- top sampled stack is roughly:
  - `rns_net::interface::tcp_server::client_reader_loop`
  - `TcpStream::read`
  - `__libc_recv`
  - then unresolved kernel frames

Approximate top share:

- about `43%` of sampled cycles in the receive path

### 2. Proof-Heavy Raw Traffic, `perf record`

```bash
python3 bench/three_node/run_benchmark.py \
  --waves proof_heavy \
  --profile middle \
  --profile-kind perf \
  --perf-mode record \
  --output-json /tmp/rns-kernel-boundary-proof.json \
  --output-md /tmp/rns-kernel-boundary-proof.md \
  --keep-artifacts
```

Artifacts:

- [`/tmp/rns-kernel-boundary-proof.md`](/tmp/rns-kernel-boundary-proof.md)
- [`/tmp/rns-kernel-boundary-proof.json`](/tmp/rns-kernel-boundary-proof.json)
- [`/tmp/rns-three-node-bench-jix5naoz/perf-proof_heavy.txt`](/tmp/rns-three-node-bench-jix5naoz/perf-proof_heavy.txt)

Wave result:

- `150` packets delivered per edge
- `150` proofs received per edge
- middle `cpu_percent ~= 0.67`

Main perf finding:

- the middle node is still dominated by the TCP server read path
- the top `rns` symbol is again `rns_net::interface::tcp_server::client_reader_loop`
- no obvious crypto symbols showed up in the top sampled symbols for the middle node in this run

Approximate top share:

- about `38%` of sampled cycles in `client_reader_loop`

Important nuance:

- earlier `perf stat` runs showed `proof_heavy` costs more total CPU than `raw_small`
- but `perf record` on the middle node still points to receive/ingest as the dominant top hotspot
- that means proof work may be present but is not the clearest dominant stack on this forwarding node in the sampled window

### 3. Raw Small, `perf record`

```bash
python3 bench/three_node/run_benchmark.py \
  --waves raw_small \
  --profile middle \
  --profile-kind perf \
  --perf-mode record \
  --output-json /tmp/rns-kernel-boundary-raw.json \
  --output-md /tmp/rns-kernel-boundary-raw.md \
  --keep-artifacts
```

Artifacts:

- [`/tmp/rns-kernel-boundary-raw.md`](/tmp/rns-kernel-boundary-raw.md)
- [`/tmp/rns-kernel-boundary-raw.json`](/tmp/rns-kernel-boundary-raw.json)
- [`/tmp/rns-three-node-bench-l6c0vrjw/perf-raw_small.txt`](/tmp/rns-three-node-bench-l6c0vrjw/perf-raw_small.txt)

Wave result:

- `150` packets delivered per edge
- no proofs
- middle `cpu_percent ~= 0.33`

Main perf finding:

- again dominated by the TCP read path into userspace
- top sampled share is about `42%` under:
  - `rns_net::interface::tcp_server::client_reader_loop`
  - `TcpStream::read`
  - `__libc_recv`
  - unresolved kernel frames

Secondary observed symbols:

- `rns_net::hdlc::Decoder::feed`
- `rns_core::transport::TransportEngine::cull_expired_announce_entries`

## `strace` Attempt

Tried to use `strace -c -f -p <middle_pid>` through the harness.

Command shape:

```bash
python3 bench/three_node/run_benchmark.py \
  --waves link_setup,link_data \
  --profile middle \
  --profile-kind strace \
  --profile-waves link_data \
  --output-json /tmp/rns-kernel-boundary-linkdata.json \
  --output-md /tmp/rns-kernel-boundary-linkdata.md \
  --keep-artifacts
```

Artifacts:

- [`/tmp/rns-kernel-boundary-linkdata.json`](/tmp/rns-kernel-boundary-linkdata.json)
- [`/tmp/rns-kernel-boundary-linkdata.md`](/tmp/rns-kernel-boundary-linkdata.md)
- attempted output file: [`/tmp/rns-three-node-bench-lkc5r_mb/strace-link_data.txt`](/tmp/rns-three-node-bench-lkc5r_mb/strace-link_data.txt)

Result:

- the wave succeeded
- `strace` output was empty
- recorded `returncode = 1`

Likely reason:

- `kernel.yama.ptrace_scope = 1`
- `strace` is attaching from a sibling process, which is blocked by Yama ptrace restrictions

## Current Interpretation

This is the important conclusion so far:

- on the middle transport node, the most visible hotspot is the userspace-to-kernel receive boundary
- the steady-state forwarding path is not obviously dominated by RNS crypto in the sampled top stacks
- the middle node spends a significant fraction of sampled time in:
  - TCP reader loop
  - libc `recv`
  - kernel receive path

So:

- a full "RNS in a kernel module" implementation is still not justified
- but a narrower kernel datapath idea is more plausible than before
- if anything is worth exploring later, it would be:
  - a receive/forward fast path
  - not moving all protocol, control plane, and crypto into kernel space

This conclusion is still provisional because kernel symbols are unresolved.

## Exact Next Steps For Tomorrow

### 1. Relax the remaining host restrictions

Run:

```bash
sudo sysctl -w kernel.kptr_restrict=0
sudo sysctl -w kernel.yama.ptrace_scope=0
```

Why:

- `kptr_restrict=0` should give readable kernel stack names in `perf report`
- `ptrace_scope=0` should allow `strace -c -f -p <pid>` from the harness

### 2. Rerun the same three profiles

Rerun:

- `raw_small`
- `proof_heavy`
- `link_setup,link_data` with profiling only on `link_data`

using the same commands above.

### 3. Specifically inspect kernel-side names

Once `kptr_restrict=0` is in place, inspect whether the unresolved kernel frames become things like:

- `tcp_recvmsg`
- `sock_recvmsg`
- `skb_copy_datagram_iter`
- `copy_to_user` / `copy_from_user`
- `epoll`
- `schedule`

That is the evidence needed to judge whether boundary crossing is a meaningful fraction of cost.

### 4. If `strace` starts working, compare syscall time/counts

Look for high time/counts in:

- `recvfrom` / `recvmsg`
- `sendto` / `sendmsg`
- `epoll_wait`
- `read` / `write`
- `futex`

This would give a syscall-level view of the kernel/userland ping-pong.

## Short Resume Summary

If resuming from scratch, the current working summary is:

- harness correctness is in good shape
- channel/window bug is fixed
- steady-state `perf record` support is implemented
- middle-node forwarding looks receive-path heavy
- kernel/userland boundary cost appears material
- full kernel module still looks unjustified
- next step is to unlock kernel symbols and ptrace, then rerun the same focused profiles
