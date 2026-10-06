# Optional CLI interface builds

Measured on 2026-10-06, Linux x86_64, Ryzen 9 5950X, Rust 1.96.0, portable
release profile and the existing jemalloc allocator. No CPU-specific flags,
LTO changes, stripping changes, or queue-policy changes were made.

`rns-cli` and `rns-ctl` now forward external interface features explicitly.
Their defaults retain all interfaces. Local shared-instance support is a
mandatory CLI dependency: removing it breaks remote management and several
CLI tools. The reduced selection below therefore contains TCP and local only.
ARM CI keeps full interfaces by using the default feature set. Other workspace
packages keep their existing defaults; Cargo feature unification still applies.

| Measurement | Full | TCP/local |
|---|---:|---:|
| rnsd executable bytes | 6,134,968 | 5,168,320 |
| Median process launch to `--help` exit | 0.915 ms | 0.908 ms |
| Median process launch to TCP listener accepting | 13.26 ms | 13.86 ms |

The executable is 15.8% smaller (966,648 bytes). This is a code-size result,
not evidence of improved packet throughput, RSS, or general startup latency.
Help timing used 50 samples per binary after warmup, alternating order. Listener
readiness used ten samples per binary after warmup, alternating order, a 1 ms
poll, persistent per-binary config/identity directories, transport and shared
instance disabled, and one loopback TCP server. All 22 startup/shutdown runs
passed. These are warm-cache, lightly loaded checks, not cold-boot measurements.
No builds or tests overlapped the launch measurements.

Build commands:

```sh
cargo build --release -p rns-cli --bin rnsd
cargo build --release -p rns-cli --bin rnsd --no-default-features --features iface-tcp
```

The final builds took 2.55 and 2.59 seconds with cached dependencies/artifacts.
These are not clean-build comparisons and support no build-time speedup claim.
A controlled cold-build comparison remains unmeasured; the shared target was
reused to avoid another large diagnostic build tree.

Validation: ten package-specific feature-resolution checks cover defaults,
local-only, TCP/local, TCP/local with native hooks, and AX.25 including its KISS
dependency. Local-only and TCP/native-hook builds compile all CLI binaries.
Default CLI library tests pass (133 rns-cli, 45 rns-ctl). Reduced rns-net builds
still emit existing unused-code warnings. CI checks reduced configurations;
ARM cross-compilation is left to CI, not claimed as locally tested.

Compact local evidence is in `.local/interface-builds/`: build/check/test logs,
feature graphs, raw launch samples, diagnostic scripts, binary hashes, and the
two measured executables (about 11 MiB total). No separate target tree is kept.
