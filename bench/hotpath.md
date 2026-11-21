# Hot-path invariance gate

`scripts/hotpath` measures fixed hot-path operations and compares them with a
recorded baseline. It is meant for refactoring: a change that should not alter
behaviour should not make these operations more expensive either.

**The bar.** For every case, against the baseline:

- instructions per operation may rise by at most **+1 %**;
- heap allocations per operation (allocation plus reallocation calls) may
  **not rise at all**;
- heap bytes requested per operation may **not rise at all**.

Decreases always pass. Record a new baseline when a change is meant to make a
case cheaper, so later changes are held to the new level.

## Usage

```sh
./scripts/hotpath record DIR            # measure and write DIR/hotpath.json
./scripts/hotpath check BASELINE.json   # re-measure, print a table, exit 1 on a regression
./scripts/hotpath measure               # print the current numbers as JSON
```

`-j N` (before the subcommand) runs N cases in parallel; the numbers do not
depend on it. The typical flow:

```sh
git switch master && ./scripts/hotpath record .local/hotpath-base
git switch my-refactor && ./scripts/hotpath check .local/hotpath-base/hotpath.json
```

Linux, Python 3, Cargo and valgrind are required. The script builds a release
binary of `rns-bench` with the `allocation-profiler` feature into
`target/hotpath/` (or `$CARGO_TARGET_DIR`). A full record or check takes about
2 s of measurement with the default parallelism (5 s with `-j 1`) plus the
build. The baseline records the commit, a
dirty-tree flag, `rustc --version` and the valgrind version; `check` warns when
the toolchain differs, since compiler or valgrind upgrades shift instruction
counts. Compare runs from the same machine type and toolchain.

## How it measures

`rns-bench hotpath list` prints the cases; `rns-bench hotpath run CASE [N]`
builds the case's fixed inputs (fixed keys, `FixedRng`, deterministic
payloads), runs the operation three times to settle first-use state, then runs
it N times inside `rns_bench_hotpath_measured`, an unmangled, non-inlined
function.

- **Instructions**: the script runs each case under
  `valgrind --tool=callgrind --collect-atstart=no
  --toggle-collect=rns_bench_hotpath_measured`, so only instructions executed
  inside the measured loop (including the allocator and every callee) are
  counted; setup and teardown are not. Instructions per operation is the total
  divided by N; the loop itself adds about a dozen instructions in total.
- **Allocations**: the process counts Rust `GlobalAlloc` calls (the
  `allocation-profiler` wrapper in `tools/rns-bench/src/heap.rs`) immediately
  before and after the measured loop. Native `malloc` from C dependencies is not
  counted. The counting wrapper's own instructions are part of the instruction
  totals, consistently in baseline and check.

Both numbers are exact: repeated runs of the same binary give identical
results, and `check` re-runs each case with the baseline's N so the totals
compare exactly. The cases hold steady state (no table grows across
iterations), so allocations per operation are whole numbers.

The instruction count is not a timing. It does not see cache misses, branch
mispredictions or SIMD width; a change can keep instructions flat and still be
slower, or the reverse. It is a stable proxy that catches added work. Code that picks an
implementation from CPU features at run time sees the CPU valgrind emulates,
which may lack extensions the host has (SHA or AVX-512, for instance), so the
measured path can differ from the native one. Shared
code compiled differently can move a case's count slightly even when that case
was not touched (inlining decisions change with the surrounding code); such
shifts were observed below 0.5 %.

## Cases

| Case | Operation | N |
|------|-----------|---|
| `packet_pack` | `RawPacket::pack`, HEADER_2 data, 128 B payload (includes the packet hash) | 2000 |
| `packet_unpack` | `RawPacket::unpack` of the same packet (parse, copy, hash) | 2000 |
| `packet_hash` | `RawPacket::packet_hash_of` (SHA-256 of the hashable part) | 2000 |
| `hdlc_roundtrip` | `hdlc::frame` + `hdlc::Decoder::feed`, 500 B with escapes | 2000 |
| `kiss_roundtrip` | `kiss::frame` + `kiss::Decoder::feed`, 500 B with escapes | 2000 |
| `ifac_roundtrip` | `ifac::mask_outbound` + `unmask_inbound`, 16 B IFAC, 200 B packet | 200 |
| `announce_create` | `AnnounceData::pack` (Ed25519 sign) + `RawPacket::pack` | 200 |
| `announce_validate` | `AnnounceData::unpack` + `validate` (Ed25519 verify) | 200 |
| `transport_forward` | `TransportEngine::handle_inbound` of a HEADER_2 data packet for a known path, forwarded | 1000 |
| `path_lookup` | `TransportEngine::next_hop_interface` over 1024 paths | 20000 |
| `link_encrypt` | `link_encrypt` (Token, AES-256), 400 B | 1000 |
| `link_decrypt` | `link_decrypt` (Token, AES-256), 400 B | 1000 |
| `resource_adv_roundtrip` | `ResourceAdvertisement::pack` + `unpack`, full hashmap segment | 1000 |
| `resource_assembly_64k` | a 64 KiB Resource on a fresh `ResourceReceiver`: advertisement, accept, all parts, hashmap update, `assemble` with hash check (no encryption, no compression) | 10 |
| `msgpack_roundtrip` | `msgpack::pack` + `unpack_exact` of a request-like structure | 2000 |
| `channel_envelope_roundtrip` | `pack_envelope` + `unpack_envelope`, 200 B | 5000 |
| `driver_inbound_local` | rns-net `Driver`: an `Event::Frame` of a 128 B data packet for a registered SINGLE destination, delivered raw to the application callback | 1000 |
| `driver_inbound_forward` | rns-net `Driver` of a transport node: an `Event::Frame` of a HEADER_2 data packet for a known path (257 paths), forwarded out of another interface | 1000 |
| `driver_inbound_link_data` | rns-net `Driver`: an `Event::Frame` of 256 B link DATA on a link the driver answered, through `LinkManager` and the link-action dispatch to the callback | 1000 |
| `link_data_receive` | `LinkManager::handle_local_delivery_into` of 256 B link DATA on an active link (decrypt, `LinkDataReceived`) | 1000 |
| `link_resource_receive` | an 8 KiB Resource (stored, 18 parts) replayed into a link's `LinkManager`: advertisement, every part, assembly with hash check, then `tick` | 20 |
| `pickle_decode_rpc` | `pickle::decode` of an RPC request and of a six-entry path table response | 2000 |

Notes on the boundaries:

- `transport_forward` forgets the packet's hash after each operation
  (`forget_packet_hash`), so every iteration forwards the same packet against
  the same table sizes. That removal is part of the measured operation.
- `resource_assembly_64k` replays a recorded transfer: setup runs a real
  sender against a receiver and records each part and hashmap update; each
  operation feeds that recording to a new receiver. Sender work is excluded.
- Results and outputs of each operation are passed through `black_box`, so
  nothing is optimised away.
- The `driver_*` cases build an rns-net `Driver` without its event loop and
  hand it each frame through `Driver::handle_event_for_bench`: the handling
  one loop turn gives the event (clock held for the turn), then the writer
  wake and flush the loop does once its queue is empty. Each frame is first
  copied into fresh `PacketBytes`, as an interface reader hands it over. The
  interfaces' writers are inline sinks (no worker threads), the callbacks
  only count, and the engine's table hashing is seeded from `FixedRng`. As in
  `transport_forward`, the engine forgets the packet's hash after each frame.
- `driver_inbound_link_data` sets its link up with a real handshake against
  an initiator `LinkManager` during setup; the driver's side of the link
  uses the OS random generator, which changes key bytes but not the counts.
  `link_data_receive` and `link_resource_receive` use two `LinkManager`s
  handshaking with `FixedRng`.
- `link_resource_receive` records the initiator's packets of one live
  transfer (advertisement and parts; the responder's requests are answered
  live during setup) and replays them into the responder each operation.
  The closing `LinkManager::tick` forgets the concluded Resource, which would
  otherwise refuse the same advertisement again; it is part of the measured
  operation. Its 18 parts fit the first four windows (4, 5, 6, 7 parts), so the
  replay does not depend on rate-based window growth.
- `pickle_decode_rpc` decodes fixed bytes as rns-net's own encoder writes
  them (protocol 2, no memo opcodes). Memoized pickles, as Python writes
  them, fill the decoder's memo, a `HashMap` with a per-process random
  seed whose drop order moves glibc's allocator by about 1 % between runs.

Adding a case: add it to `CASES` in `tools/rns-bench/src/hotpath.rs`. `check`
reports a case missing from the baseline as `new` without gating it, and fails
on a baseline case that no longer exists. Changing an existing case's inputs
changes its numbers; record a new baseline in the same change.

Validate the tool with:

```sh
cargo test --locked -p rns-bench --features allocation-profiler hotpath
cargo clippy --locked -p rns-bench --all-targets --all-features -- -D warnings
```
