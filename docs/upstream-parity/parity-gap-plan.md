# Plan: close the remaining gaps to Reticulum 1.6.0

Status: in progress, 2026-11-09. Baseline: Reticulum 1.6.0, rgit `c5d205ff`
([parity record](reticulum-1.6.0-rgit-2-parity.md)).

The per-commit audits only review commits after a baseline, so features that
upstream added before rns-rs started tracking it were never compared. This
inventory compares the whole current upstream surface instead: every
configuration key `Reticulum.py` reads, every RPC call it serves, every flag
of the shared utilities, and the utility list. Every gap below predates the
earliest audited range (upstream introduced them between 2021 and May 2026),
which is why no audit caught them.

## Progress

- Phase 1 is done (pull request #231).
- Phase 3 (3.1 with 2.6) is done: `autoconnect_policy`, defaulting to
  `upstream`, with `autoconnect_discovered_interfaces` and `bootstrap_only`.
  A bootstrap interface whose target is unreachable cannot be attached; the
  monitor retries it every 5 s, where upstream creates it and lets it
  reconnect.
- Phase 2 items 2.1 to 2.5, 2.7 and 2.8 are done (pull request #232). Notes:
  - 2.1: like upstream's updater, a fetch only adds entries; one a source
    drops stays until the next start, which loads the source's saved list
    afresh. Link request stamps for the 5.25 link cost come from the
    announced cost, as for any link.
  - 2.4 fixed a leak: rns-rs announced a discoverable interface's IFAC name
    and passphrase whenever it had IFAC, not only with `publish_ifac`.
  - Testing 2.5 found that upstream receivers dropped every rns-rs discovery
    announce without a configured location, because rns-rs left out the
    latitude, longitude and height fields upstream requires. They are always
    sent now.
  - 2.7: `force_shared_instance_bitrate` is reported, but sends are not
    paced to it as upstream's local interfaces do.

## How each item is done

Each item follows the audit workflow without an upstream commit to map:
read the upstream code end to end, write a failing test first, port the
behaviour across every affected surface (config, driver, RPC, CLI, docs), run
the affected crates' suites, and run live Python/Rust interop whenever the
behaviour crosses the wire or a Python client could observe it. Each item
lands as its own commit, recorded in a new active audit section ("Pre-baseline
gaps"), so the next parity record can claim it. Work goes to `dev` in batches,
one pull request per phase.

## Phase 1: RPC calls Python clients use (interop-breaking)

A Python application or utility attached to an rns-rs shared instance, or an
rns-rs utility attached to a Python one, fails on these today.

| # | Item | Upstream | Work |
|---|---|---|---|
| 1.1 | Blackhole RPC names | `get: blackholed_identities`, `get: is_blackholed`, `blackhole_identity`, `unblackhole_identity` (since 1.1.0 and 1.3.2) | Serve the upstream calls and shapes beside the native `blackholed` / `blackhole` / `unblackhole` names, and make the rns-rs `rnpath` client use the upstream ones, so either side's `rnpath -b/-B/-U` works against the other. Interop: Python `rnpath` against an rns-rs instance and the reverse. |
| 1.2 | Packet signal quality | `get: packet_rssi`, `packet_snr`, `packet_q` with a `packet_hash` (since 0.2.9) | Keep a bounded per-packet RSSI/SNR/Q cache for packets delivered to local clients, as `Transport.local_client_rssi_cache` does, and serve the three calls; `RnsNode` gets the matching queries. |
| 1.3 | Path retention | `destination_data: used / retain / unretain`, `identity_data: retain` (since 1.1.7 and 1.2.4) | Map to the native known-destination store's usage and retention flags; serve the calls and expose them on `RnsNode`. |
| 1.4 | RPC over the Unix socket | `rpc_type = AF_UNIX` on Linux | The rns-rs RPC server already listens on `\0rns/<instance>/rpc`; the rns-rs RPC client still only speaks TCP, so rns-rs utilities and type registration cannot reach a Python shared instance's default RPC. Add the abstract-socket client and use it whenever the instance does. |

## Phase 2: configuration upstream reads that rns-rs ignores

| # | Item | Upstream | Work |
|---|---|---|---|
| 2.1 | Blackhole list subscription | `[reticulum] blackhole_sources`, `blackhole_update_interval` (`BlackholeUpdater`, since 1.1.0) | rns-rs publishes its list (`publish_blackhole`) but cannot fetch one. Port the updater: link to each source's `rnstransport.info.blackhole` destination, request the list (with the 5.25 link cost from upstream 426673e9), merge entries with their source, refresh on the interval (minimum 2 minutes, default 1 hour), and expire entries a source drops. Interop: an rns-rs node subscribed to a Python publisher, and the reverse. |
| 2.2 | Trusted discovery sources | `[reticulum] interface_discovery_sources` (since 1.1.0) | Only accept discovery announces whose network identity is listed, when the list is set. |
| 2.3 | Radio discovery fields | `discovery_frequency`, `discovery_bandwidth`, `discovery_modulation` (since 1.1.0) | Carry the three fields in discovery announces for RNode, KISS and Weave interfaces, parse them on receipt, store and show them (`rnstatus` discovered interfaces). |
| 2.4 | IFAC publication | `publish_ifac` (since 1.1.0) | Include the interface's network name and passphrase in its discovery announce when set; on receipt, the existing sanitising (upstream 1.5.5 audit) already applies. |
| 2.5 | Encrypted discovery | `discovery_encrypt` (since 1.1.0) | Encrypt the discovery payload for the network identity, as `InterfaceAnnouncer` does, and decrypt received ones when the network identity is known. Interop both ways. |
| 2.6 | Bootstrap interfaces | `bootstrap_only` (since 1.1.0) | Tear down bootstrap-only interfaces once the auto-connect target is reached, and bring them back when no auto-connected interface is online. Depends on item 3.1. |
| 2.7 | Shared instance options | `shared_instance_type` (`unix` or `tcp`), `rpc_key`, `force_shared_instance_bitrate` | Choose the shared instance transport explicitly, accept a configured RPC key, and report the forced bitrate on the shared instance interface. |
| 2.8 | `listen_on` | Backbone alias for `listen_ip` (since 0.9.4) | Accept it. |

## Phase 3: auto-connecting discovered interfaces

| # | Item | Upstream | Work |
|---|---|---|---|
| 3.1 | `autoconnect_discovered_interfaces` | `[reticulum] autoconnect_discovered_interfaces = N` (since 1.1.0) | Both behaviours, chosen at startup; see "Decision" below. |

### How upstream does it

- Discovery (`discover_interfaces = yes`) only listens for and stores
  discovered interfaces. Connecting to them is a separate switch:
  `autoconnect_discovered_interfaces = N`, off by default.
- With `N` set, a qualified discovered Backbone interface (Reticulum 1.5.7 or
  later, affordable stamp costs, not blackholed) is connected as soon as it
  is heard, until `N` auto-connected interfaces exist. At startup it also
  reconnects stored discoveries, up to `N`.
- A monitor runs every 5 s. An auto-connected interface that has been down
  for 12 s is detached. When more than a quarter of the `N` slots are free,
  one random available transport-capable discovery is connected.
- `N` counts only auto-connected interfaces. Interfaces in the configuration
  file are always connected and never count against `N`.
- `bootstrap_only` interfaces are torn down once `N` auto-connected
  interfaces are online, and brought back when none are.

### How rns-rs does it

- One bounded Backbone peer pool holds every outbound Backbone connection:
  configured peers and discovered ones together.
  `backbone_peer_pool_max_connected` caps active connections across both
  (0, the default, disables the pool); configured peers have priority 60,
  discovered ones 40, and the highest-priority candidates hold the slots.
- A discovered interface becomes a pool candidate when `discover_interfaces`
  is on and the pool is enabled, with the same qualification checks as
  upstream. There is no separate on/off switch for connecting.
- A peer that fails repeatedly (`backbone_peer_pool_failure_threshold` within
  `backbone_peer_pool_failure_window`) is cooled down for
  `backbone_peer_pool_cooldown`; configured peers back off and retry instead.
- Both VPS nodes run it with 20 active slots over 22 configured peers and
  about 170 standby discoveries.

### What breaks today

- An upstream-style configuration (`discover_interfaces = yes`,
  `autoconnect_discovered_interfaces = 4`) auto-connects nothing on rns-rs:
  the key is ignored and the pool is off by default.
- An rns-rs node with the pool on auto-connects discovered peers without
  being asked, where upstream would need the switch.
- On rns-rs, configured peers can be left in standby when the pool is
  smaller than the configured peer list; upstream always connects them.

### Decision

Both behaviours are kept, chosen at startup by a new
`[reticulum] autoconnect_policy` key; it is not switchable at runtime, so
there is no handover between policies to handle.

- `autoconnect_policy = upstream` (the default): upstream's semantics.
  Discovered interfaces are connected only with
  `autoconnect_discovered_interfaces = N`, up to `N`; configured peers always
  connect and do not count against `N`; the 5 s monitor detaches an
  auto-connected interface down for 12 s and refills one slot at a time when
  more than a quarter of the slots are free; `bootstrap_only` interfaces are
  torn down at `N` online and brought back at none.
- `autoconnect_policy = pool`: today's rns-rs Backbone peer pool (shared
  `backbone_peer_pool_max_connected` cap, priorities, failure cooldown),
  unchanged. `autoconnect_discovered_interfaces` and `bootstrap_only` are
  read but have no effect, with a warning.

The VPS configurations set `autoconnect_policy = pool` before the change is
deployed, so their behaviour does not change. The policy is consulted only
when the pool or monitor is evaluated (on the driver tick, on discovery
announces and on peer state changes), never per packet, so the choice has no
measurable cost.

## Phase 4: utilities

| # | Item | Upstream | Work |
|---|---|---|---|
| 4.1 | `rnid` flags | `--config`, `-v`/`-q`, `-a`/`--announce [aspects]`, `-t seconds` | Add them with upstream semantics. |
| 4.2 | `rnpath -w` | path request timeout | Add it. |
| 4.3 | `rnir`, `rnpkg` | Placeholder utilities: they start Reticulum and exit | Matching placeholders, so scripts that call them behave the same. |
| 4.4 | `rnodeconf` | RNode configuration and firmware utility, 4,528 lines | A native `rnodeconf` in its own crate, in stages below. |

### `rnodeconf` stages

`rnodeconf` talks to an RNode over its serial KISS interface, the same
command set the native RNode interface already uses, plus device commands.

1. **Device information and TNC configuration.** Detect the device; show
   its information (`-i`: firmware version, platform, product, model,
   hardware revision, EEPROM signature check) and configuration (`-c`);
   switch between TNC and normal mode (`-T`, `-N`) and set the TNC radio
   parameters (`--freq`, `--bw`, `--txp`, `--sf`, `--cr`).
2. **EEPROM and keys.** `--eeprom-backup`, `--eeprom-dump`, `--eeprom-wipe`;
   signing keys (`-k` to generate, `-S` to show the public part,
   `--trust-key`); bootstrapping a device's EEPROM without flashing (`-r`
   with `--platform`, `--product`, `--model`, `--hwrev`); setting the
   installed firmware hash (`-H`).
3. **Peripherals.** Bluetooth (`-b`, `-B`, `-p`), Wi-Fi (`-w` with
   `--channel`, `--ssid`, `--psk`, `--show-psk`, `--ip`, `--nm`), display
   (`-D` intensity, `-t` timeout, `--display-addr`, `--recondition-display`),
   NeoPixel intensity (`--np`) and interference avoidance (`-x`, `-X`).
4. **Firmware.** Release discovery from the firmware release feed
   (`--fw-version`, `--fw-url`, `--nocheck`), download and hash check,
   flashing (`-f`, `-u`, `-a` autoinstall, `--baud-flash`) and extracting the
   installed firmware (`-e`). Upstream drives `esptool.py`, `avrdude` and
   `adafruit-nrfutil`; the native tool either calls the same external
   flashers or uses Rust flashing crates where they exist (ESP32 via
   `espflash`). The per-board flashing parameters are ported as a table.
5. **Hardware validation.** Each stage is checked against at least one real
   RNode; the parity record states which boards were tested.

Stages 1 to 3 are self-contained and testable against a device or a serial
mock. Stage 4 needs the most hardware and care, since a wrong flash can
brick a board; it comes last.

## Order and checkpoints

1. Phase 1 (one PR), then Phase 2 items 2.1 to 2.5, 2.7 and 2.8 (one PR).
2. Decision on 3.1, then 3.1 with 2.6 (one PR).
3. Phase 4 items 4.1 to 4.3 (one PR).
4. `rnodeconf` stages 1 to 3, then stage 4 (one PR each).
5. After each PR: a new active audit section with the evidence, and after
   the last one a parity record claiming the full 1.6.0 surface.

Not in scope: Python-only internals with no observable behaviour (worker
pool sizing, Android job runners), and upstream's documentation build.
