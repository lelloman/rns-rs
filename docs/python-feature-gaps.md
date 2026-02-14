# Python vs Rust Reticulum Feature Gap Analysis

This document tracks features present in the Python Reticulum implementation that are missing or incomplete in the Rust implementation (`rns-rs`).

**Last Updated:** 2026-02-14

---

## Summary

| Category | Missing in Rust | Priority | Status |
|----------|-----------------|----------|--------|
| **BackboneClientInterface** | Client mode for backbone | N/A | **Done** |
| **Ingress Control System** | Burst limiting, announce holding | N/A | **Done** |
| **RNodeMultiInterface** | Multi-subinterface RNode | Medium | Not started |
| **WeaveInterface** | Weave device protocol | Low | Not started |
| **AX25KISSInterface** | AX.25 amateur radio | Low | Not started |
| **Android Interfaces** | Android-specific interfaces | Low | Not started |
| **Interface Config Options** | Various per-interface options | Medium | Mostly done |
| **Transport Layer** | Core routing | N/A | **Feature complete** |
| **Link/Channel/Resource** | Encrypted links, transfers | N/A | **Feature complete** |
| **DirectLink (NAT Punch)** | Direct P2P UDP | N/A | **Rust exclusive** |

---

## Missing Interface Types

### ~~1. BackboneClientInterface~~ (Done)

Implemented in `rns-net/src/interface/backbone.rs` — `start_client()` with `BackboneClientConfig`. Supports connecting to remote backbone servers with auto-reconnect.

---

### 2. RNodeMultiInterface

**Python Reference:** `RNS/Interfaces/RNodeMultiInterface.py` (921 lines)

Manages up to 11 RNode sub-interfaces with:
- Peer-to-peer direct RNode communication
- NAT hole punching for direct connections
- RNodeSubInterface class

**Rust status:** Single RNodeInterface only (`interface/rnode.rs`)

**Config example (Python only):**
```ini
[[RNodeMulti]]
  type = RNodeMultiInterface
  port = /dev/ttyUSB0
  [[[Interface 1]]]
    frequency = 868000000
  [[[Interface 2]]]
    frequency = 915000000
```

**Priority:** Medium — Requires nested config parsing (`[[[triple-bracket]]]`).

---

### 3. WeaveInterface

**Python Reference:** `RNS/Interfaces/WeaveInterface.py` (1,015 lines)

Weave device protocol (WDCL) implementation for:
- Device discovery
- CPU/memory monitoring
- Switch and endpoint identity management
- Multiple sub-interfaces via RNodeMultiInterface

**Config example (Python only):**
```ini
[[Weave]]
  type = WeaveInterface
  port = /dev/ttyUSB0
```

**Priority:** Low — Specialized hardware protocol.

---

### 4. AX25KISSInterface

**Python Reference:** `RNS/Interfaces/AX25KISSInterface.py` (250+ lines)

AX.25 variant of KISS interface with amateur radio support.

**Priority:** Low — Amateur radio specific.

---

### 5. Android-Specific Interfaces

**Python Reference:** `RNS/Interfaces/Android/` directory

- `Android/RNodeInterface.py`
- `Android/KISSInterface.py`
- `Android/SerialInterface.py`

**Priority:** Low — Android platform specific.

---

## ~~Missing Ingress Control System~~ (Done)

Implemented in `rns-core/src/transport/ingress_control.rs`. Per-interface burst detection holds announces from unknown destinations during bursts, then releases them (lowest hops first) after a penalty period. Integrated into `process_inbound_announce()` and `tick()`.

---

## Missing Interface Configuration Options

### ~~Interface Mode Constants~~ (Done)

**Python Reference:** `RNS/Interfaces/Interface.py:44-56`

```python
MODE_FULL = 0x01
MODE_POINT_TO_POINT = 0x02
MODE_ACCESS_POINT = 0x03
MODE_ROAMING = 0x04
MODE_BOUNDARY = 0x05
MODE_GATEWAY = 0x06
DISCOVER_PATHS_FOR = [MODE_ACCESS_POINT, MODE_GATEWAY, MODE_ROAMING]
```

**Rust status:** Fully implemented.

- Mode constants and config parsing: `constants.rs`, `node.rs:parse_interface_mode()`
- Per-mode path expiry and roaming grace: `announce_proc.rs`, path request handler
- Announce broadcast filtering (ROAMING/BOUNDARY/AP): `outbound.rs:should_transmit_announce()` — checks source interface mode to decide whether to forward non-local announces
- Boundary exemption for `mark_path_unresponsive()`: boundary interfaces cannot poison path tables
- `DISCOVER_PATHS_FOR` path request forwarding: AP/GATEWAY/ROAMING interfaces forward path requests for unknown destinations and store `DiscoveryPathRequest` entries, consumed when the announce arrives
- ROAMING loop prevention: path requests arriving on a ROAMING interface whose known path routes back through the same interface are silently dropped
- Discovery auto-configuration: `AutoInterface` → GATEWAY, `RNodeInterface` with `discoverable=true` → ACCESS_POINT (when mode not already set)

---

### Auto-MTU Optimization

**Python Reference:** `RNS/Interfaces/Interface.py:140-163`

Python automatically adjusts HW_MTU based on bitrate:
```python
if bitrate >= 1_000_000_000: HW_MTU = 524288
elif bitrate > 750_000_000:  HW_MTU = 262144
elif bitrate > 400_000_000:  HW_MTU = 131072
# ... etc
```

**Rust status:** Fixed MTU values.

---

### TCPInterface Options Missing

**Python Reference:** `RNS/Interfaces/TCPInterface.py:97-149`

| Option | Description | Rust Status |
|--------|-------------|-------------|
| `kiss_framing` | Enable KISS framing | Missing |
| `i2p_tunneled` | I2P tunnel mode | Missing |
| `connect_timeout` | Connection timeout | Missing |
| `max_reconnect_tries` | Max reconnection attempts | Missing |
| `fixed_mtu` | Fixed MTU override | Missing |

---

### ~~AutoInterface Options Missing~~ (Done)

All options (`group_id`, `discovery_scope`, `multicast_address_type`, `allowed_interfaces`, `ignored_interfaces`) are implemented in `AutoInterfaceConfig`.

---

### RNodeInterface Options Missing

**Python Reference:** `RNS/Interfaces/RNodeInterface.py:149-250+`

| Option | Description | Rust Status |
|--------|-------------|-------------|
| `txpower` | Transmit power | Partial |
| `frequency` | Radio frequency | Partial |
| `bandwidth` | Channel bandwidth | Partial |
| `sf` | Spreading factor | Partial |
| `cr` | Coding rate | Partial |
| `encrypt` | Enable encryption | Missing |
| `discoverable` | Discovery mode | Missing |
| `blink_time` | LED blink duration | Missing |

---

### ~~BackboneInterface Options Missing~~ (Done)

Client mode with `target_host`/`target_port` now implemented via `BackboneClientConfig`.

---

## I2P Interface Status

**Python:** Full implementation (838 lines) with:
- SAM v3.1 protocol integration
- Asyncio event loop for tunnel management
- Outbound and inbound peer handling

**Rust:** Has `i2p/` directory with `mod.rs` and `sam.rs`. Appears to be a lighter implementation. **Needs verification of completeness.**

---

## Features Rust Has That Python Doesn't

### DirectLink NAT Hole Punching

**Location:** `rns-core/src/holepunch/` and `rns-net/src/holepunch/`

This is an rns-rs extension allowing two peers to upgrade from a relayed Reticulum link to a direct P2P UDP connection.

**Components:**
- `engine.rs` — Pure state machine (STUN → negotiate → punch → confirm)
- `orchestrator.rs` — Session manager
- `probe.rs` — STUN-like probe server/client
- `puncher.rs` — UDP hole punch execution
- `udp_direct.rs` — Direct UDP interface

**Documentation:** `docs/direct-link-protocol.md`

---

## Feature-Complete Areas

### Transport Layer

Path finding, tunnels, rate limiting, announce queuing, retransmission, shared instance support, blackholes, announce cache.

### Link/Channel/Buffer/Resource

4-way handshake, encrypted channel, buffer streaming, resource transfers with windowed flow control.

---

## Verification Commands

Check Python interface files:
```bash
ls -la /home/lelloman/Reticulum/RNS/Interfaces/
```

Compare with Rust interfaces:
```bash
ls -la /home/lelloman/lelloprojects/rns-rs/rns-net/src/interface/
```

Search for ingress control in Rust:
```bash
grep -r "ingress_control\|ic_burst\|ic_max_held" /home/lelloman/lelloprojects/rns-rs/
```

Search for missing interface types:
```bash
grep -r "WeaveInterface\|RNodeMultiInterface\|AX25KISS\|BackboneClient" /home/lelloman/lelloprojects/rns-rs/
```

---

## Implementation Priority Recommendations

1. **High Priority**
   - ~~BackboneClientInterface~~ — Done
   - ~~`remote` field for BackboneInterface~~ — Done

2. **Medium Priority**
   - ~~Ingress Control System~~ — Done
   - RNodeMultiInterface — Multi-radio support
   - Per-interface config options — Feature parity

3. **Low Priority**
   - WeaveInterface — Specialized hardware
   - AX25KISSInterface — Amateur radio niche
   - Android interfaces — Platform specific
