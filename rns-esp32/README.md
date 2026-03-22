# rns-esp32

Reticulum LoRa transport node firmware for **Heltec WiFi LoRa 32 (V3)** with SX1262 radio.

## Hardware

- **Board**: Heltec WiFi LoRa 32 (V3) - ESP32-S3 based
- **Radio**: SX1262 LoRa module (built-in)
- **Display**: SSD1306 128x64 OLED (built-in)
- **Frequency**: 868 MHz (EU band, configurable)

## Features

- **Dual mode operation**:
  - **Standalone**: Runs a full Reticulum transport node over LoRa
  - **RNode Bridge**: Acts as a KISS interface over USB serial for a PC running `rns-net`
- LoRa packet transport for Reticulum network
- OLED display with multiple info pages (cycled via short-press PRG button)
- Identity persistence via NVS (Non-Volatile Storage)
- Signed control-plane support over LoRa for up to 3 build-time controller identities
- Persistent BLE-open policy backed by NVS, with a compile-time default
- IFAC cryptographic helpers are implemented, but runtime IFAC configuration is not wired up yet
- Button gestures:
  - **Short press**: Cycle display page
  - **Double press**: Send ping broadcast
- **Long press (>800ms)**: Trigger Reticulum announce

## Authenticated Control Plane

The firmware can compile in up to 3 controller public keys and accept signed control packets over LoRa in standalone mode.

- Request destination: `rns_esp32.control.<node_identity_hash>`
- Reply destination: `rns_esp32.control.reply.<controller_identity_hash>`
- Supported commands:
  - `GetRadio`
  - `SetRadio`
  - `GetBlePolicy`
  - `SetBlePolicy`

`SetRadio` changes the active standalone radio config at runtime only. It does not persist across reboot.

When a `SetRadio` command is accepted, the node immediately applies the new values to the SX1262 and updates the standalone OLED radio page to show the active runtime configuration. This makes it possible to remotely verify what the node is currently using from the device itself, even if the controller is running on another `rns-rs` platform.

`SetBlePolicy` controls whether the existing BLE bridge mode is open to any nearby BLE client. That policy is persisted in NVS.

The node now announces both its transport destination and its control destination when you trigger an announce.

## RNode Bridge Mode

When a PC connects via USB serial and sends an RNode DETECT handshake, the device automatically switches from standalone mode to bridge mode. In bridge mode it:

- Responds to the RNode KISS protocol (DETECT, FW_VERSION, PLATFORM, MCU)
- Accepts radio configuration commands (frequency, bandwidth, SF, CR, TX power)
- Bridges KISS data frames between USB serial and the SX1262 LoRa radio
- Reverts to standalone mode after 30 seconds without host serial activity

Use the `rnode_lora` example from `rns-net` to connect from a PC:

```bash
RUST_LOG=info cargo run --example rnode_lora -- /dev/ttyUSB0
```

## Firmware Versioning

The firmware now embeds two version forms:

- **RNode protocol version**: the `FW_VERSION` response uses the Cargo package `major.minor`
- **Full build version**: startup logs include `major.minor.commit_count-short_hash[-dirty]`

Example:

```text
0.1.131-706648c-dirty
```

The `-dirty` suffix means the repository had uncommitted changes at build time.

## Pre-built Firmware

Pre-built flashable images are available on the
[GitHub Releases](https://github.com/lelloman/rns-rs/releases) page.

Flash with esptool:
```bash
esptool.py write_flash 0x0 rns-esp32-vX.Y.Z-esp32s3.bin
```

Or with espflash:
```bash
espflash write-bin 0x0 rns-esp32-vX.Y.Z-esp32s3.bin
```

## Prerequisites

1. Install Rust with ESP target support:
   ```bash
   cargo install espup
   espup install
   . $HOME/export-esp.sh
   ```

2. Install `espflash` for flashing:
   ```bash
   cargo install espflash
   ```

3. Connect your Heltec V3 via USB.

## Building

```bash
cd rns-esp32
cargo build --features firmware --target xtensa-esp32s3-espidf --release
```

Optional build-time control config:

```bash
export RNS_ESP32_CONTROL_PUBKEYS="<128-hex-char-pubkey>[,<128-hex-char-pubkey>...]"
export RNS_ESP32_BT_OPEN_DEFAULT=false
cargo build --features firmware --target xtensa-esp32s3-espidf --release
```

- `RNS_ESP32_CONTROL_PUBKEYS` accepts 0-3 comma-separated 64-byte public keys in hex
- `RNS_ESP32_BT_OPEN_DEFAULT` sets the compile-time default for the persisted BLE-open policy
- if `RNS_ESP32_CONTROL_PUBKEYS` is unset, the signed LoRa control plane is not enabled

## Flashing

```bash
cargo run --features firmware --target xtensa-esp32s3-espidf --release
```

Or manually:
```bash
espflash flash --monitor target/xtensa-esp32s3-espidf/release/rns-esp32
```

## Host-Side Tests

The crate now exposes host-testable protocol and state helpers, so the default test command no longer tries to flash hardware:

```bash
cd rns-esp32
cargo test
```

Use the explicit Xtensa target plus `--features firmware` for firmware-only builds and on-device checks.

## Hardware-In-The-Loop Testing

For real RF regression testing, connect two Heltec V3 boards to the same host and run:

```bash
RUST_LOG=info cargo run -p rns-net --example rnode_hil -- /dev/ttyUSB0 /dev/ttyUSB1 868.0
```

The runner will:

- detect both boards over USB serial
- configure matching LoRa settings on both radios
- verify packet delivery A -> B and B -> A
- send `LEAVE` and verify both boards can be detected again

This is intended for bench or lab runners, not always-on CI without dedicated hardware.

## Configuration

Edit `src/config.rs` to modify LoRa parameters:
- Frequency
- Bandwidth
- Spreading factor
- TX power
- Coding rate

The board pinout and partition table are also part of the firmware configuration.

Build-time environment variables control the authenticated LoRa control plane and the default BLE-open policy.

## Transport Memory Profile

The ESP32 firmware now uses an explicit constrained `TransportConfig` profile instead of relying on the large desktop/server defaults from `rns-core`.

- `packet_hashlist_max_entries = 1024`
- `max_discovery_pr_tags = 256`
- `max_path_destinations = 256`
- `max_tunnel_destinations_total = 128`
- `known_destinations_ttl = 24h`
- `max_paths_per_destination = 2`

These caps bound the main transport tables that would otherwise grow only by TTL eviction. If you are operating an ESP32 node from another `rns-rs` platform, these are the limits the device is using unless you change the firmware profile.

## Display Pages

1. **Stats**: Identity hash (short), TX/RX byte counters, announce count
2. **Radio Info**: Active frequency, SF, bandwidth, coding rate, TX power
3. **Identity**: Full 32-byte identity hash

In standalone mode, the radio page reflects the current active runtime radio configuration. In bridge mode, the bridge radio page reflects the bridge-specific radio settings while the bridge is active.

## Architecture

```
main.rs         - Hardware init, thread spawning, mode switching
├── lora.rs     - SX1262 SPI driver (TX/RX), radio reconfiguration
├── rnode.rs    - RNode KISS protocol handler, USB bridge mode
├── display.rs  - SSD1306 OLED rendering
├── button.rs   - GPIO0 button with gesture detection
├── driver.rs   - Event loop, TransportEngine integration
├── ifac.rs     - Interface Access Code crypto
├── rng.rs      - Hardware RNG wrapper
└── config.rs   - Pin assignments, LoRa params
```

## License

Same as parent project.
