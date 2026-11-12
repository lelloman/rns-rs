# Reticulum 1.6.0 Surface Parity Record

## Baseline

| Field | Value |
|---|---|
| Accepted version | `1.6.0` |
| Normative commit | rgit `16621a78` ([parity record](reticulum-1.6.0-rgit-3-parity.md)) |
| Scope | The whole upstream surface, not a commit range: every configuration key `Reticulum.py` reads, every RPC call it serves, every flag of the shared utilities, and the utility list |
| Plan | [parity-gap-plan.md](parity-gap-plan.md) |
| Acceptance date | `2026-11-12` |

The per-commit records only cover commits after a baseline, so features
upstream added before rns-rs tracked it were never compared. The gap plan
inventoried the whole surface against upstream and listed every difference
found. This record closes that plan: each item is done, and what still
differs is listed below.

## Items

| Item | Done in | Evidence |
|---|---|---|
| 1.1 Blackhole RPC names | #231 | Python `rnpath -b/-B/-U` against an rns-rs instance and the reverse (`utility_interop`) |
| 1.2 Packet RSSI, SNR and Q | #231 | RPC and `RnsNode` query tests |
| 1.3 Path retention calls | #231 | RPC tests over the known-destination store |
| 1.4 RPC over the Unix socket | #231 | rns-rs utilities reach a Python shared instance on its abstract socket (`utility_interop`) |
| 2.1 Blackhole list subscription | #232 | rns-rs fetches a Python publisher's list and the reverse (`utility_interop`) |
| 2.2 Trusted discovery sources | #232 | Discovery tests |
| 2.3 Radio discovery fields | #232 | Discovery round trips and `rnstatus` |
| 2.4 IFAC publication | #232 | Discovery tests; fixed a leak of IFAC names without `publish_ifac` |
| 2.5 Encrypted discovery | #232 | Python and rns-rs discovery announces decrypted both ways |
| 2.6 Bootstrap interfaces | #234 | Monitor tests under `autoconnect_policy = upstream` |
| 2.7 Shared instance options | #232 | Config and RPC tests |
| 2.8 `listen_on` | #232 | Config tests |
| 3.1 `autoconnect_discovered_interfaces` | #234 | Monitor and pool tests; `autoconnect_policy` chooses upstream's behaviour (default) or the rns-rs peer pool |
| 4.1 `rnid` flags | #237 | `-a/--announce [aspects]` announces through the shared instance (seen by the instance); `-t` now reads its value; `-v`/`-q` and upstream's `-U`, `-F`, `-I`, `-O` names (`rnid_cli`) |
| 4.2 `rnpath -w` | #237 | `rnpath <destination>` requests the path, waits up to `-w` (at least the medium path timeout) and prints what Python's prints, for a found and an unknown destination, on RNS 1.4.2, 1.5.4 and 16621a78 (`utility_interop`) |
| 4.3 `rnir`, `rnpkg` | #237 | Start Reticulum and exit; `rnpkg --exampleconfig` matches Python (`placeholders`) |
| 4.4 `rnodeconf` | #235, #236, #237 | Every option compared with upstream's Python `rnodeconf` against fake devices, a local release site and fake flashers, on RNS 1.4.2, 1.5.4 and 16621a78 (`rns-rnodeconf` tests) |

## Remaining Differences

| Area | Difference |
|---|---|
| `force_shared_instance_bitrate` | Reported on the shared instance interface, but sends are not paced to it as upstream's local interfaces do. |
| Bootstrap interfaces | A bootstrap interface whose target is unreachable is not attached and is retried every 5 s; upstream creates it and lets it reconnect. |
| `rnodeconf` hardware | Checked on two Heltec LoRa32 v3 boards (ESP32-S3, firmware 1.86), see below; writing a new EEPROM (`-r`, `--eeprom-wipe`) has only been checked against fake devices. |
| `rnodeconf -e` on ESP32-S3 | Fails, as upstream's does: both read the flash as a classic ESP32 (`--chip esp32`, its offsets), and the failed attempt leaves the board in its bootloader until reset. |
| `rnodeconf` recovery esptool | Upstream carries a GPL-2.0 esptool in its source for `-e` and for packages without one; rns-rs uses the copy an upstream extraction left behind, or an installed `esptool`. |
| `rnodeconf` fixes | `-f` works without the autoinstall wizard, where upstream fails with a Python error; `-e` and `-a` use a port upstream does not list, where upstream exits; display, NeoPixel and WiFi mode values are KISS-escaped; EEPROM backups go inside the `eeprom` directory. |
| `rnid -a`, `rnir`, `rnpkg` | Without a running shared instance, `rnid -a` reports that it cannot connect, where upstream starts an instance of its own; `rnir` and `rnpkg` start one. |
| `rnid` exit codes | Only the announce errors use upstream's codes (4, 9, 254); other failures exit with 1. |

## `rnodeconf` on Hardware

Two Heltec LoRa32 v3 RNodes (ESP32-S3, 8 MB flash, CP2102), 2026-11-12:

| Check | Result |
|---|---|
| `-i`, `-c`, `-K -L`, `--eeprom-dump`, `-P` | Output identical to upstream's Python `rnodeconf` on the same board |
| `-D`, `-t`, `-x` then `-c`, then restored | The firmware stored and reported each value |
| `-u -U` | Release information and the 1.86 package fetched from GitHub, byte-identical to upstream's download; flashed with the package's esptool; firmware hash set; target and actual hashes equal the image's |
| `-a` on the second board | Wizard, firmware check and flash completed; its EEPROM was already valid, so bootstrapping made no changes, as upstream's does |

Not in scope, as in the plan: Python-only internals with no observable
behaviour, and upstream's documentation build.
