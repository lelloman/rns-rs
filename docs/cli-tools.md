# CLI Tools

The `rns-cli` crate ships the Reticulum command-line programs with the same
names and roles as their Python counterparts, plus two sidecar daemons. They
are the lower-level building blocks; most deployments run
[`rns-server`](rns-server-operator-runbook.md) and reach for these when they
need to script, debug, or run pieces independently.

```bash
cargo build --release -p rns-cli
ls target/release/rn*
```

All tools accept `--config DIR` to select the config directory (default
`~/.reticulum`) and connect to the running `rnsd` through its shared instance.

| Tool | Purpose | More |
|------|---------|------|
| `rnsd` | The node daemon | below |
| `rnstatus` | Interface status, traffic counters, attach/detach/reload | [rnstatus](rnstatus.md) |
| `rnpath` | Display and manage the path table, request paths | `rnpath --help`; `rnpath -t -u` shows and sorts by last path use; `rnpath <hash> -w 30` requests a path and waits up to 30 s |
| `rnprobe` | Send a probe packet to a destination and measure RTT | `rnprobe --help` |
| `rnid` | Identity creation, inspection, encryption, and signatures | `rnid --help`; `rnid -i ID -a app.aspect` announces the identity's destination |
| `rnsh` | Remote shell over a Reticulum link | [rnsh](rnsh.md) |
| `rncp` | File transfer with authenticated fetch | below |
| `rnx` | Remote command execution | below |
| `rnir`, `rnpkg` | Placeholders, as upstream ships them: they start Reticulum and exit | `rnpkg --exampleconfig` |
| `rns-statsd` | Statistics sidecar, writes to a SQLite database | below |
| `rns-sentineld` | Sentinel policy sidecar | below |

## `rnsd`

```text
Usage: rnsd [OPTIONS]

Options:
  --config PATH, -c PATH  Path to config directory
  -s                      Service mode (log to file)
  --exampleconfig         Print example config and exit
  -v                      Increase verbosity (can repeat)
  -q                      Decrease verbosity (can repeat)
  --version               Print version and exit
```

In service mode the log goes to `<config dir>/logfile`, rotated at 5 MiB with
one archive kept, and the configured log level is used as is. In the
foreground, `-v` and `-q` adjust the configured level.

## `rncp`

```text
rncp [options] <file> <destination>
rncp --fetch [options] <remote-file> <destination>
rncp --listen [options]
```

Key options: `-l/--listen` to receive, `-f/--fetch` to pull a file,
`-F/--allow-fetch` to serve authenticated fetches, `-j/--jail DIR` to confine
fetches, `-s/--save DIR`, `-a/--allowed HASH` (repeatable), `-n/--no-auth`,
`-i/--identity PATH`, `-b/--announce SECONDS`, `-C/--no-compress`,
`-w/--timeout SECONDS`, `-p/--print-identity`.

## `rnx`

```text
rnx [options] <destination> <command>
rnx --listen [options]
rnx --interactive [options] <destination>
```

Key options: `-l/--listen`, `-x/--interactive`, `-a/--allowed HASH`
(repeatable), `-n/--noauth`, `-N/--noid`, `-b/--no-announce`,
`-d/--detailed`, `-m/--mirror` to mirror the remote exit status,
`-w/--timeout`, `-W/--result-timeout`, `--stdin TEXT`, `--stdout BYTES`,
`--stderr BYTES`, `-i/--identity PATH`, `-p/--print-identity`.

## Sidecars: `rns-statsd` and `rns-sentineld`

Both binaries exist only in hook-enabled builds (`rns-hooks-wasm`,
`rns-hooks-native`, or `rns-hooks-builtin` on `rns-cli`). Each attaches a hook
to the running node and consumes its events:

- `rns-statsd --db PATH [OPTIONS]` collects packet, announce, link, interface,
  and system statistics into a SQLite database. `rns-server` points it at
  `<config dir>/stats.db` by default and the control plane serves the data
  under `/api/stats/*`. Retention is described in the
  [operator runbook](rns-server-operator-runbook.md#statistics-database-retention).
- `rns-sentineld [OPTIONS]` watches Backbone peer events through the sentinel
  hook and temporarily blacklists peers that repeatedly stall on writes or
  idle out (by default two write stalls or four idle timeouts within five
  minutes, blacklisted for two minutes). Docker suite 20 exercises it.

Under `rns-server` both are started automatically by re-executing the server
binary with hidden role flags, so you rarely run them by hand.

## `rnodeconf`

The `rns-rnodeconf` crate builds `rnodeconf`, a native port of upstream's RNode
configuration utility. It talks to an RNode over its serial KISS interface,
prints what upstream prints, and sends the device the same command frames.

```bash
cargo build --release -p rns-rnodeconf
target/release/rnodeconf -i /dev/ttyUSB0
```

Implemented so far:

- `-i` shows the device information: product, model, firmware version,
  hardware revision, serial number, modem chip, frequency range, maximum TX
  power, manufacturing date and, for a device in TNC mode, its radio
  settings. The EEPROM checksum and device signature are checked against
  upstream's vendor keys, the public half of a local
  `~/.config/rnodeconf/firmware/signing.key` and any
  `~/.config/rnodeconf/trusted_keys/*.pubkey`, as upstream does.
- `-c` shows the device configuration (Bluetooth, WiFi, interference
  avoidance, display and NeoPixel settings); `--show-psk` shows the WiFi PSK.
- `-T` switches to TNC mode with `--freq`, `--bw`, `--txp`, `--sf` and `--cr`,
  asking for any not given; `-N` switches back to normal (host-controlled)
  mode.
- `--eeprom-dump` prints the device's EEPROM; `--eeprom-backup` saves it to
  `~/.config/rnodeconf/eeprom/<date>_<time>.eeprom`; `--eeprom-wipe` erases
  it. Upstream joins that directory and the file name without a separator,
  so its backups land beside the `eeprom` directory instead of inside it.
- `-k` creates the local signing keys if missing:
  `~/.config/rnodeconf/firmware/device.key` (a Reticulum identity) and
  `signing.key` (RSA-1024, PKCS#8 DER, readable by upstream). `-P` shows
  their public halves. `--trust-key <hex>` trusts another public key for
  device verification.
- `-r` bootstraps an unprovisioned device's EEPROM with `--model`,
  `--hwrev` and optionally `--product` (default `03`), signs it with
  `signing.key`, numbers it from `firmware/serial.counter` and reads it
  back. Upstream finds an NRF52 board again by its USB serial number after
  the reset; this keeps the same port.
- `-S` signs the device hash with `device.key`; `-H <sha256>` stores the
  expected firmware hash; `-K` and `-L` show the target and actual
  firmware hashes.
- Display: `-D` intensity, `-t` blanking timeout (0 disables blanking),
  `-R` rotation, `--display-addr` (then the device restarts),
  `--recondition-display`. `--np` sets the NeoPixel intensity; `-x` and
  `-X` enable and disable interference avoidance. Upstream sends the
  display, NeoPixel and WiFi mode values without KISS escaping, so a value
  of 192 or 219 breaks its frame; these are escaped.
- Bluetooth: `-b` on, `-B` off, `-p` pairing mode until Enter is pressed.
- WiFi: `-w` mode (`OFF`, `AP` or `STATION`), `--channel`, `--ssid`,
  `--psk`, `--ip` and `--nm` (`NONE` deletes a value or returns to DHCP).

- Firmware: `-u` updates a provisioned device to the latest release (or
  `--fw-version`), refusing an installed or older version unless `-U`
  is given. Release information and packages come from the RNode firmware
  releases or `--fw-url`, are cached in `~/.config/rnodeconf/update/` and
  checked against the release's SHA-256; `--nocheck` skips the online
  check, `-C` clears the cache. The board is flashed by the flasher
  upstream runs: the `esptool.py` inside an ESP32 package (run with
  `python3`, or the interpreter `RNODECONF_PYTHON` names), `avrdude`, or
  `adafruit-nrfutil`, at `--baud-flash` for ESP32 boards. `-f` flashes an
  AVR board with a cached `rnode_firmware.hex` of `--fw-version`, then
  bootstraps its EEPROM; upstream's `-f` fails with a Python error past
  its version check unless the autoinstall wizard runs it.

- `-e` copies the firmware off a provisioned ESP32 RNode into
  `~/.config/rnodeconf/extracted/`, and `--use-extracted` installs it on
  another board of the same type. Upstream reads the flash with a copy of
  esptool carried inside its own source and written out as
  `~/.config/rnodeconf/recovery_esptool.py`; that copy is GPL-2.0
  licensed and not bundled here, so `-e` uses it when an upstream
  extraction has left it there and otherwise an installed `esptool.py` or
  `esptool` (`pip3 install esptool`). ESP32 updates fall back to an
  installed esptool the same way when a package carries none. Upstream's
  `-e` fails with a Python error on a port it does not list, such as a
  pseudo-terminal; this one uses the port as given.

- `-a` runs upstream's autoinstall wizard: choose the port (from a menu
  when none is given), the kind of device and its model, confirm, and it
  fetches the firmware, creates the signing keys if missing, flashes the
  board and bootstraps its EEPROM. Its menus are translated from
  upstream's source by `rns-rnodeconf/tools/translate_wizard.py`, so they
  read exactly as upstream's. Like `-e`, it uses a port upstream does not
  list (upstream exits) as given.

Every option is implemented and compared with upstream's Python
`rnodeconf` against fake devices, release sites and flashers; no real
RNode has been flashed with it yet. The crate's tests run the tool against a fake
RNode on a pseudo-terminal, and the interop CI jobs run upstream's Python
`rnodeconf` against the same fake device and require the same output and the
same frames sent.

## Examples in `rns-net`

The `rns-net` crate has runnable examples that double as API documentation:

```bash
cargo run -p rns-net --example echo          # application-facing API
cargo run -p rns-net --example message       # two clients exchanging encrypted messages via a local transport node
cargo run -p rns-net --example tcp_connect   # connect to a Python RNS TCP server and log announces
cargo run -p rns-net --example rnsd          # a minimal daemon built on the public API
RUST_LOG=info cargo run -p rns-net --example rnode_lora -- /dev/ttyUSB0   # log LoRa traffic from an RNode
```

`rnode_hil` and `weave_hil` are opt-in hardware-in-the-loop runners.

## Related

- [rns-ctl](rns-ctl.md) bundles daemon and client roles into one binary with
  an HTTP API.
- [rns-git](rns-git.md) adds `rngit`, `git-remote-rns`, and `rngcs`.
- [rntun](../rns-tun/README.md) is the Linux tunnelling CLI.
