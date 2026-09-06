# Dependency verification — 2026-09-06

Ticket: [LLPR/RNS-1](https://crumbles.lelloman.com/w/LLPR/RNS/1)

Baseline: `70deb224bc9cdd6775b56fd8d50dfd5836a88a34`.

**The workspace dependencies are not all up to date.** Most direct Rust
dependencies match the latest published stable versions observed on docs.rs,
but seven dependencies in application crates require manifest changes to reach
those versions, as do two dependencies in the vendored macro.
ESP32 and the stats-scraper example also retain older compatible versions.
Android application dependencies have additional available updates.

This is a verification report, not an upgrade. Manifests, lockfiles, runtime
code, vendored sources, and workflow configuration are unchanged. The earlier
[upgrade audit](dependency-upgrades-2026.md) documents a historical maintenance
series; its final statement about only three remaining packages is not a
current inventory of the expanded workspace.

## Method and limits

- Inspected every tracked Cargo manifest and all 13 tracked Cargo lockfiles,
  including optional, target, build, and development dependencies, the excluded
  ESP32 project, hook examples, SDK, and vendored macro.
- Compared all 46 distinct external direct Rust dependency names with their
  published package pages on docs.rs on 2026-09-06. Each row links its observed
  version. Local path packages are repository source, not registry update targets.
- Compared selected Android dependencies with official upstream release pages.
  Versions below are declared versions; Gradle's resolved graph was unavailable.
- Rust, Cargo, and Java are absent from this runner. Both
  `cargo update --dry-run --verbose` and `cargo test --workspace --locked`
  failed immediately with `cargo: not found`. Shell requests to crates.io and
  its index returned HTTP 403, so published documentation was read through the
  browsing tool. No resolver, build, RustSec, or platform test pass is claimed.
- The direct Rust dependency inventory is complete; the transitive observations below
  are not an exhaustive registry comparison or proof that every compatible
  update will resolve. Newer versions are candidates, not tested upgrades.

## Direct Rust dependency inventory

H = root `Cargo.lock`; E = `rns-esp32/Cargo.lock`;
S = `rns-hooks/examples/stats_scraper/Cargo.lock`.
The lock columns show all occurrences, including transitive older generations;
compare the manifest requirement to identify the direct generation. A Cargo
requirement such as `zeroize = "1.8.2"` is a compatible range, not an exact pin:
its direct dependency already resolves to 1.9.0.

| Package | Direct requirement(s) | H | E | S | Latest stable observed |
| --- | --- | --- | --- | --- | --- |
| aes | 0.9 | 0.9.3 | 0.9.2 | — | [0.9.3](https://docs.rs/crate/aes/0.9.3) |
| anyhow | 1 | 1.0.104 | 1.0.104 | — | [1.0.104](https://docs.rs/crate/anyhow/1.0.104) |
| argon2 | 0.5.3 | 0.5.3 | — | — | [0.6.0](https://docs.rs/crate/argon2/0.6.0) |
| base64 | 0.22.1 | 0.22.1, 0.23.1 | — | — | [0.23.1](https://docs.rs/crate/base64/0.23.1) |
| bzip2 | 0.6 | 0.6.1 | — | — | [0.6.1](https://docs.rs/crate/bzip2/0.6.1) |
| cbc | 0.2 | 0.2.1 | 0.2.1 | — | [0.2.1](https://docs.rs/crate/cbc/0.2.1) |
| chacha20poly1305 | 0.10.1 | 0.10.1 | — | — | [0.11.0](https://docs.rs/crate/chacha20poly1305/0.11.0) |
| criterion | 0.8 | 0.8.2 | — | — | [0.8.2](https://docs.rs/crate/criterion/0.8.2) |
| ctrlc | 3 | 3.5.2 | — | — | [3.5.2](https://docs.rs/crate/ctrlc/3.5.2) |
| ed25519-dalek | 3 | 3.0.0 | 3.0.0 | — | [3.0.0](https://docs.rs/crate/ed25519-dalek/3.0.0) |
| embedded-graphics | 0.8 | — | 0.8.2 | — | [0.8.2](https://docs.rs/crate/embedded-graphics/0.8.2) |
| embedded-hal | 1 | — | 0.2.7, 1.0.0 | — | [1.0.0](https://docs.rs/crate/embedded-hal/1.0.0) |
| embuild | 0.33 | 0.33.3 | 0.33.3 | — | [0.33.3](https://docs.rs/crate/embuild/0.33.3) |
| env_logger | 0.11 | 0.11.11 | — | — | [0.11.11](https://docs.rs/crate/env_logger/0.11.11) |
| esp-idf-hal | 0.46 | — | 0.46.2 | — | [0.46.2](https://docs.rs/crate/esp-idf-hal/0.46.2) |
| esp-idf-svc | 0.52 | — | 0.52.1 | — | [0.52.1](https://docs.rs/crate/esp-idf-svc/0.52.1) |
| esp-idf-sys | 0.37 | 0.37.2 | 0.37.2 | — | [0.37.2](https://docs.rs/crate/esp-idf-sys/0.37.2) |
| hmac | 0.13 | 0.13.0 | 0.13.0 | — | [0.13.0](https://docs.rs/crate/hmac/0.13.0) |
| jni | 0.21.1 | 0.21.1 | — | — | [0.22.4](https://docs.rs/crate/jni/0.22.4) |
| libc | 0.2 | 0.2.189 | 0.2.189 | 0.2.183 | [0.2.189](https://docs.rs/crate/libc/0.2.189) |
| libloading | 0.9 | 0.8.9, 0.9.0 | 0.8.9 | — | [0.9.0](https://docs.rs/crate/libloading/0.9.0) |
| libm | 0.2 | 0.2.16 | 0.2.16 | — | [0.2.16](https://docs.rs/crate/libm/0.2.16) |
| log | 0.4 | 0.4.34 | 0.4.33 | — | [0.4.34](https://docs.rs/crate/log/0.4.34) |
| polling | 3 | 3.11.0 | — | — | [3.11.0](https://docs.rs/crate/polling/3.11.0) |
| postcard | 1.1.3 | 1.1.3 | — | — | [1.1.3](https://docs.rs/crate/postcard/1.1.3) |
| proc-macro2 | 1.0 | 1.0.107 | 1.0.107 | — | [1.0.107](https://docs.rs/crate/proc-macro2/1.0.107) |
| pulldown-cmark | 0.11 | — | 0.11.3 | — | [0.13.4](https://docs.rs/crate/pulldown-cmark/0.13.4) |
| quote | 1.0 | 1.0.47 | 1.0.47 | — | [1.0.47](https://docs.rs/crate/quote/1.0.47) |
| rand_core | 0.6.4 | 0.6.4, 0.10.1 | 0.10.1 | — | [0.10.1](https://docs.rs/crate/rand_core/0.10.1) |
| rayon | 1 | 1.12.0 | — | — | [1.12.0](https://docs.rs/crate/rayon/1.12.0) |
| rcgen | 0.14 | 0.14.10 | — | — | [0.14.10](https://docs.rs/crate/rcgen/0.14.10) |
| rusqlite | 0.40 | 0.40.2 | — | — | [0.40.2](https://docs.rs/crate/rusqlite/0.40.2) |
| rustls | 0.23 | 0.23.43 | — | — | [0.23.43](https://docs.rs/crate/rustls/0.23.43) |
| serde | 1 | 1.0.229 | 1.0.229 | — | [1.0.229](https://docs.rs/crate/serde/1.0.229) |
| serde_json | 1 | 1.0.151 | 1.0.151 | — | [1.0.151](https://docs.rs/crate/serde_json/1.0.151) |
| sha2 | 0.11 | 0.10.9, 0.11.0 | 0.11.0 | 0.11.0 | [0.11.0](https://docs.rs/crate/sha2/0.11.0) |
| socket2 | 0.6 | 0.6.5 | — | — | [0.6.5](https://docs.rs/crate/socket2/0.6.5) |
| ssd1306 | 0.10 | — | 0.10.0 | — | [0.10.0](https://docs.rs/crate/ssd1306/0.10.0) |
| syn | 1.0 | 1.0.109, 2.0.119, 3.0.3 | 1.0.109, 2.0.119, 3.0.3 | — | [3.0.5](https://docs.rs/crate/syn/3.0.5) |
| tempfile | 3 | 3.27.0 | 3.27.0 | — | [3.27.0](https://docs.rs/crate/tempfile/3.27.0) |
| tikv-jemallocator | 0.7 | 0.7.0 | — | — | [0.7.0](https://docs.rs/crate/tikv-jemallocator/0.7.0) |
| toml | 0.9 | 0.9.12+spec-1.1.0 | — | — | [1.1.5+spec-1.1.0](https://docs.rs/crate/toml/1.1.5+spec-1.1.0) |
| wasmtime | 47 | 47.0.4 | — | — | [48.0.1](https://docs.rs/crate/wasmtime/48.0.1) |
| wat | 1 | 1.258.0 | — | — | [1.258.0](https://docs.rs/crate/wat/1.258.0) |
| x25519-dalek | 3 | 3.0.0 | 3.0.0 | — | [3.0.0](https://docs.rs/crate/x25519-dalek/3.0.0) |
| zeroize | 1.8.2 | 1.9.0 | — | — | [1.9.0](https://docs.rs/crate/zeroize/1.9.0) |

## Available Rust upgrades

| Consumer | Dependency | Locked → observed stable | Required follow-up |
| --- | --- | --- | --- |
| rns-hooks | wasmtime | 47.0.4 → 48.0.1 | Review new runtime generation; rerun sandbox, fuel, WASM examples, and hook integration suites |
| rns-tun | toml | 0.9.12+spec-1.1.0 → 1.1.5+spec-1.1.0 | Review API and parsing behavior; verify tunnel configuration fixtures |
| rns-tun-android | jni | 0.21.1 → 0.22.4 | Review JNI API migration; build all four Android ABIs and exercise native boundary |
| rns-tun-android | argon2 | 0.5.3 → 0.6.0 | Review together with export/import crypto; preserve existing encrypted data compatibility |
| rns-tun-android | chacha20poly1305 | 0.10.1 → 0.11.0 | Review crypto trait and feature changes with Argon2/RNG consumers |
| rns-tun-android | rand_core | 0.6.4 → 0.10.1 | Review RNG API/features and crypto trait compatibility; the existing transitive 0.10.1 does not upgrade this direct dependency |
| rns-tun-android | base64 | 0.22.1 → 0.23.1 | Review encoding/decoding API and persisted export format |

All seven targets are outside their existing Cargo requirement. Changing only
lockfiles cannot upgrade them. No compatibility assessment from the earlier
maintenance series should be reused as evidence for these new target versions.

### Lockfile drift and vendored constraints

- ESP32 still locks AES 0.9.2 and log 0.4.33, while the root and observed latest
  versions are 0.9.3 and 0.4.34. Both newer versions fit the declared ranges;
  resolve and validate the ESP32 graph before accepting a refresh.
- The stats-scraper example locks transitive libc 0.2.183; root/ESP32 and the
  observed latest are 0.2.189. The other nine example lockfiles and SDK lockfile
  contain only local packages, so have no external registry versions to refresh.
- Both main lockfiles contain syn 3.0.3; 3.0.5 is published. This is an additional
  transitive update candidate. The vendored macro directly uses syn 1.0.109;
  that separate generation cannot be replaced by a lockfile-only update to 3.x.
- The vendored macro's optional pulldown-cmark dependency remains 0.11.3 versus
  published 0.13.4. This also requires a reviewed manifest/API migration.
- Preserve the ESP32 local maybe-async-cfg 0.2.4 patch. Its purpose and exact
  upstream pin are documented in [PATCHES.md](../vendor/maybe-async-cfg/PATCHES.md).
  Neither its version label nor the age of syn 1 is justification to overwrite
  the reviewed local source with a registry package.
- The prior audit documents generic-array 0.14.7 constrained by crypto-common
  0.1.7's exact requirement, and ESP32 az 1.2.1 constrained by embedded-graphics
  `~1.2.0`. These versions remain in the lockfiles. The published latest
  [generic-array 1.4.5](https://docs.rs/crate/generic-array/1.4.5) and
  [az 1.3.0](https://docs.rs/crate/az/1.3.0) do not demonstrate that these
  transitive constraints can be relaxed. No constraint was forced in this audit.

## Android application observations

Source: [app/build.gradle.kts](../rns-tun-android/app/build.gradle.kts).
Stable releases are distinguished from alpha/beta/RC releases.

| Dependency | Declared | Stable release observed | Evidence |
| --- | --- | --- | --- |
| activity-compose | 1.12.3 | 1.13.0 | [Android Activity releases](https://developer.android.com/jetpack/androidx/releases/activity) |
| core-ktx | 1.17.0 | 1.19.0 | [Android Core releases](https://developer.android.com/jetpack/androidx/releases/core) |
| lifecycle runtime-compose, service, viewmodel-compose | 2.10.0 | 2.11.0 | [Android Lifecycle releases](https://developer.android.com/jetpack/androidx/releases/lifecycle) |
| datastore-core | 1.2.0 | 1.2.1 | [Android DataStore releases](https://developer.android.com/jetpack/androidx/releases/datastore) |
| kotlinx-coroutines-android / test | 1.10.2 | 1.11.0 | [Coroutines release](https://github.com/Kotlin/kotlinx.coroutines/releases/tag/1.11.0) |
| kotlinx-serialization-json | 1.9.0 | 1.11.0 available | [Serialization release](https://github.com/Kotlin/kotlinx.serialization/releases/tag/v1.11.0); upstream latest redirect points to 1.12.0-RC, which is not a stable target |
| ZXing core | 3.5.4 | 3.5.4 | [ZXing release](https://github.com/zxing/zxing/releases/tag/zxing-3.5.4) |
| JUnit 4 | 4.13.2 | 4.13.2 | [JUnit 4 release](https://github.com/junit-team/junit4/releases/tag/r4.13.2) |

Compose BOM 2026.06.00 and its managed libraries, ZXing Android Embedded 4.3.0,
AndroidX test JUnit 1.3.0, and Espresso 3.7.0 are inventoried but not certified
current here. Resolve the Gradle graph and compare its BOM-managed versions
before changing individual Compose artifacts.

Build tool pins (Rust 1.96.0, Gradle 9.5.0, AGP 9.3.0, Kotlin plugins 2.4.10,
Android SDK/NDK and cargo-ndk) and GitHub Action references were inspected but
are not certified current by the package comparison. Upgrading these needs
its own compatibility checks; this report makes no blanket freshness claim.

## Maintenance coverage and next verification

[Dependabot](../.github/dependabot.yml) currently monitors Cargo at the root and
ESP32 with `lockfile-only`, plus GitHub Actions. It does not cover the independent
hook example workspaces or Android Gradle dependencies, and its configured
Cargo strategy does not address the seven manifest-incompatible upgrades.

On an environment with the project's toolchains and registry access:

1. Run `cargo update --dry-run --verbose` at the root and with
   `--manifest-path rns-esp32/Cargo.toml`; repeat for each hook example manifest,
   especially stats_scraper. Inspect the resolver output for compatible updates
   and retained constraints before changing any lockfile.
2. Review the upstream changes for each incompatible upgrade and the vendored
   macro separately, following the compatibility checks in the prior audit.
3. For accepted updates, run the affected CI lanes: workspace tests, hooks/WASM,
   TLS, host lint, ESP32, and Android as applicable. Run RustSec separately;
   version freshness is not an advisory scan.

Validation for this documentation-only ticket: checked inventory coverage and
reported locked versions against the tracked manifests/lockfiles, checked local
Markdown link targets, and ran `git diff --check`. Rust resolution and tests
remain unavailable for the environment reasons above.
