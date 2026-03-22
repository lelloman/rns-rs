# ESP32 Firmware Release Runbook

This runbook documents the release process for the `rns-esp32` firmware.
Unlike the workspace crates (published to crates.io), the ESP32 firmware is
distributed as a pre-built flashable image via GitHub Releases.

## How it works

A GitHub Actions workflow (`.github/workflows/esp32-release.yml`) builds the
firmware and publishes the flashable binary automatically when a matching tag
is pushed.

## 1. Preconditions

- All changes must be committed and pushed to `master`
- The ESP32 firmware must build locally (if possible) or at least the
  workspace crates it depends on (`rns-crypto`, `rns-core`) must be in a
  consistent state
- Update `rns-esp32/Cargo.toml` version if needed

## 2. Tag and push

From a clean `master`:

```bash
git checkout master
git pull origin master
git tag rns-esp32-v<VERSION>
git push origin rns-esp32-v<VERSION>
```

Example:

```bash
git tag rns-esp32-v0.1.0
git push origin rns-esp32-v0.1.0
```

The tag must match the pattern `rns-esp32-v*` to trigger the workflow.

## 3. Monitor the build

Watch the workflow run at:

```
https://github.com/lelloman/rns-rs/actions/workflows/esp32-release.yml
```

The build takes ~10-15 minutes (longer on first run due to ESP-IDF download).

## 4. Verify the release

Once the workflow completes, a GitHub Release will be created at:

```
https://github.com/lelloman/rns-rs/releases/tag/rns-esp32-v<VERSION>
```

The release includes:

- `rns-esp32-v<VERSION>-esp32s3.bin` — merged flashable image (bootloader +
  partition table + app)

## 5. Flashing

Users can flash the pre-built image with:

```bash
esptool.py write_flash 0x0 rns-esp32-v<VERSION>-esp32s3.bin
```

Or with espflash:

```bash
espflash write-bin 0x0 rns-esp32-v<VERSION>-esp32s3.bin
```

## 6. If the build fails

Fix the issue on a branch, merge to `master`, then either:

- Delete the remote tag and re-tag:

  ```bash
  git push origin --delete rns-esp32-v<VERSION>
  git tag -d rns-esp32-v<VERSION>
  git tag rns-esp32-v<VERSION>
  git push origin rns-esp32-v<VERSION>
  ```

- Or bump the version and tag with a new version number.

## Notes

- The workflow uses `espup` to install the Espressif Rust toolchain (the
  `xtensa-esp32s3-espidf` target is not in upstream rustup)
- The firmware embeds the git commit hash and count via `build.rs`, so the
  workflow checks out with full history (`fetch-depth: 0`)
- The flashable `.bin` is a merged image created by
  `espflash save-image --chip esp32s3 --merge`, containing the bootloader,
  partition table, and application at their correct flash offsets
