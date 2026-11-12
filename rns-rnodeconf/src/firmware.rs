//! Firmware releases and flashing, as upstream `rnodeconf`'s
//! `ensure_firmware_file`, `get_partition_hash` and `get_flasher_call` do
//! them: release information and firmware packages come from the RNode
//! firmware releases (or `--fw-url`), are cached under
//! `~/.config/rnodeconf/update/<version>/` and checked against the
//! release's SHA-256 before use; the board is then flashed by the external
//! flasher upstream runs (the `esptool.py` shipped in an ESP32 package,
//! `avrdude`, or `adafruit-nrfutil`).

use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::{graceful_exit, log, rom};

/// upstream `firmware_version_url`.
const FIRMWARE_VERSION_URL: &str =
    "https://github.com/markqvist/rnode_firmware/releases/latest/download/release.json";
/// upstream `fallback_firmware_version_url`, the same URL.
const FALLBACK_FIRMWARE_VERSION_URL: &str =
    "https://github.com/markqvist/rnode_firmware/releases/latest/download/release.json";
/// upstream `firmware_update_url`.
const FIRMWARE_UPDATE_URL: &str = "https://github.com/markqvist/RNode_Firmware/releases/download/";

/// The firmware package name upstream uses for one extracted from a device.
pub const EXTRACTED: &str = "extracted_rnode_firmware.zip";

/// The firmware selection and download settings for one run.
pub struct Firmware {
    pub config_dir: PathBuf,
    pub selected_version: Option<String>,
    pub selected_hash: Option<String>,
    pub fw_url: Option<String>,
    pub nocheck: bool,
}

impl Firmware {
    pub fn update_dir(&self) -> PathBuf {
        self.config_dir.join("update")
    }

    pub fn extracted_dir(&self) -> PathBuf {
        self.config_dir.join("extracted")
    }

    /// `UPD_DIR/<version>/`, as upstream builds it: a string path.
    pub fn version_dir(&self) -> String {
        format!(
            "{}/{}",
            self.update_dir().display(),
            self.selected_version.as_deref().unwrap_or("None")
        )
    }

    /// upstream `ensure_firmware_file`: make sure `fw_filename` for the
    /// selected (or latest) version is cached and intact, exiting otherwise.
    pub fn ensure(&mut self, fw_filename: &str) {
        if fw_filename == EXTRACTED {
            self.ensure_extracted(fw_filename);
            return;
        }
        let upd = self.update_dir().display().to_string();
        if !self.nocheck {
            if let Err(e) = self.select_release(fw_filename, &upd) {
                log(&format!(
                    "An error occurred while reading version information for {fw_filename}. The contained exception was:"
                ));
                log(&e);
                graceful_exit(0);
            }
        } else if self.selected_version.is_none() {
            log("Online firmware version check was disabled, but no firmware version specified for install.");
            log("use the --fw-version option to manually specify a version.");
            graceful_exit(98);
        }

        let version = self.selected_version.clone().unwrap_or_default();
        let update_target_url = match &self.fw_url {
            Some(url) => {
                let target = format!("{url}download/{version}/{fw_filename}");
                log(&format!("Retrieving firmware from custom url {target}"));
                target
            }
            None => format!("{FIRMWARE_UPDATE_URL}{version}/{fw_filename}"),
        };
        let version_dir = format!("{upd}/{version}");
        let fw_path = format!("{version_dir}/{fw_filename}");
        let fetched = (|| -> Result<(), String> {
            std::fs::create_dir_all(&version_dir).map_err(|e| e.to_string())?;
            if !Path::new(&fw_path).is_file() {
                log(&format!("Firmware {fw_path} not found."));
                log(&format!(
                    "Downloading missing firmware file: {fw_filename} for version {version}"
                ));
                download(&update_target_url, Path::new(&fw_path))?;
                log("Firmware file downloaded");
            } else {
                log(&format!(
                    "Using existing firmware file: {fw_filename} for version {version}"
                ));
            }
            Ok(())
        })();
        if let Err(e) = fetched {
            log("Could not download required firmware file: ");
            log(&update_target_url);
            log("The contained exception was:");
            log(&e);
            graceful_exit(0);
        }

        if self.selected_hash.is_none() {
            let version_file = format!("{fw_path}.version");
            self.selected_hash = std::fs::read_to_string(&version_file)
                .ok()
                .and_then(|info| info.split_whitespace().nth(1).map(str::to_string));
            if self.selected_hash.is_none() {
                log("Could not read locally cached release information.");
                log(&format!(
                    "Ensure {version_file} exists and has the correct format and hash."
                ));
                log("You can clear the cache with the --clear-cache option and try again.");
                log(&format!(
                    "No release hash found for {fw_filename}. The firmware integrity could not be verified."
                ));
                graceful_exit(97);
            }
        }
        let expected = self.selected_hash.clone().unwrap_or_default();
        log("Verifying firmware integrity...");
        let checked = std::fs::read(&fw_path)
            .map_err(|e| e.to_string())
            .and_then(|data| {
                crate::signature::unhex(&expected)
                    .map(|_| crate::hexstr(&rns_crypto::sha256::sha256(&data)))
                    .ok_or_else(|| {
                        "non-hexadecimal number found in fromhex() arg at position 0".to_string()
                    })
            });
        match checked {
            Ok(file_hash) if file_hash == expected => {}
            Ok(file_hash) => {
                log("");
                log(&format!(
                    "Firmware hash {file_hash} but should be {expected}, possibly due to download corruption."
                ));
                log("Firmware corrupt. Try clearing the local firmware cache with: rnodeconf --clear-cache");
                graceful_exit(96);
            }
            Err(e) => {
                log("An error occurred while checking firmware file integrity. The contained exception was:");
                log(&e);
                graceful_exit(95);
            }
        }
    }

    fn ensure_extracted(&mut self, fw_filename: &str) {
        let ext = self.extracted_dir();
        let version_file = ext.join("extracted_rnode_firmware.version");
        if !version_file.is_file() {
            log("No extracted firmware is available, cannot continue.");
            log("Extract a firmware from an existing RNode first, using the --extract-firmware option.");
            graceful_exit(183);
        }
        let required = [
            "extracted_console_image.bin",
            "extracted_rnode_firmware.bin",
            "extracted_rnode_firmware.boot_app0",
            "extracted_rnode_firmware.bootloader",
            "extracted_rnode_firmware.partitions",
        ];
        if required.iter().any(|f| !ext.join(f).is_file()) {
            log("One or more required firmware files are missing from the extracted RNode");
            log("Firmware archive. Installation cannot continue. Please try extracting the");
            log("firmware again with the --extract-firmware option.");
            graceful_exit(184);
        }
        let info = std::fs::read_to_string(&version_file).unwrap_or_default();
        let mut parts = info.split_whitespace();
        self.selected_version = parts.next().map(str::to_string);
        self.selected_hash = parts.next().map(str::to_string);
        log(&format!(
            "Using existing firmware file: {fw_filename} for version {}",
            self.selected_version.as_deref().unwrap_or_default()
        ));
    }

    /// The release lookup part of `ensure_firmware_file`: write
    /// `<fw_filename>.version.latest` and select its version and hash.
    fn select_release(&mut self, fw_filename: &str, upd: &str) -> Result<(), String> {
        let latest = format!("{upd}/{fw_filename}.version.latest");
        let record = |info_path: &str| -> Result<(), String> {
            let text = std::fs::read(info_path).map_err(|e| e.to_string())?;
            let release: serde_json::Value =
                serde_json::from_slice(&text).map_err(|e| e.to_string())?;
            let variant = release
                .get(fw_filename)
                .ok_or_else(|| format!("'{fw_filename}'"))?;
            let field = |name: &str| -> Result<String, String> {
                match variant.get(name) {
                    Some(serde_json::Value::String(s)) => Ok(s.clone()),
                    Some(other) => Ok(other.to_string()),
                    None => Err(format!("'{name}'")),
                }
            };
            let info = format!("{} {}", field("version")?, field("hash")?);
            std::fs::write(&latest, info).map_err(|e| e.to_string())
        };

        let primary = if self.selected_version.is_none() && self.fw_url.is_none() {
            let info_path = format!("{upd}/release_info.json");
            download(FIRMWARE_VERSION_URL, Path::new(&info_path)).and_then(|_| record(&info_path))
        } else {
            let version_url = match (&self.fw_url, &self.selected_version) {
                (Some(url), None) => format!("{url}latest/download/release.json"),
                (Some(url), Some(version)) => format!("{url}download/{version}/release.json"),
                (None, version) => format!(
                    "{FIRMWARE_UPDATE_URL}{}/release.json",
                    version.as_deref().unwrap_or_default()
                ),
            };
            log(&format!(
                "Retrieving specified version info from {version_url}"
            ));
            let info_path = format!("{upd}/version_release_info.json");
            let fetched =
                download(&version_url, Path::new(&info_path)).and_then(|_| record(&info_path));
            if fetched.is_err() {
                log("Failed to retrive version information for your board.");
                log("Check your internet connection and try again.");
                log("If you don't have Internet access currently, use the --fw-version option to manually specify a version.");
                log("You can also use --extract to copy the firmware from a known-good RNode of the same model.");
                graceful_exit(0);
            }
            Ok(())
        };
        if primary.is_err() {
            log("");
            log("WARNING!");
            log("Failed to retrieve latest version information for your board from the default server.");
            log(&format!(
                "Will retry using the following fallback URL: {FALLBACK_FIRMWARE_VERSION_URL}"
            ));
            log("");
            log("Hit enter if you want to proceed");
            crate::wait_for_enter();
            let info_path = format!("{upd}/fallback_release_info.json");
            if let Err(e) = download(FALLBACK_FIRMWARE_VERSION_URL, Path::new(&info_path))
                .and_then(|_| record(&info_path))
            {
                log(&format!("Error while trying fallback URL: {e}"));
                return Err(e);
            }
        }

        let info = std::fs::read_to_string(&latest).map_err(|e| e.to_string())?;
        let mut parts = info.split_whitespace();
        let version = parts.next().unwrap_or_default().to_string();
        if version == "not" {
            log("No valid version found for this board, exiting.");
            graceful_exit(199);
        }
        self.selected_hash = Some(
            parts
                .next()
                .ok_or_else(|| "list index out of range".to_string())?
                .to_string(),
        );
        let version_dir = format!("{upd}/{version}");
        std::fs::create_dir_all(&version_dir).map_err(|e| e.to_string())?;
        std::fs::copy(&latest, format!("{version_dir}/{fw_filename}.version"))
            .map_err(|e| e.to_string())?;
        log(&format!(
            "The selected firmware for this board is version {version}"
        ));
        self.selected_version = Some(version);
        Ok(())
    }

    /// upstream's firmware package decompression into the version directory.
    pub fn decompress(&self, fw_filename: &str) -> Result<(), String> {
        let dir = self.version_dir();
        let file =
            std::fs::File::open(format!("{dir}/{fw_filename}")).map_err(|e| e.to_string())?;
        let mut archive = zip::ZipArchive::new(file).map_err(|e| e.to_string())?;
        archive.extract(&dir).map_err(|e| e.to_string())
    }
}

/// upstream `get_partition_hash`: the firmware hash a device should report
/// once `partition_file` is installed. ESP32 and AVR images end with the
/// SHA-256 of what precedes it; NRF52 images are hashed whole.
pub fn partition_hash(platform: u8, partition_file: &str) -> Option<Vec<u8>> {
    let read = || -> Result<Option<Vec<u8>>, String> {
        let data =
            std::fs::read(partition_file).map_err(|e| python_io_error(&e, partition_file))?;
        Ok(match platform {
            rom::PLATFORM_ESP32 | rom::PLATFORM_AVR => {
                if data.len() < 32 {
                    return Ok(None);
                }
                let (image, hash) = data.split_at(data.len() - 32);
                (rns_crypto::sha256::sha256(image) == hash).then(|| hash.to_vec())
            }
            rom::PLATFORM_NRF52 => Some(rns_crypto::sha256::sha256(&data).to_vec()),
            _ => None,
        })
    };
    match read() {
        Ok(hash) => hash,
        Err(e) => {
            log("Could not calculate firmware partition hash. The contained exception was:");
            log(&e);
            None
        }
    }
}

/// Python's message for a failed `open()`.
fn python_io_error(e: &std::io::Error, path: &str) -> String {
    let errno = e.raw_os_error().unwrap_or(0);
    // SAFETY: strerror returns a static string for any errno.
    let reason = unsafe { std::ffi::CStr::from_ptr(libc::strerror(errno)) }.to_string_lossy();
    format!("[Errno {errno}] {reason}: '{path}'")
}

/// What `get_flasher_call` is asked to flash with: upstream passes either a
/// platform code or, from the command line, `--platform` as given.
#[derive(Clone, Debug, PartialEq)]
pub enum FlashPlatform {
    Rom(u8),
    Named(String),
}

/// Where flashing runs and how fast.
pub struct FlashTarget<'a> {
    pub port: &'a str,
    pub baud_flash: &'a str,
}

/// upstream `get_flasher_call`: the flasher command line for `fw_filename`,
/// or `None` when no flasher matches. Exits when a needed flasher is not
/// installed, as upstream does.
pub fn flasher_call(
    firmware: &Firmware,
    platform: &FlashPlatform,
    fw_filename: &str,
    target: &FlashTarget,
) -> Option<Vec<String>> {
    let version = firmware.selected_version.clone().unwrap_or_default();
    let upd = firmware.update_dir().display().to_string();
    let version_dir = format!("{upd}/{version}");
    let missing = |flasher: &str, install: &str| -> ! {
        log("");
        log(&format!(
            "You do not currently have the \"{flasher}\" program installed on your system."
        ));
        log("Unfortunately, that means we can't proceed, since it is needed to flash your");
        log("board. You can install it via your package manager, for example:");
        log("");
        log(&format!("  {install}"));
        log("");
        log(&format!("Please install \"{flasher}\" and try again."));
        graceful_exit(0);
    };
    let strings = |parts: &[&str]| parts.iter().map(|s| s.to_string()).collect::<Vec<_>>();

    match platform {
        FlashPlatform::Named(name) if name == "unzip" => {
            if which("unzip").is_none() {
                missing("unzip", "sudo apt install unzip");
            }
            Some(strings(&[
                "unzip",
                "-o",
                &format!("{version_dir}/{fw_filename}"),
                "-d",
                &version_dir,
            ]))
        }
        FlashPlatform::Named(_) => None,
        FlashPlatform::Rom(rom::PLATFORM_AVR) => {
            if which("avrdude").is_none() {
                missing("avrdude", "sudo apt install avrdude");
            }
            match fw_filename {
                "rnode_firmware.hex" => Some(strings(&[
                    "avrdude",
                    "-P",
                    target.port,
                    "-p",
                    "m1284p",
                    "-c",
                    "arduino",
                    "-b",
                    "115200",
                    "-U",
                    &format!("flash:w:{version_dir}/{fw_filename}:i"),
                ])),
                "rnode_firmware_m2560.hex" => Some(strings(&[
                    "avrdude",
                    "-P",
                    target.port,
                    "-p",
                    "atmega2560",
                    "-c",
                    "wiring",
                    "-D",
                    "-b",
                    "115200",
                    "-U",
                    &format!("flash:w:{version_dir}/{fw_filename}"),
                ])),
                _ => None,
            }
        }
        FlashPlatform::Rom(rom::PLATFORM_ESP32) => {
            esp32_flasher_call(firmware, fw_filename, target, &version_dir, &version)
        }
        FlashPlatform::Rom(rom::PLATFORM_NRF52) => {
            if which("adafruit-nrfutil").is_none() {
                missing("adafruit-nrfutil", "pip3 install --user adafruit-nrfutil");
            }
            Some(strings(&[
                "adafruit-nrfutil",
                "dfu",
                "serial",
                "--package",
                &format!("{version_dir}/{fw_filename}"),
                "-p",
                target.port,
                "-b",
                "115200",
                "-t",
                "1200",
            ]))
        }
        FlashPlatform::Rom(_) => None,
    }
}

/// How one ESP32 firmware package is flashed.
struct Esp32Layout {
    /// The package.
    package: &'static str,
    /// The image files' common name.
    files: &'static str,
    chip: &'static str,
    flash_size: &'static str,
    /// Whether the console image is flashed: from which version, if not
    /// always.
    console_from: Option<f64>,
    /// The files and console rule used before `console_from`, if they
    /// differ.
    older_files: Option<&'static str>,
}

const fn esp32(
    package: &'static str,
    chip: &'static str,
    flash_size: &'static str,
    console_from: Option<f64>,
) -> Esp32Layout {
    Esp32Layout {
        package,
        files: package,
        chip,
        flash_size,
        console_from,
        older_files: None,
    }
}

/// upstream's ESP32 packages. The bootloader goes to 0x0 on ESP32-S3
/// chips and 0x1000 on the others.
const ESP32_LAYOUTS: &[Esp32Layout] = &[
    esp32("rnode_firmware_tbeam", "esp32", "4MB", Some(1.55)),
    Esp32Layout {
        older_files: Some("rnode_firmware_tbeam"),
        ..esp32("rnode_firmware_tbeam_sx1262", "esp32", "4MB", Some(1.55))
    },
    Esp32Layout {
        older_files: Some("rnode_firmware_lora32v20"),
        ..esp32("rnode_firmware_lora32v10", "esp32", "4MB", Some(1.59))
    },
    esp32("rnode_firmware_lora32v20", "esp32", "4MB", Some(1.55)),
    esp32("rnode_firmware_lora32v21", "esp32", "4MB", Some(1.55)),
    esp32("rnode_firmware_lora32v21_tcxo", "esp32", "4MB", None),
    esp32("rnode_firmware_heltec32v2", "esp32", "8MB", Some(1.55)),
    esp32("rnode_firmware_heltec32v3", "esp32-s3", "8MB", None),
    esp32("rnode_firmware_heltec32v4pa", "esp32-s3", "16MB", None),
    esp32("rnode_firmware_featheresp32", "esp32", "4MB", Some(1.55)),
    esp32("rnode_firmware_esp32_generic", "esp32", "4MB", Some(1.55)),
    esp32("rnode_firmware_ng20", "esp32", "4MB", Some(1.55)),
    esp32("rnode_firmware_ng21", "esp32", "4MB", Some(1.55)),
    esp32("rnode_firmware_t3s3", "esp32s3", "4MB", None),
    esp32("rnode_firmware_t3s3_sx127x", "esp32s3", "4MB", None),
    esp32("rnode_firmware_t3s3_sx1280_pa", "esp32s3", "4MB", None),
    esp32("rnode_firmware_tbeam_supreme", "esp32s3", "4MB", None),
    esp32("rnode_firmware_tdeck", "esp32s3", "4MB", None),
    esp32("rnode_firmware_xiao_esp32s3", "esp32s3", "8MB", None),
];

fn esp32_flasher_call(
    firmware: &Firmware,
    fw_filename: &str,
    target: &FlashTarget,
    version_dir: &str,
    version: &str,
) -> Option<Vec<String>> {
    // upstream converts the version with float(), which --fw-version has
    // already been checked against.
    let numeric_version: f64 = version.trim().parse().unwrap_or(0.0);
    let flasher = format!("{version_dir}/esptool.py");
    if !Path::new(&flasher).is_file() {
        let recovery = firmware.config_dir.join("recovery_esptool.py");
        if recovery.is_file() {
            let _ = std::fs::create_dir_all(version_dir);
            if std::fs::copy(&recovery, &flasher).is_ok() {
                log("No flasher present, using recovery flasher to write firmware to device");
            }
        }
    }
    if Path::new(&flasher).is_file() {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&flasher, std::fs::Permissions::from_mode(0o750));
    }
    let mut call: Vec<String> = vec![python(), flasher.clone()];
    if which(&flasher).is_none() {
        // Without a packaged or recovery esptool, an installed one.
        let Some(installed) = installed_esptool() else {
            log("");
            log(&format!(
                "You do not currently have the \"{flasher}\" program installed on your system."
            ));
            log("Unfortunately, that means we can't proceed, since it is needed to flash your");
            log("board. You can install it via your package manager, for example:");
            log("");
            log("  sudo apt install esptool");
            log("");
            log(&format!("Please install \"{flasher}\" and try again."));
            graceful_exit(0);
        };
        call = vec![installed.display().to_string()];
    }

    let head = |chip: &str, size: &str| -> Vec<String> {
        [
            "--chip",
            chip,
            "--port",
            target.port,
            "--baud",
            target.baud_flash,
            "--before",
            "default_reset",
            "--after",
            "hard_reset",
            "write_flash",
            "-z",
            "--flash_mode",
            "dio",
            "--flash_freq",
            "80m",
            "--flash_size",
            size,
        ]
        .iter()
        .map(|s| s.to_string())
        .collect()
    };

    if fw_filename == EXTRACTED {
        let ext = firmware.extracted_dir().display().to_string();
        call.extend(head("esp32", "4MB"));
        for (offset, file) in [
            ("0x1000", "extracted_rnode_firmware.bootloader"),
            ("0xe000", "extracted_rnode_firmware.boot_app0"),
            ("0x8000", "extracted_rnode_firmware.partitions"),
            ("0x10000", "extracted_rnode_firmware.bin"),
            ("0x210000", "extracted_console_image.bin"),
        ] {
            call.push(offset.to_string());
            call.push(format!("{ext}/{file}"));
        }
        return Some(call);
    }

    let Some(layout) = ESP32_LAYOUTS
        .iter()
        .find(|l| fw_filename.strip_suffix(".zip") == Some(l.package))
    else {
        log("No flasher available for this board, cannot install firmware.");
        return None;
    };
    let current = layout
        .console_from
        .is_none_or(|from| numeric_version >= from);
    let files = if current {
        layout.files
    } else {
        layout.older_files.unwrap_or(layout.files)
    };
    let bootloader_offset = if layout.chip == "esp32" {
        "0x1000"
    } else {
        "0x0"
    };
    call.extend(head(layout.chip, layout.flash_size));
    let mut images = vec![
        ("0xe000", format!("{version_dir}/{files}.boot_app0")),
        (
            bootloader_offset,
            format!("{version_dir}/{files}.bootloader"),
        ),
        ("0x10000", format!("{version_dir}/{files}.bin")),
    ];
    if current {
        images.push(("0x210000", format!("{version_dir}/console_image.bin")));
    }
    images.push(("0x8000", format!("{version_dir}/{files}.partitions")));
    for (offset, file) in images {
        call.push(offset.to_string());
        call.push(file);
    }
    Some(call)
}

/// The esptool `-e` reads a device's flash with, as a command prefix:
/// upstream's recovery esptool if an upstream extraction left it in the
/// configuration directory, else an installed `esptool.py` or `esptool`.
/// Upstream carries the recovery esptool inside its own source; it is
/// GPL-2.0 licensed, so it is not bundled here.
pub fn extraction_esptool(config_dir: &Path) -> Option<Vec<String>> {
    let recovery = config_dir.join("recovery_esptool.py");
    if recovery.is_file() {
        return Some(vec![python(), recovery.display().to_string()]);
    }
    installed_esptool().map(|path| vec![path.display().to_string()])
}

fn installed_esptool() -> Option<PathBuf> {
    which("esptool.py").or_else(|| which("esptool"))
}

/// The Python interpreter that runs a package's `esptool.py`, where
/// upstream uses its own (`sys.executable`).
fn python() -> String {
    std::env::var("RNODECONF_PYTHON").unwrap_or_else(|_| "python3".to_string())
}

/// Python's `shutil.which`: a path is checked as given, a bare name is
/// looked up on `PATH`; either must be an executable file.
pub fn which(name: &str) -> Option<PathBuf> {
    use std::os::unix::fs::PermissionsExt;
    let executable = |path: &Path| {
        std::fs::metadata(path)
            .map(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
            .unwrap_or(false)
    };
    if name.contains('/') {
        let path = PathBuf::from(name);
        return executable(&path).then_some(path);
    }
    std::env::split_paths(&std::env::var_os("PATH")?)
        .map(|dir| dir.join(name))
        .find(|path| executable(path))
}

/// upstream `urlretrieve`: fetch `url` into `path`.
pub fn download(url: &str, path: &Path) -> Result<(), String> {
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let agent = ureq::Agent::config_builder()
        .tls_config(
            ureq::tls::TlsConfig::builder()
                .unversioned_rustls_crypto_provider(provider)
                .build(),
        )
        .http_status_as_error(false)
        .build()
        .new_agent();
    let mut response = agent
        .get(url)
        .call()
        .map_err(|e| format!("<urlopen error {e}>"))?;
    let status = response.status();
    if !status.is_success() {
        return Err(format!(
            "HTTP Error {}: {}",
            status.as_u16(),
            status.canonical_reason().unwrap_or_default()
        ));
    }
    let mut reader = response.body_mut().with_config().limit(u64::MAX).reader();
    let mut file = std::fs::File::create(path).map_err(|e| e.to_string())?;
    std::io::copy(&mut reader, &mut file).map_err(|e| e.to_string())?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn firmware(version: &str) -> Firmware {
        Firmware {
            config_dir: PathBuf::from("CNF"),
            selected_version: Some(version.to_string()),
            selected_hash: None,
            fw_url: None,
            nocheck: true,
        }
    }

    /// upstream's flasher commands, as `tests/vectors/flasher_calls.json`
    /// records them for every package, platform and version boundary.
    #[test]
    fn flasher_calls_match_upstream() {
        let dir = tempfile::tempdir().unwrap();
        let calls: serde_json::Value =
            serde_json::from_str(include_str!("../tests/vectors/flasher_calls.json")).unwrap();
        // Executables for every flasher, so none is reported missing.
        let bin = dir.path().join("bin");
        std::fs::create_dir_all(&bin).unwrap();
        for tool in ["avrdude", "adafruit-nrfutil", "unzip"] {
            let path = bin.join(tool);
            std::fs::write(&path, "").unwrap();
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        // SAFETY: tests in this module do not read the environment
        // concurrently.
        unsafe {
            std::env::set_var("PATH", &bin);
            std::env::set_var("RNODECONF_PYTHON", "PYTHON");
        }
        let target = FlashTarget {
            port: "PORT",
            baud_flash: "BAUD",
        };
        for case in calls.as_array().unwrap() {
            let version = case["version"].as_str().unwrap();
            let mut fw = firmware(version);
            fw.config_dir = dir.path().join("CNF");
            let version_dir = format!("{}/update/{version}", fw.config_dir.display());
            std::fs::create_dir_all(&version_dir).unwrap();
            std::fs::write(format!("{version_dir}/esptool.py"), "").unwrap();
            let platform = match case["platform"].as_str().unwrap() {
                "esp32" => FlashPlatform::Rom(rom::PLATFORM_ESP32),
                "avr" => FlashPlatform::Rom(rom::PLATFORM_AVR),
                _ => FlashPlatform::Rom(rom::PLATFORM_NRF52),
            };
            let file = case["file"].as_str().unwrap();
            let ours = flasher_call(&fw, &platform, file, &target).map(|call| {
                call.iter()
                    .map(|part| {
                        part.replace(&format!("{}/update", fw.config_dir.display()), "UPD")
                            .replace(&format!("{}/extracted", fw.config_dir.display()), "EXT")
                    })
                    .collect::<Vec<_>>()
            });
            let upstream: Option<Vec<String>> = case["call"].as_array().map(|parts| {
                parts
                    .iter()
                    .map(|p| p.as_str().unwrap().to_string())
                    .collect()
            });
            let ours = ours.map(|mut call| {
                if call.len() > 1 && call[1].ends_with("/esptool.py") {
                    call[1] = format!("UPD/{version}/esptool.py");
                }
                call
            });
            assert_eq!(ours, upstream, "{} {file} {version}", case["platform"]);
        }
    }
}
