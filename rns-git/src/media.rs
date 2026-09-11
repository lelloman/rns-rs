//! Optional WebP conversion for Nomad Network media responses.
//!
//! Temporary files are owned by the conversion call. The returned bytes belong
//! to the Resource, so disconnects cannot leave link-owned spool directories.
use std::ffi::OsStr;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

const TIMEOUT: Duration = Duration::from_secs(8);
static NO_BACKEND_LOGGED: AtomicBool = AtomicBool::new(false);
const BACKENDS: &[(&str, &[&str])] = &[
    ("magick", &["-", "webp:-"]),
    ("convert", &["-", "webp:-"]),
    ("gm", &["convert", "-", "webp:-"]),
    (
        "ffmpeg",
        &[
            "-y",
            "-loglevel",
            "error",
            "-i",
            "-",
            "-f",
            "webp",
            "pipe:1",
        ],
    ),
    (
        "avconv",
        &[
            "-y",
            "-loglevel",
            "error",
            "-i",
            "-",
            "-f",
            "webp",
            "pipe:1",
        ],
    ),
];

fn select_backend(
    forced: Option<&OsStr>,
    available: impl Fn(&str) -> bool,
) -> Option<(&'static str, &'static [&'static str])> {
    BACKENDS
        .iter()
        .copied()
        .find(|(name, _)| forced.is_none_or(|forced| forced == OsStr::new(name)) && available(name))
}

fn executable_available(name: &str) -> bool {
    std::env::var_os("PATH").is_some_and(|path| {
        std::env::split_paths(&path).any(|directory| {
            let path = directory.join(name);
            let Ok(metadata) = path.metadata() else {
                return false;
            };
            if !metadata.is_file() {
                return false;
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                metadata.permissions().mode() & 0o111 != 0
            }
            #[cfg(not(unix))]
            {
                true
            }
        })
    })
}

pub(crate) fn convert_to_webp(input: &[u8]) -> Option<Vec<u8>> {
    convert_with_options(
        input,
        ConversionOptions {
            quality: None,
            ..Default::default()
        },
    )
}

/// Encoding controls for standalone file conversion.
#[derive(Debug, Clone, Copy)]
pub struct ConversionOptions {
    /// Encoder quality, clamped to 1–100; None uses the encoder default.
    pub quality: Option<i32>,
    /// Preserve aspect ratio and shrink to fit; zero/None disables resizing.
    pub max_dimension: Option<u32>,
    pub timeout: Duration,
}

impl Default for ConversionOptions {
    fn default() -> Self {
        Self {
            quality: Some(85),
            max_dimension: None,
            timeout: TIMEOUT,
        }
    }
}

/// Convert a file into an owned temporary WebP file, removed when dropped.
/// The source is never modified; unavailable backends or conversion failures
/// return None. Call `persist` on the returned file to retain it permanently.
pub fn convert_file_to_webp(
    source: impl AsRef<Path>,
    options: ConversionOptions,
) -> Option<tempfile::NamedTempFile> {
    let input = std::fs::read(source).ok()?;
    let output = convert_with_options(&input, options)?;
    let mut file = tempfile::Builder::new()
        .prefix("rns_media_")
        .suffix(".webp")
        .tempfile()
        .ok()?;
    file.write_all(&output).ok()?;
    file.seek(SeekFrom::Start(0)).ok()?;
    Some(file)
}

fn configured_args(name: &str, args: &[&str], options: ConversionOptions) -> Vec<String> {
    let mut result: Vec<String> = args.iter().map(|arg| (*arg).to_owned()).collect();
    let mut extra = Vec::new();
    if let Some(quality) = options.quality {
        extra.extend(["-quality".into(), quality.clamp(1, 100).to_string()]);
    }
    let image_magick = matches!(name, "magick" | "convert" | "gm");
    if let Some(dimension) = options.max_dimension.filter(|dimension| *dimension > 0) {
        if image_magick {
            extra.extend(["-resize".into(), format!("{dimension}x{dimension}>")]);
        } else {
            extra.extend(["-vf".into(), format!("scale='min(iw,{dimension})':'min(ih,{dimension})':force_original_aspect_ratio=decrease")]);
        }
    }
    let index = if image_magick {
        result.len() - 1
    } else {
        result
            .iter()
            .position(|arg| arg == "-f")
            .unwrap_or(result.len())
    };
    result.splice(index..index, extra);
    result
}

fn convert_with_options(input: &[u8], options: ConversionOptions) -> Option<Vec<u8>> {
    let forced = std::env::var_os("RNGIT_MEDIA_BACKEND").filter(|value| !value.is_empty());
    let Some((name, args)) = select_backend(forced.as_deref(), executable_available) else {
        if !NO_BACKEND_LOGGED.swap(true, Ordering::Relaxed) {
            log::warn!("No WebP encoding backend available; install ImageMagick or ffmpeg to enable media conversion");
        }
        return None;
    };
    NO_BACKEND_LOGGED.store(false, Ordering::Relaxed);
    match convert(
        input,
        Command::new(name).args(configured_args(name, args, options)),
        options.timeout,
    ) {
        Ok(output) => Some(output),
        Err(err) => {
            log::warn!("Media conversion via {name} failed: {err}; serving original media");
            None
        }
    }
}

fn convert(input: &[u8], command: &mut Command, timeout: Duration) -> crate::Result<Vec<u8>> {
    let mut source = tempfile::tempfile()?;
    source.write_all(input)?;
    source.seek(SeekFrom::Start(0))?;
    let mut output = tempfile::tempfile()?;
    let mut error = tempfile::tempfile()?;
    let mut child = command
        .stdin(Stdio::from(source))
        .stdout(Stdio::from(output.try_clone()?))
        .stderr(Stdio::from(error.try_clone()?))
        .spawn()?;
    let deadline = Instant::now() + timeout;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(10)),
            result => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(crate::Error::msg(match result {
                    Err(err) => err.to_string(),
                    _ => "media conversion timed out".into(),
                }));
            }
        }
    };
    if !status.success() {
        error.seek(SeekFrom::Start(0))?;
        let mut details = Vec::new();
        error.take(1024).read_to_end(&mut details)?;
        return Err(crate::Error::msg(format!(
            "{status}: {}",
            String::from_utf8_lossy(&details)
        )));
    }
    output.seek(SeekFrom::Start(0))?;
    let mut bytes = Vec::new();
    output.read_to_end(&mut bytes)?;
    if webp_dimensions(&bytes).is_none() {
        return Err(crate::Error::msg("invalid WebP output"));
    }
    Ok(bytes)
}

fn webp_dimensions(data: &[u8]) -> Option<(u32, u32)> {
    if data.len() < 30 || &data[..4] != b"RIFF" || &data[8..12] != b"WEBP" {
        return None;
    }
    let (width, height) = match &data[12..16] {
        b"VP8X" => (
            u32::from_le_bytes([data[24], data[25], data[26], 0]) + 1,
            u32::from_le_bytes([data[27], data[28], data[29], 0]) + 1,
        ),
        b"VP8 " => (
            (u16::from_le_bytes([data[26], data[27]]) & 0x3fff) as u32,
            (u16::from_le_bytes([data[28], data[29]]) & 0x3fff) as u32,
        ),
        b"VP8L" => {
            let bits = u32::from_le_bytes(data[21..25].try_into().ok()?);
            ((bits & 0x3fff) + 1, ((bits >> 14) & 0x3fff) + 1)
        }
        _ => return None,
    };
    (width > 0 && height > 0).then_some((width, height))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backend_options_clamp_quality_and_disable_zero_resize() {
        for (name, args) in BACKENDS {
            let configured = configured_args(
                name,
                args,
                ConversionOptions {
                    quality: Some(200),
                    max_dimension: Some(0),
                    ..Default::default()
                },
            );
            assert!(configured
                .windows(2)
                .any(|pair| pair == ["-quality", "100"]));
            assert!(!configured
                .iter()
                .any(|arg| arg == "-resize" || arg == "-vf"));
            let configured = configured_args(
                name,
                args,
                ConversionOptions {
                    quality: Some(-5),
                    max_dimension: Some(640),
                    ..Default::default()
                },
            );
            assert!(configured.windows(2).any(|pair| pair == ["-quality", "1"]));
            assert!(configured.iter().any(|arg| arg.contains("640")));
            assert_eq!(configured.last().unwrap(), args.last().unwrap());
        }
    }

    #[test]
    #[ignore = "requires an installed WebP backend"]
    fn file_conversion_resizes_without_upscaling_and_owns_cleanup() {
        let mut source = tempfile::NamedTempFile::new().unwrap();
        let pixels =
            b"P6\n4 2\n255\n\xff\0\0\0\xff\0\xff\0\0\0\xff\0\xff\0\0\0\xff\0\xff\0\0\0\xff\0";
        source.write_all(pixels).unwrap();
        for (limit, dimensions) in [(2, (2, 1)), (8, (4, 2))] {
            let output = convert_file_to_webp(
                source.path(),
                ConversionOptions {
                    max_dimension: Some(limit),
                    ..Default::default()
                },
            )
            .unwrap();
            let path = output.path().to_owned();
            assert_eq!(
                webp_dimensions(&std::fs::read(&path).unwrap()),
                Some(dimensions)
            );
            drop(output);
            assert!(!path.exists());
            assert_eq!(std::fs::read(source.path()).unwrap(), pixels);
        }
        std::fs::write(source.path(), b"not an image").unwrap();
        assert!(convert_file_to_webp(source.path(), Default::default()).is_none());
        assert!(convert_file_to_webp(source.path().join("missing"), Default::default()).is_none());
    }

    #[test]
    fn backend_preference_and_forced_selection() {
        assert_eq!(select_backend(None, |_| true).unwrap().0, "magick");
        assert_eq!(
            select_backend(None, |name| name == "ffmpeg").unwrap().0,
            "ffmpeg"
        );
        assert_eq!(
            select_backend(Some(OsStr::new("gm")), |_| true).unwrap().0,
            "gm"
        );
        assert!(select_backend(Some(OsStr::new("unknown")), |_| true).is_none());
        assert!(select_backend(Some(OsStr::new("magick")), |name| name == "convert").is_none());
    }

    #[test]
    fn validates_all_webp_headers_and_rejects_invalid_output() {
        let mut bytes = vec![0; 30];
        bytes[..4].copy_from_slice(b"RIFF");
        bytes[8..12].copy_from_slice(b"WEBP");
        for header in [b"VP8X", b"VP8L"] {
            bytes[12..16].copy_from_slice(header);
            assert_eq!(webp_dimensions(&bytes), Some((1, 1)));
        }
        bytes[12..16].copy_from_slice(b"VP8 ");
        assert_eq!(webp_dimensions(&bytes), None);
        bytes[26] = 2;
        bytes[28] = 3;
        assert_eq!(webp_dimensions(&bytes), Some((2, 3)));
        assert_eq!(webp_dimensions(&bytes[..29]), None);
        bytes[0] = 0;
        assert_eq!(webp_dimensions(&bytes), None);
    }

    #[test]
    fn conversion_rejects_invalid_output_failure_and_timeout() {
        assert!(convert(b"invalid", &mut Command::new("cat"), TIMEOUT).is_err());
        assert!(convert(b"", &mut Command::new("false"), TIMEOUT).is_err());
        let start = Instant::now();
        assert!(convert(
            b"",
            Command::new("sleep").arg("5"),
            Duration::from_millis(30)
        )
        .unwrap_err()
        .to_string()
        .contains("timed out"));
        assert!(start.elapsed() < Duration::from_secs(1));
    }

    #[test]
    #[ignore = "requires an installed WebP backend"]
    fn real_backend_converts_pixels() {
        let pixels = b"P6\n2 1\n255\n\xff\0\0\0\xff\0";
        let output = convert_to_webp(pixels).expect("available backend must convert pixels");
        assert_eq!(webp_dimensions(&output), Some((2, 1)));
    }
}
