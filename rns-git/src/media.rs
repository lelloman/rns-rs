//! Optional WebP conversion for Nomad Network media responses.
//!
//! Temporary files are owned by the conversion call. The returned bytes belong
//! to the Resource, so disconnects cannot leave link-owned spool directories.
//!
//! As upstream's `media.py` since 840eb369, only input whose first bytes are a
//! PNG, JPEG, GIF, TIFF, WebP or BMP signature reaches an encoder, ImageMagick
//! and GraphicsMagick are told that format explicitly (`png:-` rather than
//! `-`, with which they would detect any format they know), and input larger
//! than [`CONV_SIZE_MAX`] is not converted.
use std::ffi::OsStr;
use std::fs::File;
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

/// File extensions served as images and offered for conversion (upstream's
/// `SUPPORTED_IMAGE_EXTS`), lowercase with the leading dot.
pub const SUPPORTED_IMAGE_EXTS: &[&str] = &[
    ".webp", ".png", ".jpg", ".jpeg", ".gif", ".tiff", ".tif", ".bmp",
];

/// The largest input, in bytes, that is converted (upstream's
/// `CONV_SIZE_MAX`); larger media is served unconverted.
pub const CONV_SIZE_MAX: usize = 32 * 1024 * 1024;

/// How many leading bytes classify the input (upstream's `SNIFF_BYTES`).
const SNIFF_BYTES: usize = 64;

fn is_bmp_header(data: &[u8]) -> bool {
    let Some(header) = data.first_chunk::<18>() else {
        return false;
    };
    if &header[..2] != b"BM" {
        return false;
    }
    let dib_size = u32::from_le_bytes([header[14], header[15], header[16], header[17]]);
    matches!(dib_size, 12 | 40 | 52 | 56 | 64 | 108 | 124)
}

type Signature = fn(&[u8]) -> bool;

/// Upstream's `_IMAGE_SIGNATURES`, checked in this order.
const IMAGE_SIGNATURES: &[(&str, Signature)] = &[
    ("png", |data| data.starts_with(b"\x89PNG\r\n\x1a\n")),
    ("jpeg", |data| data.starts_with(b"\xff\xd8\xff")),
    ("gif", |data| {
        data.starts_with(b"GIF87a") || data.starts_with(b"GIF89a")
    }),
    ("tiff", |data| {
        data.starts_with(b"II*\0") || data.starts_with(b"MM\0*")
    }),
    ("webp", |data| webp_dimensions(data).is_some()),
    ("bmp", is_bmp_header),
];

/// The image format whose signature `data` starts with: `png`, `jpeg`, `gif`,
/// `tiff`, `webp` or `bmp`, or `None` for anything else (upstream's
/// `detect_image_format`). The name is also the encoder's input coder.
pub fn detect_image_format(data: &[u8]) -> Option<&'static str> {
    IMAGE_SIGNATURES
        .iter()
        .find(|(_, matches)| matches(data))
        .map(|(name, _)| *name)
}

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

/// An encoder backend: its name, its argument template and the command that
/// runs it (the executable of that name, or a stand-in in tests).
struct Backend {
    name: &'static str,
    args: &'static [&'static str],
    command: Command,
}

fn available_backend() -> Option<Backend> {
    let forced = std::env::var_os("RNGIT_MEDIA_BACKEND").filter(|value| !value.is_empty());
    let Some((name, args)) = select_backend(forced.as_deref(), executable_available) else {
        if !NO_BACKEND_LOGGED.swap(true, Ordering::Relaxed) {
            log::warn!("No WebP encoding backend available; install ImageMagick or ffmpeg to enable media conversion");
        }
        return None;
    };
    NO_BACKEND_LOGGED.store(false, Ordering::Relaxed);
    Some(Backend {
        name,
        args,
        command: Command::new(name),
    })
}

pub(crate) fn convert_to_webp(input: &[u8]) -> Option<Vec<u8>> {
    let backend = available_backend()?;
    convert_bytes(
        input,
        ConversionOptions {
            quality: None,
            ..Default::default()
        },
        backend,
    )
}

/// Encoding controls for standalone file conversion.
#[derive(Debug, Clone, Copy)]
pub struct ConversionOptions {
    /// Encoder quality, clamped to 1–100; None uses the encoder default.
    pub quality: Option<i32>,
    /// Preserve aspect ratio and shrink to fit; zero/None disables resizing.
    pub max_dimension: Option<u32>,
    /// How long the conversion process may run before it is killed and the
    /// conversion fails. Defaults to 8 seconds.
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
/// The source is never modified. Unavailable backends, a source larger than
/// [`CONV_SIZE_MAX`] or not starting with a supported image signature (see
/// [`detect_image_format`]), and conversion failures return None. Call
/// `persist` on the returned file to retain it permanently.
pub fn convert_file_to_webp(
    source: impl AsRef<Path>,
    options: ConversionOptions,
) -> Option<tempfile::NamedTempFile> {
    let backend = available_backend()?;
    convert_file(source.as_ref(), options, backend)
}

fn configured_args(
    name: &str,
    args: &[&str],
    options: ConversionOptions,
    input_spec: Option<&str>,
) -> Vec<String> {
    let mut result: Vec<String> = args.iter().map(|arg| (*arg).to_owned()).collect();
    let mut extra = Vec::new();
    if let Some(quality) = options.quality {
        extra.extend(["-quality".into(), quality.clamp(1, 100).to_string()]);
    }
    let image_magick = matches!(name, "magick" | "convert" | "gm");
    // Only ImageMagick and GraphicsMagick take the explicit input coder, in
    // place of their first `-`; ffmpeg and avconv keep `-i -`.
    if let Some(input_spec) = input_spec.filter(|_| image_magick) {
        if let Some(input) = result.iter_mut().find(|arg| *arg == "-") {
            *input = input_spec.to_owned();
        }
    }
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

/// Upstream's `convert_to_webp`, for input already in memory: classify the
/// leading bytes, refuse oversized input, then encode with the detected coder.
fn convert_bytes(input: &[u8], options: ConversionOptions, backend: Backend) -> Option<Vec<u8>> {
    let deadline = Instant::now() + options.timeout;
    let Some(format) = detect_image_format(input.get(..SNIFF_BYTES).unwrap_or(input)) else {
        log::debug!("Media conversion failed: Input format is not supported");
        return None;
    };
    // Upstream stops relaying once more than CONV_SIZE_MAX bytes have passed;
    // the whole input is at hand here, so it is refused before encoding.
    if input.len() > CONV_SIZE_MAX {
        log::debug!(
            "Media conversion failed: Streaming input exceeded maximum size of {}",
            prettysize(CONV_SIZE_MAX as f64)
        );
        return None;
    }
    let Backend {
        name,
        args,
        mut command,
    } = backend;
    command.args(configured_args(
        name,
        args,
        options,
        Some(&format!("{format}:-")),
    ));
    match encode_bytes(input, &mut command, deadline) {
        Ok(Ok(bytes)) if webp_dimensions(&bytes).is_some() => {
            log::debug!("Media converted to WebP with {name}");
            Some(bytes)
        }
        Ok(Ok(_)) => {
            log::warn!("Media conversion via {name} produced invalid WebP output");
            None
        }
        Ok(Err((failure, timeout))) => {
            // Upstream's encoder waits for what is left of the deadline, a
            // Python float, and reports that.
            failure.log(name, &prettytime(timeout.as_secs_f64(), false));
            None
        }
        Err(err) => {
            log::warn!("Error during media conversion: {err}");
            None
        }
    }
}

type EncodeResult = std::io::Result<Result<Vec<u8>, (EncoderFailure, Duration)>>;

fn encode_bytes(input: &[u8], command: &mut Command, deadline: Instant) -> EncodeResult {
    let mut source = tempfile::tempfile()?;
    source.write_all(input)?;
    source.seek(SeekFrom::Start(0))?;
    let mut output = tempfile::tempfile()?;
    let timeout = deadline.saturating_duration_since(Instant::now());
    if let Err(failure) = run_encoder(command, source, &output, timeout) {
        return Ok(Err((failure, timeout)));
    }
    output.seek(SeekFrom::Start(0))?;
    let mut bytes = Vec::new();
    output.read_to_end(&mut bytes)?;
    Ok(Ok(bytes))
}

/// Upstream's `convert_file_to_webp`: the encoder reads the source file itself
/// once its size and leading bytes are accepted.
fn convert_file(
    source: &Path,
    options: ConversionOptions,
    backend: Backend,
) -> Option<tempfile::NamedTempFile> {
    match try_convert_file(source, options, backend) {
        Ok(output) => output,
        Err(err) => {
            log::warn!("Error during media conversion: {err}");
            None
        }
    }
}

fn try_convert_file(
    source: &Path,
    options: ConversionOptions,
    backend: Backend,
) -> std::io::Result<Option<tempfile::NamedTempFile>> {
    if !source.is_file() {
        log::warn!(
            "Cannot convert media: Source file does not exist: {}",
            source.display()
        );
        return Ok(None);
    }
    if source
        .metadata()
        .is_ok_and(|metadata| metadata.len() > CONV_SIZE_MAX as u64)
    {
        log::debug!(
            "Cannot convert media: Source file exceeds maximum size of {}",
            prettysize(CONV_SIZE_MAX as f64)
        );
        return Ok(None);
    }
    let mut output = tempfile::Builder::new()
        .prefix("rns_media_")
        .suffix(".webp")
        .tempfile()?;
    let mut input = File::open(source)?;
    let mut prefix = Vec::with_capacity(SNIFF_BYTES);
    (&mut input)
        .take(SNIFF_BYTES as u64)
        .read_to_end(&mut prefix)?;
    let Some(format) = detect_image_format(&prefix) else {
        log::debug!("Cannot convert media: Source file is not a supported media format");
        return Ok(None);
    };
    let Backend {
        name,
        args,
        mut command,
    } = backend;
    command.args(configured_args(
        name,
        args,
        options,
        Some(&format!("{format}:-")),
    ));
    input.seek(SeekFrom::Start(0))?;
    if let Err(failure) = run_encoder(&mut command, input, output.as_file(), options.timeout) {
        // Upstream's default timeout is the Python int 8.
        let timeout = options.timeout;
        failure.log(
            name,
            &prettytime(timeout.as_secs_f64(), timeout.subsec_nanos() == 0),
        );
        return Ok(None);
    }
    output.seek(SeekFrom::Start(0))?;
    let mut header = Vec::with_capacity(30);
    output.as_file_mut().take(30).read_to_end(&mut header)?;
    if webp_dimensions(&header).is_none() {
        log::warn!("Invalid media conversion output from {name}");
        return Ok(None);
    }
    log::debug!("Media converted to WebP with {name}");
    output.seek(SeekFrom::Start(0))?;
    Ok(Some(output))
}

/// Why an encoder run failed, logged as upstream's `_await` logs it.
#[derive(Debug)]
enum EncoderFailure {
    TimedOut,
    /// A non-zero exit, with the start of the encoder's standard error.
    Failed(String),
    Error(std::io::Error),
}

impl From<std::io::Error> for EncoderFailure {
    fn from(err: std::io::Error) -> Self {
        EncoderFailure::Error(err)
    }
}

impl EncoderFailure {
    fn message(&self, name: &str, timeout: &str) -> String {
        match self {
            EncoderFailure::TimedOut => {
                format!("Media conversion via {name} timed out after {timeout}")
            }
            EncoderFailure::Failed(stderr) if stderr.is_empty() => {
                format!("Media conversion via {name} failed.")
            }
            EncoderFailure::Failed(stderr) => {
                format!("Media conversion via {name} failed. Encoder: {stderr}")
            }
            EncoderFailure::Error(err) => format!("Error during media conversion: {err}"),
        }
    }

    fn log(&self, name: &str, timeout: &str) {
        log::warn!("{}", self.message(name, timeout));
    }
}

fn run_encoder(
    command: &mut Command,
    input: File,
    output: &File,
    timeout: Duration,
) -> Result<(), EncoderFailure> {
    let mut error = tempfile::tempfile()?;
    let mut child = command
        .stdin(Stdio::from(input))
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
                return Err(match result {
                    Err(err) => EncoderFailure::Error(err),
                    _ => EncoderFailure::TimedOut,
                });
            }
        }
    };
    if !status.success() {
        error.seek(SeekFrom::Start(0))?;
        let mut details = Vec::new();
        error.take(1024).read_to_end(&mut details)?;
        return Err(EncoderFailure::Failed(
            String::from_utf8_lossy(&details).trim().to_owned(),
        ));
    }
    Ok(())
}

/// `RNS.prettysize(num)`.
fn prettysize(mut num: f64) -> String {
    for unit in ["", "K", "M", "G", "T", "P", "E", "Z"] {
        if num.abs() < 1000.0 {
            return if unit.is_empty() {
                format!("{num:.0} B")
            } else {
                format!("{num:.2} {unit}B")
            };
        }
        num /= 1000.0;
    }
    format!("{num:.2}YB")
}

/// `RNS.prettytime(time)`, for a Python `int` (`integral`) or `float`.
fn prettytime(time: f64, integral: bool) -> String {
    let neg = time < 0.0;
    let mut time = time.abs();
    let days = (time / 86400.0).floor();
    time %= 86400.0;
    let hours = (time / 3600.0).floor();
    time %= 3600.0;
    let minutes = (time / 60.0).floor();
    time %= 60.0;
    let seconds = if integral {
        time.trunc()
    } else {
        (time * 100.0).round() / 100.0
    };
    let mut components = Vec::new();
    for (value, unit) in [(days, "d"), (hours, "h"), (minutes, "m")] {
        if value > 0.0 {
            components.push(format!("{value}{unit}"));
        }
    }
    if seconds > 0.0 {
        // A Python float always prints a fractional part.
        components.push(if integral || seconds.fract() != 0.0 {
            format!("{seconds}s")
        } else {
            format!("{seconds:.1}s")
        });
    }
    let text = match components.split_last() {
        None => return "0s".into(),
        Some((last, [])) => last.clone(),
        Some((last, rest)) => format!("{} and {last}", rest.join(", ")),
    };
    if neg {
        format!("-{text}")
    } else {
        text
    }
}

fn webp_dimensions(data: &[u8]) -> Option<(u32, u32)> {
    let data = data.first_chunk::<30>()?;
    if &data[..4] != b"RIFF" || &data[8..12] != b"WEBP" {
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
            let bits = u32::from_le_bytes([data[21], data[22], data[23], data[24]]);
            ((bits & 0x3fff) + 1, ((bits >> 14) & 0x3fff) + 1)
        }
        _ => return None,
    };
    (width > 0 && height > 0).then_some((width, height))
}

#[cfg(test)]
mod tests {
    use super::*;

    const PNG: &[u8] = b"\x89PNG\r\n\x1a\n";

    fn backend_args(name: &str) -> &'static [&'static str] {
        BACKENDS.iter().find(|(n, _)| *n == name).unwrap().1
    }

    /// A 1x1 VP8X WebP header, which `webp_dimensions` accepts.
    fn webp_header() -> Vec<u8> {
        let mut bytes = vec![0; 30];
        bytes[..4].copy_from_slice(b"RIFF");
        bytes[8..12].copy_from_slice(b"WEBP");
        bytes[12..16].copy_from_slice(b"VP8X");
        bytes
    }

    /// A 24-bit bottom-up BMP with a BITMAPINFOHEADER.
    fn bmp(width: u32, height: u32) -> Vec<u8> {
        let row = (width * 3 + 3) & !3;
        let mut data = Vec::new();
        data.extend(b"BM");
        data.extend((54 + row * height).to_le_bytes());
        data.extend([0; 4]);
        data.extend(54u32.to_le_bytes());
        data.extend(40u32.to_le_bytes());
        data.extend(width.to_le_bytes());
        data.extend(height.to_le_bytes());
        data.extend(1u16.to_le_bytes());
        data.extend(24u16.to_le_bytes());
        data.extend([0; 24]);
        for y in 0..height {
            for x in 0..width {
                data.extend([(x * 60) as u8, (y * 60) as u8, 0xff]);
            }
            data.extend(vec![0; (row - width * 3) as usize]);
        }
        data
    }

    /// A stand-in for the encoder `name` that records its arguments and its
    /// standard input under `dir` and prints a valid WebP header.
    fn fake_backend(name: &'static str, dir: &Path) -> Backend {
        let record = dir.join("encoder");
        std::fs::write(record.with_extension("out"), webp_header()).unwrap();
        let mut command = Command::new("sh");
        command
            .arg("-c")
            .arg(r#"printf '%s\n' "$@" > "$0.args"; cat > "$0.stdin"; cat "$0.out""#)
            .arg(record);
        Backend {
            name,
            args: backend_args(name),
            command,
        }
    }

    /// The arguments and standard input the fake encoder in `dir` got, if it
    /// ran.
    fn invocation(dir: &Path) -> Option<(Vec<String>, Vec<u8>)> {
        let args = std::fs::read_to_string(dir.join("encoder.args")).ok()?;
        let stdin = std::fs::read(dir.join("encoder.stdin")).unwrap();
        Some((args.lines().map(str::to_owned).collect(), stdin))
    }

    fn script_backend(script: &str) -> Backend {
        let mut command = Command::new("sh");
        command.arg("-c").arg(script).arg("encoder");
        Backend {
            name: "magick",
            args: backend_args("magick"),
            command,
        }
    }

    #[test]
    fn image_formats_are_classified_by_their_signatures_as_upstream() {
        let bmp_with_dib = |size: u32| {
            let mut data = bmp(1, 1);
            data[14..18].copy_from_slice(&size.to_le_bytes());
            data
        };
        let mut cases: Vec<(Vec<u8>, Option<&str>)> = vec![
            ([PNG, b"rest"].concat(), Some("png")),
            (PNG[..7].to_vec(), None),
            (b"\xff\xd8\xff\xe0".to_vec(), Some("jpeg")),
            (b"\xff\xd8".to_vec(), None),
            (b"GIF87a".to_vec(), Some("gif")),
            (b"GIF89a\x01\0".to_vec(), Some("gif")),
            (b"GIF88a".to_vec(), None),
            (b"II*\0".to_vec(), Some("tiff")),
            (b"MM\0*".to_vec(), Some("tiff")),
            (b"II\0*".to_vec(), None),
            (webp_header(), Some("webp")),
            (webp_header()[..29].to_vec(), None),
            (b"P6\n2 1\n255\n\xff\0\0\0\xff\0".to_vec(), None),
            (
                b"<svg xmlns=\"http://www.w3.org/2000/svg\"/>".to_vec(),
                None,
            ),
            (b"push graphic-context\nviewbox 0 0 1 1\n".to_vec(), None),
            (b"not an image".to_vec(), None),
            (Vec::new(), None),
        ];
        let mut zero_sized_webp = webp_header();
        zero_sized_webp[12..16].copy_from_slice(b"VP8 ");
        cases.push((zero_sized_webp, None));
        for size in [12, 40, 52, 56, 64, 108, 124] {
            cases.push((bmp_with_dib(size), Some("bmp")));
        }
        for size in [0, 16, 41, 128, 0x2800_0000] {
            cases.push((bmp_with_dib(size), None));
        }
        cases.push((bmp(1, 1)[..17].to_vec(), None));
        for (data, expected) in cases {
            assert_eq!(detect_image_format(&data), expected, "{data:?}");
        }
    }

    #[test]
    fn only_imagemagick_backends_take_the_explicit_input_coder() {
        let plain = ConversionOptions {
            quality: None,
            ..Default::default()
        };
        let configured =
            |name, options, spec| configured_args(name, backend_args(name), options, spec);
        assert_eq!(
            configured("magick", plain, Some("png:-")),
            ["png:-", "webp:-"]
        );
        assert_eq!(
            configured("convert", plain, Some("jpeg:-")),
            ["jpeg:-", "webp:-"]
        );
        assert_eq!(
            configured("gm", plain, Some("gif:-")),
            ["convert", "gif:-", "webp:-"]
        );
        assert_eq!(
            configured(
                "magick",
                ConversionOptions {
                    max_dimension: Some(640),
                    ..Default::default()
                },
                Some("bmp:-")
            ),
            ["bmp:-", "-quality", "85", "-resize", "640x640>", "webp:-"]
        );
        for name in ["ffmpeg", "avconv"] {
            let configured = configured(name, plain, Some("tiff:-"));
            assert_eq!(configured, backend_args(name));
            assert!(configured.windows(2).any(|pair| pair == ["-i", "-"]));
        }
    }

    #[test]
    fn input_that_is_not_a_supported_image_never_reaches_the_encoder() {
        let mut bad_dib = bmp(1, 1);
        bad_dib[14] = 41;
        let inputs: [&[u8]; 5] = [
            b"not an image",
            b"P6\n2 1\n255\n\xff\0\0\0\xff\0",
            b"<svg xmlns=\"http://www.w3.org/2000/svg\"/>",
            b"push graphic-context\nviewbox 0 0 1 1\n",
            &bad_dib,
        ];
        for input in inputs {
            let dir = tempfile::tempdir().unwrap();
            assert!(convert_bytes(
                input,
                Default::default(),
                fake_backend("magick", dir.path())
            )
            .is_none());
            assert!(invocation(dir.path()).is_none());

            let source = dir.path().join("image.png");
            std::fs::write(&source, input).unwrap();
            assert!(convert_file(
                &source,
                Default::default(),
                fake_backend("magick", dir.path())
            )
            .is_none());
            assert!(invocation(dir.path()).is_none());
        }
    }

    #[test]
    fn input_over_the_size_cap_never_reaches_the_encoder() {
        let mut input = PNG.to_vec();
        input.resize(CONV_SIZE_MAX + 1, 0);
        let dir = tempfile::tempdir().unwrap();
        assert!(convert_bytes(
            &input,
            Default::default(),
            fake_backend("magick", dir.path())
        )
        .is_none());
        assert!(invocation(dir.path()).is_none());
        input.truncate(CONV_SIZE_MAX);
        assert!(convert_bytes(
            &input,
            Default::default(),
            fake_backend("magick", dir.path())
        )
        .is_some());
        assert_eq!(invocation(dir.path()).unwrap().1.len(), CONV_SIZE_MAX);

        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("image.png");
        let file = File::create(&source).unwrap();
        (&file).write_all(PNG).unwrap();
        file.set_len(CONV_SIZE_MAX as u64 + 1).unwrap();
        assert!(convert_file(
            &source,
            Default::default(),
            fake_backend("magick", dir.path())
        )
        .is_none());
        assert!(invocation(dir.path()).is_none());
        file.set_len(CONV_SIZE_MAX as u64).unwrap();
        assert!(convert_file(
            &source,
            Default::default(),
            fake_backend("magick", dir.path())
        )
        .is_some());
        assert_eq!(invocation(dir.path()).unwrap().1.len(), CONV_SIZE_MAX);
    }

    #[test]
    fn a_supported_image_reaches_the_encoder_whole_with_its_coder() {
        // Longer than the sniffed prefix, so the whole file must be read again.
        let input = bmp(8, 4);
        assert!(input.len() > SNIFF_BYTES);
        for (name, coder) in [
            ("magick", Some(0)),
            ("convert", Some(0)),
            ("gm", Some(1)),
            ("ffmpeg", None),
            ("avconv", None),
        ] {
            let dir = tempfile::tempdir().unwrap();
            let output = convert_bytes(
                &input,
                ConversionOptions {
                    quality: None,
                    ..Default::default()
                },
                fake_backend(name, dir.path()),
            );
            assert_eq!(output, Some(webp_header()));
            let (args, stdin) = invocation(dir.path()).unwrap();
            assert_eq!(stdin, input);
            match coder {
                Some(index) => assert_eq!(args[index], "bmp:-", "{name}: {args:?}"),
                None => assert_eq!(args, backend_args(name), "{name}"),
            }

            let dir = tempfile::tempdir().unwrap();
            let source = dir.path().join("image.bmp");
            std::fs::write(&source, &input).unwrap();
            let output =
                convert_file(&source, Default::default(), fake_backend(name, dir.path())).unwrap();
            assert_eq!(std::fs::read(output.path()).unwrap(), webp_header());
            let (args, stdin) = invocation(dir.path()).unwrap();
            assert_eq!(stdin, input);
            assert!(args.windows(2).any(|pair| pair == ["-quality", "85"]));
            match coder {
                Some(index) => assert_eq!(args[index], "bmp:-", "{name}: {args:?}"),
                None => assert!(!args.iter().any(|arg| arg.contains("bmp"))),
            }
            assert_eq!(std::fs::read(&source).unwrap(), input);
        }
    }

    #[test]
    fn encoder_failures_and_invalid_output_are_not_converted() {
        let png = [PNG, b"rest"].concat();
        let echo = || script_backend("cat");
        assert!(convert_bytes(&png, Default::default(), echo()).is_none());
        assert!(convert_bytes(&png, Default::default(), script_backend("exit 1")).is_none());
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("image.png");
        std::fs::write(&source, &png).unwrap();
        assert!(convert_file(&source, Default::default(), echo()).is_none());
        assert!(
            convert_file(&dir.path().join("missing.png"), Default::default(), echo()).is_none()
        );
        let start = Instant::now();
        let options = ConversionOptions {
            timeout: Duration::from_millis(30),
            ..Default::default()
        };
        assert!(convert_bytes(&png, options, script_backend("sleep 5")).is_none());
        assert!(convert_file(&source, options, script_backend("sleep 5")).is_none());
        assert!(start.elapsed() < Duration::from_secs(2));
    }

    #[test]
    fn encoder_runs_report_exit_status_and_timeout() {
        let output = tempfile::tempfile().unwrap();
        let input = || tempfile::tempfile().unwrap();
        assert!(run_encoder(&mut Command::new("cat"), input(), &output, TIMEOUT).is_ok());
        assert!(matches!(
            run_encoder(
                Command::new("sh").args(["-c", "echo ' boom ' >&2; exit 3"]),
                input(),
                &output,
                TIMEOUT
            ),
            Err(EncoderFailure::Failed(stderr)) if stderr == "boom"
        ));
        assert!(matches!(
            run_encoder(&mut Command::new("false"), input(), &output, TIMEOUT),
            Err(EncoderFailure::Failed(stderr)) if stderr.is_empty()
        ));
        let start = Instant::now();
        assert!(matches!(
            run_encoder(
                Command::new("sleep").arg("5"),
                input(),
                &output,
                Duration::from_millis(30)
            ),
            Err(EncoderFailure::TimedOut)
        ));
        assert!(start.elapsed() < Duration::from_secs(1));
        assert!(matches!(
            run_encoder(
                &mut Command::new("/nonexistent/encoder"),
                input(),
                &output,
                TIMEOUT
            ),
            Err(EncoderFailure::Error(_))
        ));
    }

    #[test]
    fn failures_are_logged_with_upstreams_messages() {
        assert_eq!(prettysize(CONV_SIZE_MAX as f64), "33.55 MB");
        assert_eq!(prettysize(999.0), "999 B");
        assert_eq!(prettysize(1000.0), "1.00 KB");
        for (time, integral, expected) in [
            (8.0, true, "8s"),
            (8.0, false, "8.0s"),
            (7.994, false, "7.99s"),
            (7.996, false, "8.0s"),
            (0.0, true, "0s"),
            (0.004, false, "0s"),
            (61.5, false, "1m and 1.5s"),
            (3600.0, true, "1h"),
            (90061.25, false, "1d, 1h, 1m and 1.25s"),
        ] {
            assert_eq!(prettytime(time, integral), expected, "{time}");
        }
        assert_eq!(
            EncoderFailure::TimedOut.message("magick", "8s"),
            "Media conversion via magick timed out after 8s"
        );
        assert_eq!(
            EncoderFailure::Failed("boom".into()).message("gm", "8s"),
            "Media conversion via gm failed. Encoder: boom"
        );
        assert_eq!(
            EncoderFailure::Failed(String::new()).message("gm", "8s"),
            "Media conversion via gm failed."
        );
    }

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
                None,
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
                None,
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
        let pixels = bmp(4, 2);
        source.write_all(&pixels).unwrap();
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
    #[ignore = "requires an installed WebP backend"]
    fn real_backend_converts_pixels() {
        let output = convert_to_webp(&bmp(2, 1)).expect("available backend must convert pixels");
        assert_eq!(webp_dimensions(&output), Some((2, 1)));
    }
}
