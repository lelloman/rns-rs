use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use rns_core::msgpack::{self, Value};
use rns_crypto::identity::Identity;
use rns_crypto::sha256::sha256;

use crate::client::{decode_status, SyncClient};
use crate::config::ClientConfig;
use crate::logging;
use crate::protocol;
use crate::util::{
    default_reticulum_dir, default_rngit_dir, parse_hex_16, parse_rns_url_with_aliases,
};
use crate::{Error, Result};

pub fn main<I>(args: I) -> Result<()>
where
    I: IntoIterator<Item = String>,
{
    let options = ReleaseOptions::parse(args)?;
    let rngit_dir = options.config_dir.unwrap_or_else(default_rngit_dir);
    let rns_dir = options.rns_config_dir.or_else(default_reticulum_dir);
    let (config, created) = ClientConfig::load_or_create(rngit_dir, rns_dir)?;
    logging::init_file_logger(&config.dir.join("client_log"), config.log_level)?;
    if created {
        return Err(Error::msg(format!(
            "created default config at {}; edit it and run again",
            config.dir.join("client_config").display()
        )));
    }
    let (dest_hash, repository) =
        parse_rns_url_with_aliases(&options.remote, &config.destination_aliases)?;

    let default_signer_path = config.identity_path.clone();
    let default_package_name = repository
        .rsplit('/')
        .next()
        .filter(|name| !name.is_empty())
        .unwrap_or(&repository)
        .to_string();
    let client = SyncClient::connect(config, dest_hash)?;
    let mut transport = NetReleaseTransport { client, repository };
    run_release_command_with_defaults(
        &mut transport,
        &options.command,
        Some(default_signer_path.as_path()),
        Some(default_package_name.as_str()),
        Some(&dest_hash),
        io::stdout(),
    )
}

trait ReleaseTransport {
    fn request(&mut self, data: Vec<u8>) -> Result<Vec<u8>>;

    fn request_resource(&mut self, data: Vec<u8>) -> Result<Vec<u8>> {
        self.request(data)
    }
}

struct NetReleaseTransport {
    client: SyncClient,
    repository: String,
}

impl ReleaseTransport for NetReleaseTransport {
    fn request(&mut self, data: Vec<u8>) -> Result<Vec<u8>> {
        let response = self.client.request(
            protocol::PATH_RELEASE,
            request_with_repository(data, &self.repository)?,
        )?;
        let bytes = protocol::response_bin(&response.data)?;
        decode_status(bytes)
    }

    fn request_resource(&mut self, data: Vec<u8>) -> Result<Vec<u8>> {
        let response = self.client.request(
            protocol::PATH_RELEASE,
            request_with_repository(data, &self.repository)?,
        )?;
        if let Some(metadata) = response.metadata {
            crate::client::ensure_metadata_ok(&metadata)?;
            return Ok(response.data);
        }
        let bytes = protocol::response_bin(&response.data)?;
        decode_status(bytes)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ReleaseOptions {
    config_dir: Option<PathBuf>,
    rns_config_dir: Option<PathBuf>,
    remote: String,
    command: ReleaseCommand,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ReleaseCommand {
    List,
    View {
        tag: String,
    },
    Fetch {
        target: String,
        required_signer: Option<String>,
    },
    Create {
        tag: String,
        artifacts_dir: PathBuf,
        notes_path: Option<PathBuf>,
        signer_path: Option<PathBuf>,
        package_name: Option<String>,
    },
    Delete {
        tag: String,
        yes: bool,
    },
    Latest {
        tag: String,
        yes: bool,
    },
}

impl ReleaseOptions {
    fn parse<I>(args: I) -> Result<Self>
    where
        I: IntoIterator<Item = String>,
    {
        let mut config_dir = None;
        let mut rns_config_dir = None;
        let mut notes_path = None;
        let mut signer_path = None;
        let mut package_name = None;
        let mut yes = false;
        let mut positional = Vec::new();
        let mut args = args.into_iter();
        while let Some(arg) = args.next() {
            match arg.as_str() {
                "-c" | "--config" => {
                    config_dir = Some(PathBuf::from(
                        args.next()
                            .ok_or_else(|| Error::msg("missing config path"))?,
                    ));
                }
                "--rnsconfig" => {
                    rns_config_dir = Some(PathBuf::from(
                        args.next()
                            .ok_or_else(|| Error::msg("missing RNS config path"))?,
                    ));
                }
                "--notes" => {
                    notes_path = Some(PathBuf::from(
                        args.next()
                            .ok_or_else(|| Error::msg("missing notes path"))?,
                    ));
                }
                "-s" | "--signer" => {
                    signer_path = Some(PathBuf::from(
                        args.next()
                            .ok_or_else(|| Error::msg("missing signer identity path"))?,
                    ));
                }
                "-n" | "--name" => {
                    package_name = Some(
                        args.next()
                            .ok_or_else(|| Error::msg("missing package name"))?,
                    );
                }
                "-y" | "--yes" => yes = true,
                "-h" | "--help" => return Err(Error::msg(usage())),
                other => positional.push(other.to_string()),
            }
        }

        if positional.len() < 2 {
            return Err(Error::msg(usage()));
        }
        let remote = positional[0].clone();
        let command = match positional[1].as_str() {
            "list" => {
                if positional.len() != 2 {
                    return Err(Error::msg("release list does not take a target"));
                }
                ReleaseCommand::List
            }
            "view" => ReleaseCommand::View {
                tag: positional
                    .get(2)
                    .cloned()
                    .ok_or_else(|| Error::msg("release view requires a tag"))?,
            },
            "fetch" => ReleaseCommand::Fetch {
                target: positional
                    .get(2)
                    .cloned()
                    .ok_or_else(|| Error::msg("release fetch requires a target"))?,
                required_signer: signer_path.map(|path| path.to_string_lossy().into_owned()),
            },
            "create" => {
                parse_create_target(&positional[2..], notes_path, signer_path, package_name)?
            }
            "delete" => ReleaseCommand::Delete {
                tag: positional
                    .get(2)
                    .cloned()
                    .ok_or_else(|| Error::msg("release delete requires a tag"))?,
                yes,
            },
            "latest" => ReleaseCommand::Latest {
                tag: positional
                    .get(2)
                    .cloned()
                    .ok_or_else(|| Error::msg("release latest requires a tag"))?,
                yes,
            },
            other => return Err(Error::msg(format!("unknown release operation {other}"))),
        };
        Ok(Self {
            config_dir,
            rns_config_dir,
            remote,
            command,
        })
    }
}

fn parse_create_target(
    args: &[String],
    notes_path: Option<PathBuf>,
    signer_path: Option<PathBuf>,
    package_name: Option<String>,
) -> Result<ReleaseCommand> {
    let first = args
        .first()
        .ok_or_else(|| Error::msg("release create requires <tag>:<artifacts-dir>"))?;
    let (tag, artifacts_dir) = if let Some((tag, dir)) = first.split_once(':') {
        (tag.to_string(), PathBuf::from(dir))
    } else {
        let dir = args
            .get(1)
            .ok_or_else(|| Error::msg("release create requires an artifacts directory"))?;
        (first.clone(), PathBuf::from(dir))
    };
    if tag.is_empty() {
        return Err(Error::msg("release tag cannot be empty"));
    }
    Ok(ReleaseCommand::Create {
        tag,
        artifacts_dir,
        notes_path,
        signer_path,
        package_name,
    })
}

#[cfg(test)]
fn run_release_command(
    transport: &mut impl ReleaseTransport,
    command: &ReleaseCommand,
    output: impl Write,
) -> Result<()> {
    run_release_command_with_defaults(transport, command, None, None, None, output)
}

fn run_release_command_with_defaults(
    transport: &mut impl ReleaseTransport,
    command: &ReleaseCommand,
    default_signer_path: Option<&Path>,
    default_package_name: Option<&str>,
    origin_hash: Option<&[u8; 16]>,
    mut output: impl Write,
) -> Result<()> {
    match command {
        ReleaseCommand::List => {
            let body = transport.request(request("list", &[]))?;
            let releases = msgpack::unpack_exact(&body)
                .map_err(|e| Error::msg(format!("invalid release list: {e}")))?;
            print_release_list(&releases, &mut output)
        }
        ReleaseCommand::View { tag } => {
            let body = transport.request(request("view", &[("tag", Value::Str(tag.clone()))]))?;
            let release = msgpack::unpack_exact(&body)
                .map_err(|e| Error::msg(format!("invalid release view: {e}")))?;
            print_release_view(&release, &mut output)
        }
        ReleaseCommand::Fetch {
            target,
            required_signer,
        } => fetch_release_into(
            transport,
            target,
            required_signer.as_deref(),
            Path::new("."),
            &mut output,
        ),
        ReleaseCommand::Create {
            tag,
            artifacts_dir,
            notes_path,
            signer_path,
            package_name,
        } => create_release(
            transport,
            tag,
            artifacts_dir,
            notes_path.as_deref(),
            signer_path.as_deref().or(default_signer_path),
            package_name.as_deref().or(default_package_name),
            origin_hash,
            &mut output,
        ),
        ReleaseCommand::Delete { tag, yes } => {
            if !yes {
                return Err(Error::msg("release delete requires --yes"));
            }
            transport.request(request("delete", &[("tag", Value::Str(tag.clone()))]))?;
            writeln!(output, "Deleted release {tag}")?;
            Ok(())
        }
        ReleaseCommand::Latest { tag, yes } => {
            if !yes {
                return Err(Error::msg("release latest requires --yes"));
            }
            transport.request(request("latest", &[("tag", Value::Str(tag.clone()))]))?;
            writeln!(output, "Release {tag} set as latest")?;
            Ok(())
        }
    }
}

fn create_release(
    transport: &mut impl ReleaseTransport,
    tag: &str,
    artifacts_dir: &Path,
    notes_path: Option<&Path>,
    signer_path: Option<&Path>,
    package_name: Option<&str>,
    origin_hash: Option<&[u8; 16]>,
    mut output: impl Write,
) -> Result<()> {
    if !artifacts_dir.is_dir() {
        return Err(Error::msg(format!(
            "artifact directory does not exist: {}",
            artifacts_dir.display()
        )));
    }
    let notes = load_notes(artifacts_dir, notes_path)?;
    let mut artifacts = artifact_files(artifacts_dir)?;
    if let Some(signer_path) = signer_path {
        sign_release_artifacts(
            artifacts_dir,
            &artifacts,
            tag,
            &notes.content,
            signer_path,
            package_name,
            origin_hash,
        )?;
        artifacts = artifact_files(artifacts_dir)?;
    }
    writeln!(output, "Initializing release {tag}")?;
    transport.request(request(
        "create",
        &[
            ("step", Value::Str("init".into())),
            ("tag", Value::Str(tag.to_string())),
            ("notes", Value::Str(notes.content)),
            ("notes_format", Value::Str(notes.format)),
        ],
    ))?;

    for (index, artifact) in artifacts.iter().enumerate() {
        let data = fs::read(&artifact.path)?;
        writeln!(
            output,
            "Uploading {} ({}/{}, {} bytes)",
            artifact.name,
            index + 1,
            artifacts.len(),
            data.len()
        )?;
        transport.request(request(
            "create",
            &[
                ("step", Value::Str("artifact".into())),
                ("tag", Value::Str(tag.to_string())),
                ("artifact_name", Value::Str(artifact.name.clone())),
                ("artifact_data", Value::Bin(data)),
            ],
        ))?;
    }
    writeln!(output, "Finalizing release {tag}")?;
    transport.request(request(
        "create",
        &[
            ("step", Value::Str("finalize".into())),
            ("tag", Value::Str(tag.to_string())),
        ],
    ))?;
    writeln!(
        output,
        "Created release {tag} with {} artifact(s)",
        artifacts.len()
    )?;
    Ok(())
}

fn sign_release_artifacts(
    artifacts_dir: &Path,
    artifacts: &[ArtifactFile],
    tag: &str,
    notes: &str,
    signer_path: &Path,
    package_name: Option<&str>,
    origin_hash: Option<&[u8; 16]>,
) -> Result<()> {
    let signer = rns_net::storage::load_identity(signer_path).map_err(|e| {
        Error::msg(format!(
            "could not load signer identity {}: {e}",
            signer_path.display()
        ))
    })?;
    let timestamp = current_unix_timestamp()?;
    let mut manifest_artifacts = Vec::new();

    for artifact in artifacts {
        if artifact.name.ends_with(".rsg") || artifact.name.ends_with(".rsm") {
            continue;
        }
        let data = fs::read(&artifact.path)?;
        let rsg = create_rsg(
            &signer,
            &data,
            false,
            vec![("timestamp".into(), Value::UInt(timestamp))],
        )?;
        fs::write(artifacts_dir.join(format!("{}.rsg", artifact.name)), &rsg)?;
        manifest_artifacts.push(Value::Map(vec![
            (Value::Str("name".into()), Value::Str(artifact.name.clone())),
            (Value::Str("rsg".into()), Value::Bin(rsg)),
        ]));
    }

    let package_name = package_name
        .map(str::to_string)
        .or_else(|| {
            artifacts_dir
                .file_name()
                .map(|name| name.to_string_lossy().into_owned())
        })
        .unwrap_or_else(|| "release".into());
    let mut manifest_meta = vec![
        ("name".into(), Value::Str(package_name)),
        ("version".into(), Value::Str(tag.to_string())),
        ("released".into(), Value::Str(unix_timestamp_iso(timestamp))),
        ("timestamp".into(), Value::UInt(timestamp)),
        ("commit".into(), Value::Nil),
        ("artifacts".into(), Value::Array(manifest_artifacts)),
    ];
    if let Some(origin_hash) = origin_hash {
        manifest_meta.push(("origin".into(), Value::Bin(origin_hash.to_vec())));
    }
    let manifest = create_rsg(&signer, notes.as_bytes(), true, manifest_meta)?;
    fs::write(artifacts_dir.join("manifest.rsm"), manifest)?;
    Ok(())
}

fn fetch_release_into(
    transport: &mut impl ReleaseTransport,
    target: &str,
    required_signer: Option<&str>,
    output_dir: &Path,
    mut output: impl Write,
) -> Result<()> {
    let (tag, requested_artifact) = parse_fetch_target(target)?;
    let required_signer = required_signer.map(parse_hex_16).transpose()?;
    let manifest = transport.request_resource(request(
        "fetch",
        &[
            ("tag", Value::Str(tag.clone())),
            ("artifact", Value::Str("manifest.rsm".into())),
        ],
    ))?;
    let manifest = validate_embedded_manifest(&manifest, required_signer)?;
    writeln!(
        output,
        "Release manifest validated, signed by {}",
        crate::util::hex(&manifest.signer_hash)
    )?;
    let artifacts = manifest_artifacts(&manifest.envelope)?;
    if artifacts.is_empty() {
        return Err(Error::msg("Release manifest contains no artifacts"));
    }
    let selected = select_manifest_artifacts(&artifacts, &requested_artifact)?;
    fs::create_dir_all(output_dir)?;

    for artifact in selected {
        let output_path = output_dir.join(&artifact.name);
        if output_path.exists() {
            let existing = fs::read(&output_path)?;
            if validate_rsg(&artifact.rsg, &existing, required_signer).is_ok() {
                writeln!(
                    output,
                    "Existing file {} validated, not fetching again",
                    artifact.name
                )?;
                continue;
            }
            writeln!(
                output,
                "Existing file {} does not match manifest, fetching and overwriting",
                artifact.name
            )?;
        }
        let data = transport.request_resource(request(
            "fetch",
            &[
                ("tag", Value::Str(tag.clone())),
                ("artifact", Value::Str(artifact.name.clone())),
            ],
        ))?;
        validate_rsg(&artifact.rsg, &data, required_signer)?;
        fs::write(&output_path, data)?;
        writeln!(output, "Fetched {}", artifact.name)?;
    }
    Ok(())
}

fn parse_fetch_target(target: &str) -> Result<(String, String)> {
    let (tag, artifact) = target
        .split_once(':')
        .ok_or_else(|| Error::msg("Invalid release specification"))?;
    if tag.is_empty() || artifact.is_empty() {
        return Err(Error::msg("Invalid release specification"));
    }
    Ok((tag.to_string(), artifact.to_string()))
}

#[derive(Debug)]
struct ValidRsg {
    envelope: Value,
    signer_hash: [u8; 16],
}

#[derive(Debug, Clone)]
struct ManifestArtifact {
    name: String,
    rsg: Vec<u8>,
}

fn validate_embedded_manifest(rsg: &[u8], required_signer: Option<[u8; 16]>) -> Result<ValidRsg> {
    let envelope = rsg_envelope(rsg)?;
    let message = rsg_embedded_message(&envelope)
        .ok_or_else(|| Error::msg("No embedded message in release manifest"))?;
    validate_rsg_parts(rsg, &message, required_signer, Some(envelope))
}

fn validate_rsg(rsg: &[u8], message: &[u8], required_signer: Option<[u8; 16]>) -> Result<ValidRsg> {
    validate_rsg_parts(rsg, message, required_signer, None)
}

fn validate_rsg_parts(
    rsg: &[u8],
    message: &[u8],
    required_signer: Option<[u8; 16]>,
    envelope: Option<Value>,
) -> Result<ValidRsg> {
    const SIG_LEN: usize = 64;
    if rsg.len() <= SIG_LEN {
        return Err(Error::msg("invalid RSG"));
    }
    let signature: [u8; SIG_LEN] = rsg[..SIG_LEN].try_into().unwrap();
    let envelope_bytes = &rsg[SIG_LEN..];
    let envelope = match envelope {
        Some(envelope) => envelope,
        None => msgpack::unpack_exact(envelope_bytes)
            .map_err(|e| Error::msg(format!("invalid RSG envelope: {e}")))?,
    };
    if envelope.map_get("hashtype").and_then(Value::as_str) != Some("sha256") {
        return Err(Error::msg("unsupported RSG hash type"));
    }
    let signed_hash = envelope
        .map_get("hash")
        .and_then(Value::as_bin)
        .ok_or_else(|| Error::msg("RSG is missing hash"))?;
    let calculated_hash = sha256(message);
    if signed_hash != calculated_hash.as_slice() {
        return Err(Error::msg("RSG hash does not match message"));
    }
    let meta = envelope
        .map_get("meta")
        .ok_or_else(|| Error::msg("RSG is missing metadata"))?;
    let pubkey = meta
        .map_get("pubkey")
        .and_then(Value::as_bin)
        .ok_or_else(|| Error::msg("RSG is missing public key"))?;
    let public_key: [u8; 64] = pubkey
        .try_into()
        .map_err(|_| Error::msg("RSG public key has invalid length"))?;
    let identity = Identity::from_public_key(&public_key);
    let signer_hash = *identity.hash();
    let meta_signer = meta
        .map_get("signer")
        .and_then(Value::as_bin)
        .ok_or_else(|| Error::msg("RSG is missing signer"))?;
    if meta_signer != signer_hash.as_slice() {
        return Err(Error::msg("RSG signer does not match public key"));
    }
    if let Some(required) = required_signer {
        if signer_hash != required {
            return Err(Error::msg(format!(
                "RSG is not signed by required signer {}",
                crate::util::hex(&required)
            )));
        }
    }
    if !identity.verify(&signature, envelope_bytes) {
        return Err(Error::msg("RSG signature verification failed"));
    }
    Ok(ValidRsg {
        envelope,
        signer_hash,
    })
}

fn rsg_envelope(rsg: &[u8]) -> Result<Value> {
    const SIG_LEN: usize = 64;
    if rsg.len() <= SIG_LEN {
        return Err(Error::msg("invalid RSG"));
    }
    msgpack::unpack_exact(&rsg[SIG_LEN..])
        .map_err(|e| Error::msg(format!("invalid RSG envelope: {e}")))
}

fn rsg_embedded_message(value: &Value) -> Option<Vec<u8>> {
    value
        .map_get("message")
        .and_then(Value::as_bin)
        .map(ToOwned::to_owned)
        .or_else(|| {
            value
                .map_get("message")
                .and_then(Value::as_str)
                .map(|message| message.as_bytes().to_vec())
        })
}

fn manifest_artifacts(manifest: &Value) -> Result<Vec<ManifestArtifact>> {
    let artifacts = manifest
        .map_get("meta")
        .and_then(|meta| meta.map_get("artifacts"))
        .and_then(Value::as_array)
        .ok_or_else(|| Error::msg("Release manifest contains no artifacts"))?;
    artifacts
        .iter()
        .map(|artifact| {
            let name = artifact
                .map_get("name")
                .and_then(Value::as_str)
                .ok_or_else(|| Error::msg("manifest artifact is missing name"))?;
            if name.contains('/') || name.contains('\\') || name == "." || name == ".." {
                return Err(Error::msg("manifest artifact has invalid name"));
            }
            let rsg = artifact
                .map_get("rsg")
                .and_then(Value::as_bin)
                .ok_or_else(|| Error::msg("manifest artifact is missing RSG"))?;
            Ok(ManifestArtifact {
                name: name.to_string(),
                rsg: rsg.to_vec(),
            })
        })
        .collect()
}

fn select_manifest_artifacts(
    artifacts: &[ManifestArtifact],
    requested: &str,
) -> Result<Vec<ManifestArtifact>> {
    if requested == "all" {
        return Ok(artifacts.to_vec());
    }
    artifacts
        .iter()
        .find(|artifact| artifact.name == requested)
        .cloned()
        .map(|artifact| vec![artifact])
        .ok_or_else(|| Error::msg("No available artifacts specified for fetch"))
}

fn create_rsg(
    identity: &Identity,
    message: &[u8],
    embed_message: bool,
    extra_meta: Vec<(String, Value)>,
) -> Result<Vec<u8>> {
    const SIG_LEN: usize = 64;
    let public_key = identity
        .get_public_key()
        .ok_or_else(|| Error::msg("signer identity has no public key"))?;
    let mut meta = vec![
        (
            Value::Str("signer".into()),
            Value::Bin(identity.hash().to_vec()),
        ),
        (Value::Str("pubkey".into()), Value::Bin(public_key.to_vec())),
    ];
    for (key, value) in extra_meta {
        if !meta
            .iter()
            .any(|(existing, _)| matches!(existing, Value::Str(existing) if existing == &key))
        {
            meta.push((Value::Str(key), value));
        }
    }

    let mut envelope = vec![
        (Value::Str("hashtype".into()), Value::Str("sha256".into())),
        (
            Value::Str("hash".into()),
            Value::Bin(sha256(message).to_vec()),
        ),
        (Value::Str("meta".into()), Value::Map(meta)),
    ];
    if embed_message {
        envelope.push((Value::Str("message".into()), Value::Bin(message.to_vec())));
    }
    let envelope = msgpack::pack(&Value::Map(envelope));
    let signature = identity
        .sign(&envelope)
        .map_err(|_| Error::msg("signer identity has no private key"))?;
    let mut rsg = Vec::with_capacity(SIG_LEN + envelope.len());
    rsg.extend_from_slice(&signature);
    rsg.extend_from_slice(&envelope);
    Ok(rsg)
}

fn current_unix_timestamp() -> Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| Error::msg(format!("system clock is before UNIX epoch: {e}")))?
        .as_secs())
}

fn unix_timestamp_iso(timestamp: u64) -> String {
    let days = (timestamp / 86_400) as i64;
    let seconds = timestamp % 86_400;
    let (year, month, day) = civil_from_days(days);
    let hour = seconds / 3_600;
    let minute = (seconds % 3_600) / 60;
    let second = seconds % 60;
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z")
}

fn civil_from_days(days_since_epoch: i64) -> (i64, u64, u64) {
    let z = days_since_epoch + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = mp + if mp < 10 { 3 } else { -9 };
    let year = y + if month <= 2 { 1 } else { 0 };
    (year, month as u64, day as u64)
}

fn request(operation: &str, fields: &[(&str, Value)]) -> Vec<u8> {
    let mut map = vec![
        (
            Value::UInt(protocol::IDX_REPOSITORY),
            Value::Str("__repository__".into()),
        ),
        (
            Value::Str("operation".into()),
            Value::Str(operation.to_string()),
        ),
    ];
    map.extend(
        fields
            .iter()
            .map(|(key, value)| (Value::Str((*key).into()), value.clone())),
    );
    msgpack::pack(&Value::Map(map))
}

fn request_with_repository(data: Vec<u8>, repository: &str) -> Result<Vec<u8>> {
    let mut value =
        msgpack::unpack_exact(&data).map_err(|e| Error::msg(format!("invalid request: {e}")))?;
    if let Value::Map(entries) = &mut value {
        for (key, val) in entries {
            if matches!(key, Value::UInt(v) if *v == protocol::IDX_REPOSITORY) {
                *val = Value::Str(repository.to_string());
                return Ok(msgpack::pack(&value));
            }
        }
    }
    Err(Error::msg("release request missing repository field"))
}

fn usage() -> &'static str {
    "usage: rngit release [--config DIR] [--rnsconfig DIR] [--notes PATH] [-s|--signer PATH] [-n|--name NAME] [-y|--yes] <rns://destination/repo> <list|view|fetch|create|delete|latest> [target]"
}

struct Notes {
    content: String,
    format: String,
}

fn load_notes(artifacts_dir: &Path, explicit: Option<&Path>) -> Result<Notes> {
    let path = explicit
        .map(Path::to_path_buf)
        .or_else(|| {
            let micron = artifacts_dir.join("RELEASE.mu");
            micron.exists().then_some(micron)
        })
        .or_else(|| {
            let markdown = artifacts_dir.join("RELEASE.md");
            markdown.exists().then_some(markdown)
        });
    let Some(path) = path else {
        return Ok(Notes {
            content: String::new(),
            format: "markdown".into(),
        });
    };
    let format = if path.extension().and_then(|ext| ext.to_str()) == Some("mu") {
        "micron"
    } else {
        "markdown"
    };
    Ok(Notes {
        content: fs::read_to_string(path)?,
        format: format.into(),
    })
}

struct ArtifactFile {
    name: String,
    path: PathBuf,
}

fn artifact_files(dir: &Path) -> Result<Vec<ArtifactFile>> {
    let mut out = Vec::new();
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        if !entry.file_type()?.is_file() {
            continue;
        }
        let name = entry.file_name().to_string_lossy().into_owned();
        if matches!(name.as_str(), "RELEASE.md" | "RELEASE.mu") {
            continue;
        }
        out.push(ArtifactFile {
            name,
            path: entry.path(),
        });
    }
    out.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(out)
}

fn print_release_list(value: &Value, mut output: impl Write) -> Result<()> {
    let (releases, latest) = match value {
        Value::Array(releases) => (releases.as_slice(), None),
        Value::Map(_) => {
            let releases = value
                .map_get("releases")
                .and_then(Value::as_array)
                .ok_or_else(|| Error::msg("release list response is missing releases"))?;
            let latest = value.map_get("latest").and_then(Value::as_str);
            (releases, latest)
        }
        _ => return Err(Error::msg("release list response is not an array or map")),
    };
    if releases.is_empty() {
        writeln!(output, "No releases")?;
        return Ok(());
    }
    for release in releases {
        let tag = release.map_get("tag").and_then(Value::as_str).unwrap_or("");
        let status = release
            .map_get("status")
            .and_then(Value::as_str)
            .unwrap_or("unknown");
        let artifacts = release
            .map_get("artifacts")
            .and_then(Value::as_integer)
            .unwrap_or(0);
        let preview = release
            .map_get("preview")
            .and_then(Value::as_str)
            .unwrap_or("");
        writeln!(
            output,
            "{tag:<16} {status:<10} {artifacts:>3} artifact(s) {preview}"
        )?;
    }
    if let Some(latest) = latest.filter(|latest| !latest.is_empty()) {
        writeln!(output, "\nThe latest release is: {latest}")?;
    }
    Ok(())
}

fn print_release_view(value: &Value, mut output: impl Write) -> Result<()> {
    let tag = value.map_get("tag").and_then(Value::as_str).unwrap_or("");
    let status = value
        .map_get("status")
        .and_then(Value::as_str)
        .unwrap_or("unknown");
    let thanks = value
        .map_get("thanks")
        .and_then(Value::as_integer)
        .unwrap_or(0);
    writeln!(output, "Release : {tag}")?;
    writeln!(output, "Status  : {status}")?;
    writeln!(output, "Thanks  : {thanks}")?;
    if let Some(notes) = value.map_get("notes").and_then(Value::as_str) {
        if !notes.is_empty() {
            writeln!(output, "\n{notes}")?;
        }
    }
    if let Some(artifacts) = value.map_get("artifacts").and_then(Value::as_array) {
        writeln!(output, "\nArtifacts:")?;
        for artifact in artifacts {
            let name = artifact
                .map_get("name")
                .and_then(Value::as_str)
                .unwrap_or("");
            let size = artifact
                .map_get("size")
                .and_then(Value::as_integer)
                .unwrap_or(0);
            writeln!(output, "- {name} ({size} bytes)")?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct FakeTransport {
        responses: Vec<Vec<u8>>,
        resource_responses: Vec<Vec<u8>>,
        requests: Vec<Value>,
    }

    impl ReleaseTransport for FakeTransport {
        fn request(&mut self, data: Vec<u8>) -> Result<Vec<u8>> {
            self.requests.push(msgpack::unpack_exact(&data).unwrap());
            Ok(self.responses.remove(0))
        }

        fn request_resource(&mut self, data: Vec<u8>) -> Result<Vec<u8>> {
            self.requests.push(msgpack::unpack_exact(&data).unwrap());
            Ok(self.resource_responses.remove(0))
        }
    }

    #[test]
    fn parses_release_commands() {
        let list = ReleaseOptions::parse([
            "rns://00112233445566778899aabbccddeeff/group/repo".into(),
            "list".into(),
        ])
        .unwrap();
        assert!(matches!(list.command, ReleaseCommand::List));

        let create = ReleaseOptions::parse([
            "--notes".into(),
            "NOTES.md".into(),
            "rns://00112233445566778899aabbccddeeff/group/repo".into(),
            "create".into(),
            "v1:dist".into(),
        ])
        .unwrap();
        assert_eq!(
            create.command,
            ReleaseCommand::Create {
                tag: "v1".into(),
                artifacts_dir: PathBuf::from("dist"),
                notes_path: Some(PathBuf::from("NOTES.md")),
                signer_path: None,
                package_name: None,
            }
        );

        let signed_create = ReleaseOptions::parse([
            "--signer".into(),
            "signer.rid".into(),
            "--name".into(),
            "pkg".into(),
            "rns://00112233445566778899aabbccddeeff/group/repo".into(),
            "create".into(),
            "v2".into(),
            "dist".into(),
        ])
        .unwrap();
        assert_eq!(
            signed_create.command,
            ReleaseCommand::Create {
                tag: "v2".into(),
                artifacts_dir: PathBuf::from("dist"),
                notes_path: None,
                signer_path: Some(PathBuf::from("signer.rid")),
                package_name: Some("pkg".into()),
            }
        );

        let fetch = ReleaseOptions::parse([
            "rns://00112233445566778899aabbccddeeff/group/repo".into(),
            "fetch".into(),
            "v1:app.bin".into(),
        ])
        .unwrap();
        assert_eq!(
            fetch.command,
            ReleaseCommand::Fetch {
                target: "v1:app.bin".into(),
                required_signer: None,
            }
        );

        let delete = ReleaseOptions::parse([
            "-y".into(),
            "rns://00112233445566778899aabbccddeeff/group/repo".into(),
            "delete".into(),
            "v1".into(),
        ])
        .unwrap();
        assert_eq!(
            delete.command,
            ReleaseCommand::Delete {
                tag: "v1".into(),
                yes: true
            }
        );

        let latest = ReleaseOptions::parse([
            "--yes".into(),
            "rns://00112233445566778899aabbccddeeff/group/repo".into(),
            "latest".into(),
            "v1".into(),
        ])
        .unwrap();
        assert_eq!(
            latest.command,
            ReleaseCommand::Latest {
                tag: "v1".into(),
                yes: true
            }
        );
    }

    #[test]
    fn create_sends_init_artifacts_and_finalize() {
        let tmp = tempfile::tempdir().unwrap();
        fs::write(tmp.path().join("RELEASE.md"), "# Notes\n").unwrap();
        fs::write(tmp.path().join("b.bin"), b"b").unwrap();
        fs::write(tmp.path().join("a.bin"), b"a").unwrap();
        let mut fake = FakeTransport {
            responses: vec![Vec::new(), Vec::new(), Vec::new(), Vec::new()],
            resource_responses: Vec::new(),
            requests: Vec::new(),
        };
        let mut out = Vec::new();

        create_release(
            &mut fake,
            "v1",
            tmp.path(),
            None,
            None,
            None,
            None,
            &mut out,
        )
        .unwrap();

        assert_eq!(fake.requests.len(), 4);
        assert_eq!(
            fake.requests[0]
                .map_get("operation")
                .and_then(Value::as_str),
            Some("create")
        );
        assert_eq!(
            fake.requests[0].map_get("step").and_then(Value::as_str),
            Some("init")
        );
        assert_eq!(
            fake.requests[0].map_get("notes").and_then(Value::as_str),
            Some("# Notes\n")
        );
        assert_eq!(
            fake.requests[1]
                .map_get("artifact_name")
                .and_then(Value::as_str),
            Some("a.bin")
        );
        assert_eq!(
            fake.requests[2]
                .map_get("artifact_name")
                .and_then(Value::as_str),
            Some("b.bin")
        );
        assert_eq!(
            fake.requests[3].map_get("step").and_then(Value::as_str),
            Some("finalize")
        );
        let out = String::from_utf8(out).unwrap();
        assert!(out.contains("Initializing release v1"));
        assert!(out.contains("Uploading a.bin (1/2, 1 bytes)"));
        assert!(out.contains("Uploading b.bin (2/2, 1 bytes)"));
        assert!(out.contains("Finalizing release v1"));
        assert!(out.ends_with("Created release v1 with 2 artifact(s)\n"));
    }

    #[test]
    fn create_with_signer_writes_artifact_signatures_and_manifest() {
        let tmp = tempfile::tempdir().unwrap();
        let signer_dir = tempfile::tempdir().unwrap();
        fs::write(tmp.path().join("RELEASE.md"), "# Notes\n").unwrap();
        fs::write(tmp.path().join("app.bin"), b"app").unwrap();
        let signer = rns_crypto::identity::Identity::new(&mut rns_crypto::OsRng);
        let signer_path = signer_dir.path().join("signer.rid");
        rns_net::storage::save_identity(&signer, &signer_path).unwrap();
        let mut fake = FakeTransport {
            responses: vec![Vec::new(), Vec::new(), Vec::new(), Vec::new(), Vec::new()],
            resource_responses: Vec::new(),
            requests: Vec::new(),
        };
        let mut out = Vec::new();

        create_release(
            &mut fake,
            "v1",
            tmp.path(),
            None,
            Some(&signer_path),
            Some("pkg"),
            Some(&[0x11; 16]),
            &mut out,
        )
        .unwrap();

        assert!(tmp.path().join("app.bin.rsg").exists());
        assert!(tmp.path().join("manifest.rsm").exists());
        assert_eq!(fake.requests.len(), 5);
        let uploaded = fake.requests[1..4]
            .iter()
            .filter_map(|request| request.map_get("artifact_name").and_then(Value::as_str))
            .collect::<Vec<_>>();
        assert_eq!(uploaded, vec!["app.bin", "app.bin.rsg", "manifest.rsm"]);

        let manifest = rsg_envelope(&tmp.path().join("manifest.rsm"));
        let meta = manifest.map_get("meta").unwrap();
        assert_eq!(meta.map_get("name").and_then(Value::as_str), Some("pkg"));
        assert_eq!(meta.map_get("version").and_then(Value::as_str), Some("v1"));
        assert!(meta.map_get("released").and_then(Value::as_str).is_some());
        assert_eq!(
            meta.map_get("origin").and_then(Value::as_bin),
            Some(&[0x11; 16][..])
        );
        assert!(meta.map_get("commit").is_some_and(Value::is_nil));
        let artifacts = meta.map_get("artifacts").and_then(Value::as_array).unwrap();
        assert_eq!(artifacts.len(), 1);
        let artifact = &artifacts[0];
        assert_eq!(
            artifact.map_get("name").and_then(Value::as_str),
            Some("app.bin")
        );
        assert!(artifact.map_get("rsg").and_then(Value::as_bin).is_some());

        let artifact_sig = rsg_envelope(&tmp.path().join("app.bin.rsg"));
        assert!(artifact_sig
            .map_get("meta")
            .unwrap()
            .map_get("timestamp")
            .and_then(Value::as_integer)
            .is_some());
    }

    fn rsg_envelope(path: &Path) -> Value {
        let data = fs::read(path).unwrap();
        msgpack::unpack_exact(&data[64..]).unwrap()
    }

    #[test]
    fn fetch_validates_release_target_before_requesting() {
        let mut fake = FakeTransport::default();
        let err = run_release_command(
            &mut fake,
            &ReleaseCommand::Fetch {
                target: "v1".into(),
                required_signer: None,
            },
            Vec::new(),
        )
        .unwrap_err();
        assert!(err.to_string().contains("Invalid release specification"));
        assert!(fake.requests.is_empty());
    }

    #[test]
    fn fetch_validates_manifest_and_downloads_artifact() {
        let tmp = tempfile::tempdir().unwrap();
        let signer = rns_crypto::identity::Identity::new(&mut rns_crypto::OsRng);
        let artifact_rsg = create_rsg(&signer, b"app", false, Vec::new()).unwrap();
        let manifest = create_rsg(
            &signer,
            b"notes",
            true,
            vec![(
                "artifacts".into(),
                Value::Array(vec![Value::Map(vec![
                    (Value::Str("name".into()), Value::Str("app.bin".into())),
                    (Value::Str("rsg".into()), Value::Bin(artifact_rsg)),
                ])]),
            )],
        )
        .unwrap();
        let required = crate::util::hex(signer.hash());
        let mut fake = FakeTransport {
            responses: Vec::new(),
            resource_responses: vec![manifest, b"app".to_vec()],
            requests: Vec::new(),
        };
        let mut out = Vec::new();

        fetch_release_into(
            &mut fake,
            "v1:app.bin",
            Some(&required),
            tmp.path(),
            &mut out,
        )
        .unwrap();

        assert_eq!(fs::read(tmp.path().join("app.bin")).unwrap(), b"app");
        assert_eq!(fake.requests.len(), 2);
        assert_eq!(
            fake.requests[0].map_get("artifact").and_then(Value::as_str),
            Some("manifest.rsm")
        );
        assert_eq!(
            fake.requests[1].map_get("artifact").and_then(Value::as_str),
            Some("app.bin")
        );
        let out = String::from_utf8(out).unwrap();
        assert!(out.contains("Release manifest validated"));
        assert!(out.contains("Fetched app.bin"));
    }

    #[test]
    fn list_and_view_format_msgpack_responses() {
        let release = Value::Map(vec![
            (Value::Str("tag".into()), Value::Str("v1".into())),
            (Value::Str("status".into()), Value::Str("published".into())),
            (Value::Str("artifacts".into()), Value::UInt(2)),
            (Value::Str("preview".into()), Value::Str("First".into())),
        ]);
        let list_body = Value::Map(vec![
            (
                Value::Str("releases".into()),
                Value::Array(vec![release.clone()]),
            ),
            (Value::Str("latest".into()), Value::Str("v1".into())),
        ]);
        let mut out = Vec::new();
        print_release_list(&list_body, &mut out).unwrap();
        let list = String::from_utf8(out).unwrap();
        assert!(list.contains("v1"));
        assert!(list.contains("published"));
        assert!(list.contains("First"));
        assert!(list.contains("The latest release is: v1"));

        let mut out = Vec::new();
        print_release_list(&Value::Array(vec![release]), &mut out).unwrap();
        let legacy_list = String::from_utf8(out).unwrap();
        assert!(legacy_list.contains("v1"));

        let view_body = Value::Map(vec![
            (Value::Str("tag".into()), Value::Str("v1".into())),
            (Value::Str("status".into()), Value::Str("published".into())),
            (Value::Str("thanks".into()), Value::UInt(3)),
            (Value::Str("notes".into()), Value::Str("Notes".into())),
            (
                Value::Str("artifacts".into()),
                Value::Array(vec![Value::Map(vec![
                    (Value::Str("name".into()), Value::Str("dist.tar".into())),
                    (Value::Str("size".into()), Value::UInt(9)),
                ])]),
            ),
        ]);
        let mut out = Vec::new();
        print_release_view(&view_body, &mut out).unwrap();
        let view = String::from_utf8(out).unwrap();
        assert!(view.contains("Release : v1"));
        assert!(view.contains("Thanks  : 3"));
        assert!(view.contains("dist.tar (9 bytes)"));
    }

    #[test]
    fn delete_requires_explicit_yes() {
        let mut fake = FakeTransport::default();
        let err = run_release_command(
            &mut fake,
            &ReleaseCommand::Delete {
                tag: "v1".into(),
                yes: false,
            },
            Vec::new(),
        )
        .unwrap_err();
        assert!(err.to_string().contains("--yes"));
        assert!(fake.requests.is_empty());
    }

    #[test]
    fn delete_with_yes_sends_delete_request() {
        let mut fake = FakeTransport {
            responses: vec![Vec::new()],
            resource_responses: Vec::new(),
            requests: Vec::new(),
        };
        let mut out = Vec::new();
        run_release_command(
            &mut fake,
            &ReleaseCommand::Delete {
                tag: "v1".into(),
                yes: true,
            },
            &mut out,
        )
        .unwrap();

        assert_eq!(fake.requests.len(), 1);
        assert_eq!(
            fake.requests[0]
                .map_get("operation")
                .and_then(Value::as_str),
            Some("delete")
        );
        assert_eq!(
            fake.requests[0].map_get("tag").and_then(Value::as_str),
            Some("v1")
        );
        assert_eq!(String::from_utf8(out).unwrap(), "Deleted release v1\n");
    }

    #[test]
    fn latest_requires_yes_and_sends_latest_request() {
        let mut fake = FakeTransport::default();
        let err = run_release_command(
            &mut fake,
            &ReleaseCommand::Latest {
                tag: "v1".into(),
                yes: false,
            },
            Vec::new(),
        )
        .unwrap_err();
        assert!(err.to_string().contains("--yes"));
        assert!(fake.requests.is_empty());

        let mut fake = FakeTransport {
            responses: vec![Vec::new()],
            resource_responses: Vec::new(),
            requests: Vec::new(),
        };
        let mut out = Vec::new();
        run_release_command(
            &mut fake,
            &ReleaseCommand::Latest {
                tag: "v1".into(),
                yes: true,
            },
            &mut out,
        )
        .unwrap();

        assert_eq!(fake.requests.len(), 1);
        assert_eq!(
            fake.requests[0]
                .map_get("operation")
                .and_then(Value::as_str),
            Some("latest")
        );
        assert_eq!(
            fake.requests[0].map_get("tag").and_then(Value::as_str),
            Some("v1")
        );
        assert_eq!(
            String::from_utf8(out).unwrap(),
            "Release v1 set as latest\n"
        );
    }
}
