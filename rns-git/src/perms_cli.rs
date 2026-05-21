use std::fs;
use std::io::{self, Write};
use std::path::PathBuf;
use std::time::Duration;

use rns_core::msgpack::{self, Value};

use crate::client::{decode_status, SyncClient};
use crate::config::ClientConfig;
use crate::logging;
use crate::protocol;
use crate::util::{default_reticulum_dir, default_rngit_dir, parse_rns_url_with_aliases};
use crate::{Error, Result};

const PERMS_TIMEOUT: Duration = Duration::from_secs(120);

pub fn main<I>(args: I) -> Result<()>
where
    I: IntoIterator<Item = String>,
{
    let options = PermsOptions::parse(args)?;
    let rngit_dir = options.config_dir.unwrap_or_else(default_rngit_dir);
    let rns_dir = options.rns_config_dir.or_else(default_reticulum_dir);
    let (mut config, created) = ClientConfig::load_or_create(rngit_dir, rns_dir)?;
    logging::init_file_logger(&config.dir.join("client_log"), config.log_level)?;
    if created {
        return Err(Error::msg(format!(
            "created default config at {}; edit it and run again",
            config.dir.join("client_config").display()
        )));
    }
    let (dest_hash, target_path) =
        parse_rns_url_with_aliases(&options.remote, &config.destination_aliases)?;
    if let Some(identity_path) = options.identity_path {
        config.identity_path = identity_path;
    }

    let client = SyncClient::connect(config, dest_hash)?;
    let mut transport = NetPermsTransport {
        client,
        target_path,
    };
    run_perms_command(
        &mut transport,
        options.content_path.as_deref(),
        io::stdout(),
    )
}

trait PermsTransport {
    fn request(&mut self, data: Vec<u8>) -> Result<Vec<u8>>;

    fn request_with_timeout(&mut self, data: Vec<u8>, _timeout: Duration) -> Result<Vec<u8>> {
        self.request(data)
    }

    fn target_path(&self) -> &str;
}

struct NetPermsTransport {
    client: SyncClient,
    target_path: String,
}

impl PermsTransport for NetPermsTransport {
    fn request(&mut self, data: Vec<u8>) -> Result<Vec<u8>> {
        self.request_with_timeout(data, PERMS_TIMEOUT)
    }

    fn request_with_timeout(&mut self, data: Vec<u8>, timeout: Duration) -> Result<Vec<u8>> {
        let response = self
            .client
            .request_with_timeout(protocol::PATH_PERMS, data, timeout)?;
        let bytes = protocol::response_bin(&response.data)?;
        decode_status(bytes)
    }

    fn target_path(&self) -> &str {
        &self.target_path
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PermsOptions {
    config_dir: Option<PathBuf>,
    rns_config_dir: Option<PathBuf>,
    identity_path: Option<PathBuf>,
    content_path: Option<PathBuf>,
    remote: String,
}

impl PermsOptions {
    fn parse<I>(args: I) -> Result<Self>
    where
        I: IntoIterator<Item = String>,
    {
        let mut config_dir = None;
        let mut rns_config_dir = None;
        let mut identity_path = None;
        let mut content_path = None;
        let mut remote = None;
        let mut iter = args.into_iter();
        while let Some(arg) = iter.next() {
            match arg.as_str() {
                "--config" => config_dir = Some(next_path(&mut iter, "--config")?),
                "--rnsconfig" => rns_config_dir = Some(next_path(&mut iter, "--rnsconfig")?),
                "-i" | "--identity" => identity_path = Some(next_path(&mut iter, "--identity")?),
                "--content" => content_path = Some(next_path(&mut iter, "--content")?),
                "-h" | "--help" => return Err(Error::msg(usage())),
                other if other.starts_with('-') => {
                    return Err(Error::msg(format!("unknown perms option {other}")));
                }
                _ => {
                    if remote.replace(arg).is_some() {
                        return Err(Error::msg(
                            "perms takes exactly one group or repository URL",
                        ));
                    }
                }
            }
        }
        Ok(Self {
            config_dir,
            rns_config_dir,
            identity_path,
            content_path,
            remote: remote.ok_or_else(|| Error::msg(usage()))?,
        })
    }
}

fn next_path(iter: &mut impl Iterator<Item = String>, flag: &str) -> Result<PathBuf> {
    iter.next()
        .map(PathBuf::from)
        .ok_or_else(|| Error::msg(format!("{flag} requires a value")))
}

fn run_perms_command(
    transport: &mut impl PermsTransport,
    content_path: Option<&std::path::Path>,
    mut output: impl Write,
) -> Result<()> {
    let target = target_from_path(transport.target_path())?;
    match content_path {
        Some(path) => {
            let content = fs::read_to_string(path)?;
            transport
                .request_with_timeout(request(&target, "set", Some(&content)), PERMS_TIMEOUT)?;
            writeln!(
                output,
                "Permissions updated for {}",
                transport.target_path()
            )?;
            Ok(())
        }
        None => {
            let body =
                transport.request_with_timeout(request(&target, "get", None), PERMS_TIMEOUT)?;
            let value = msgpack::unpack_exact(&body)
                .map_err(|err| Error::msg(format!("invalid permissions response: {err}")))?;
            let content = value
                .map_get("content")
                .and_then(Value::as_str)
                .unwrap_or("");
            write!(output, "{content}")?;
            Ok(())
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum PermsTarget {
    Group(String),
    Repository(String),
}

fn target_from_path(path: &str) -> Result<PermsTarget> {
    let trimmed = path.trim_matches('/');
    if trimmed.is_empty() {
        return Err(Error::msg("invalid permissions target"));
    }
    if trimmed.contains('/') {
        Ok(PermsTarget::Repository(trimmed.to_string()))
    } else {
        Ok(PermsTarget::Group(trimmed.to_string()))
    }
}

fn request(target: &PermsTarget, step: &str, content: Option<&str>) -> Vec<u8> {
    let mut map = match target {
        PermsTarget::Group(group) => vec![
            (Value::UInt(protocol::IDX_GROUP), Value::Str(group.clone())),
            (Value::Str("operation".into()), Value::Str("gperms".into())),
            (Value::Str("step".into()), Value::Str(step.into())),
        ],
        PermsTarget::Repository(repo) => vec![
            (
                Value::UInt(protocol::IDX_REPOSITORY),
                Value::Str(repo.clone()),
            ),
            (Value::Str("operation".into()), Value::Str("rperms".into())),
            (Value::Str("step".into()), Value::Str(step.into())),
        ],
    };
    if let Some(content) = content {
        map.push((Value::Str("content".into()), Value::Str(content.into())));
    }
    msgpack::pack(&Value::Map(map))
}

fn usage() -> &'static str {
    "usage: rngit perms [--config DIR] [--rnsconfig DIR] [-i|--identity PATH] [--content PATH] <rns://destination/group[/repo]>"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct FakeTransport {
        target_path: String,
        responses: Vec<Vec<u8>>,
        requests: Vec<Value>,
        timeouts: Vec<Duration>,
    }

    impl PermsTransport for FakeTransport {
        fn request(&mut self, data: Vec<u8>) -> Result<Vec<u8>> {
            self.request_with_timeout(data, PERMS_TIMEOUT)
        }

        fn request_with_timeout(&mut self, data: Vec<u8>, timeout: Duration) -> Result<Vec<u8>> {
            self.requests.push(msgpack::unpack_exact(&data).unwrap());
            self.timeouts.push(timeout);
            Ok(self.responses.remove(0))
        }

        fn target_path(&self) -> &str {
            &self.target_path
        }
    }

    #[test]
    fn parses_perms_options() {
        let opts = PermsOptions::parse([
            "--config".into(),
            "cfg".into(),
            "--rnsconfig".into(),
            "rns".into(),
            "--identity".into(),
            "id".into(),
            "--content".into(),
            "allowed.txt".into(),
            "rns://00112233445566778899aabbccddeeff/group/repo".into(),
        ])
        .unwrap();
        assert_eq!(opts.config_dir, Some(PathBuf::from("cfg")));
        assert_eq!(opts.rns_config_dir, Some(PathBuf::from("rns")));
        assert_eq!(opts.identity_path, Some(PathBuf::from("id")));
        assert_eq!(opts.content_path, Some(PathBuf::from("allowed.txt")));
    }

    #[test]
    fn target_path_distinguishes_group_and_repository() {
        assert_eq!(
            target_from_path("group").unwrap(),
            PermsTarget::Group("group".into())
        );
        assert_eq!(
            target_from_path("group/repo").unwrap(),
            PermsTarget::Repository("group/repo".into())
        );
    }

    #[test]
    fn get_prints_permissions_and_sends_group_request() {
        let mut fake = FakeTransport {
            target_path: "group".into(),
            responses: vec![msgpack::pack(&Value::Map(vec![(
                Value::Str("content".into()),
                Value::Str("read = all\n".into()),
            )]))],
            requests: Vec::new(),
            timeouts: Vec::new(),
        };
        let mut out = Vec::new();

        run_perms_command(&mut fake, None, &mut out).unwrap();

        assert_eq!(String::from_utf8(out).unwrap(), "read = all\n");
        assert_eq!(fake.timeouts, vec![PERMS_TIMEOUT]);
        assert_eq!(
            fake.requests[0]
                .map_get("operation")
                .and_then(Value::as_str),
            Some("gperms")
        );
        assert_eq!(
            fake.requests[0].map_get("step").and_then(Value::as_str),
            Some("get")
        );
    }

    #[test]
    fn set_reads_content_and_sends_repository_request() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("repo.allowed");
        fs::write(&path, "write = all\n").unwrap();
        let mut fake = FakeTransport {
            target_path: "group/repo".into(),
            responses: vec![Vec::new()],
            requests: Vec::new(),
            timeouts: Vec::new(),
        };
        let mut out = Vec::new();

        run_perms_command(&mut fake, Some(&path), &mut out).unwrap();

        assert_eq!(
            fake.requests[0]
                .map_get("operation")
                .and_then(Value::as_str),
            Some("rperms")
        );
        assert_eq!(
            fake.requests[0].map_get("content").and_then(Value::as_str),
            Some("write = all\n")
        );
        assert_eq!(
            String::from_utf8(out).unwrap(),
            "Permissions updated for group/repo\n"
        );
    }
}
