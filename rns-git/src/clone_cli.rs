use std::path::PathBuf;
use std::time::Duration;

use crate::client::{decode_status, SyncClient};
use crate::config::ClientConfig;
use crate::logging;
use crate::protocol;
use crate::util::{
    default_reticulum_dir, default_rngit_dir, parse_rns_url_with_aliases, resolve_rns_url_aliases,
};
use crate::{Error, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CloneCommand {
    Fork,
    Mirror,
}

impl CloneCommand {
    fn path(self) -> &'static str {
        match self {
            CloneCommand::Fork => protocol::PATH_FORK,
            CloneCommand::Mirror => protocol::PATH_MIRROR,
        }
    }

    fn name(self) -> &'static str {
        match self {
            CloneCommand::Fork => "fork",
            CloneCommand::Mirror => "mirror",
        }
    }
}

pub fn main<I>(command: CloneCommand, args: I) -> Result<()>
where
    I: IntoIterator<Item = String>,
{
    let options = CloneOptions::parse(args)?;
    let rngit_dir = options.config_dir.unwrap_or_else(default_rngit_dir);
    let rns_dir = options.rns_config_dir.or_else(default_reticulum_dir);
    let mut config = ClientConfig::load_or_create_for_run(rngit_dir, rns_dir)?;
    logging::init_file_logger(&config.dir.join("client_log"), config.log_level)?;
    let (dest_hash, repository) =
        parse_rns_url_with_aliases(&options.target, &config.destination_aliases)?;
    if let Some(identity_path) = options.identity_path {
        config.identity_path = identity_path;
    }

    let source = resolve_rns_url_aliases(&options.source, &config.destination_aliases)?;
    let client = SyncClient::connect(config, dest_hash)?;
    let response = client.request_with_timeout(
        command.path(),
        protocol::remote_clone_request(&repository, &source),
        Duration::from_secs(7200),
    )?;
    let bytes = protocol::response_bin(&response.data)?;
    decode_status(bytes)?;
    println!("Repository {}ed to {repository}", command.name());
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CloneOptions {
    config_dir: Option<PathBuf>,
    rns_config_dir: Option<PathBuf>,
    identity_path: Option<PathBuf>,
    source: String,
    target: String,
}

impl CloneOptions {
    fn parse<I>(args: I) -> Result<Self>
    where
        I: IntoIterator<Item = String>,
    {
        let mut config_dir = None;
        let mut rns_config_dir = None;
        let mut identity_path = None;
        let mut positional = Vec::new();
        let mut iter = args.into_iter();
        while let Some(arg) = iter.next() {
            match arg.as_str() {
                "--config" => config_dir = Some(next_path(&mut iter, "--config")?),
                "--rnsconfig" => rns_config_dir = Some(next_path(&mut iter, "--rnsconfig")?),
                "-i" | "--identity" => identity_path = Some(next_path(&mut iter, "--identity")?),
                "-h" | "--help" => return Err(Error::msg(usage())),
                other if other.starts_with('-') => {
                    return Err(Error::msg(format!("unknown clone option {other}")));
                }
                _ => positional.push(arg),
            }
        }
        if positional.len() != 2 {
            return Err(Error::msg(usage()));
        }
        Ok(Self {
            config_dir,
            rns_config_dir,
            identity_path,
            source: positional.remove(0),
            target: positional.remove(0),
        })
    }
}

fn next_path(iter: &mut impl Iterator<Item = String>, flag: &str) -> Result<PathBuf> {
    iter.next()
        .map(PathBuf::from)
        .ok_or_else(|| Error::msg(format!("{flag} requires a value")))
}

fn usage() -> &'static str {
    "usage: rngit <fork|mirror> [--config DIR] [--rnsconfig DIR] [-i|--identity PATH] <source-url> <rns://destination/group/repo>"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_clone_options() {
        let opts = CloneOptions::parse([
            "--config".into(),
            "cfg".into(),
            "--rnsconfig".into(),
            "rns".into(),
            "-i".into(),
            "id".into(),
            "https://example.invalid/repo.git".into(),
            "rns://00112233445566778899aabbccddeeff/group/repo".into(),
        ])
        .unwrap();
        assert_eq!(opts.config_dir, Some(PathBuf::from("cfg")));
        assert_eq!(opts.rns_config_dir, Some(PathBuf::from("rns")));
        assert_eq!(opts.identity_path, Some(PathBuf::from("id")));
        assert_eq!(opts.source, "https://example.invalid/repo.git");
        assert_eq!(
            opts.target,
            "rns://00112233445566778899aabbccddeeff/group/repo"
        );
    }

    #[test]
    fn rejects_wrong_clone_positional_count() {
        assert!(CloneOptions::parse(["source".into()]).is_err());
    }
}
