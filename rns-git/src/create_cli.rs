use std::path::PathBuf;
use std::time::Duration;

use crate::client::{decode_status, SyncClient};
use crate::config::ClientConfig;
use crate::logging;
use crate::protocol;
use crate::util::{default_reticulum_dir, default_rngit_dir, parse_rns_url_with_aliases};
use crate::{Error, Result};

pub fn main<I>(args: I) -> Result<()>
where
    I: IntoIterator<Item = String>,
{
    let options = CreateOptions::parse(args)?;
    let rngit_dir = options.config_dir.unwrap_or_else(default_rngit_dir);
    let rns_dir = options.rns_config_dir.or_else(default_reticulum_dir);
    let mut config = ClientConfig::load_or_create_for_run(rngit_dir, rns_dir)?;
    logging::init_file_logger(&config.dir.join("client_log"), config.log_level)?;
    let (dest_hash, repository) =
        parse_rns_url_with_aliases(&options.remote, &config.destination_aliases)?;
    if let Some(identity_path) = options.identity_path {
        config.identity_path = identity_path;
    }

    let client = SyncClient::connect(config, dest_hash)?;
    let response = client.request_with_timeout(
        protocol::PATH_CREATE,
        protocol::repository_request(&repository),
        Duration::from_secs(120),
    )?;
    let bytes = protocol::response_bin(&response.data)?;
    decode_status(bytes)?;
    println!("Repository {repository} created");
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CreateOptions {
    config_dir: Option<PathBuf>,
    rns_config_dir: Option<PathBuf>,
    identity_path: Option<PathBuf>,
    remote: String,
}

impl CreateOptions {
    fn parse<I>(args: I) -> Result<Self>
    where
        I: IntoIterator<Item = String>,
    {
        let mut config_dir = None;
        let mut rns_config_dir = None;
        let mut identity_path = None;
        let mut remote = None;
        let mut iter = args.into_iter();
        while let Some(arg) = iter.next() {
            match arg.as_str() {
                "--config" => config_dir = Some(next_path(&mut iter, "--config")?),
                "--rnsconfig" => rns_config_dir = Some(next_path(&mut iter, "--rnsconfig")?),
                "-i" | "--identity" => identity_path = Some(next_path(&mut iter, "--identity")?),
                "-h" | "--help" => return Err(Error::msg(usage())),
                other if other.starts_with('-') => {
                    return Err(Error::msg(format!("unknown create option {other}")));
                }
                _ => {
                    if remote.replace(arg).is_some() {
                        return Err(Error::msg("create takes exactly one repository URL"));
                    }
                }
            }
        }
        Ok(Self {
            config_dir,
            rns_config_dir,
            identity_path,
            remote: remote.ok_or_else(|| Error::msg(usage()))?,
        })
    }
}

fn next_path(iter: &mut impl Iterator<Item = String>, flag: &str) -> Result<PathBuf> {
    iter.next()
        .map(PathBuf::from)
        .ok_or_else(|| Error::msg(format!("{flag} requires a value")))
}

fn usage() -> &'static str {
    "usage: rngit create [--config DIR] [--rnsconfig DIR] [-i|--identity PATH] <rns://destination/group/repo>"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_create_options() {
        let opts = CreateOptions::parse([
            "--config".into(),
            "cfg".into(),
            "--rnsconfig".into(),
            "rns".into(),
            "--identity".into(),
            "id".into(),
            "rns://00112233445566778899aabbccddeeff/group/repo".into(),
        ])
        .unwrap();
        assert_eq!(opts.config_dir, Some(PathBuf::from("cfg")));
        assert_eq!(opts.rns_config_dir, Some(PathBuf::from("rns")));
        assert_eq!(opts.identity_path, Some(PathBuf::from("id")));
        assert_eq!(
            opts.remote,
            "rns://00112233445566778899aabbccddeeff/group/repo"
        );
    }

    #[test]
    fn rejects_missing_create_remote() {
        assert!(CreateOptions::parse(Vec::<String>::new()).is_err());
    }
}
