use std::path::PathBuf;
use std::thread;
use std::time::Duration;

use rns_core::types::IdentityHash;
use rns_crypto::identity::Identity;
use rns_net::link_manager::ResourceStrategy;
use rns_net::{
    AnnouncedIdentity, Callbacks, DestHash, Destination, PacketHash, RequestResponse, RnsNode,
};

use crate::acl::{Access, Operation};
use crate::config::ServerConfig;
use crate::protocol;
use crate::util::{default_reticulum_dir, default_rngit_dir, hex, load_or_create_identity};
use crate::{git, Error, Result};

pub fn main<I>(args: I) -> Result<()>
where
    I: IntoIterator<Item = String>,
{
    let options = ServerOptions::parse(args)?;
    git::check_git_available()?;

    let rngit_dir = options.config_dir.unwrap_or_else(default_rngit_dir);
    let rns_dir = options.rns_config_dir.or_else(default_reticulum_dir);
    let (config, created) = ServerConfig::load_or_create(rngit_dir, rns_dir)?;
    if created {
        return Err(Error::msg(format!(
            "created default config at {}; edit it and run rngit again",
            config.dir.join("server_config").display()
        )));
    }

    let identity = load_or_create_identity(&config.identity_path)?;
    if options.print_identity {
        let client = load_or_create_identity(&config.client_identity_path)?;
        print_identity(&identity, &client);
        return Ok(());
    }

    run_server(config, identity)
}

pub fn run_server(config: ServerConfig, identity: Identity) -> Result<()> {
    let node = RnsNode::from_config(
        config.reticulum_dir.as_deref(),
        Box::<ServerCallbacks>::default(),
    )?;

    let announce_interval = Duration::from_secs(config.announce_interval_secs);
    let destination = register_repository_destination(&node, config, &identity)?;

    loop {
        thread::sleep(announce_interval);
        let _ = node.announce(&destination, &identity, None);
    }
}

pub fn register_repository_destination(
    node: &RnsNode,
    config: ServerConfig,
    identity: &Identity,
) -> Result<Destination> {
    crate::util::ensure_dir(&config.repositories_dir)?;
    let access = Access::new(
        &config.allow_read,
        &config.allow_write,
        config.repositories_dir.clone(),
    )?;
    let destination = Destination::single_in(
        protocol::APP_NAME,
        &[protocol::ASPECT_REPOSITORIES],
        IdentityHash(*identity.hash()),
    );
    let public_key = identity
        .get_public_key()
        .ok_or_else(|| Error::msg("repository identity has no public key"))?;
    let private_key = identity
        .get_private_key()
        .ok_or_else(|| Error::msg("repository identity has no private key"))?;
    let sig_prv: [u8; 32] = private_key[32..64].try_into().unwrap();
    let sig_pub: [u8; 32] = public_key[32..64].try_into().unwrap();

    node.register_link_destination(
        destination.hash.0,
        sig_prv,
        sig_pub,
        ResourceStrategy::AcceptAll as u8,
    )
    .map_err(|_| Error::msg("failed to register link destination"))?;
    register_handlers(node, config, access)?;
    node.announce(&destination, identity, None)
        .map_err(|_| Error::msg("failed to announce rngit destination"))?;
    Ok(destination)
}

fn register_handlers(node: &RnsNode, config: ServerConfig, access: Access) -> Result<()> {
    let list_config = config.clone();
    let list_access = access.clone();
    node.register_request_handler(
        protocol::PATH_LIST,
        None,
        move |_link, _path, data, remote| {
            Some(
                handle_list(&list_config, &list_access, data, remote)
                    .unwrap_or_else(error_response),
            )
        },
    )
    .map_err(|_| Error::msg("failed to register list handler"))?;

    let fetch_config = config.clone();
    let fetch_access = access.clone();
    node.register_request_handler_response(
        protocol::PATH_FETCH,
        None,
        move |_link, _path, data, remote| {
            Some(
                handle_fetch(&fetch_config, &fetch_access, data, remote)
                    .unwrap_or_else(|err| RequestResponse::Bytes(error_response(err))),
            )
        },
    )
    .map_err(|_| Error::msg("failed to register fetch handler"))?;

    let push_config = config.clone();
    let push_access = access.clone();
    node.register_request_handler(
        protocol::PATH_PUSH,
        None,
        move |_link, _path, data, remote| {
            Some(
                handle_push(&push_config, &push_access, data, remote)
                    .unwrap_or_else(error_response),
            )
        },
    )
    .map_err(|_| Error::msg("failed to register push handler"))?;

    node.register_request_handler(
        protocol::PATH_DELETE,
        None,
        move |_link, _path, data, remote| {
            Some(handle_delete(&config, &access, data, remote).unwrap_or_else(error_response))
        },
    )
    .map_err(|_| Error::msg("failed to register delete handler"))?;

    Ok(())
}

pub fn handle_list(
    config: &ServerConfig,
    access: &Access,
    data: &[u8],
    remote: Option<&([u8; 16], [u8; 64])>,
) -> Result<Vec<u8>> {
    let repo = protocol::repository_from_request(data)?;
    let remote_hash = remote.map(|(hash, _)| hash);
    if !access.allows(Operation::Read, &repo, remote_hash)? {
        return Ok(protocol::status_bytes(
            protocol::RES_DISALLOWED,
            b"read denied",
        ));
    }
    let path = git::repository_path(&config.repositories_dir, &repo)?;
    match git::list_refs_text(&path) {
        Ok(refs) => Ok(protocol::status_bytes(protocol::RES_OK, refs)),
        Err(err) if err.to_string() == "repository not found" => Ok(protocol::status_bytes(
            protocol::RES_NOT_FOUND,
            b"repository not found",
        )),
        Err(err) => Ok(protocol::status_bytes(
            protocol::RES_REMOTE_FAIL,
            err.to_string(),
        )),
    }
}

pub fn handle_fetch(
    config: &ServerConfig,
    access: &Access,
    data: &[u8],
    remote: Option<&([u8; 16], [u8; 64])>,
) -> Result<RequestResponse> {
    let (repo, have) = protocol::parse_fetch_request(data)?;
    let remote_hash = remote.map(|(hash, _)| hash);
    if !access.allows(Operation::Read, &repo, remote_hash)? {
        return Ok(RequestResponse::Bytes(protocol::status_bytes(
            protocol::RES_DISALLOWED,
            b"read denied",
        )));
    }
    let path = git::repository_path(&config.repositories_dir, &repo)?;
    match git::create_bundle(&path, &have) {
        Ok(bundle) if bundle.is_empty() => Ok(RequestResponse::Bytes(protocol::status_bytes(
            protocol::RES_OK,
            Vec::new(),
        ))),
        Ok(bundle) => Ok(RequestResponse::Resource {
            data: bundle,
            metadata: Some(protocol::metadata_status(protocol::RES_OK)),
            auto_compress: true,
        }),
        Err(err) if err.to_string() == "repository not found" => Ok(RequestResponse::Bytes(
            protocol::status_bytes(protocol::RES_NOT_FOUND, b"repository not found"),
        )),
        Err(err) => Ok(RequestResponse::Bytes(protocol::status_bytes(
            protocol::RES_REMOTE_FAIL,
            err.to_string(),
        ))),
    }
}

pub fn handle_push(
    config: &ServerConfig,
    access: &Access,
    data: &[u8],
    remote: Option<&([u8; 16], [u8; 64])>,
) -> Result<Vec<u8>> {
    let (repo, bundle, updates) = protocol::parse_push_request(data)?;
    let remote_hash = remote.map(|(hash, _)| hash);
    if !access.allows(Operation::Write, &repo, remote_hash)? {
        return Ok(protocol::status_bytes(
            protocol::RES_DISALLOWED,
            b"write denied",
        ));
    }
    let path = git::repository_path(&config.repositories_dir, &repo)?;
    match git::apply_push(&path, &bundle, &updates) {
        Ok(()) => Ok(protocol::status_bytes(protocol::RES_OK, b"ok")),
        Err(err) => Ok(protocol::status_bytes(
            protocol::RES_REMOTE_FAIL,
            err.to_string(),
        )),
    }
}

pub fn handle_delete(
    config: &ServerConfig,
    access: &Access,
    data: &[u8],
    remote: Option<&([u8; 16], [u8; 64])>,
) -> Result<Vec<u8>> {
    let repo = protocol::repository_from_request(data)?;
    let remote_hash = remote.map(|(hash, _)| hash);
    if !access.allows(Operation::Write, &repo, remote_hash)? {
        return Ok(protocol::status_bytes(
            protocol::RES_DISALLOWED,
            b"write denied",
        ));
    }
    let path = git::repository_path(&config.repositories_dir, &repo)?;
    if !path.exists() {
        return Ok(protocol::status_bytes(
            protocol::RES_NOT_FOUND,
            b"repository not found",
        ));
    }
    std::fs::remove_dir_all(path)?;
    Ok(protocol::status_bytes(protocol::RES_OK, b"deleted"))
}

fn error_response(err: Error) -> Vec<u8> {
    protocol::status_bytes(protocol::RES_INVALID_REQ, err.to_string())
}

fn print_identity(identity: &Identity, client: &Identity) {
    let destination = Destination::single_in(
        protocol::APP_NAME,
        &[protocol::ASPECT_REPOSITORIES],
        IdentityHash(*identity.hash()),
    );
    println!("client_identity = {}", hex(client.hash()));
    println!("repository_identity = {}", hex(identity.hash()));
    println!("destination = {}", hex(&destination.hash.0));
}

#[derive(Default)]
struct ServerCallbacks;

impl Callbacks for ServerCallbacks {
    fn on_announce(&mut self, _announced: AnnouncedIdentity) {}

    fn on_path_updated(&mut self, _dest_hash: DestHash, _hops: u8) {}

    fn on_local_delivery(&mut self, _dest_hash: DestHash, _raw: Vec<u8>, _packet_hash: PacketHash) {
    }
}

#[derive(Debug, Default)]
struct ServerOptions {
    config_dir: Option<PathBuf>,
    rns_config_dir: Option<PathBuf>,
    print_identity: bool,
}

impl ServerOptions {
    fn parse<I>(args: I) -> Result<Self>
    where
        I: IntoIterator<Item = String>,
    {
        let mut options = ServerOptions::default();
        let mut args = args.into_iter();
        while let Some(arg) = args.next() {
            match arg.as_str() {
                "-c" | "--config" => {
                    options.config_dir = Some(PathBuf::from(
                        args.next()
                            .ok_or_else(|| Error::msg("missing config path"))?,
                    ));
                }
                "--rnsconfig" => {
                    options.rns_config_dir = Some(PathBuf::from(
                        args.next()
                            .ok_or_else(|| Error::msg("missing RNS config path"))?,
                    ));
                }
                "--print-identity" => options.print_identity = true,
                "--service" | "--interactive" => {}
                "-h" | "--help" => return Err(Error::msg(usage())),
                other => {
                    return Err(Error::msg(format!(
                        "unknown argument: {other}\n{}",
                        usage()
                    )))
                }
            }
        }
        Ok(options)
    }
}

fn usage() -> &'static str {
    "usage: rngit [--config DIR] [--rnsconfig DIR] [--print-identity] [--service]"
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(root: &std::path::Path) -> ServerConfig {
        ServerConfig {
            dir: root.to_path_buf(),
            reticulum_dir: None,
            repositories_dir: root.join("repositories"),
            identity_path: root.join("repositories_identity"),
            client_identity_path: root.join("client_identity"),
            announce_interval_secs: 300,
            allow_read: vec!["all".into()],
            allow_write: vec!["all".into()],
        }
    }

    #[test]
    fn list_missing_repo_returns_not_found_status() {
        let tmp = tempfile::tempdir().unwrap();
        let config = cfg(tmp.path());
        let access = Access::new(
            &config.allow_read,
            &config.allow_write,
            config.repositories_dir.clone(),
        )
        .unwrap();
        let req = protocol::repository_request("group/repo");
        let resp = handle_list(&config, &access, &req, None).unwrap();
        assert_eq!(resp[0], protocol::RES_NOT_FOUND);
    }

    #[test]
    fn push_is_blocked_by_acl() {
        let tmp = tempfile::tempdir().unwrap();
        let mut config = cfg(tmp.path());
        config.allow_write = vec!["none".into()];
        let access = Access::new(
            &config.allow_read,
            &config.allow_write,
            config.repositories_dir.clone(),
        )
        .unwrap();
        let req = protocol::push_request("repo", Vec::new(), Vec::new());
        let resp = handle_push(&config, &access, &req, None).unwrap();
        assert_eq!(resp[0], protocol::RES_DISALLOWED);
    }

    #[test]
    fn fetch_existing_repo_can_return_ok_status_or_resource() {
        let tmp = tempfile::tempdir().unwrap();
        let config = cfg(tmp.path());
        let access = Access::new(
            &config.allow_read,
            &config.allow_write,
            config.repositories_dir.clone(),
        )
        .unwrap();
        let repo = config.repositories_dir.join("repo");
        git::ensure_bare_repository(&repo).unwrap();
        let req = protocol::fetch_request("repo", &[]);
        match handle_fetch(&config, &access, &req, None).unwrap() {
            RequestResponse::Bytes(bytes) => assert_eq!(bytes[0], protocol::RES_OK),
            RequestResponse::Resource { metadata, .. } => assert!(metadata.is_some()),
        }
    }
}
