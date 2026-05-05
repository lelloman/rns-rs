use std::path::PathBuf;
use std::thread;
use std::time::Duration;

use rns_core::display::prettyb256rep;
use rns_core::types::IdentityHash;
use rns_crypto::identity::Identity;
use rns_net::link_manager::ResourceStrategy;
use rns_net::{
    AnnouncedIdentity, Callbacks, DestHash, Destination, PacketHash, RequestResponse, RnsNode,
};

use crate::acl::{Access, Operation};
use crate::config::ServerConfig;
use crate::logging;
use crate::pages;
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
    logging::init_file_logger(&config.dir.join("server_log"), config.log_level)?;
    if created {
        return Err(Error::msg(format!(
            "created default config at {}; edit it and run rngit again",
            config.dir.join("server_config").display()
        )));
    }

    let identity = load_or_create_identity(&config.identity_path)?;
    if options.print_identity {
        let client = load_or_create_identity(&config.client_identity_path)?;
        print_identity(&identity, &client, options.base256, config.serve_nomadnet);
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
    let destinations = register_server_destinations(&node, config.clone(), &identity)?;

    loop {
        thread::sleep(announce_interval);
        let _ = node.announce(&destinations.repositories, &identity, None);
        if let Some(page_destination) = destinations.nomadnet.as_ref() {
            let _ = node.announce(
                page_destination,
                &identity,
                Some(config.node_name.as_bytes()),
            );
        }
    }
}

#[derive(Debug)]
pub struct ServerDestinations {
    pub repositories: Destination,
    pub nomadnet: Option<Destination>,
}

pub fn register_server_destinations(
    node: &RnsNode,
    config: ServerConfig,
    identity: &Identity,
) -> Result<ServerDestinations> {
    let repositories = register_repository_destination(node, config.clone(), identity)?;
    let nomadnet = if config.serve_nomadnet {
        Some(pages::register_nomadnet_destination(
            node, &config, identity,
        )?)
    } else {
        None
    };
    Ok(ServerDestinations {
        repositories,
        nomadnet,
    })
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
        &config.allow_create,
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
    let path = git::repository_path(&config.repositories_dir, &repo)?;
    let op = if git::is_bare_repository(&path) {
        Operation::Write
    } else {
        Operation::Create
    };
    if !access.allows(op, &repo, remote_hash)? {
        let message = match op {
            Operation::Create => b"create denied".as_slice(),
            Operation::Write => b"write denied".as_slice(),
            Operation::Read => b"read denied".as_slice(),
        };
        return Ok(protocol::status_bytes(protocol::RES_DISALLOWED, message));
    }
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

fn repository_destination(identity: &Identity) -> Destination {
    Destination::single_in(
        protocol::APP_NAME,
        &[protocol::ASPECT_REPOSITORIES],
        IdentityHash(*identity.hash()),
    )
}

fn identity_report(
    identity: &Identity,
    client: &Identity,
    base256: bool,
    serve_nomadnet: bool,
) -> String {
    let destination = repository_destination(identity);
    let mut out = String::new();
    out.push_str(&format!("client_identity = {}\n", hex(client.hash())));
    if base256 {
        out.push_str(&format!(
            "client_identity_b256 = {}\n",
            prettyb256rep(client.hash())
        ));
    }
    out.push_str(&format!("repository_identity = {}\n", hex(identity.hash())));
    if base256 {
        out.push_str(&format!(
            "repository_identity_b256 = {}",
            prettyb256rep(identity.hash())
        ));
        out.push('\n');
    }
    out.push_str(&format!("destination = {}\n", hex(&destination.hash.0)));
    if base256 {
        out.push_str(&format!(
            "destination_b256 = {}\n",
            prettyb256rep(&destination.hash.0)
        ));
    }
    if serve_nomadnet {
        let page_destination = pages::destination_for_identity(identity);
        out.push_str(&format!(
            "nomadnet_destination = {}\n",
            hex(&page_destination.hash.0)
        ));
        if base256 {
            out.push_str(&format!(
                "nomadnet_destination_b256 = {}\n",
                prettyb256rep(&page_destination.hash.0)
            ));
        }
    }
    out
}

fn print_identity(identity: &Identity, client: &Identity, base256: bool, serve_nomadnet: bool) {
    print!(
        "{}",
        identity_report(identity, client, base256, serve_nomadnet)
    );
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
    base256: bool,
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
                "-Z" | "--base256" => options.base256 = true,
                "--service" | "--interactive" => {
                    return Err(Error::msg(format!(
                        "{arg} is not supported by this rngit binary\n{}",
                        usage()
                    )))
                }
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
    "usage: rngit [--config DIR] [--rnsconfig DIR] [--print-identity] [-Z|--base256]"
}

#[cfg(test)]
mod tests {
    use super::*;
    use rns_crypto::OsRng;

    fn cfg(root: &std::path::Path) -> ServerConfig {
        ServerConfig {
            dir: root.to_path_buf(),
            reticulum_dir: None,
            repositories_dir: root.join("repositories"),
            identity_path: root.join("repositories_identity"),
            client_identity_path: root.join("client_identity"),
            node_name: "Anonymous Git Node".into(),
            announce_interval_secs: 300,
            serve_nomadnet: false,
            allow_read: vec!["all".into()],
            allow_write: vec!["all".into()],
            allow_create: vec!["all".into()],
            log_level: logging::DEFAULT_LOG_LEVEL,
        }
    }

    #[test]
    fn parses_base256_print_identity_options() {
        let opts = ServerOptions::parse(vec![
            "--print-identity".to_string(),
            "--base256".to_string(),
        ])
        .unwrap();
        assert!(opts.print_identity);
        assert!(opts.base256);

        let short = ServerOptions::parse(vec!["-Z".to_string()]).unwrap();
        assert!(short.base256);
    }

    #[test]
    fn rejects_unsupported_service_mode_flags() {
        let service = ServerOptions::parse(vec!["--service".to_string()]).unwrap_err();
        assert!(service.to_string().contains("not supported"));

        let interactive = ServerOptions::parse(vec!["--interactive".to_string()]).unwrap_err();
        assert!(interactive.to_string().contains("not supported"));
    }

    #[test]
    fn repository_destination_uses_git_repositories_name() {
        let identity = Identity::new(&mut OsRng);
        let destination = repository_destination(&identity);
        let expected =
            Destination::single_in("git", &["repositories"], IdentityHash(*identity.hash()));
        assert_eq!(destination.hash, expected.hash);
    }

    #[test]
    fn identity_report_includes_nomadnet_destination_only_when_enabled() {
        let identity = Identity::new(&mut OsRng);
        let client = Identity::new(&mut OsRng);

        let without_pages = identity_report(&identity, &client, false, false);
        assert!(!without_pages.contains("nomadnet_destination"));

        let with_pages = identity_report(&identity, &client, true, true);
        let nomadnet = pages::destination_for_identity(&identity);
        assert!(with_pages.contains(&format!("nomadnet_destination = {}", hex(&nomadnet.hash.0))));
        assert!(with_pages.contains("nomadnet_destination_b256 = "));
    }

    #[test]
    fn list_missing_repo_returns_not_found_status() {
        let tmp = tempfile::tempdir().unwrap();
        let config = cfg(tmp.path());
        let access = Access::new(
            &config.allow_read,
            &config.allow_write,
            &config.allow_create,
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
        config.allow_create = vec!["none".into()];
        let access = Access::new(
            &config.allow_read,
            &config.allow_write,
            &config.allow_create,
            config.repositories_dir.clone(),
        )
        .unwrap();
        let req = protocol::push_request("repo", Vec::new(), Vec::new());
        let resp = handle_push(&config, &access, &req, None).unwrap();
        assert_eq!(resp[0], protocol::RES_DISALLOWED);
    }

    #[test]
    fn push_can_create_missing_repo_with_global_create() {
        let tmp = tempfile::tempdir().unwrap();
        let mut config = cfg(tmp.path());
        config.allow_write = vec!["none".into()];
        config.allow_create = vec!["all".into()];
        let access = Access::new(
            &config.allow_read,
            &config.allow_write,
            &config.allow_create,
            config.repositories_dir.clone(),
        )
        .unwrap();
        let req = protocol::push_request("repo", Vec::new(), Vec::new());
        let resp = handle_push(&config, &access, &req, None).unwrap();
        assert_eq!(resp[0], protocol::RES_OK);
        assert!(git::is_bare_repository(
            &config.repositories_dir.join("repo")
        ));
    }

    #[test]
    fn global_write_alone_cannot_create_missing_repo() {
        let tmp = tempfile::tempdir().unwrap();
        let mut config = cfg(tmp.path());
        config.allow_write = vec!["all".into()];
        config.allow_create = vec!["none".into()];
        let access = Access::new(
            &config.allow_read,
            &config.allow_write,
            &config.allow_create,
            config.repositories_dir.clone(),
        )
        .unwrap();
        let req = protocol::push_request("repo", Vec::new(), Vec::new());
        let resp = handle_push(&config, &access, &req, None).unwrap();
        assert_eq!(resp[0], protocol::RES_DISALLOWED);
        assert!(!config.repositories_dir.join("repo").exists());
    }

    #[test]
    fn existing_repo_push_still_requires_write() {
        let tmp = tempfile::tempdir().unwrap();
        let mut config = cfg(tmp.path());
        config.allow_write = vec!["none".into()];
        config.allow_create = vec!["all".into()];
        git::ensure_bare_repository(&config.repositories_dir.join("repo")).unwrap();
        let access = Access::new(
            &config.allow_read,
            &config.allow_write,
            &config.allow_create,
            config.repositories_dir.clone(),
        )
        .unwrap();
        let req = protocol::push_request("repo", Vec::new(), Vec::new());
        let resp = handle_push(&config, &access, &req, None).unwrap();
        assert_eq!(resp[0], protocol::RES_DISALLOWED);
    }

    #[test]
    fn repo_allowed_file_can_grant_create_for_missing_bare_repo() {
        let tmp = tempfile::tempdir().unwrap();
        let mut config = cfg(tmp.path());
        config.allow_write = vec!["none".into()];
        config.allow_create = vec!["none".into()];
        let repo = config.repositories_dir.join("group/repo");
        std::fs::create_dir_all(&repo).unwrap();
        std::fs::write(repo.join(".allowed"), "create = all\n").unwrap();
        let access = Access::new(
            &config.allow_read,
            &config.allow_write,
            &config.allow_create,
            config.repositories_dir.clone(),
        )
        .unwrap();
        let req = protocol::push_request("group/repo", Vec::new(), Vec::new());
        let resp = handle_push(&config, &access, &req, None).unwrap();
        assert_eq!(resp[0], protocol::RES_OK);
        assert!(git::is_bare_repository(&repo));
    }

    #[test]
    fn group_allowed_file_can_grant_create_for_missing_repo() {
        let tmp = tempfile::tempdir().unwrap();
        let mut config = cfg(tmp.path());
        config.allow_write = vec!["none".into()];
        config.allow_create = vec!["none".into()];
        let group = config.repositories_dir.join("group");
        std::fs::create_dir_all(&group).unwrap();
        std::fs::write(group.join("group.allowed"), "create = all\n").unwrap();
        let access = Access::new(
            &config.allow_read,
            &config.allow_write,
            &config.allow_create,
            config.repositories_dir.clone(),
        )
        .unwrap();
        let req = protocol::push_request("group/repo", Vec::new(), Vec::new());
        let resp = handle_push(&config, &access, &req, None).unwrap();
        assert_eq!(resp[0], protocol::RES_OK);
        assert!(git::is_bare_repository(
            &config.repositories_dir.join("group/repo")
        ));
    }

    #[test]
    fn push_rejects_invalid_repository_name_before_create_acl() {
        let tmp = tempfile::tempdir().unwrap();
        let mut config = cfg(tmp.path());
        config.allow_write = vec!["none".into()];
        config.allow_create = vec!["all".into()];
        let access = Access::new(
            &config.allow_read,
            &config.allow_write,
            &config.allow_create,
            config.repositories_dir.clone(),
        )
        .unwrap();
        let req = protocol::push_request("../repo", Vec::new(), Vec::new());
        assert!(handle_push(&config, &access, &req, None).is_err());
    }

    #[test]
    fn fetch_existing_repo_can_return_ok_status_or_resource() {
        let tmp = tempfile::tempdir().unwrap();
        let config = cfg(tmp.path());
        let access = Access::new(
            &config.allow_read,
            &config.allow_write,
            &config.allow_create,
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
