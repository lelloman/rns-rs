use std::path::PathBuf;
use std::thread;
use std::time::Duration;

use rns_core::display::prettyb256rep;
use rns_core::msgpack::{self, Value};
use rns_core::types::IdentityHash;
use rns_crypto::identity::Identity;
use rns_net::ResourceStrategy;
use rns_net::{Callbacks, Destination, RequestResponse, RnsNode};

use crate::acl::Access;
use crate::config::ServerConfig;
use crate::logging;
use crate::pages;
use crate::protocol;
use crate::util::{default_reticulum_dir, default_rngit_dir, hex, load_or_create_identity};
use crate::{git, Error, Result};

mod perms;
mod releases;
mod repos;
mod work;

#[cfg(test)]
use perms::handle_permissions_step;
pub(crate) use perms::handle_perms;
pub use releases::{handle_release, handle_release_response};
pub(crate) use repos::{
    handle_create, handle_delete, handle_fork, handle_list, handle_mirror, handle_sync,
};
pub use repos::{handle_fetch, handle_push};
pub(crate) use work::handle_work;

/// Runs the `rngit` server with command-line `args` (without the program
/// name). Blocks for as long as the server runs; returns only on an error, or
/// after printing the identities when `--print-identity` is given.
///
/// # Errors
/// Bad arguments (`--help` returns the usage text as the error), no `git`
/// executable, or a failure loading the configuration, identity or Reticulum node.
pub fn main<I>(args: I) -> Result<()>
where
    I: IntoIterator<Item = String>,
{
    let options = ServerOptions::parse(args)?;
    git::check_git_available()?;

    let rngit_dir = options.config_dir.unwrap_or_else(default_rngit_dir);
    let rns_dir = options.rns_config_dir.or_else(default_reticulum_dir);
    let config = ServerConfig::load_or_create_for_run(rngit_dir, rns_dir)?;
    logging::init_file_logger(&config.dir.join("server_log"), config.log_level)?;

    let identity = load_or_create_identity(&config.identity_path)?;
    if options.print_identity {
        let client = load_or_create_identity(&config.client_identity_path)?;
        print_identity(&identity, &client, options.base256, config.serve_nomadnet);
        return Ok(());
    }

    run_server(config, identity)
}

pub(crate) fn run_server(config: ServerConfig, identity: Identity) -> Result<()> {
    let node = RnsNode::from_config(
        config.reticulum_dir.as_deref(),
        Box::<ServerCallbacks>::default(),
    )?;

    let announce_interval = Duration::from_secs(config.announce_interval_secs);
    let destinations = register_server_destinations(&node, config.clone(), &identity)?;

    loop {
        thread::sleep(announce_interval);
        let _ = node.announce_queued(&destinations.repositories, &identity, None);
        if let Some(page_destination) = destinations.nomadnet.as_ref() {
            let _ = node.announce_queued(
                page_destination,
                &identity,
                Some(config.node_name.as_bytes()),
            );
        }
    }
}

/// The destinations a server registers on its node.
#[derive(Debug)]
pub struct ServerDestinations {
    /// The repository protocol destination (`git.repositories`).
    pub repositories: Destination,
    /// The Nomad Network page destination (`nomadnetwork.node`), when pages are enabled.
    pub nomadnet: Option<Destination>,
}

/// Registers the repository destination and its request handlers on `node`,
/// plus the page destination when [`ServerConfig::serve_nomadnet`] is set, and
/// queues an announce for each. Creates the repositories directory if missing.
///
/// # Errors
/// `identity` has no private key, an access list in `config` is malformed, or
/// the node refuses a registration.
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

pub(crate) fn register_repository_destination(
    node: &RnsNode,
    config: ServerConfig,
    identity: &Identity,
) -> Result<Destination> {
    crate::util::ensure_dir(&config.repositories_dir)?;
    let access = Access::new_with_aliases(
        &config.allow_read,
        &config.allow_write,
        &config.allow_create,
        &config.allow_stats,
        &config.allow_release,
        &config.allow_interact,
        &config.allow_admin,
        config.repositories_dir.clone(),
        config.identity_aliases.clone(),
    )?
    .with_propose(&config.allow_propose)?
    .with_blocked_identities(config.blocked_identities.clone());
    let mut destination = Destination::single_in(
        protocol::APP_NAME,
        &[protocol::ASPECT_REPOSITORIES],
        IdentityHash(*identity.hash()),
    );
    config.costs.apply(node, &mut destination);
    let public_key = identity
        .get_public_key()
        .ok_or_else(|| Error::msg("repository identity has no public key"))?;
    let private_key = identity
        .get_private_key()
        .ok_or_else(|| Error::msg("repository identity has no private key"))?;
    let (_, sig_prv) = rns_crypto::identity::split_key(&private_key);
    let (_, sig_pub) = rns_crypto::identity::split_key(&public_key);

    node.register_link_destination(
        destination.hash.0,
        sig_prv,
        sig_pub,
        ResourceStrategy::AcceptAll as u8,
    )
    .map_err(|_| Error::msg("failed to register link destination"))?;
    register_handlers(node, config, access)?;
    node.announce_queued(&destination, identity, None)
        .map_err(|_| Error::msg("failed to announce rngit destination"))?;
    Ok(destination)
}

/// A request handler answering with status bytes.
type BytesHandler =
    fn(&ServerConfig, &Access, &[u8], Option<&([u8; 16], [u8; 64])>) -> Result<Vec<u8>>;

/// A request handler that may answer with a resource.
type ResponseHandler =
    fn(&ServerConfig, &Access, &[u8], Option<&([u8; 16], [u8; 64])>) -> Result<RequestResponse>;

fn register_handlers(node: &RnsNode, config: ServerConfig, access: Access) -> Result<()> {
    let register_bytes = |path: &str, name: &str, handler: BytesHandler| {
        let config = config.clone();
        let access = access.clone();
        node.register_request_handler(path, None, move |_link, _path, data, remote| {
            Some(handler(&config, &access, data, remote).unwrap_or_else(error_response))
        })
        .map_err(|_| Error::msg(format!("failed to register {name} handler")))
    };
    let register_response = |path: &str, name: &str, handler: ResponseHandler| {
        let config = config.clone();
        let access = access.clone();
        node.register_request_handler_response(path, None, move |_link, _path, data, remote| {
            Some(
                handler(&config, &access, data, remote)
                    .unwrap_or_else(|err| RequestResponse::Bytes(error_response(err))),
            )
        })
        .map_err(|_| Error::msg(format!("failed to register {name} handler")))
    };

    register_bytes(protocol::PATH_LIST, "list", handle_list)?;
    register_response(protocol::PATH_FETCH, "fetch", handle_fetch)?;
    register_bytes(protocol::PATH_PUSH, "push", handle_push)?;
    register_bytes(protocol::PATH_CREATE, "create", handle_create)?;
    register_bytes(protocol::PATH_FORK, "fork", handle_fork)?;
    register_bytes(protocol::PATH_SYNC, "sync", handle_sync)?;
    register_bytes(protocol::PATH_MIRROR, "mirror", handle_mirror)?;
    register_response(protocol::PATH_RELEASE, "release", handle_release_response)?;
    register_bytes(protocol::PATH_WORK, "work", handle_work)?;
    register_bytes(protocol::PATH_PERMS, "permissions", handle_perms_packed)?;
    register_bytes(protocol::PATH_DELETE, "delete", handle_delete)?;
    Ok(())
}

/// [`handle_perms`] with its status response, errors included, wrapped in a
/// msgpack bin as the permissions protocol expects.
fn handle_perms_packed(
    config: &ServerConfig,
    access: &Access,
    data: &[u8],
    remote: Option<&([u8; 16], [u8; 64])>,
) -> Result<Vec<u8>> {
    Ok(msgpack::pack(&Value::Bin(
        handle_perms(config, access, data, remote).unwrap_or_else(error_response),
    )))
}

fn error_response(err: Error) -> Vec<u8> {
    protocol::status_bytes(protocol::RES_INVALID_REQ, err.to_string())
}

fn remote_error_response(context: &str, repository: &str, err: impl std::fmt::Display) -> Vec<u8> {
    log::error!("rngit {context} failed for {repository}: {err}");
    protocol::status_bytes(protocol::RES_REMOTE_FAIL, b"Remote error")
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

impl Callbacks for ServerCallbacks {}

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
mod tests;
