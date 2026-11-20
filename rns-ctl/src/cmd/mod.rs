//! The `rns-ctl` subcommands. Each `run` takes the subcommand's parsed
//! arguments, prints its output and returns its exit status (runtime errors
//! give 1); argument errors still exit the process with status 2.

/// `rns-ctl backbone`: backbone peer state, blacklist and provider info.
pub mod backbone;
/// `rns-ctl config`: runtime configuration of a running node.
pub mod config;
/// `rns-ctl daemon`: run the node daemon, as `rnsd`.
pub mod daemon;
pub mod hook;
pub mod http;
/// `rns-ctl id`: identity management, as `rnid`.
pub mod id;
/// `rns-ctl path`: path table display and management, as `rnpath`.
pub mod path;
/// `rns-ctl probe`: path reachability probes, as `rnprobe`.
pub mod probe;
/// `rns-ctl status`: interface status, as `rnstatus`.
pub mod status;

use std::path::Path;

use rns_cli::exit::Exit;
use rns_cli::shared_instance::LocalInstance;
use rns_net::pickle::PickleValue;
use rns_net::RpcClient;

/// A client of the shared instance's RPC server in the config directory at
/// `config_path`; on a failure, the error printed and status 1.
pub(crate) fn connect_rpc(config_path: Option<&str>) -> Result<RpcClient, Exit> {
    let config_dir = rns_net::storage::resolve_config_dir(config_path.map(Path::new));
    let rpc = match LocalInstance::open(&config_dir) {
        Ok(instance) => instance.rpc,
        Err(e) => {
            eprintln!("{e}");
            return Err(Exit::FAILURE);
        }
    };
    rpc.connect().map_err(|e| {
        eprintln!("Could not connect to rnsd: {}", e);
        eprintln!("Is rnsd running?");
        Exit::FAILURE
    })
}

/// One RPC call; on a failure, the error printed and status 1.
pub(crate) fn rpc_call(client: &mut RpcClient, request: PickleValue) -> Result<PickleValue, Exit> {
    client.call(&request).map_err(|e| {
        eprintln!("RPC error: {}", e);
        Exit::FAILURE
    })
}
