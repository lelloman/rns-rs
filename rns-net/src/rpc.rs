//! RPC server and client for cross-process daemon communication.
//!
//! Implements Python `multiprocessing.connection` wire protocol:
//! - 4-byte big-endian signed i32 length prefix + payload
//! - HMAC-SHA256 challenge-response authentication
//! - msgpack serialization for request/response dictionaries
//!
//! Server translates RPC dicts into [`QueryRequest`] events, sends
//! them through the driver event channel, and returns RPC responses.

mod client;
mod handlers;
mod responses;
mod server;
mod stats;
#[cfg(test)]
mod tests;
mod wire;

use client::*;
pub use client::{RpcClient, SharedInstanceRpc};
pub(crate) use handlers::*;
pub use responses::discovered_interfaces_to_pickle;
pub(crate) use responses::*;
pub use server::RpcServer;
pub(crate) use server::*;
pub(crate) use stats::*;
pub use wire::derive_auth_key;
pub(crate) use wire::*;

use std::io::{self, Read, Write};
use std::net::{IpAddr, TcpListener, TcpStream};
#[cfg(target_os = "linux")]
use std::os::linux::net::SocketAddrExt;
#[cfg(target_os = "linux")]
use std::os::unix::net::{SocketAddr, UnixListener, UnixStream};
use std::sync::mpsc;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::thread;
use std::time::Duration;

use rns_core::msgpack::{self, Value as MsgpackValue};
use rns_core::transport::types::InterfaceId;
use rns_crypto::hmac::hmac_sha256;
use rns_crypto::sha256::sha256;

#[cfg(test)]
use crate::event::TrafficDetail;
use crate::event::{
    query, BackboneInterfaceEntry, BackbonePeerStateEntry, BlackholeInfo, BurstClassStats,
    DrainStatus, DynamicBurstStats, Event, EventSender, HookInfo, InterfaceStatsResponse,
    KnownDestinationEntry, LifecycleState, LinkDistributionEntry, PathTableEntry,
    ProviderBridgeStats, Query, QueryRequest, QueryResponse, RateTableEntry,
    RuntimeConfigApplyMode, RuntimeConfigEntry, RuntimeConfigError, RuntimeConfigErrorCode,
    RuntimeConfigSource, RuntimeConfigValue, SingleInterfaceStat,
};
use crate::listen::{Listener, ListenerWake};
use crate::pickle::{self, PickleValue};
use rns_crypto::md5::hmac_md5;

const CHALLENGE_PREFIX: &[u8] = b"#CHALLENGE#";
const WELCOME: &[u8] = b"#WELCOME#";
const FAILURE: &[u8] = b"#FAILURE#";
pub(crate) const CHALLENGE_LEN: usize = 40;
const MAX_CONCURRENT_RPC_CONNECTIONS: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RpcCodec {
    Msgpack,
    Pickle,
}

/// RPC address types.
#[derive(Debug, Clone)]
pub enum RpcAddr {
    /// A TCP server at this host and port.
    Tcp(String, u16),
    /// The RPC server of the local shared instance named `instance_name`.
    /// A client reaches it as upstream's do on Linux, on the abstract socket
    /// `\0rns/<instance_name>/rpc`; where that socket is not there (another
    /// platform, or a Python instance with `shared_instance_type = tcp`), it
    /// uses TCP on 127.0.0.1 and `port`. A shared instance serves RPC on
    /// one of the two: the abstract socket (`RpcServer::start_abstract_unix`)
    /// where it can, else TCP.
    Local {
        /// The shared instance's name.
        instance_name: String,
        /// The TCP port used where the abstract socket is not available.
        port: u16,
    },
}

impl RpcAddr {
    /// The RPC server of the local shared instance a config describes: on
    /// TCP for `shared_instance_type = tcp`, else as [`RpcAddr::Local`].
    pub fn for_shared_instance(reticulum: &crate::config::ReticulumSection) -> Self {
        if reticulum.shared_instance_tcp {
            RpcAddr::Tcp("127.0.0.1".into(), reticulum.instance_control_port)
        } else {
            RpcAddr::local(
                reticulum.instance_name.clone(),
                reticulum.instance_control_port,
            )
        }
    }

    /// Whether a server accepts connections here, without authenticating:
    /// a readiness check.
    pub fn accepts_connections(&self) -> io::Result<()> {
        ClientStream::connect(self).map(drop)
    }

    /// The RPC server of the local shared instance; see [`RpcAddr::Local`].
    pub fn local(instance_name: impl Into<String>, port: u16) -> Self {
        RpcAddr::Local {
            instance_name: instance_name.into(),
            port,
        }
    }
}

/// Entry points for the fuzz targets in `fuzz/`: what a local client can
/// send the RPC server. Not a stable API.
#[doc(hidden)]
pub mod fuzz {
    use super::*;

    const AUTH_KEY: [u8; 32] = [0x5a; 32];

    /// Bytes from a client that has not authenticated: the framing and the
    /// challenge exchange, which any local process can reach.
    pub fn handshake(data: &[u8]) {
        let mut session = ServerSession::new(AUTH_KEY, [0x3c; CHALLENGE_LEN]);
        for chunk in data.chunks(9) {
            if session.receive(chunk).is_err() {
                break;
            }
        }
    }

    /// A request from an authenticated client, answered by a driver that
    /// knows nothing: decoding it and reading its arguments.
    pub fn request(data: &[u8]) {
        let _ = answer_request(data, &mut NoDriver);
    }

    struct NoDriver;

    impl RpcDriver for NoDriver {
        fn query(&mut self, _: QueryRequest) -> io::Result<QueryResponse> {
            Err(io::Error::other("no driver"))
        }

        fn send(&mut self, _: Event) -> io::Result<()> {
            Ok(())
        }

        fn inbound_queue_snapshot(&self) -> crate::event::InboundQueueSnapshot {
            crate::event::InboundQueueSnapshot {
                heights: Default::default(),
                capacities: Default::default(),
                dropped: Default::default(),
            }
        }

        fn dynamic_burst_stats(&self, _: InterfaceId) -> Option<DynamicBurstStats> {
            None
        }
    }

    #[cfg(test)]
    mod tests {
        #[test]
        fn fuzz_entry_points_take_any_bytes() {
            let get_path_table = crate::pickle::encode(&crate::pickle::PickleValue::Dict(vec![(
                crate::pickle::PickleValue::String("get".into()),
                crate::pickle::PickleValue::String("path_table".into()),
            )]));
            let inputs: [&[u8]; 5] = [
                b"",
                &[0xff, 0xff, 0xff, 0xff, 0, 0, 0, 0, 0xff, 0xff, 0xff, 0xff],
                &[0, 0, 0, 3, b'a', b'b', b'c'],
                &[0x80; 64],
                &get_path_table,
            ];
            for data in inputs {
                super::handshake(data);
                super::request(data);
            }
        }
    }
}
