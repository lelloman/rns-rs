use std::collections::VecDeque;
use std::io::{self, BufRead, Write};
use std::path::PathBuf;
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use rns_core::msgpack::{self, Value};
use rns_core::types::{DestHash, LinkId};
use rns_net::{AnnouncedIdentity, Callbacks, PacketHash, RnsNode};

use crate::config::ClientConfig;
use crate::protocol::{self, RefUpdate};
use crate::util::{
    default_reticulum_dir, default_rngit_dir, load_or_create_identity, parse_rns_url,
};
use crate::{git, Error, Result};

pub fn main<I>(args: I) -> Result<()>
where
    I: IntoIterator<Item = String>,
{
    let options = ClientOptions::parse(args)?;
    let (dest_hash, repository) = parse_rns_url(&options.url)?;
    let rngit_dir = options.config_dir.unwrap_or_else(default_rngit_dir);
    let rns_dir = options.rns_config_dir.or_else(default_reticulum_dir);
    let (config, created) = ClientConfig::load_or_create(rngit_dir, rns_dir)?;
    if created {
        return Err(Error::msg(format!(
            "created default config at {}; edit it and run again",
            config.dir.join("client_config").display()
        )));
    }

    let helper = RemoteHelper::connect(config, dest_hash)?;
    helper.run(repository)
}

struct RemoteHelper {
    client: SyncClient,
}

impl RemoteHelper {
    fn connect(config: ClientConfig, dest_hash: [u8; 16]) -> Result<Self> {
        let callbacks = SharedCallbacks::default();
        let state = callbacks.state.clone();
        let node = RnsNode::from_config(config.reticulum_dir.as_deref(), Box::new(callbacks))?;
        let client_identity = load_or_create_identity(&config.identity_path)?;

        let dest = DestHash(dest_hash);
        node.request_path(&dest)
            .map_err(|_| Error::msg("failed to request destination path"))?;
        let deadline = Instant::now() + Duration::from_secs(config.connect_timeout_secs);
        while !node.has_path(&dest).unwrap_or(false) && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(250));
        }

        let recalled = node
            .recall_identity(&dest)
            .map_err(|_| Error::msg("failed to recall destination identity"))?
            .ok_or_else(|| Error::msg("destination identity is unknown"))?;
        let sig_pub: [u8; 32] = recalled.public_key[32..64].try_into().unwrap();
        let link_id = node
            .create_link(dest_hash, sig_pub)
            .map_err(|_| Error::msg("failed to create RNS link"))?;
        let private_key = client_identity
            .get_private_key()
            .ok_or_else(|| Error::msg("client identity has no private key"))?;
        node.identify_on_link(link_id, private_key)
            .map_err(|_| Error::msg("failed to identify on RNS link"))?;

        wait_for_link(
            &state,
            link_id,
            Duration::from_secs(config.connect_timeout_secs),
        )?;
        Ok(Self {
            client: SyncClient {
                node,
                link_id,
                state,
                request_timeout: Duration::from_secs(config.request_timeout_secs),
            },
        })
    }

    fn run(self, repository: String) -> Result<()> {
        let stdin = io::stdin();
        let stdout = io::stdout();
        self.run_io(repository, stdin.lock(), stdout.lock())
    }

    fn run_io<R: BufRead, W: Write>(
        &self,
        repository: String,
        mut input: R,
        mut output: W,
    ) -> Result<()> {
        let mut line = String::new();
        let mut fetch_refs = Vec::new();
        let mut push_specs = Vec::new();

        loop {
            line.clear();
            if input.read_line(&mut line)? == 0 {
                break;
            }
            let command = line.trim_end();
            if command.is_empty() {
                if !fetch_refs.is_empty() {
                    self.fetch(&repository, &fetch_refs)?;
                    fetch_refs.clear();
                    writeln!(output)?;
                    output.flush()?;
                }
                if !push_specs.is_empty() {
                    for spec in push_specs.drain(..) {
                        self.push(&repository, &spec)?;
                        writeln!(output, "ok {}", spec.remote)?;
                    }
                    writeln!(output)?;
                    output.flush()?;
                }
                continue;
            }

            if command == "capabilities" {
                writeln!(output, "option")?;
                writeln!(output, "list")?;
                writeln!(output, "fetch")?;
                writeln!(output, "push")?;
                writeln!(output)?;
            } else if command == "list" || command == "list for-push" {
                let refs = self.list(&repository)?;
                output.write_all(&refs)?;
                writeln!(output)?;
            } else if let Some(rest) = command.strip_prefix("option ") {
                let _ = rest;
                writeln!(output, "ok")?;
            } else if let Some(rest) = command.strip_prefix("fetch ") {
                fetch_refs.push(parse_fetch_command(rest)?);
            } else if let Some(rest) = command.strip_prefix("push ") {
                push_specs.push(parse_push_spec(rest)?);
            } else {
                writeln!(output, "error unsupported command")?;
            }
            output.flush()?;
        }
        Ok(())
    }

    fn list(&self, repository: &str) -> Result<Vec<u8>> {
        let response = self.client.request(
            protocol::PATH_LIST,
            protocol::repository_request(repository),
        )?;
        let bytes = protocol::response_bin(&response.data)?;
        decode_status(bytes)
    }

    fn fetch(&self, repository: &str, refs: &[FetchRef]) -> Result<()> {
        let have = refs.iter().map(|r| r.sha.clone()).collect::<Vec<_>>();
        let response = self.client.request(
            protocol::PATH_FETCH,
            protocol::fetch_request(repository, &have),
        )?;
        if let Some(metadata) = response.metadata {
            ensure_metadata_ok(&metadata)?;
            let bundle = protocol::response_bin(&response.data)?;
            git::fetch_bundle_into_local(
                &bundle,
                &refs.iter().map(|r| r.name.clone()).collect::<Vec<_>>(),
            )?;
            return Ok(());
        }
        let bytes = protocol::response_bin(&response.data)?;
        let bundle = decode_status(bytes)?;
        if !bundle.is_empty() {
            git::fetch_bundle_into_local(
                &bundle,
                &refs.iter().map(|r| r.name.clone()).collect::<Vec<_>>(),
            )?;
        }
        Ok(())
    }

    fn push(&self, repository: &str, spec: &PushSpec) -> Result<()> {
        let mut updates = Vec::new();
        let mut bundle_refs = Vec::new();
        if spec.local.is_empty() {
            updates.push(RefUpdate {
                refname: spec.remote.clone(),
                old: None,
                new: None,
                force: spec.force,
            });
        } else {
            let sha = git::local_ref_sha(&spec.local)?
                .ok_or_else(|| Error::msg(format!("unknown local ref {}", spec.local)))?;
            bundle_refs.push(spec.local.clone());
            updates.push(RefUpdate {
                refname: spec.remote.clone(),
                old: None,
                new: Some(sha),
                force: spec.force,
            });
        }

        let bundle = git::create_local_bundle(&bundle_refs)?;
        let response = self.client.request(
            protocol::PATH_PUSH,
            protocol::push_request(repository, bundle, updates),
        )?;
        let bytes = protocol::response_bin(&response.data)?;
        let _ = decode_status(bytes)?;
        Ok(())
    }
}

struct SyncClient {
    node: RnsNode,
    link_id: [u8; 16],
    state: Arc<(Mutex<ClientState>, Condvar)>,
    request_timeout: Duration,
}

impl SyncClient {
    fn request(&self, path: &str, data: Vec<u8>) -> Result<Response> {
        {
            let (lock, _) = &*self.state;
            lock.lock().unwrap().responses.clear();
        }
        self.node
            .send_request(self.link_id, path, &data)
            .map_err(|_| Error::msg("failed to send request"))?;
        let deadline = Instant::now() + self.request_timeout;
        let (lock, cv) = &*self.state;
        let mut state = lock.lock().unwrap();
        loop {
            if let Some(response) = state.responses.pop_front() {
                return Ok(response);
            }
            let now = Instant::now();
            if now >= deadline {
                return Err(Error::msg("request timed out"));
            }
            let wait = deadline.saturating_duration_since(now);
            let (next, _) = cv.wait_timeout(state, wait).unwrap();
            state = next;
        }
    }
}

#[derive(Default)]
struct SharedCallbacks {
    state: Arc<(Mutex<ClientState>, Condvar)>,
}

#[derive(Default)]
struct ClientState {
    established: Vec<[u8; 16]>,
    responses: VecDeque<Response>,
}

#[derive(Debug, Clone)]
struct Response {
    data: Vec<u8>,
    metadata: Option<Vec<u8>>,
}

impl Callbacks for SharedCallbacks {
    fn on_announce(&mut self, _announced: AnnouncedIdentity) {}

    fn on_path_updated(&mut self, _dest_hash: DestHash, _hops: u8) {}

    fn on_local_delivery(&mut self, _dest_hash: DestHash, _raw: Vec<u8>, _packet_hash: PacketHash) {
    }

    fn on_link_established(
        &mut self,
        link_id: LinkId,
        _dest_hash: DestHash,
        _rtt: f64,
        _is_initiator: bool,
    ) {
        let (lock, cv) = &*self.state;
        lock.lock().unwrap().established.push(link_id.0);
        cv.notify_all();
    }

    fn on_response_with_metadata(
        &mut self,
        _link_id: LinkId,
        _request_id: [u8; 16],
        data: Vec<u8>,
        metadata: Option<Vec<u8>>,
    ) {
        let (lock, cv) = &*self.state;
        lock.lock()
            .unwrap()
            .responses
            .push_back(Response { data, metadata });
        cv.notify_all();
    }
}

fn wait_for_link(
    state: &Arc<(Mutex<ClientState>, Condvar)>,
    link_id: [u8; 16],
    timeout: Duration,
) -> Result<()> {
    let deadline = Instant::now() + timeout;
    let (lock, cv) = &**state;
    let mut state = lock.lock().unwrap();
    loop {
        if state.established.contains(&link_id) {
            return Ok(());
        }
        let now = Instant::now();
        if now >= deadline {
            return Err(Error::msg("link establishment timed out"));
        }
        let (next, _) = cv
            .wait_timeout(state, deadline.saturating_duration_since(now))
            .unwrap();
        state = next;
    }
}

fn decode_status(bytes: Vec<u8>) -> Result<Vec<u8>> {
    let Some((&code, body)) = bytes.split_first() else {
        return Err(Error::msg("empty response"));
    };
    if code == protocol::RES_OK {
        Ok(body.to_vec())
    } else {
        Err(Error::msg(format!(
            "remote returned status 0x{code:02x}: {}",
            String::from_utf8_lossy(body)
        )))
    }
}

fn ensure_metadata_ok(metadata: &[u8]) -> Result<()> {
    let value = msgpack::unpack_exact(metadata)
        .map_err(|e| Error::msg(format!("invalid response metadata: {e}")))?;
    let Some(map) = value.as_map() else {
        return Err(Error::msg("response metadata is not a map"));
    };
    let code = map.iter().find_map(|(key, value)| {
        if matches!(key, Value::UInt(v) if *v == protocol::IDX_RESULT_CODE) {
            value.as_uint().map(|v| v as u8)
        } else {
            None
        }
    });
    match code {
        Some(protocol::RES_OK) => Ok(()),
        Some(code) => Err(Error::msg(format!("remote returned status 0x{code:02x}"))),
        None => Err(Error::msg("response metadata missing status code")),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct FetchRef {
    sha: String,
    name: String,
}

fn parse_fetch_command(input: &str) -> Result<FetchRef> {
    let mut parts = input.split_whitespace();
    let sha = parts
        .next()
        .ok_or_else(|| Error::msg("fetch command missing sha"))?;
    let name = parts
        .next()
        .ok_or_else(|| Error::msg("fetch command missing ref"))?;
    Ok(FetchRef {
        sha: sha.to_string(),
        name: name.to_string(),
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PushSpec {
    local: String,
    remote: String,
    force: bool,
}

fn parse_push_spec(input: &str) -> Result<PushSpec> {
    let (force, spec) = input
        .strip_prefix('+')
        .map(|s| (true, s))
        .unwrap_or((false, input));
    let (local, remote) = spec
        .split_once(':')
        .ok_or_else(|| Error::msg("push spec must be <local>:<remote>"))?;
    Ok(PushSpec {
        local: local.to_string(),
        remote: remote.to_string(),
        force,
    })
}

#[derive(Debug, Default)]
struct ClientOptions {
    config_dir: Option<PathBuf>,
    rns_config_dir: Option<PathBuf>,
    url: String,
}

impl ClientOptions {
    fn parse<I>(args: I) -> Result<Self>
    where
        I: IntoIterator<Item = String>,
    {
        let mut options = ClientOptions::default();
        let mut positional = Vec::new();
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
                "-h" | "--help" => return Err(Error::msg(usage())),
                other => positional.push(other.to_string()),
            }
        }
        options.url = positional
            .last()
            .cloned()
            .ok_or_else(|| Error::msg(usage()))?;
        Ok(options)
    }
}

fn usage() -> &'static str {
    "usage: git-remote-rns [--config DIR] [--rnsconfig DIR] <remote-name> <rns://destination/repo>"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_fetch_command() {
        assert_eq!(
            parse_fetch_command("abc refs/heads/main").unwrap(),
            FetchRef {
                sha: "abc".into(),
                name: "refs/heads/main".into()
            }
        );
    }

    #[test]
    fn parses_forced_push_spec() {
        assert_eq!(
            parse_push_spec("+refs/heads/main:refs/heads/main").unwrap(),
            PushSpec {
                local: "refs/heads/main".into(),
                remote: "refs/heads/main".into(),
                force: true
            }
        );
    }

    #[test]
    fn decodes_status_payload() {
        assert_eq!(
            decode_status(protocol::status_bytes(protocol::RES_OK, b"refs")).unwrap(),
            b"refs"
        );
        assert!(decode_status(protocol::status_bytes(protocol::RES_NOT_FOUND, b"no")).is_err());
    }

    #[test]
    fn metadata_status_ok_is_accepted() {
        assert!(ensure_metadata_ok(&protocol::metadata_status(protocol::RES_OK)).is_ok());
        assert!(ensure_metadata_ok(&protocol::metadata_status(protocol::RES_REMOTE_FAIL)).is_err());
    }
}
