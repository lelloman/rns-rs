//! A stream's next segments, built on threads of their own while the current
//! one is still being transferred.
//!
//! The sender advertises a stream's next segment when the proof of the
//! current one arrives. Built on the driver (encrypting, MACing and hashing
//! about a MiB), the segment took about 2.5 ms, and the driver built it in
//! its idle time once the current segment was fully sent: nearly every proof
//! arrived during that build and waited for it. Here the driver reads the
//! next segment from the stream as soon as the current one is advertised and
//! hands it to this thread; at the proof it takes the segment back, built a
//! whole segment's transfer earlier.
//!
//! On a fast link building a segment takes longer than sending one, and the
//! proof arrives while the next segment is still being built. Once that
//! happens the stream builds [`FAST_SEGMENT_LOOKAHEAD`] segments ahead, each
//! on a thread of its own; the driver still reads them from the stream in
//! order. On a slow link the next segment is always ready in time and only
//! one is held ahead. The parallel engine only.
use super::*;
use rns_core::resource::ResourceSender;
use std::sync::{mpsc, Arc, Mutex};

/// Segments built ahead of the one being transferred for a stream whose
/// proof came before the next segment was built, and threads building them.
/// With 1 MiB segments, each about 8 ms to build, four keep up with a link
/// of about 500 MB/s.
const FAST_SEGMENT_LOOKAHEAD: u64 = 4;

/// A stream's segment: its link, original hash and segment index.
type Key = (LinkId, [u8; 32], u64);
type Built = Result<Box<ResourceSender>, BuildError>;

/// Why a segment could not be built on the builder thread.
#[derive(Debug)]
enum BuildError {
    Token(rns_crypto::token::TokenError),
    Sender(rns_core::resource::ResourceError),
}

impl std::fmt::Display for BuildError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            // Reported in its Debug form, as it always was.
            BuildError::Token(error) => write!(f, "{error:?}"),
            BuildError::Sender(error) => error.fmt(f),
        }
    }
}

/// A stream's next segment to build: its data, read from the stream by the
/// driver, and what encrypting and cutting it takes.
struct SegmentBuild {
    data: Vec<u8>,
    /// The link's derived key, for a token of the build's own.
    key: zeroize::Zeroizing<Vec<u8>>,
    sdu: usize,
    rtt: f64,
    auto_compress: bool,
    now: f64,
    segment_index: u64,
    total_segments: u64,
    original_hash: [u8; 32],
}

/// Encrypts a segment with a token of the build's own, as the link would.
struct TokenEncrypt(rns_crypto::token::Token);

impl rns_core::resource::ResourceEncrypt for TokenEncrypt {
    fn encrypt(&self, data: &[u8]) -> Vec<u8> {
        self.0.encrypt(data, &mut rns_crypto::OsRng)
    }

    fn encrypt_untagged(&self, data: &[u8]) -> Option<(Vec<u8>, rns_crypto::hmac::HmacSha256)> {
        Some(self.0.encrypt_untagged(data, &mut rns_crypto::OsRng))
    }
}

impl SegmentBuild {
    /// The segment's sender, as the driver builds it inline
    /// (`build_stream_segment`); the driver then applies the stream's and
    /// link's settings.
    fn run(&self) -> Built {
        let token = rns_crypto::token::Token::new(&self.key).map_err(BuildError::Token)?;
        ResourceSender::new(
            &self.data,
            None,
            self.sdu,
            &TokenEncrypt(token),
            &ResourceCompressor,
            &mut rns_crypto::OsRng,
            self.now,
            self.auto_compress,
            false,
            None,
            self.segment_index,
            self.total_segments,
            Some(self.original_hash),
            self.rtt,
            6.0,
        )
        .map(Box::new)
        .map_err(BuildError::Sender)
    }
}

pub(super) struct SegmentBuilder {
    tx: Option<mpsc::Sender<(Key, SegmentBuild)>>,
    rx: mpsc::Receiver<(Key, Built)>,
    handles: Vec<std::thread::JoinHandle<()>>,
    in_flight: std::collections::HashSet<Key>,
    ready: std::collections::HashMap<Key, Built>,
    /// Streams that had to wait for a segment, built further ahead.
    outpaced: std::collections::HashSet<(LinkId, [u8; 32])>,
}

impl SegmentBuilder {
    fn start() -> std::io::Result<Self> {
        let (tx, jobs) = mpsc::channel::<(Key, SegmentBuild)>();
        let jobs = Arc::new(Mutex::new(jobs));
        let (results, rx) = mpsc::channel();
        let mut handles = Vec::new();
        for _ in 0..FAST_SEGMENT_LOOKAHEAD {
            let jobs = Arc::clone(&jobs);
            let results = results.clone();
            let spawned = std::thread::Builder::new()
                .name("rns-segment-build".into())
                .spawn(move || loop {
                    // The lock is held only while waiting for a job: the
                    // build runs without it.
                    let job = match jobs.lock() {
                        Ok(jobs) => jobs.recv(),
                        Err(_) => return,
                    };
                    let Ok((key, build)) = job else { return };
                    if results.send((key, build.run())).is_err() {
                        return;
                    }
                });
            match spawned {
                Ok(handle) => handles.push(handle),
                // The threads started still build every segment, one fewer
                // at a time.
                Err(error) if !handles.is_empty() => {
                    log::debug!("segment builder thread not started: {error}");
                    break;
                }
                Err(error) => return Err(error),
            }
        }
        Ok(Self {
            tx: Some(tx),
            rx,
            handles,
            in_flight: Default::default(),
            ready: Default::default(),
            outpaced: Default::default(),
        })
    }

    /// Indices of the segments of the stream `original_hash` on `link_id`
    /// built or being built.
    fn indices<'a>(
        &'a self,
        link_id: &'a LinkId,
        original_hash: &'a [u8; 32],
    ) -> impl Iterator<Item = u64> + 'a {
        self.in_flight
            .iter()
            .chain(self.ready.keys())
            .filter(move |(link, hash, _)| link == link_id && hash == original_hash)
            .map(|&(_, _, index)| index)
    }

    pub(super) fn has(&self, link_id: &LinkId, original_hash: &[u8; 32]) -> bool {
        self.indices(link_id, original_hash).next().is_some()
    }

    fn collect(&mut self, wait: bool) {
        loop {
            let next = if wait {
                self.rx.recv().ok()
            } else {
                self.rx.try_recv().ok()
            };
            let Some((key, built)) = next else {
                if wait {
                    // The thread is gone: nothing more will come.
                    self.in_flight.clear();
                    self.tx = None;
                }
                return;
            };
            self.in_flight.remove(&key);
            self.ready.insert(key, built);
            if wait {
                return;
            }
        }
    }

    /// The first segment built for the stream `original_hash` on
    /// `link_id`, waiting for it if it is still being built; `None` if none
    /// was asked for. Having to wait makes the stream build
    /// [`FAST_SEGMENT_LOOKAHEAD`] segments ahead.
    fn take(&mut self, link_id: &LinkId, original_hash: &[u8; 32]) -> Option<Built> {
        self.collect(false);
        let key = (
            *link_id,
            *original_hash,
            self.indices(link_id, original_hash).min()?,
        );
        if self.in_flight.contains(&key) {
            self.outpaced.insert((*link_id, *original_hash));
        }
        while !self.ready.contains_key(&key) && self.in_flight.contains(&key) {
            self.collect(true);
        }
        self.ready.remove(&key)
    }

    /// Segments to build ahead for the stream `original_hash` on `link_id`.
    fn lookahead(&self, link_id: &LinkId, original_hash: &[u8; 32]) -> u64 {
        if self.outpaced.contains(&(*link_id, *original_hash)) {
            FAST_SEGMENT_LOOKAHEAD
        } else {
            1
        }
    }
}

impl Drop for SegmentBuilder {
    fn drop(&mut self) {
        self.tx.take();
        for handle in self.handles.drain(..) {
            let _ = handle.join();
        }
    }
}

impl LinkManager {
    /// Whether a stream's next segment is built on the builder thread.
    pub(super) fn builds_segments() -> bool {
        !crate::engine::FOLD_WORK && !proof_pool::one_cpu()
    }

    /// Whether the next segment of the stream `original_hash` on `link_id`
    /// is being built, or built and waiting, on the builder threads.
    pub(super) fn segment_building(&self, link_id: &LinkId, original_hash: &[u8; 32]) -> bool {
        self.segment_builder
            .as_ref()
            .is_some_and(|builder| builder.has(link_id, original_hash))
    }

    /// Start building the segments after the one the stream `original_hash`
    /// on `link_id` has advertised, up to its lookahead of them built or
    /// being built: read each from the stream here, encrypt and hash it
    /// there.
    pub(super) fn schedule_segment_build(&mut self, link_id: &LinkId, original_hash: [u8; 32]) {
        if !Self::builds_segments() {
            return;
        }
        if self.segment_builder.is_none() {
            if self.segment_builder_failed {
                return;
            }
            match SegmentBuilder::start() {
                Ok(builder) => self.segment_builder = Some(builder),
                Err(error) => {
                    log::warn!("stream segments built on the driver: {error}");
                    self.segment_builder_failed = true;
                    return;
                }
            }
        }
        while self.schedule_one_segment_build(link_id, original_hash) {}
    }

    /// Start building the segment after the last one of the stream
    /// `original_hash` on `link_id` advertised or built, if there is one and
    /// fewer than its lookahead are built or being built; whether one was
    /// started.
    fn schedule_one_segment_build(&mut self, link_id: &LinkId, original_hash: [u8; 32]) -> bool {
        let Some(builder) = self.segment_builder.as_ref() else {
            return false;
        };
        let ahead = builder.indices(link_id, &original_hash).count() as u64;
        if ahead >= builder.lookahead(link_id, &original_hash) {
            return false;
        }
        let last_built = builder.indices(link_id, &original_hash).max();
        let Some(link) = self
            .links
            .get_mut(link_id)
            .filter(|link| link.engine.state() == LinkState::Active)
        else {
            return false;
        };
        let Some(total_segments) = link
            .outgoing_splits
            .get(&original_hash)
            .map(|split| split.total_segments)
        else {
            return false;
        };
        let Some(current) = link
            .outgoing_resources
            .iter()
            .filter(|s| s.flags.split && s.original_hash == original_hash)
            .map(|s| s.segment_index)
            .max()
        else {
            return false;
        };
        let current = last_built.map_or(current, |last| last.max(current));
        if current >= total_segments {
            return false;
        }
        let Some(key) = link
            .engine
            .derived_key()
            .map(|k| zeroize::Zeroizing::new(k.to_vec()))
        else {
            return false;
        };
        let sdu = Self::resource_sdu_for_link(link);
        let rtt = link.engine.rtt().unwrap_or(1.0);
        let Some(stream) = link.outgoing_streams.get_mut(&original_hash) else {
            return false;
        };
        // A read that fails leaves the segment to the inline path, which
        // reads again and reports the failure.
        let Ok(data) = Self::read_stream_segment(stream, constants::RESOURCE_MAX_EFFICIENT_SIZE)
        else {
            return false;
        };
        let build = SegmentBuild {
            data,
            key,
            sdu,
            rtt,
            auto_compress: stream.auto_compress,
            now: time::now(),
            segment_index: current + 1,
            total_segments,
            original_hash,
        };
        let Some(builder) = self.segment_builder.as_mut() else {
            return false;
        };
        let key = (*link_id, original_hash, current + 1);
        let sent = builder
            .tx
            .as_ref()
            .is_some_and(|tx| tx.send((key, build)).is_ok());
        if sent {
            builder.in_flight.insert(key);
            return true;
        }
        // The threads are gone; the data read is lost with them, so the
        // stream cannot go on.
        builder.tx = None;
        self.segment_builder_failed = true;
        if let Some(link) = self.links.get_mut(link_id) {
            link.outgoing_streams.remove(&original_hash);
        }
        false
    }

    /// Take the next segment of the stream `original_hash` on `link_id`
    /// built on the builder thread, with the stream's and link's settings
    /// applied; `None` if none was built.
    pub(super) fn take_built_segment(
        &mut self,
        link_id: &LinkId,
        original_hash: [u8; 32],
    ) -> Option<Result<ResourceSender, ResourceTransferError>> {
        let built = self
            .segment_builder
            .as_mut()?
            .take(link_id, &original_hash)?;
        let link = self.links.get(link_id)?;
        let stream = link.outgoing_streams.get(&original_hash)?;
        Some(match built {
            Ok(sender) => {
                let mut sender = *sender;
                sender.data_size = (stream.declared_length + stream.metadata_overhead) as usize;
                sender.flags.has_metadata = stream.metadata_overhead != 0;
                Self::configure_sender(link, &mut sender, stream.app_flag);
                Ok(sender)
            }
            Err(error) => Err(ResourceTransferError::Protocol(error.to_string())),
        })
    }

    /// Drop segments built for streams that ended meanwhile, and what was
    /// kept of how far ahead to build theirs.
    pub(super) fn sweep_built_segments(&mut self) {
        let Some(builder) = self.segment_builder.as_mut() else {
            return;
        };
        builder.collect(false);
        let links = &self.links;
        let streaming = |link_id: &LinkId, hash: &[u8; 32]| {
            links
                .get(link_id)
                .is_some_and(|link| link.outgoing_streams.contains_key(hash))
        };
        builder
            .ready
            .retain(|(link_id, hash, _), _| streaming(link_id, hash));
        builder
            .outpaced
            .retain(|(link_id, hash)| streaming(link_id, hash));
    }
}
