//! A stream's next segment, built on a thread of its own while the current
//! one is still being transferred.
//!
//! The sender advertises a stream's next segment when the proof of the
//! current one arrives. Built on the driver (encrypting, MACing and hashing
//! about a MiB), the segment took about 2.5 ms, and the driver built it in
//! its idle time once the current segment was fully sent: nearly every proof
//! arrived during that build and waited for it. Here the driver reads the
//! next segment from the stream as soon as the current one is advertised and
//! hands it to this thread; at the proof it takes the segment back, built a
//! whole segment's transfer earlier. The parallel engine only.
use super::*;
use rns_core::resource::ResourceSender;
use std::sync::mpsc;

type Key = (LinkId, [u8; 32]);
type Built = Result<Box<ResourceSender>, String>;

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
        let token = rns_crypto::token::Token::new(&self.key).map_err(|e| format!("{e:?}"))?;
        ResourceSender::new(
            &self.data,
            None,
            self.sdu,
            &TokenEncrypt(token),
            &Bzip2Compressor,
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
        .map_err(|error| error.to_string())
    }
}

pub(super) struct SegmentBuilder {
    tx: Option<mpsc::Sender<(Key, SegmentBuild)>>,
    rx: mpsc::Receiver<(Key, Built)>,
    handle: Option<std::thread::JoinHandle<()>>,
    in_flight: std::collections::HashSet<Key>,
    ready: std::collections::HashMap<Key, Built>,
}

impl SegmentBuilder {
    fn start() -> std::io::Result<Self> {
        let (tx, jobs) = mpsc::channel::<(Key, SegmentBuild)>();
        let (results, rx) = mpsc::channel();
        let handle = std::thread::Builder::new()
            .name("rns-segment-build".into())
            .spawn(move || {
                while let Ok((key, build)) = jobs.recv() {
                    if results.send((key, build.run())).is_err() {
                        return;
                    }
                }
            })?;
        Ok(Self {
            tx: Some(tx),
            rx,
            handle: Some(handle),
            in_flight: Default::default(),
            ready: Default::default(),
        })
    }

    pub(super) fn has(&self, key: &Key) -> bool {
        self.in_flight.contains(key) || self.ready.contains_key(key)
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

    /// The segment built for `key`, waiting for it if it is still being
    /// built; `None` if none was asked for.
    fn take(&mut self, key: &Key) -> Option<Built> {
        self.collect(false);
        while !self.ready.contains_key(key) && self.in_flight.contains(key) {
            self.collect(true);
        }
        self.ready.remove(key)
    }
}

impl Drop for SegmentBuilder {
    fn drop(&mut self) {
        self.tx.take();
        if let Some(handle) = self.handle.take() {
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
    /// is being built, or built and waiting, on the builder thread.
    pub(super) fn segment_building(&self, link_id: &LinkId, original_hash: &[u8; 32]) -> bool {
        self.segment_builder
            .as_ref()
            .is_some_and(|builder| builder.has(&(*link_id, *original_hash)))
    }

    /// Start building the segment after the one the stream `original_hash`
    /// on `link_id` has advertised, if it has one and none is built or being
    /// built: read it from the stream here, encrypt and hash it there.
    pub(super) fn schedule_segment_build(&mut self, link_id: &LinkId, original_hash: [u8; 32]) {
        if !Self::builds_segments() || self.segment_building(link_id, &original_hash) {
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
        let Some(link) = self
            .links
            .get_mut(link_id)
            .filter(|link| link.engine.state() == LinkState::Active)
        else {
            return;
        };
        let Some(total_segments) = link
            .outgoing_splits
            .get(&original_hash)
            .map(|split| split.total_segments)
        else {
            return;
        };
        let Some(current) = link
            .outgoing_resources
            .iter()
            .filter(|s| s.flags.split && s.original_hash == original_hash)
            .map(|s| s.segment_index)
            .max()
        else {
            return;
        };
        if current >= total_segments {
            return;
        }
        let Some(key) = link
            .engine
            .derived_key()
            .map(|k| zeroize::Zeroizing::new(k.to_vec()))
        else {
            return;
        };
        let sdu = Self::resource_sdu_for_link(link);
        let rtt = link.engine.rtt().unwrap_or(1.0);
        let Some(stream) = link.outgoing_streams.get_mut(&original_hash) else {
            return;
        };
        // A read that fails leaves the segment to the inline path, which
        // reads again and reports the failure.
        let Ok(data) = Self::read_stream_segment(stream, constants::RESOURCE_MAX_EFFICIENT_SIZE)
        else {
            return;
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
        let builder = self.segment_builder.as_mut().unwrap();
        let key = (*link_id, original_hash);
        let sent = builder
            .tx
            .as_ref()
            .is_some_and(|tx| tx.send((key, build)).is_ok());
        if sent {
            builder.in_flight.insert(key);
        } else {
            // The thread is gone; the data read is lost with it, so the
            // stream cannot go on.
            builder.tx = None;
            self.segment_builder_failed = true;
            if let Some(link) = self.links.get_mut(link_id) {
                link.outgoing_streams.remove(&original_hash);
            }
        }
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
            .take(&(*link_id, original_hash))?;
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
            Err(error) => Err(ResourceTransferError::Protocol(error)),
        })
    }

    /// Drop segments built for streams that ended meanwhile.
    pub(super) fn sweep_built_segments(&mut self) {
        let Some(builder) = self.segment_builder.as_mut() else {
            return;
        };
        builder.collect(false);
        let links = &self.links;
        builder.ready.retain(|(link_id, hash), _| {
            links
                .get(link_id)
                .is_some_and(|link| link.outgoing_streams.contains_key(hash))
        });
    }
}
