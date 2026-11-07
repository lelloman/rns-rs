//! Decryption of incoming resource parts on a thread of its own, as they
//! arrive in order, so that a resource's assembly finds its parts already
//! authenticated and decrypted and its proof goes out at once.
//!
//! A segment's proof waits for its assembly, and the sender advertises the
//! next segment only once the proof arrives: decrypting the whole segment at
//! assembly put about 1.5 ms per MiB on every segment change. Here the
//! driver copies each part to this thread once the parts before it are
//! held, and takes the decryption back at assembly, a few parts behind at
//! most. The parallel engine only; the compact engine decrypts ahead in its
//! idle slices.
use super::*;
use rns_crypto::token::TokenDecryptStream;
use std::sync::mpsc;

/// Resources smaller than this decrypt at assembly: a few parts leave no
/// transfer to overlap with, and the thread's wakeups and the round trip to
/// take the decryption back cost more than decrypting them. Request
/// responses of 1-4 KiB lost 13% of their rate fed to the thread.
const MIN_TRANSFER: u64 = 64 * 1024;

enum Message {
    Start(u64, Box<TokenDecryptStream>),
    Part(u64, Vec<u8>),
    /// Hand the decryption and how many parts it took back.
    Finish(
        u64,
        mpsc::SyncSender<Option<(Box<TokenDecryptStream>, usize)>>,
    ),
    Forget(u64),
}

/// One incoming resource being decrypted on the feeder.
pub(super) struct Feed {
    key: u64,
    link_id: LinkId,
    /// Parts sent so far, in order from the first.
    fed: usize,
}

pub(super) struct DecryptFeeder {
    tx: Option<mpsc::Sender<Message>>,
    handle: Option<std::thread::JoinHandle<()>>,
    next_key: u64,
    /// By resource hash.
    feeds: std::collections::HashMap<[u8; 32], Feed>,
}

impl DecryptFeeder {
    fn start() -> std::io::Result<Self> {
        let (tx, rx) = mpsc::channel::<Message>();
        let handle = std::thread::Builder::new()
            .name("rns-resource-decrypt".into())
            .spawn(move || {
                let mut streams: std::collections::HashMap<u64, (Box<TokenDecryptStream>, usize)> =
                    Default::default();
                while let Ok(message) = rx.recv() {
                    match message {
                        Message::Start(key, stream) => {
                            streams.insert(key, (stream, 0));
                        }
                        Message::Part(key, data) => {
                            if let Some((stream, parts)) = streams.get_mut(&key) {
                                stream.update(&data);
                                *parts += 1;
                            }
                        }
                        Message::Finish(key, reply) => {
                            let _ = reply.send(streams.remove(&key));
                        }
                        Message::Forget(key) => {
                            streams.remove(&key);
                        }
                    }
                }
            })?;
        Ok(Self {
            tx: Some(tx),
            handle: Some(handle),
            next_key: 0,
            feeds: Default::default(),
        })
    }

    fn send(&mut self, message: Message) -> bool {
        let sent = self.tx.as_ref().is_some_and(|tx| tx.send(message).is_ok());
        if !sent {
            // The thread is gone: assembly decrypts everything itself.
            self.tx = None;
            self.feeds.clear();
        }
        sent
    }
}

impl Drop for DecryptFeeder {
    fn drop(&mut self) {
        self.tx.take();
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

impl LinkManager {
    /// Whether incoming resource parts are decrypted on the feeder.
    pub(super) fn feeds_decryption() -> bool {
        !crate::engine::FOLD_WORK && !proof_pool::one_cpu()
    }

    /// Send the feeder the parts of the resource `resource_hash` on
    /// `link_id` that are now held in order and not yet sent, starting its
    /// decryption with the first.
    pub(super) fn feed_decryption(&mut self, link_id: &LinkId, resource_hash: [u8; 32]) {
        if !Self::feeds_decryption() {
            return;
        }
        let worth_feeding = self.links.get(link_id).is_some_and(|link| {
            link.incoming_resources.iter().any(|r| {
                r.resource_hash[..] == resource_hash[..]
                    && r.decrypts()
                    && r.transfer_size >= MIN_TRANSFER
            })
        });
        if !worth_feeding {
            return;
        }
        if self.decrypt_feeder.is_none() {
            if self.decrypt_feeder_failed {
                return;
            }
            match DecryptFeeder::start() {
                Ok(feeder) => self.decrypt_feeder = Some(feeder),
                Err(error) => {
                    log::warn!("resource decryption stays at assembly: {error}");
                    self.decrypt_feeder_failed = true;
                    return;
                }
            }
        }
        let Some(link) = self.links.get(link_id) else {
            return;
        };
        let Some(receiver) = link
            .incoming_resources
            .iter()
            .find(|r| r.resource_hash[..] == resource_hash[..])
            .filter(|r| r.decrypts() && r.transfer_size >= MIN_TRANSFER)
        else {
            return;
        };
        let feeder = self.decrypt_feeder.as_mut().unwrap();
        if !feeder.feeds.contains_key(&resource_hash) {
            if receiver.parts_in_order_from(0).next().is_none() {
                return;
            }
            let Some(mut stream) = link
                .engine
                .decrypt_stream(constants::RESOURCE_RANDOM_HASH_SIZE)
            else {
                return;
            };
            receiver.prepare_decrypt_stream(&mut stream);
            let key = feeder.next_key;
            feeder.next_key += 1;
            if !feeder.send(Message::Start(key, Box::new(stream))) {
                return;
            }
            feeder.feeds.insert(
                resource_hash,
                Feed {
                    key,
                    link_id: *link_id,
                    fed: 0,
                },
            );
        }
        let Some(feed) = feeder.feeds.get(&resource_hash) else {
            return;
        };
        let (key, from) = (feed.key, feed.fed);
        let mut sent = 0;
        for part in receiver.parts_in_order_from(from) {
            if !feeder.send(Message::Part(key, part.to_vec())) {
                return;
            }
            sent += 1;
        }
        if let Some(feed) = feeder.feeds.get_mut(&resource_hash) {
            feed.fed += sent;
        }
    }

    /// Take back the decryption of the resource `resource_hash` on
    /// `link_id` for its assembly, which then feeds it only the parts not
    /// sent. Without one, assembly decrypts every part.
    pub(super) fn finish_decryption(&mut self, link_id: &LinkId, resource_hash: [u8; 32]) {
        let Some(feeder) = self.decrypt_feeder.as_mut() else {
            return;
        };
        let Some(feed) = feeder.feeds.remove(&resource_hash) else {
            return;
        };
        let (reply, back) = mpsc::sync_channel(1);
        if !feeder.send(Message::Finish(feed.key, reply)) {
            return;
        }
        let Ok(Some((stream, parts))) = back.recv() else {
            return;
        };
        if parts != feed.fed {
            return;
        }
        if let Some(receiver) = self.links.get_mut(link_id).and_then(|link| {
            link.incoming_resources
                .iter_mut()
                .find(|r| r.resource_hash[..] == resource_hash[..])
        }) {
            receiver.resume_decrypt(stream, parts);
        }
    }

    /// Drop the decryptions of resources that ended without assembling
    /// (cancelled, failed, or their link closed).
    pub(super) fn sweep_decryptions(&mut self) {
        let Some(feeder) = self.decrypt_feeder.as_mut() else {
            return;
        };
        let links = &self.links;
        let ended: Vec<([u8; 32], u64)> = feeder
            .feeds
            .iter()
            .filter(|(hash, feed)| {
                !links.get(&feed.link_id).is_some_and(|link| {
                    link.incoming_resources
                        .iter()
                        .any(|r| r.resource_hash[..] == hash[..] && r.decrypts())
                })
            })
            .map(|(hash, feed)| (*hash, feed.key))
            .collect();
        for (hash, key) in ended {
            feeder.feeds.remove(&hash);
            feeder.send(Message::Forget(key));
        }
    }

    #[cfg(test)]
    pub(super) fn decryptions_fed(&self) -> usize {
        self.decrypt_feeder.as_ref().map_or(0, |f| f.feeds.len())
    }
}
