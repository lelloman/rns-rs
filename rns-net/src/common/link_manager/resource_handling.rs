//! Resource transfers over links, both ways.

mod actions;
mod advertisements;
mod control;
mod idle;
mod parts;
mod sending;
mod streams;

pub(super) use actions::*;

use super::*;

/// Incoming transfers a link keeps in progress at once. A Python sender
/// advertises one resource at a time per link; the headroom covers concurrent
/// requests and responses. Further advertisements are refused until one ends.
pub(super) const MAX_ACTIVE_INCOMING_RESOURCES: usize = 16;

/// Bytes of held resource parts one idle job decrypts ahead: about one part
/// of a large-MTU link, or every part a small response holds.
const IDLE_DECRYPT_BYTES: usize = 64 * 1024;

/// Encrypts resource data with a link's session key, and can leave the tag
/// to the sender so that it is hashed together with the sender's own passes.
struct LinkResourceEncrypt<'a>(&'a LinkEngine);

impl rns_core::resource::ResourceEncrypt for LinkResourceEncrypt<'_> {
    fn encrypt(&self, data: &[u8]) -> Vec<u8> {
        self.0
            .encrypt(data, &mut rns_crypto::OsRng)
            .unwrap_or_else(|_| data.to_vec())
    }

    fn encrypt_untagged(&self, data: &[u8]) -> Option<(Vec<u8>, rns_crypto::hmac::HmacSha256)> {
        self.0.encrypt_untagged(data, &mut rns_crypto::OsRng).ok()
    }
}

pub(super) struct ResourceSendParams<'a> {
    pub(super) data: &'a [u8],
    pub(super) metadata: Option<&'a [u8]>,
    pub(super) auto_compress: bool,
    pub(super) app_flag: bool,
    pub(super) compressor: &'a dyn rns_core::buffer::types::Compressor,
    pub(super) is_response: bool,
    pub(super) request_id: Option<Vec<u8>>,
    pub(super) rng: &'a mut dyn Rng,
    pub(super) now: f64,
}
