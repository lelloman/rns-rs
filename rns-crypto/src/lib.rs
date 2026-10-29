#![cfg_attr(not(feature = "std"), no_std)]
extern crate alloc;

pub mod aes128;
pub mod aes256;
pub mod ed25519;
pub mod hkdf;
pub mod hmac;
pub mod identity;
pub mod pkcs7;
pub mod ratchet;
pub mod sha256;
pub mod sha512;
pub mod stamp_value;
pub mod token;
pub mod x25519;

/// Trait for random number generation.
/// Callers provide an implementation; in `std` builds this wraps OS randomness.
pub trait Rng {
    fn fill_bytes(&mut self, dest: &mut [u8]);
}

/// Deterministic RNG for testing.
pub struct FixedRng {
    bytes: alloc::vec::Vec<u8>,
    pos: usize,
}

impl FixedRng {
    pub fn new(bytes: &[u8]) -> Self {
        Self {
            bytes: bytes.to_vec(),
            pos: 0,
        }
    }
}

impl Rng for FixedRng {
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        for b in dest.iter_mut() {
            *b = self.bytes[self.pos % self.bytes.len()];
            self.pos += 1;
        }
    }
}

/// OS-backed RNG using getrandom(2) syscall on Linux.
#[cfg(feature = "std")]
pub struct OsRng;

#[cfg(feature = "std")]
impl Rng for OsRng {
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        // ESP-IDF: use hardware RNG via esp_fill_random
        #[cfg(target_os = "espidf")]
        {
            unsafe {
                esp_idf_sys::esp_fill_random(
                    dest.as_mut_ptr() as *mut core::ffi::c_void,
                    dest.len(),
                );
            }
        }
        #[cfg(not(target_os = "espidf"))]
        {
            use std::io::Read;
            // Opened once: opening it for every draw cost an open and a close
            // per token IV and random hash. Reads through `&File` need no lock.
            static URANDOM: std::sync::OnceLock<std::fs::File> = std::sync::OnceLock::new();
            let mut f = URANDOM.get_or_init(|| {
                std::fs::File::open("/dev/urandom").expect("Failed to open /dev/urandom")
            });
            f.read_exact(dest)
                .expect("Failed to read from /dev/urandom");
        }
    }
}

#[cfg(all(test, feature = "std", not(target_os = "espidf")))]
mod tests {
    use super::{OsRng, Rng};

    #[test]
    fn os_rng_fills_buffers_from_concurrent_threads() {
        let draws: std::vec::Vec<[u8; 32]> = (0..8)
            .map(|_| {
                std::thread::spawn(|| {
                    let mut out = [0u8; 32];
                    OsRng.fill_bytes(&mut out);
                    out
                })
            })
            .collect::<std::vec::Vec<_>>()
            .into_iter()
            .map(|thread| thread.join().unwrap())
            .collect();
        for (i, a) in draws.iter().enumerate() {
            assert_ne!(a, &[0u8; 32]);
            for b in &draws[i + 1..] {
                assert_ne!(a, b);
            }
        }
    }
}
