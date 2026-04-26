#![cfg_attr(not(feature = "std"), no_std)]
extern crate alloc;

pub mod aes128;
pub mod aes256;
pub mod ed25519;
pub mod hkdf;
pub mod hmac;
pub mod identity;
pub mod pkcs7;
pub mod sha256;
pub mod sha512;
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
            let mut f = std::fs::File::open("/dev/urandom").expect("Failed to open /dev/urandom");
            f.read_exact(dest)
                .expect("Failed to read from /dev/urandom");
        }
    }
}
