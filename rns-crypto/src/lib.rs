#![cfg_attr(not(feature = "std"), no_std)]
extern crate alloc;

pub mod pkcs7;
pub mod sha256;
pub mod sha512;
pub mod hmac;
pub mod hkdf;
pub mod aes128;
pub mod aes256;
pub mod token;
pub mod x25519;
pub mod ed25519;
pub mod identity;

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
        // Use getrandom(2) syscall directly on Linux
        #[cfg(target_os = "linux")]
        {
            let ret = unsafe {
                libc_getrandom(dest.as_mut_ptr(), dest.len(), 0)
            };
            assert!(ret == dest.len() as isize, "getrandom failed");
        }
        #[cfg(not(target_os = "linux"))]
        {
            // Fallback: read from /dev/urandom
            use std::io::Read;
            let mut f = std::fs::File::open("/dev/urandom").expect("Failed to open /dev/urandom");
            f.read_exact(dest).expect("Failed to read from /dev/urandom");
        }
    }
}

#[cfg(all(feature = "std", target_os = "linux"))]
unsafe fn libc_getrandom(buf: *mut u8, buflen: usize, flags: u32) -> isize {
    // getrandom syscall number on x86_64 is 318, aarch64 is 278
    #[cfg(target_arch = "x86_64")]
    {
        let ret: isize;
        core::arch::asm!(
            "syscall",
            in("rax") 318u64,
            in("rdi") buf as u64,
            in("rsi") buflen as u64,
            in("rdx") flags as u64,
            lateout("rax") ret,
            lateout("rcx") _,
            lateout("r11") _,
        );
        ret
    }
    #[cfg(target_arch = "aarch64")]
    {
        let ret: isize;
        core::arch::asm!(
            "svc #0",
            in("x8") 278u64,
            in("x0") buf as u64,
            in("x1") buflen as u64,
            in("x2") flags as u64,
            lateout("x0") ret,
        );
        ret
    }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    {
        compile_error!("Unsupported architecture for getrandom syscall");
    }
}
