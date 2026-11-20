//! The ESP32 hardware random number generator.

/// ESP32 hardware RNG wrapper implementing `rns_crypto::Rng`.
///
/// This is provided separately from `rns_crypto::OsRng` for cases where:
/// 1. The `std` feature of `rns-crypto` is not enabled
/// 2. Explicit control over RNG usage is desired (e.g., for identity generation)
///
/// When `rns-crypto` is built with both `std` and `espidf` features, its `OsRng`
/// also uses `esp_fill_random` internally. Both implementations are equivalent.
pub(crate) struct EspRng;

impl rns_crypto::Rng for EspRng {
    #[allow(unsafe_code, reason = "the hardware RNG is a C call")]
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        // SAFETY: `dest` is valid for writes of `dest.len()` bytes.
        unsafe {
            esp_idf_sys::esp_fill_random(dest.as_mut_ptr() as *mut core::ffi::c_void, dest.len());
        }
    }
}

/// A number in `lo..=hi` from the hardware random number generator, for
/// the CSMA backoff.
#[allow(unsafe_code, reason = "the hardware RNG is a C call")]
pub(crate) fn random_range(lo: u32, hi: u32) -> u32 {
    // SAFETY: esp_random reads the hardware random number generator.
    let r = unsafe { esp_idf_sys::esp_random() };
    lo + r % (hi - lo + 1)
}
