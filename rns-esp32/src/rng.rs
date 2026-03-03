/// ESP32 hardware RNG wrapper implementing `rns_crypto::Rng`.
pub struct EspRng;

impl rns_crypto::Rng for EspRng {
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        unsafe {
            esp_idf_sys::esp_fill_random(
                dest.as_mut_ptr() as *mut core::ffi::c_void,
                dest.len(),
            );
        }
    }
}
