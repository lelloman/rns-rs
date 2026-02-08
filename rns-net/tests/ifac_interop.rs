//! Interop tests: verify Rust IFAC mask/unmask matches Python RNS output.
//! Run `python3 ../tests/generate_vectors.py` first to generate fixtures.

use std::fs;
use std::path::PathBuf;

fn fixture_path(name: &str) -> PathBuf {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest
        .join("..")
        .join("tests")
        .join("fixtures")
        .join("ifac")
        .join(name)
}

fn load_fixture(name: &str) -> serde_json::Value {
    let path = fixture_path(name);
    let content = fs::read_to_string(&path).unwrap_or_else(|e| {
        panic!(
            "Failed to read {}: {}. Run generate_vectors.py first.",
            path.display(),
            e
        )
    });
    serde_json::from_str(&content).unwrap()
}

fn hex_to_bytes(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect()
}

#[test]
fn ifac_interop_python_vectors() {
    let vectors = load_fixture("ifac_vectors.json");
    for v in vectors.as_array().unwrap() {
        let desc = v["description"].as_str().unwrap();
        let netname = v["netname"].as_str();
        let netkey = v["netkey"].as_str();
        let ifac_size = v["ifac_size"].as_u64().unwrap() as usize;
        let raw_packet = hex_to_bytes(v["raw_packet"].as_str().unwrap());
        let expected_masked = hex_to_bytes(v["masked_packet"].as_str().unwrap());
        let expected_key = hex_to_bytes(v["ifac_key"].as_str().unwrap());

        // 1. Derive IFAC state — verify key matches Python
        let state = rns_net::ifac::derive_ifac(netname, netkey, ifac_size);
        assert_eq!(
            state.key.to_vec(),
            expected_key,
            "IFAC key mismatch for {}",
            desc
        );

        // 2. Mask outbound — verify matches Python masked bytes
        let masked = rns_net::ifac::mask_outbound(&raw_packet, &state);
        assert_eq!(
            masked, expected_masked,
            "Masked packet mismatch for {}",
            desc
        );

        // 3. Unmask inbound — verify recovers original raw packet from Python-masked data
        let recovered = rns_net::ifac::unmask_inbound(&expected_masked, &state)
            .unwrap_or_else(|| panic!("Unmask of Python-masked packet failed for {}", desc));
        assert_eq!(
            recovered, raw_packet,
            "Recovered packet mismatch for {}",
            desc
        );
    }
}
