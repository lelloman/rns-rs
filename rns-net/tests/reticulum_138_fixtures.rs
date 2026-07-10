use rns_core::packet::{PacketError, RawPacket};
use rns_crypto::token::Token;
use rns_net::{encode_ax25_ui_frame, validate_ax25_address, WdclFrame};
use serde_json::Value;

fn fixture() -> Value {
    serde_json::from_str(include_str!(
        "../../tests/fixtures/conformance_1_3_8/runtime_vectors.json"
    ))
    .unwrap()
}

fn decode_hex(value: &str) -> Vec<u8> {
    (0..value.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&value[index..index + 2], 16).unwrap())
        .collect()
}

#[test]
fn exact_baseline_packet_ax25_rnode_and_wdcl_vectors_match() {
    let fixture = fixture();
    assert_eq!(fixture["baseline"]["version"], "1.3.8");
    assert_eq!(
        fixture["baseline"]["commit"],
        "de0f399a1696895dcb95ad1efa19f3b21a7886ab"
    );

    for vector in fixture["vectors"]["packet_hops"].as_array().unwrap() {
        let hops = vector["hops"].as_u64().unwrap() as u8;
        let result = RawPacket::unpack(&decode_hex(vector["raw"].as_str().unwrap()));
        if vector["unpack_ok"].as_bool().unwrap() {
            assert_eq!(result.unwrap().hops, hops);
        } else {
            assert!(matches!(result, Err(PacketError::InvalidHopCount(value)) if value == hops));
        }
    }

    for vector in fixture["vectors"]["ax25"].as_array().unwrap() {
        let address = validate_ax25_address(
            vector["callsign"].as_str().unwrap(),
            vector["ssid"].as_u64().unwrap() as u8,
        )
        .unwrap();
        assert_eq!(
            encode_ax25_ui_frame(&address, &decode_hex(vector["payload"].as_str().unwrap()),),
            decode_hex(vector["ui_frame"].as_str().unwrap())
        );
    }

    let rnode = &fixture["vectors"]["rnode"][0];
    assert_eq!(
        rns_net::rnode_kiss::rnode_multi_data_frame(
            rnode["vport"].as_u64().unwrap() as u8,
            &decode_hex(rnode["payload"].as_str().unwrap()),
        ),
        decode_hex(rnode["outbound_frame"].as_str().unwrap())
    );

    for vector in fixture["vectors"]["wdcl"].as_array().unwrap() {
        let frame = decode_hex(vector["frame"].as_str().unwrap());
        assert_eq!(WdclFrame::decode(&frame).unwrap().encode(), frame);
    }
}

#[test]
fn exact_baseline_link_accounting_vectors_count_ciphertext() {
    let fixture = fixture();
    let key = decode_hex(
        "6080e432a453d453938cc0ebd1e53f73a5d48e5f21c6dd9c7db7db7da41337c4\
         c2059963e08e4b9d8073d2fcc6c51f2de39c81fc09d2e7a4ebeda4340b556bb3",
    );
    let token = Token::new(&key).unwrap();
    for vector in fixture["vectors"]["link_accounting"].as_array().unwrap() {
        let ciphertext = decode_hex(vector["ciphertext"].as_str().unwrap());
        assert_eq!(
            ciphertext.len(),
            vector["accounted_bytes"].as_u64().unwrap() as usize
        );
        assert_eq!(
            token.decrypt(&ciphertext).unwrap(),
            decode_hex(vector["plaintext"].as_str().unwrap())
        );
    }
}
