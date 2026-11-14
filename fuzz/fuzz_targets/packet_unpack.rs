//! Every inbound frame goes through RawPacket::unpack.
#![no_main]
use libfuzzer_sys::fuzz_target;
use rns_core::packet::{PacketFlags, RawPacket};

fuzz_target!(|data: &[u8]| {
    if let Some(&first) = data.first() {
        let _ = PacketFlags::unpack(first).pack();
    }
    if let Ok(packet) = RawPacket::unpack(data) {
        let _ = packet.data();
        let _ = packet.packet_hash;
    }
    let _ = RawPacket::unpack_owned(data.to_vec());
});
