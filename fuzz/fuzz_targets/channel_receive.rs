//! Channel envelopes and buffer stream data from a link's peer.
#![no_main]
use libfuzzer_sys::fuzz_target;
use rns_core::buffer::{BufferReader, StreamDataMessage};
use rns_core::channel::{Channel, ChannelAction};
use rns_net::common::compressor::Bzip2Compressor;

/// Upper bound on one decompressed stream chunk, as the stream readers set.
const MAX_CHUNK: usize = 64 * 1024;

fn stream_data(payload: &[u8], reader: &mut BufferReader) {
    if let Ok(message) = StreamDataMessage::unpack_bounded(payload, &Bzip2Compressor, MAX_CHUNK) {
        assert!(message.data.len() <= MAX_CHUNK);
        reader.receive(&message);
        let _ = reader.read(4096);
    }
}

fuzz_target!(|data: &[u8]| {
    let mut reader = BufferReader::new(0);
    stream_data(data, &mut reader);

    // Envelopes, each a two-byte length and that many bytes.
    let mut channel = Channel::new(0.5);
    let mut rest = data;
    while let Some((len, tail)) = rest.split_first_chunk::<2>() {
        let (raw, tail) = tail.split_at(usize::from(u16::from_be_bytes(*len)).min(tail.len()));
        rest = tail;
        for action in channel.receive(raw, 0.0) {
            if let ChannelAction::MessageReceived { payload, .. } = action {
                stream_data(&payload, &mut reader);
            }
        }
    }
});
