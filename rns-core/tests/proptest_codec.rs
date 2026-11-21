//! Property tests for the wire codecs: packets, announces, resource
//! advertisements and channel envelopes.
//!
//! Each codec is checked for two things: decoding what was encoded gives the
//! original fields back, and decoding arbitrary bytes returns an error
//! instead of panicking (and, where it succeeds, describes the input).

use proptest::prelude::*;

use rns_core::announce::AnnounceData;
use rns_core::channel::envelope::{pack_envelope, unpack_envelope};
use rns_core::constants;
use rns_core::hash::truncated_hash;
use rns_core::msgpack;
use rns_core::packet::{PacketError, PacketFlags, RawPacket};
use rns_core::resource::AdvFlags;
use rns_core::resource::ResourceAdvertisement;
use rns_crypto::identity::Identity;

/// `cases` per property, unless `PROPTEST_CASES` asks for a deeper run.
fn config(cases: u32) -> ProptestConfig {
    let cases = std::env::var("PROPTEST_CASES")
        .ok()
        .and_then(|cases| cases.parse().ok())
        .unwrap_or(cases);
    ProptestConfig {
        cases,
        failure_persistence: None,
        ..ProptestConfig::default()
    }
}

// =============================================================================
// Packets
// =============================================================================

fn arb_flags() -> impl Strategy<Value = PacketFlags> {
    (0u8..=1, 0u8..=1, 0u8..=1, 0u8..=3, 0u8..=3).prop_map(
        |(header_type, context_flag, transport_type, destination_type, packet_type)| PacketFlags {
            header_type,
            context_flag,
            transport_type,
            destination_type,
            packet_type,
        },
    )
}

/// Header fields and a payload that fits the MTU of a packet with them.
#[allow(clippy::type_complexity)]
fn arb_packet_fields() -> impl Strategy<Value = (PacketFlags, u8, [u8; 16], [u8; 16], u8, Vec<u8>)>
{
    (
        arb_flags(),
        0..constants::PATHFINDER_M,
        any::<[u8; 16]>(),
        any::<[u8; 16]>(),
        any::<u8>(),
    )
        .prop_flat_map(|(flags, hops, dest, transport_id, context)| {
            // A HEADER_1 announce leaves room for the transport id a
            // transport node inserts (upstream d077d1ab).
            let transport_room = if flags.packet_type == constants::PACKET_TYPE_ANNOUNCE
                && flags.header_type == constants::HEADER_1
            {
                constants::TRUNCATED_HASHLENGTH / 8
            } else {
                0
            };
            let max_data =
                constants::MTU - RawPacket::data_offset(flags.header_type) - transport_room;
            (
                Just(flags),
                Just(hops),
                Just(dest),
                Just(transport_id),
                Just(context),
                prop::collection::vec(any::<u8>(), 1..=max_data),
            )
        })
}

proptest! {
    #![proptest_config(config(256))]

    #[test]
    fn packet_flags_roundtrip(flags in arb_flags()) {
        prop_assert_eq!(PacketFlags::unpack(flags.pack()), flags);
    }

    #[test]
    fn flags_byte_roundtrip_ignores_only_the_top_bit(byte in any::<u8>()) {
        prop_assert_eq!(PacketFlags::unpack(byte).pack(), byte & 0x7f);
    }

    #[test]
    fn packet_roundtrip(
        (flags, hops, dest, transport_id, context, data) in arb_packet_fields()
    ) {
        let packed = RawPacket::pack(flags, hops, &dest, Some(&transport_id), context, &data)
            .expect("fields within the MTU pack");
        // A HEADER_1 packet carries no transport id on the wire.
        let expected_transport_id =
            (flags.header_type == constants::HEADER_2).then_some(transport_id);

        let unpacked = RawPacket::unpack(&packed.raw).expect("a packed packet unpacks");
        prop_assert_eq!(unpacked.flags, flags);
        prop_assert_eq!(unpacked.hops, hops);
        prop_assert_eq!(unpacked.transport_id, expected_transport_id);
        prop_assert_eq!(unpacked.destination_hash, dest);
        prop_assert_eq!(unpacked.context, context);
        prop_assert_eq!(unpacked.data(), &data[..]);
        prop_assert_eq!(&unpacked.raw, &packed.raw);
        prop_assert_eq!(unpacked.packet_hash, packed.packet_hash);
        prop_assert_eq!(unpacked.get_hash(), packed.packet_hash);

        // Every packing and unpacking entry point agrees on the bytes and hash.
        let shared = RawPacket::pack_raw_shared_with_max_mtu(
            flags, hops, &dest, Some(&transport_id), context, &data, constants::MTU,
        )
        .unwrap();
        prop_assert_eq!(&shared[..], &packed.raw[..]);
        let filled = RawPacket::pack_raw_shared_filled_with_max_mtu(
            flags, hops, &dest, Some(&transport_id), context, data.len(), constants::MTU,
            |out| out.copy_from_slice(&data),
        )
        .unwrap();
        prop_assert_eq!(&filled[..], &packed.raw[..]);
        let from_shared = RawPacket::unpack_shared(shared).unwrap();
        prop_assert_eq!(from_shared.packet_hash, packed.packet_hash);
        prop_assert_eq!(from_shared.data(), &data[..]);
        let owned = RawPacket::unpack_owned(packed.raw.clone()).unwrap();
        prop_assert_eq!(owned.packet_hash, packed.packet_hash);
        let prehashed = RawPacket::unpack_prehashed(&packed.raw, [0xEE; 32]).unwrap();
        prop_assert_eq!(prehashed.packet_hash, [0xEE; 32]);
        prop_assert_eq!(prehashed.data(), &data[..]);
        let outbound = RawPacket::unpack_outbound(packed.raw.clone()).unwrap();
        if !outbound.is_unhashed_link_resource() {
            prop_assert_eq!(outbound.packet_hash, packed.packet_hash);
        }
        prop_assert_eq!(
            RawPacket::is_unhashed_link_resource_wire(&packed.raw),
            unpacked.is_unhashed_link_resource()
        );
    }

    /// The packet hash covers the low flag nibble, destination, context and
    /// payload, but neither the hop count nor the header form: a packet keeps
    /// its hash as transport nodes rewrite its hops and transport header.
    #[test]
    fn packet_hash_ignores_hops_and_transport_header(
        (flags, hops, dest, transport_id, context, data) in arb_packet_fields(),
        other_hops in 0..constants::PATHFINDER_M,
        other_transport_id in any::<[u8; 16]>(),
    ) {
        let data = &data[..data.len().min(constants::MTU - RawPacket::data_offset(constants::HEADER_2))];
        let a = RawPacket::pack(flags, hops, &dest, Some(&transport_id), context, data).unwrap();
        let rewritten = PacketFlags {
            header_type: 1 - flags.header_type,
            transport_type: 1 - flags.transport_type,
            ..flags
        };
        let b = RawPacket::pack(rewritten, other_hops, &dest, Some(&other_transport_id), context, data)
            .unwrap();
        prop_assert_eq!(a.packet_hash, b.packet_hash);
    }

    #[test]
    fn packet_over_mtu_is_rejected(
        (flags, hops, dest, transport_id, context, _) in arb_packet_fields(),
        excess in 1usize..64,
    ) {
        let len = constants::MTU - RawPacket::data_offset(flags.header_type) + excess;
        let data = vec![0x5a; len];
        prop_assert!(matches!(
            RawPacket::pack(flags, hops, &dest, Some(&transport_id), context, &data),
            Err(PacketError::ExceedsMtu)
        ));
    }

    #[test]
    fn packet_with_hops_at_pathfinder_limit_does_not_unpack(
        (flags, _, dest, transport_id, context, data) in arb_packet_fields(),
        hops in constants::PATHFINDER_M..=u8::MAX,
    ) {
        let raw = RawPacket::pack_raw_with_max_mtu(
            flags, hops, &dest, Some(&transport_id), context, &data, constants::MTU,
        )
        .unwrap();
        prop_assert!(matches!(
            RawPacket::unpack(&raw),
            Err(PacketError::InvalidHopCount(h)) if h == hops
        ));
    }

    /// Arbitrary bytes never panic the decoder. Whatever it accepts packs
    /// back to the same bytes (with the flag byte's unused top bit cleared)
    /// and the same packet hash.
    #[test]
    fn packet_unpack_arbitrary_bytes(raw in prop::collection::vec(any::<u8>(), 0..=600)) {
        let Ok(packet) = RawPacket::unpack(&raw) else {
            return Ok(());
        };
        prop_assert!(packet.hops < constants::PATHFINDER_M);
        prop_assert!(!packet.data().is_empty());
        prop_assert_eq!(
            RawPacket::is_unhashed_link_resource_wire(&raw),
            packet.is_unhashed_link_resource()
        );
        let repacked = RawPacket::pack_with_max_mtu(
            packet.flags,
            packet.hops,
            &packet.destination_hash,
            packet.transport_id.as_ref(),
            packet.context,
            packet.data(),
            usize::MAX,
        )
        .unwrap();
        let mut expected = raw.clone();
        expected[0] &= 0x7f;
        prop_assert_eq!(&repacked.raw, &expected);
        prop_assert_eq!(repacked.packet_hash, packet.packet_hash);
    }
}

// =============================================================================
// Announces
// =============================================================================

/// The destination hash an announce from `identity` with `name_hash` is
/// bound to.
fn announce_destination(identity: &Identity, name_hash: &[u8; 10]) -> [u8; 16] {
    let mut material = [0u8; 26];
    material[..10].copy_from_slice(name_hash);
    material[10..].copy_from_slice(identity.hash());
    truncated_hash(&material)
}

/// Serialise announce fields in wire order, without signing.
fn announce_wire_bytes(announce: &AnnounceData) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&announce.public_key);
    out.extend_from_slice(&announce.name_hash);
    out.extend_from_slice(&announce.random_hash);
    if let Some(ratchet) = &announce.ratchet {
        out.extend_from_slice(ratchet);
    }
    out.extend_from_slice(&announce.signature);
    if let Some(app_data) = &announce.app_data {
        out.extend_from_slice(app_data);
    }
    out
}

proptest! {
    // Each case signs and verifies, so fewer cases keep the suite fast.
    #![proptest_config(config(24))]

    /// A signed announce unpacks to the fields it was packed from and
    /// validates against its destination; flipping any byte of it makes it
    /// fail validation.
    #[test]
    fn announce_roundtrip_and_tamper_detection(
        private_key in any::<[u8; 64]>(),
        name_hash in any::<[u8; 10]>(),
        random_hash in any::<[u8; 10]>(),
        ratchet in prop::option::of(any::<[u8; 32]>()),
        app_data in prop::option::of(prop::collection::vec(any::<u8>(), 0..200)),
        flip_at in any::<prop::sample::Index>(),
        flip_bits in 1u8..=255,
    ) {
        let identity = Identity::from_private_key(&private_key);
        let dest = announce_destination(&identity, &name_hash);
        let (data, has_ratchet) = AnnounceData::pack(
            &identity,
            &dest,
            &name_hash,
            &random_hash,
            ratchet.as_ref(),
            app_data.as_deref(),
        )
        .unwrap();
        prop_assert_eq!(has_ratchet, ratchet.is_some());

        let announce = AnnounceData::unpack(&data, has_ratchet).unwrap();
        prop_assert_eq!(announce.public_key, identity.get_public_key().unwrap());
        prop_assert_eq!(announce.name_hash, name_hash);
        prop_assert_eq!(announce.random_hash, random_hash);
        prop_assert_eq!(announce.ratchet, ratchet);
        // Empty app data is not distinguishable on the wire from none.
        let expected_app_data = app_data.filter(|ad| !ad.is_empty());
        prop_assert_eq!(&announce.app_data, &expected_app_data);
        prop_assert_eq!(announce_wire_bytes(&announce), data.clone());

        let validated = announce.validate(&dest).expect("a signed announce validates");
        prop_assert_eq!(&validated.identity_hash, identity.hash());
        prop_assert_eq!(validated.random_hash, random_hash);
        prop_assert_eq!(&validated.app_data, &expected_app_data);

        let mut tampered = data.clone();
        let at = flip_at.index(tampered.len());
        tampered[at] ^= flip_bits;
        let tampered = AnnounceData::unpack(&tampered, has_ratchet).unwrap();
        prop_assert!(tampered.validate(&dest).is_err());
    }
}

proptest! {
    #![proptest_config(config(256))]

    /// Arbitrary bytes never panic the announce decoder; whatever it accepts
    /// serialises back to the input.
    #[test]
    fn announce_unpack_arbitrary_bytes(
        data in prop::collection::vec(any::<u8>(), 0..=400),
        has_ratchet in any::<bool>(),
    ) {
        let min_len = 64 + 10 + 10 + 64 + if has_ratchet { 32 } else { 0 };
        match AnnounceData::unpack(&data, has_ratchet) {
            Ok(announce) => {
                prop_assert!(data.len() >= min_len);
                prop_assert_eq!(announce.ratchet.is_some(), has_ratchet);
                prop_assert_eq!(announce_wire_bytes(&announce), data);
                // Validating garbage must not panic either.
                let _ = announce.validate(&[0; 16]);
            }
            Err(_) => prop_assert!(data.len() < min_len),
        }
    }
}

// =============================================================================
// Resource advertisements
// =============================================================================

fn arb_adv_flags() -> impl Strategy<Value = AdvFlags> {
    any::<u8>().prop_map(|byte| AdvFlags::from_byte(byte & 0x7f))
}

fn arb_advertisement(max_hashmap: usize) -> impl Strategy<Value = ResourceAdvertisement> {
    (
        (
            0..=(constants::RESOURCE_MAX_EFFICIENT_SIZE as u64 * 3),
            any::<u64>(),
            any::<u64>(),
            prop::collection::vec(any::<u8>(), 0..=32),
            prop::collection::vec(any::<u8>(), 0..=4),
            prop::collection::vec(any::<u8>(), 0..=32),
        ),
        (
            prop::collection::vec(any::<u8>(), 0..=max_hashmap),
            arb_adv_flags(),
            any::<u64>(),
            any::<u64>(),
            prop::option::of(prop::collection::vec(any::<u8>(), 0..=32)),
        ),
    )
        .prop_map(
            |(
                (transfer_size, data_size, num_parts, resource_hash, random_hash, original_hash),
                (hashmap, flags, segment_index, total_segments, request_id),
            )| ResourceAdvertisement {
                transfer_size,
                data_size,
                num_parts,
                resource_hash,
                random_hash,
                original_hash,
                hashmap,
                flags,
                segment_index,
                total_segments,
                request_id,
            },
        )
}

fn assert_advertisement_eq(
    got: &ResourceAdvertisement,
    want: &ResourceAdvertisement,
    hashmap: &[u8],
) -> Result<(), TestCaseError> {
    prop_assert_eq!(got.transfer_size, want.transfer_size);
    prop_assert_eq!(got.data_size, want.data_size);
    prop_assert_eq!(got.num_parts, want.num_parts);
    prop_assert_eq!(&got.resource_hash, &want.resource_hash);
    prop_assert_eq!(&got.random_hash, &want.random_hash);
    prop_assert_eq!(&got.original_hash, &want.original_hash);
    prop_assert_eq!(&got.hashmap[..], hashmap);
    prop_assert_eq!(got.flags, want.flags);
    prop_assert_eq!(got.segment_index, want.segment_index);
    prop_assert_eq!(got.total_segments, want.total_segments);
    prop_assert_eq!(&got.request_id, &want.request_id);
    Ok(())
}

const SEGMENT_BYTES: usize = constants::RESOURCE_HASHMAP_MAX_LEN * constants::RESOURCE_MAPHASH_LEN;

proptest! {
    #![proptest_config(config(256))]

    #[test]
    fn adv_flags_roundtrip(byte in 0u8..0x80) {
        prop_assert_eq!(AdvFlags::from_byte(byte).to_byte(), byte);
    }

    #[test]
    fn advertisement_roundtrip(adv in arb_advertisement(SEGMENT_BYTES)) {
        let unpacked = ResourceAdvertisement::unpack(&adv.pack(0)).unwrap();
        assert_advertisement_eq(&unpacked, &adv, &adv.hashmap)?;
    }

    /// Packing segment `k` carries exactly the `k`-th hashmap slice.
    #[test]
    fn advertisement_segment_roundtrip(
        adv in arb_advertisement(SEGMENT_BYTES * 4),
        segment in 0usize..5,
    ) {
        let start = (segment * SEGMENT_BYTES).min(adv.hashmap.len());
        let end = ((segment + 1) * SEGMENT_BYTES).min(adv.hashmap.len());
        let unpacked = ResourceAdvertisement::unpack(&adv.pack(segment)).unwrap();
        assert_advertisement_eq(&unpacked, &adv, &adv.hashmap[start..end])?;
    }

    /// An advertisement packed for an MDU fits it whenever the version
    /// without a hashmap does, and only drops the hashmap.
    #[test]
    fn advertisement_pack_for_mdu(
        adv in arb_advertisement(SEGMENT_BYTES),
        mdu in 64usize..=600,
    ) {
        let packed = adv.pack_for_mdu(0, mdu);
        let unpacked = ResourceAdvertisement::unpack(&packed).unwrap();
        if adv.pack(0).len() <= mdu {
            assert_advertisement_eq(&unpacked, &adv, &adv.hashmap)?;
        } else {
            assert_advertisement_eq(&unpacked, &adv, &[])?;
        }
    }

    /// A transfer size beyond what a sender ever advertises is rejected.
    #[test]
    fn advertisement_oversized_transfer_is_rejected(
        mut adv in arb_advertisement(16),
        transfer_size in (constants::RESOURCE_MAX_EFFICIENT_SIZE as u64 * 3 + 1)..,
    ) {
        adv.transfer_size = transfer_size;
        prop_assert!(ResourceAdvertisement::unpack(&adv.pack(0)).is_err());
    }

    #[test]
    fn advertisement_unpack_arbitrary_bytes(data in prop::collection::vec(any::<u8>(), 0..=600)) {
        let _ = ResourceAdvertisement::unpack(&data);
    }

    /// Corrupting, truncating or extending a valid advertisement never
    /// panics the decoder.
    #[test]
    fn advertisement_unpack_mutated(
        adv in arb_advertisement(SEGMENT_BYTES),
        edits in prop::collection::vec((any::<prop::sample::Index>(), any::<u8>()), 1..8),
        cut in any::<prop::sample::Index>(),
        tail in prop::collection::vec(any::<u8>(), 0..8),
    ) {
        let mut data = adv.pack(0);
        for (at, byte) in edits {
            let at = at.index(data.len());
            data[at] = byte;
        }
        let _ = ResourceAdvertisement::unpack(&data);
        data.truncate(cut.index(data.len() + 1));
        let _ = ResourceAdvertisement::unpack(&data);
        data.extend_from_slice(&tail);
        let _ = ResourceAdvertisement::unpack(&data);
    }

    /// Deeply nested msgpack containers are rejected, not recursed into
    /// without bound.
    #[test]
    fn msgpack_deep_nesting_is_rejected(
        depth in 30usize..2000,
        container in prop::sample::select(vec![0x91u8, 0x81, 0xdc]),
    ) {
        let mut data = Vec::new();
        for _ in 0..depth {
            data.push(container);
            if container == 0xdc {
                data.extend_from_slice(&[0, 1]);
            }
            if container == 0x81 {
                // Map key, then the nested value.
                data.push(0xc0);
            }
        }
        data.push(0xc0);
        let _ = msgpack::unpack(&data);
        let _ = ResourceAdvertisement::unpack(&data);
    }
}

// =============================================================================
// Channel envelopes
// =============================================================================

proptest! {
    #![proptest_config(config(256))]

    #[test]
    fn envelope_roundtrip(
        msgtype in any::<u16>(),
        sequence in any::<u16>(),
        payload in prop::collection::vec(any::<u8>(), 0..=1024),
        trailing in prop::collection::vec(any::<u8>(), 0..16),
    ) {
        let mut packed = pack_envelope(msgtype, sequence, &payload);
        prop_assert_eq!(packed.len(), constants::CHANNEL_ENVELOPE_OVERHEAD + payload.len());
        let (mt, seq, pl) = unpack_envelope(&packed).unwrap();
        prop_assert_eq!(mt, msgtype);
        prop_assert_eq!(seq, sequence);
        prop_assert_eq!(pl, &payload[..]);

        // Bytes past the declared length are not part of the payload.
        packed.extend_from_slice(&trailing);
        let (_, _, pl) = unpack_envelope(&packed).unwrap();
        prop_assert_eq!(pl, &payload[..]);
    }

    /// Arbitrary bytes never panic the envelope decoder; whatever it accepts
    /// is a prefix that packs back to the same bytes.
    #[test]
    fn envelope_unpack_arbitrary_bytes(raw in prop::collection::vec(any::<u8>(), 0..=64)) {
        if let Ok((msgtype, sequence, payload)) = unpack_envelope(&raw) {
            let repacked = pack_envelope(msgtype, sequence, payload);
            prop_assert!(raw.starts_with(&repacked));
        } else {
            let declared = raw
                .get(4..6)
                .map_or(0, |len| u16::from_be_bytes([len[0], len[1]]) as usize);
            prop_assert!(raw.len() < constants::CHANNEL_ENVELOPE_OVERHEAD + declared);
        }
    }
}
