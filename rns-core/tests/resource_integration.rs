extern crate rns_core;
extern crate rns_crypto;

use rns_core::constants::*;
use rns_core::resource::sender::ResourceSender;
use rns_core::resource::receiver::ResourceReceiver;
use rns_core::resource::types::*;
use rns_core::buffer::types::NoopCompressor;

fn identity_encrypt(data: &[u8]) -> Vec<u8> {
    data.to_vec()
}

fn identity_decrypt(data: &[u8]) -> Result<Vec<u8>, ()> {
    Ok(data.to_vec())
}

/// Full sender↔receiver cycle for small data (single part).
#[test]
fn test_full_cycle_single_part() {
    let data = b"Hello, Resource!";
    let mut rng = rns_crypto::FixedRng::new(&[0x42; 64]);

    let mut sender = ResourceSender::new(
        data,
        None,
        RESOURCE_SDU,
        &identity_encrypt,
        &NoopCompressor,
        &mut rng,
        1000.0,
        false,
        false,
        None,
        1,
        1,
        None,
        0.5,
        6.0,
    )
    .unwrap();

    // Advertise
    let _adv_actions = sender.advertise(1000.0);
    assert_eq!(sender.status, ResourceStatus::Advertised);
    let adv_data = sender.get_advertisement(0);

    // Receiver creates from advertisement
    let mut receiver = ResourceReceiver::from_advertisement(
        &adv_data,
        RESOURCE_SDU,
        0.5,
        1000.0,
        None,
        None,
    )
    .unwrap();

    // Accept
    let req_actions = receiver.accept(1001.0);
    assert_eq!(receiver.status, ResourceStatus::Transferring);

    let request_data = req_actions
        .iter()
        .find_map(|a| match a {
            ResourceAction::SendRequest(d) => Some(d.clone()),
            _ => None,
        })
        .unwrap();

    // Sender handles request → sends parts
    let send_actions = sender.handle_request(&request_data, 1002.0);

    // Feed all parts to receiver
    receiver.req_sent = 1001.0;
    for action in &send_actions {
        if let ResourceAction::SendPart(part_data) = action {
            receiver.receive_part(part_data, 1003.0);
        }
    }

    assert_eq!(receiver.received_count, receiver.total_parts);

    // Assemble
    let assemble_actions = receiver.assemble(&identity_decrypt, &NoopCompressor);

    // Verify proof, data, completion
    let proof_data = assemble_actions
        .iter()
        .find_map(|a| match a {
            ResourceAction::SendProof(d) => Some(d.clone()),
            _ => None,
        })
        .unwrap();

    let received_data = assemble_actions
        .iter()
        .find_map(|a| match a {
            ResourceAction::DataReceived { data, .. } => Some(data.clone()),
            _ => None,
        })
        .unwrap();

    assert_eq!(received_data, data);

    // Sender validates proof
    let proof_result = sender.handle_proof(&proof_data, 1004.0);
    assert_eq!(sender.status, ResourceStatus::Complete);
    assert!(proof_result.iter().any(|a| matches!(a, ResourceAction::Completed)));
}

/// Full cycle with multi-part data (> 3 * SDU).
#[test]
fn test_full_cycle_multi_part() {
    // Create data that needs 4+ parts: 4 * 464 = 1856 > SDU
    // Use data where each SDU-chunk is unique (identity_encrypt doesn't transform data,
    // so identical parts produce identical map hashes, causing unavoidable collisions)
    let data: Vec<u8> = (0..1500u32).map(|i| (i ^ (i >> 8)) as u8).collect();
    let seed: Vec<u8> = (0..=255).collect();
    let mut rng = rns_crypto::FixedRng::new(&seed);

    let mut sender = ResourceSender::new(
        &data,
        None,
        RESOURCE_SDU,
        &identity_encrypt,
        &NoopCompressor,
        &mut rng,
        1000.0,
        false,
        false,
        None,
        1,
        1,
        None,
        0.5,
        6.0,
    )
    .unwrap();

    // Data is: 4 (random) + 1500 = 1504 bytes → ceil(1504/464) = 4 parts
    assert!(sender.total_parts() >= 3);

    let adv_data = sender.get_advertisement(0);
    let mut receiver = ResourceReceiver::from_advertisement(
        &adv_data,
        RESOURCE_SDU,
        0.5,
        1000.0,
        None,
        None,
    )
    .unwrap();

    // Transfer loop
    let req_actions = receiver.accept(1001.0);
    let mut request_data = req_actions
        .iter()
        .find_map(|a| match a {
            ResourceAction::SendRequest(d) => Some(d.clone()),
            _ => None,
        })
        .unwrap();

    let mut iteration = 0;
    loop {
        iteration += 1;
        if iteration > 20 {
            panic!("Transfer loop exceeded max iterations");
        }

        let send_actions = sender.handle_request(&request_data, 1002.0 + iteration as f64);

        receiver.req_sent = 1001.0 + iteration as f64;
        let mut any_part_sent = false;
        for action in &send_actions {
            if let ResourceAction::SendPart(part_data) = action {
                receiver.receive_part(part_data, 1003.0 + iteration as f64);
                any_part_sent = true;
            }
        }

        if receiver.received_count == receiver.total_parts {
            break;
        }

        // Get next request if window is done
        if receiver.outstanding_parts == 0 {
            let next_req = receiver.request_next(1004.0 + iteration as f64);
            if let Some(rd) = next_req.iter().find_map(|a| match a {
                ResourceAction::SendRequest(d) => Some(d.clone()),
                _ => None,
            }) {
                request_data = rd;
            } else {
                break;
            }
        } else if !any_part_sent {
            break; // No progress
        }
    }

    assert_eq!(receiver.received_count, receiver.total_parts);

    // Assemble and verify
    let assemble_actions = receiver.assemble(&identity_decrypt, &NoopCompressor);
    let received_data = assemble_actions
        .iter()
        .find_map(|a| match a {
            ResourceAction::DataReceived { data, .. } => Some(data.clone()),
            _ => None,
        })
        .unwrap();
    assert_eq!(received_data, data);

    // Validate proof
    let proof_data = assemble_actions
        .iter()
        .find_map(|a| match a {
            ResourceAction::SendProof(d) => Some(d.clone()),
            _ => None,
        })
        .unwrap();
    sender.handle_proof(&proof_data, 2000.0);
    assert_eq!(sender.status, ResourceStatus::Complete);
}

/// Full cycle with metadata.
#[test]
fn test_full_cycle_with_metadata() {
    let data = b"resource data payload";
    let metadata = b"metadata bytes here";
    let mut rng = rns_crypto::FixedRng::new(&[0x99; 64]);

    let mut sender = ResourceSender::new(
        data,
        Some(metadata),
        RESOURCE_SDU,
        &identity_encrypt,
        &NoopCompressor,
        &mut rng,
        1000.0,
        false,
        false,
        None,
        1,
        1,
        None,
        0.5,
        6.0,
    )
    .unwrap();

    assert!(sender.flags.has_metadata);

    let adv_data = sender.get_advertisement(0);
    let mut receiver = ResourceReceiver::from_advertisement(
        &adv_data,
        RESOURCE_SDU,
        0.5,
        1000.0,
        None,
        None,
    )
    .unwrap();

    assert!(receiver.has_metadata);

    // Transfer
    let req_actions = receiver.accept(1001.0);
    let request_data = req_actions
        .iter()
        .find_map(|a| match a {
            ResourceAction::SendRequest(d) => Some(d.clone()),
            _ => None,
        })
        .unwrap();

    let send_actions = sender.handle_request(&request_data, 1002.0);
    receiver.req_sent = 1001.0;
    for action in &send_actions {
        if let ResourceAction::SendPart(part_data) = action {
            receiver.receive_part(part_data, 1003.0);
        }
    }

    // Assemble
    let assemble_actions = receiver.assemble(&identity_decrypt, &NoopCompressor);

    let (recv_data, recv_meta) = assemble_actions
        .iter()
        .find_map(|a| match a {
            ResourceAction::DataReceived { data, metadata } => Some((data.clone(), metadata.clone())),
            _ => None,
        })
        .unwrap();

    assert_eq!(recv_data, data);
    assert_eq!(recv_meta.unwrap(), metadata);

    // Proof validation
    let proof_data = assemble_actions
        .iter()
        .find_map(|a| match a {
            ResourceAction::SendProof(d) => Some(d.clone()),
            _ => None,
        })
        .unwrap();
    sender.handle_proof(&proof_data, 1004.0);
    assert_eq!(sender.status, ResourceStatus::Complete);
}

/// Sender cancel mid-transfer.
#[test]
fn test_cancel_from_sender() {
    let mut rng = rns_crypto::FixedRng::new(&[0xAA; 64]);
    let mut sender = ResourceSender::new(
        b"data",
        None,
        RESOURCE_SDU,
        &identity_encrypt,
        &NoopCompressor,
        &mut rng,
        1000.0,
        false,
        false,
        None,
        1,
        1,
        None,
        0.5,
        6.0,
    )
    .unwrap();

    sender.advertise(1000.0);

    let cancel_actions = sender.cancel();
    assert_eq!(sender.status, ResourceStatus::Failed);
    assert!(cancel_actions.iter().any(|a| matches!(a, ResourceAction::SendCancelInitiator(_))));

    // Receiver gets the cancel
    let adv_data = {
        let mut rng2 = rns_crypto::FixedRng::new(&[0xAA; 64]);
        let s = ResourceSender::new(
            b"data",
            None,
            RESOURCE_SDU,
            &identity_encrypt,
            &NoopCompressor,
            &mut rng2,
            1000.0,
            false,
            false,
            None,
            1,
            1,
            None,
            0.5,
            6.0,
        )
        .unwrap();
        s.get_advertisement(0)
    };
    let mut receiver = ResourceReceiver::from_advertisement(
        &adv_data,
        RESOURCE_SDU,
        0.5,
        1000.0,
        None,
        None,
    )
    .unwrap();
    receiver.accept(1001.0);

    let _cancel_result = receiver.handle_cancel();
    assert_eq!(receiver.status, ResourceStatus::Failed);
}

/// Receiver reject.
#[test]
fn test_reject_from_receiver() {
    let mut rng = rns_crypto::FixedRng::new(&[0xBB; 64]);
    let mut sender = ResourceSender::new(
        b"data",
        None,
        RESOURCE_SDU,
        &identity_encrypt,
        &NoopCompressor,
        &mut rng,
        1000.0,
        false,
        false,
        None,
        1,
        1,
        None,
        0.5,
        6.0,
    )
    .unwrap();

    let adv_data = sender.get_advertisement(0);
    let mut receiver = ResourceReceiver::from_advertisement(
        &adv_data,
        RESOURCE_SDU,
        0.5,
        1000.0,
        None,
        None,
    )
    .unwrap();

    let reject_actions = receiver.reject();
    assert_eq!(receiver.status, ResourceStatus::Rejected);
    assert!(reject_actions.iter().any(|a| matches!(a, ResourceAction::SendCancelReceiver(_))));

    // Sender handles the rejection
    let _reject_result = sender.handle_reject();
    assert_eq!(sender.status, ResourceStatus::Rejected);
}

/// Simulated packet loss — receiver doesn't get one part, requests retry.
#[test]
fn test_simulated_packet_loss() {
    // Use data where each SDU-chunk is unique (identity_encrypt doesn't transform data)
    let data: Vec<u8> = (0..1000u32).map(|i| (i ^ (i >> 8)) as u8).collect(); // ~3 parts
    let seed: Vec<u8> = (0..=255).collect();
    let mut rng = rns_crypto::FixedRng::new(&seed);

    let mut sender = ResourceSender::new(
        &data,
        None,
        RESOURCE_SDU,
        &identity_encrypt,
        &NoopCompressor,
        &mut rng,
        1000.0,
        false,
        false,
        None,
        1,
        1,
        None,
        0.5,
        6.0,
    )
    .unwrap();

    let adv_data = sender.get_advertisement(0);
    let mut receiver = ResourceReceiver::from_advertisement(
        &adv_data,
        RESOURCE_SDU,
        0.5,
        1000.0,
        None,
        None,
    )
    .unwrap();

    // Accept
    let req_actions = receiver.accept(1001.0);
    let request_data = req_actions
        .iter()
        .find_map(|a| match a {
            ResourceAction::SendRequest(d) => Some(d.clone()),
            _ => None,
        })
        .unwrap();

    // Sender sends parts, but we "lose" the first one
    let send_actions = sender.handle_request(&request_data, 1002.0);
    let parts: Vec<_> = send_actions
        .iter()
        .filter_map(|a| match a {
            ResourceAction::SendPart(d) => Some(d.clone()),
            _ => None,
        })
        .collect();

    assert!(!parts.is_empty());

    // Only deliver parts after the first one (simulate loss)
    receiver.req_sent = 1001.0;
    for part_data in &parts[1..] {
        receiver.receive_part(part_data, 1003.0);
    }

    // Receiver still waiting for first part, outstanding_parts > 0
    assert!(receiver.received_count < receiver.total_parts);

    // Receiver re-requests (simulating timeout path)
    // The receiver should re-request the missing parts
    let retry_actions = receiver.request_next(1005.0);
    let retry_request = retry_actions
        .iter()
        .find_map(|a| match a {
            ResourceAction::SendRequest(d) => Some(d.clone()),
            _ => None,
        })
        .unwrap();

    // Sender handles retry request
    let retry_send = sender.handle_request(&retry_request, 1006.0);
    receiver.req_sent = 1005.0;
    for action in &retry_send {
        if let ResourceAction::SendPart(part_data) = action {
            receiver.receive_part(part_data, 1007.0);
        }
    }

    // Now all parts should be received
    assert_eq!(receiver.received_count, receiver.total_parts);

    // Assemble and verify
    let assemble_actions = receiver.assemble(&identity_decrypt, &NoopCompressor);
    let received_data = assemble_actions
        .iter()
        .find_map(|a| match a {
            ResourceAction::DataReceived { data, .. } => Some(data.clone()),
            _ => None,
        })
        .unwrap();
    assert_eq!(received_data, data);
}

/// Test with request_id (is_response flow).
#[test]
fn test_with_request_id() {
    let data = b"response data";
    let request_id = vec![0xDE, 0xAD, 0xBE, 0xEF];
    let mut rng = rns_crypto::FixedRng::new(&[0xEE; 64]);

    let sender = ResourceSender::new(
        data,
        None,
        RESOURCE_SDU,
        &identity_encrypt,
        &NoopCompressor,
        &mut rng,
        1000.0,
        false,
        true, // is_response
        Some(request_id.clone()),
        1,
        1,
        None,
        0.5,
        6.0,
    )
    .unwrap();

    assert!(sender.flags.is_response);
    assert!(!sender.flags.is_request);
    assert_eq!(sender.request_id, Some(request_id));
}

/// Hashmap exhaustion and HMU cycle.
#[test]
fn test_hashmap_exhaustion_and_hmu() {
    // Create data large enough that hashmap gets segmented
    // Need > HASHMAP_MAX_LEN(74) parts = 74 * 464 = 34,336 bytes
    // Use data where each SDU-sized chunk is unique (identity_encrypt doesn't transform data,
    // so identical parts would always have identical map hashes).
    // Write the part index into each SDU boundary to guarantee uniqueness.
    let mut data = vec![0u8; 35000];
    for i in 0..data.len() {
        // Mix in the byte position using multiple octets to avoid periodicity
        let pos = i as u32;
        data[i] = (pos ^ (pos >> 8) ^ (pos >> 16)) as u8;
    }
    // Need a large unique seed for 76+ parts to avoid hash collisions
    let seed: Vec<u8> = (0u8..=255).cycle().take(1024).enumerate().map(|(i, b)| b.wrapping_add(i as u8)).collect();
    let mut rng = rns_crypto::FixedRng::new(&seed);

    let mut sender = ResourceSender::new(
        &data,
        None,
        RESOURCE_SDU,
        &identity_encrypt,
        &NoopCompressor,
        &mut rng,
        1000.0,
        false,
        false,
        None,
        1,
        1,
        None,
        0.5,
        6.0,
    )
    .unwrap();

    // Should have > 74 parts
    assert!(sender.total_parts() > RESOURCE_HASHMAP_MAX_LEN,
        "Expected > 74 parts, got {}", sender.total_parts());

    let adv_data = sender.get_advertisement(0);
    let mut receiver = ResourceReceiver::from_advertisement(
        &adv_data,
        RESOURCE_SDU,
        0.5,
        1000.0,
        None,
        None,
    )
    .unwrap();

    // Accept and start transfer loop
    let req_actions = receiver.accept(1001.0);
    let first_request = req_actions
        .iter()
        .find_map(|a| match a {
            ResourceAction::SendRequest(d) => Some(d.clone()),
            _ => None,
        })
        .unwrap();

    let mut iteration = 0;
    let mut hmu_count = 0;
    let mut pending_requests: Vec<Vec<u8>> = vec![first_request];

    loop {
        iteration += 1;
        if iteration > 200 {
            panic!("Transfer loop exceeded max iterations at received={}/{}",
                   receiver.received_count, receiver.total_parts);
        }

        if pending_requests.is_empty() {
            // No pending requests — request more
            let next_req = receiver.request_next(1004.0 + iteration as f64);
            for a in &next_req {
                if let ResourceAction::SendRequest(rd) = a {
                    pending_requests.push(rd.clone());
                }
            }
            if pending_requests.is_empty() {
                if receiver.waiting_for_hmu {
                    // Need to send a request with exhaustion flag to trigger HMU
                    receiver.waiting_for_hmu = false;
                    let req = receiver.request_next(1004.0 + iteration as f64);
                    for a in &req {
                        if let ResourceAction::SendRequest(rd) = a {
                            pending_requests.push(rd.clone());
                        }
                    }
                }
                if pending_requests.is_empty() {
                    panic!("No progress: no pending requests and not waiting for HMU at received={}/{}",
                        receiver.received_count, receiver.total_parts);
                }
            }
        }

        let request_data = pending_requests.remove(0);
        let send_actions = sender.handle_request(&request_data, 1002.0 + iteration as f64);

        // Check for HMU
        for action in &send_actions {
            if let ResourceAction::SendHmu(hmu_data) = action {
                hmu_count += 1;
                let hmu_actions = receiver.handle_hashmap_update(hmu_data, 1003.0 + iteration as f64);
                for ha in &hmu_actions {
                    if let ResourceAction::SendRequest(rd) = ha {
                        pending_requests.push(rd.clone());
                    }
                }
            }
        }

        // Feed parts and collect any new requests generated by receive_part
        receiver.req_sent = 1001.0 + iteration as f64;
        for action in &send_actions {
            if let ResourceAction::SendPart(part_data) = action {
                let recv_actions = receiver.receive_part(part_data, 1003.0 + iteration as f64);
                for ra in &recv_actions {
                    if let ResourceAction::SendRequest(rd) = ra {
                        pending_requests.push(rd.clone());
                    }
                }
            }
        }

        if receiver.received_count == receiver.total_parts {
            break;
        }
    }

    assert!(hmu_count > 0, "Expected at least one HMU, got 0");
    assert_eq!(receiver.received_count, receiver.total_parts);

    // Assemble and verify
    let assemble_actions = receiver.assemble(&identity_decrypt, &NoopCompressor);
    let received_data = assemble_actions
        .iter()
        .find_map(|a| match a {
            ResourceAction::DataReceived { data, .. } => Some(data.clone()),
            _ => None,
        })
        .unwrap();
    assert_eq!(received_data, data);

    // Validate proof
    let proof_data = assemble_actions
        .iter()
        .find_map(|a| match a {
            ResourceAction::SendProof(d) => Some(d.clone()),
            _ => None,
        })
        .unwrap();
    sender.handle_proof(&proof_data, 2000.0);
    assert_eq!(sender.status, ResourceStatus::Complete);
}
