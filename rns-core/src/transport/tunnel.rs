//! Tunnel support for virtual mesh connections between transport instances.
//!
//! Tunnels allow transport nodes to establish virtual connections that
//! preserve path information even across disconnections. When a tunnel
//! reconnects, stored paths are restored to the routing table.
//!
//! Python reference: Transport.py:2120-2217, 378-382, 733-810, 1872-1880

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use rns_crypto::identity::Identity;
use rns_crypto::Rng;

use crate::constants;
use crate::hash;

use super::types::InterfaceId;

/// A tunnel entry in the tunnel table.
#[derive(Debug, Clone)]
pub struct TunnelEntry {
    /// The tunnel ID (SHA-256(public_key || interface_hash)).
    pub tunnel_id: [u8; 32],
    /// The interface this tunnel is currently attached to (None if disconnected).
    pub interface: Option<InterfaceId>,
    /// Paths learned through this tunnel, keyed by destination_hash.
    pub paths: BTreeMap<[u8; 16], TunnelPath>,
    /// When this tunnel expires.
    pub expires: f64,
}

/// A path entry stored in a tunnel.
#[derive(Debug, Clone)]
pub struct TunnelPath {
    pub timestamp: f64,
    pub received_from: [u8; 16],
    pub hops: u8,
    pub expires: f64,
    pub random_blobs: Vec<[u8; 10]>,
    pub packet_hash: [u8; 32],
}

/// Result of validating tunnel synthesis data.
#[derive(Debug)]
pub struct ValidatedTunnel {
    pub tunnel_id: [u8; 32],
    pub public_key: [u8; 64],
    pub interface_hash: [u8; 32],
    pub random_hash: [u8; 16],
}

/// Errors from tunnel operations.
#[derive(Debug)]
pub enum TunnelError {
    /// Data length doesn't match expected.
    InvalidLength,
    /// Ed25519 signature verification failed.
    InvalidSignature,
}

impl core::fmt::Display for TunnelError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            TunnelError::InvalidLength => write!(f, "Invalid tunnel synthesis data length"),
            TunnelError::InvalidSignature => write!(f, "Invalid tunnel signature"),
        }
    }
}

/// Expected length of tunnel synthesis data:
/// public_key(64) + interface_hash(32) + random_hash(16) + signature(64) = 176
pub const TUNNEL_SYNTH_LENGTH: usize =
    constants::KEYSIZE / 8 + constants::HASHLENGTH / 8 + constants::TRUNCATED_HASHLENGTH / 8 + constants::SIGLENGTH / 8;

/// Compute tunnel_id from public key and interface hash.
///
/// tunnel_id = SHA-256(public_key || interface_hash)
pub fn compute_tunnel_id(public_key: &[u8; 64], interface_hash: &[u8; 32]) -> [u8; 32] {
    let mut data = Vec::with_capacity(96);
    data.extend_from_slice(public_key);
    data.extend_from_slice(interface_hash);
    hash::full_hash(&data)
}

/// Build tunnel synthesis data for broadcasting.
///
/// Returns (data, tunnel_id) where data = public_key(64) + interface_hash(32)
/// + random_hash(16) + signature(64) = 176 bytes.
///
/// The signature covers: public_key || interface_hash || random_hash.
pub fn build_tunnel_synthesize_data(
    identity: &Identity,
    interface_hash: &[u8; 32],
    rng: &mut dyn Rng,
) -> Result<(Vec<u8>, [u8; 32]), TunnelError> {
    let public_key = identity
        .get_public_key()
        .ok_or(TunnelError::InvalidSignature)?;

    let tunnel_id = compute_tunnel_id(&public_key, interface_hash);

    // random_hash = 16 random bytes
    let mut random_hash = [0u8; 16];
    rng.fill_bytes(&mut random_hash);

    // signed_data = public_key(64) + interface_hash(32) + random_hash(16)
    let mut signed_data = Vec::with_capacity(112);
    signed_data.extend_from_slice(&public_key);
    signed_data.extend_from_slice(interface_hash);
    signed_data.extend_from_slice(&random_hash);

    let signature = identity
        .sign(&signed_data)
        .map_err(|_| TunnelError::InvalidSignature)?;

    // data = signed_data(112) + signature(64) = 176
    let mut data = signed_data;
    data.extend_from_slice(&signature);

    Ok((data, tunnel_id))
}

/// Validate tunnel synthesis data received from a remote transport node.
///
/// Verifies the Ed25519 signature and extracts the tunnel_id.
pub fn validate_tunnel_synthesize_data(data: &[u8]) -> Result<ValidatedTunnel, TunnelError> {
    if data.len() != TUNNEL_SYNTH_LENGTH {
        return Err(TunnelError::InvalidLength);
    }

    // Parse fields
    let mut public_key = [0u8; 64];
    public_key.copy_from_slice(&data[0..64]);

    let mut interface_hash = [0u8; 32];
    interface_hash.copy_from_slice(&data[64..96]);

    let mut random_hash = [0u8; 16];
    random_hash.copy_from_slice(&data[96..112]);

    let mut signature = [0u8; 64];
    signature.copy_from_slice(&data[112..176]);

    // Verify signature over (public_key || interface_hash || random_hash)
    let signed_data = &data[0..112];
    let remote_identity = Identity::from_public_key(&public_key);
    if !remote_identity.verify(&signature, signed_data) {
        return Err(TunnelError::InvalidSignature);
    }

    // Compute tunnel_id
    let tunnel_id = compute_tunnel_id(&public_key, &interface_hash);

    Ok(ValidatedTunnel {
        tunnel_id,
        public_key,
        interface_hash,
        random_hash,
    })
}

/// Manage the tunnel table: creation, reattachment, path tracking, culling.
#[derive(Debug)]
pub struct TunnelTable {
    tunnels: BTreeMap<[u8; 32], TunnelEntry>,
}

impl TunnelTable {
    pub fn new() -> Self {
        TunnelTable {
            tunnels: BTreeMap::new(),
        }
    }

    /// Handle a validated tunnel — create new or reattach existing.
    ///
    /// Returns paths to restore if reattaching an existing tunnel.
    /// Each tuple is (destination_hash, TunnelPath).
    pub fn handle_tunnel(
        &mut self,
        tunnel_id: [u8; 32],
        interface: InterfaceId,
        now: f64,
    ) -> Vec<([u8; 16], TunnelPath)> {
        let expires = now + constants::DESTINATION_TIMEOUT;

        if let Some(entry) = self.tunnels.get_mut(&tunnel_id) {
            // Reattach: update interface and expiry
            entry.interface = Some(interface);
            entry.expires = expires;

            // Return paths for restoration
            entry
                .paths
                .iter()
                .map(|(dest, path)| (*dest, path.clone()))
                .collect()
        } else {
            // New tunnel
            self.tunnels.insert(
                tunnel_id,
                TunnelEntry {
                    tunnel_id,
                    interface: Some(interface),
                    paths: BTreeMap::new(),
                    expires,
                },
            );
            Vec::new()
        }
    }

    /// Void a tunnel's interface (disconnected), preserving paths.
    pub fn void_tunnel_interface(&mut self, tunnel_id: &[u8; 32]) {
        if let Some(entry) = self.tunnels.get_mut(tunnel_id) {
            entry.interface = None;
        }
    }

    /// Store a path in a tunnel (called when announce arrives on tunnel interface).
    pub fn store_tunnel_path(
        &mut self,
        tunnel_id: &[u8; 32],
        destination_hash: [u8; 16],
        path: TunnelPath,
        now: f64,
    ) {
        if let Some(entry) = self.tunnels.get_mut(tunnel_id) {
            entry.paths.insert(destination_hash, path);
            // Extend tunnel expiry on activity
            entry.expires = now + constants::DESTINATION_TIMEOUT;
        }
    }

    /// Cull expired tunnels and tunnel paths.
    ///
    /// Returns tunnel IDs that were removed.
    pub fn cull(&mut self, now: f64) -> Vec<[u8; 32]> {
        // Cull expired paths within each tunnel
        for entry in self.tunnels.values_mut() {
            entry.paths.retain(|_, path| {
                path.expires > now
            });
        }

        // Cull expired tunnels
        let expired: Vec<[u8; 32]> = self
            .tunnels
            .iter()
            .filter(|(_, entry)| entry.expires < now)
            .map(|(id, _)| *id)
            .collect();

        for id in &expired {
            self.tunnels.remove(id);
        }

        expired
    }

    /// Void interfaces that are no longer registered.
    pub fn void_missing_interfaces<F: Fn(&InterfaceId) -> bool>(&mut self, is_registered: F) {
        for entry in self.tunnels.values_mut() {
            if let Some(iface) = entry.interface {
                if !is_registered(&iface) {
                    entry.interface = None;
                }
            }
        }
    }

    /// Get a tunnel entry by ID.
    pub fn get(&self, tunnel_id: &[u8; 32]) -> Option<&TunnelEntry> {
        self.tunnels.get(tunnel_id)
    }

    /// Get a mutable tunnel entry by ID.
    pub fn get_mut(&mut self, tunnel_id: &[u8; 32]) -> Option<&mut TunnelEntry> {
        self.tunnels.get_mut(tunnel_id)
    }

    /// Number of tunnels in the table.
    pub fn len(&self) -> usize {
        self.tunnels.len()
    }

    /// Whether the table is empty.
    pub fn is_empty(&self) -> bool {
        self.tunnels.is_empty()
    }

    /// Iterate over all tunnel entries.
    pub fn iter(&self) -> impl Iterator<Item = (&[u8; 32], &TunnelEntry)> {
        self.tunnels.iter()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_identity() -> Identity {
        let mut rng = rns_crypto::FixedRng::new(&[0x42; 32]);
        Identity::new(&mut rng)
    }

    #[test]
    fn test_tunnel_synth_length() {
        // 64 + 32 + 16 + 64 = 176
        assert_eq!(TUNNEL_SYNTH_LENGTH, 176);
    }

    #[test]
    fn test_compute_tunnel_id() {
        let pub_key = [0xAA; 64];
        let iface_hash = [0xBB; 32];
        let tid = compute_tunnel_id(&pub_key, &iface_hash);

        // Should be SHA-256(pub_key || iface_hash)
        let mut data = Vec::new();
        data.extend_from_slice(&pub_key);
        data.extend_from_slice(&iface_hash);
        let expected = hash::full_hash(&data);
        assert_eq!(tid, expected);
    }

    #[test]
    fn test_compute_tunnel_id_deterministic() {
        let pub_key = [0x11; 64];
        let iface_hash = [0x22; 32];
        let tid1 = compute_tunnel_id(&pub_key, &iface_hash);
        let tid2 = compute_tunnel_id(&pub_key, &iface_hash);
        assert_eq!(tid1, tid2);
    }

    #[test]
    fn test_compute_tunnel_id_different_inputs() {
        let pub_key = [0x11; 64];
        let iface_hash1 = [0x22; 32];
        let iface_hash2 = [0x33; 32];
        let tid1 = compute_tunnel_id(&pub_key, &iface_hash1);
        let tid2 = compute_tunnel_id(&pub_key, &iface_hash2);
        assert_ne!(tid1, tid2);
    }

    #[test]
    fn test_build_validate_roundtrip() {
        let identity = make_identity();
        let iface_hash = [0xCC; 32];
        let mut rng = rns_crypto::FixedRng::new(&[0x55; 32]);

        let (data, tunnel_id) =
            build_tunnel_synthesize_data(&identity, &iface_hash, &mut rng).unwrap();
        assert_eq!(data.len(), TUNNEL_SYNTH_LENGTH);

        let validated = validate_tunnel_synthesize_data(&data).unwrap();
        assert_eq!(validated.tunnel_id, tunnel_id);
        assert_eq!(
            validated.public_key,
            identity.get_public_key().unwrap()
        );
        assert_eq!(validated.interface_hash, iface_hash);
    }

    #[test]
    fn test_validate_invalid_length() {
        let result = validate_tunnel_synthesize_data(&[0u8; 100]);
        assert!(matches!(result, Err(TunnelError::InvalidLength)));
    }

    #[test]
    fn test_validate_invalid_signature() {
        // Use a valid identity's public key but a wrong signature
        let identity = make_identity();
        let pub_key = identity.get_public_key().unwrap();
        let iface_hash = [0xEE; 32];
        let random_hash = [0xFF; 16];

        let mut data = Vec::with_capacity(TUNNEL_SYNTH_LENGTH);
        data.extend_from_slice(&pub_key);
        data.extend_from_slice(&iface_hash);
        data.extend_from_slice(&random_hash);
        // Append a wrong signature (64 zero bytes)
        data.extend_from_slice(&[0u8; 64]);

        let result = validate_tunnel_synthesize_data(&data);
        assert!(matches!(result, Err(TunnelError::InvalidSignature)));
    }

    #[test]
    fn test_validate_tampered_data() {
        let identity = make_identity();
        let iface_hash = [0xDD; 32];
        let mut rng = rns_crypto::FixedRng::new(&[0x66; 32]);

        let (mut data, _) =
            build_tunnel_synthesize_data(&identity, &iface_hash, &mut rng).unwrap();

        // Tamper with the random_hash
        data[100] ^= 0xFF;

        let result = validate_tunnel_synthesize_data(&data);
        assert!(matches!(result, Err(TunnelError::InvalidSignature)));
    }

    #[test]
    fn test_tunnel_table_new_tunnel() {
        let mut table = TunnelTable::new();
        let tunnel_id = [0x11; 32];
        let now = 1000.0;

        let restored = table.handle_tunnel(tunnel_id, InterfaceId(1), now);
        assert!(restored.is_empty());
        assert_eq!(table.len(), 1);

        let entry = table.get(&tunnel_id).unwrap();
        assert_eq!(entry.interface, Some(InterfaceId(1)));
        assert_eq!(entry.expires, now + constants::DESTINATION_TIMEOUT);
        assert!(entry.paths.is_empty());
    }

    #[test]
    fn test_tunnel_table_reattach() {
        let mut table = TunnelTable::new();
        let tunnel_id = [0x22; 32];
        let now = 1000.0;

        // Create tunnel
        table.handle_tunnel(tunnel_id, InterfaceId(1), now);

        // Add a path
        let dest = [0xAA; 16];
        table.store_tunnel_path(
            &tunnel_id,
            dest,
            TunnelPath {
                timestamp: now,
                received_from: [0xBB; 16],
                hops: 3,
                expires: now + constants::DESTINATION_TIMEOUT,
                random_blobs: Vec::new(),
                packet_hash: [0xCC; 32],
            },
            now,
        );

        // Void interface (disconnect)
        table.void_tunnel_interface(&tunnel_id);
        assert_eq!(table.get(&tunnel_id).unwrap().interface, None);

        // Reattach on new interface
        let restored = table.handle_tunnel(tunnel_id, InterfaceId(2), now + 100.0);
        assert_eq!(restored.len(), 1);
        assert_eq!(restored[0].0, dest);
        assert_eq!(restored[0].1.hops, 3);

        let entry = table.get(&tunnel_id).unwrap();
        assert_eq!(entry.interface, Some(InterfaceId(2)));
    }

    #[test]
    fn test_tunnel_table_store_path() {
        let mut table = TunnelTable::new();
        let tunnel_id = [0x33; 32];
        let now = 1000.0;

        table.handle_tunnel(tunnel_id, InterfaceId(1), now);

        let dest = [0xDD; 16];
        table.store_tunnel_path(
            &tunnel_id,
            dest,
            TunnelPath {
                timestamp: now,
                received_from: [0xEE; 16],
                hops: 2,
                expires: now + constants::DESTINATION_TIMEOUT,
                random_blobs: Vec::new(),
                packet_hash: [0xFF; 32],
            },
            now,
        );

        let entry = table.get(&tunnel_id).unwrap();
        assert_eq!(entry.paths.len(), 1);
        assert!(entry.paths.contains_key(&dest));
    }

    #[test]
    fn test_tunnel_table_cull_expired_tunnel() {
        let mut table = TunnelTable::new();
        let tunnel_id = [0x44; 32];
        let now = 1000.0;

        table.handle_tunnel(tunnel_id, InterfaceId(1), now);

        // Not expired yet
        let removed = table.cull(now + 100.0);
        assert!(removed.is_empty());
        assert_eq!(table.len(), 1);

        // Expired
        let removed = table.cull(now + constants::DESTINATION_TIMEOUT + 1.0);
        assert_eq!(removed.len(), 1);
        assert_eq!(removed[0], tunnel_id);
        assert!(table.is_empty());
    }

    #[test]
    fn test_tunnel_table_cull_expired_paths() {
        let mut table = TunnelTable::new();
        let tunnel_id = [0x55; 32];
        let now = 1000.0;

        table.handle_tunnel(tunnel_id, InterfaceId(1), now);

        // Add two paths with different expiry
        let dest1 = [0xAA; 16];
        let dest2 = [0xBB; 16];
        table.store_tunnel_path(
            &tunnel_id,
            dest1,
            TunnelPath {
                timestamp: now,
                received_from: [0; 16],
                hops: 1,
                expires: now + 100.0, // expires soon
                random_blobs: Vec::new(),
                packet_hash: [0; 32],
            },
            now,
        );
        table.store_tunnel_path(
            &tunnel_id,
            dest2,
            TunnelPath {
                timestamp: now,
                received_from: [0; 16],
                hops: 2,
                expires: now + constants::DESTINATION_TIMEOUT, // expires later
                random_blobs: Vec::new(),
                packet_hash: [0; 32],
            },
            now,
        );

        // Cull: dest1 should be removed, dest2 kept
        table.cull(now + 200.0);

        let entry = table.get(&tunnel_id).unwrap();
        assert_eq!(entry.paths.len(), 1);
        assert!(!entry.paths.contains_key(&dest1));
        assert!(entry.paths.contains_key(&dest2));
    }

    #[test]
    fn test_tunnel_table_void_missing_interfaces() {
        let mut table = TunnelTable::new();
        let t1 = [0x66; 32];
        let t2 = [0x77; 32];
        let now = 1000.0;

        table.handle_tunnel(t1, InterfaceId(1), now);
        table.handle_tunnel(t2, InterfaceId(2), now);

        // Only interface 1 is registered
        table.void_missing_interfaces(|id| *id == InterfaceId(1));

        assert_eq!(table.get(&t1).unwrap().interface, Some(InterfaceId(1)));
        assert_eq!(table.get(&t2).unwrap().interface, None);
    }

    #[test]
    fn test_tunnel_table_void_tunnel_preserves_paths() {
        let mut table = TunnelTable::new();
        let tunnel_id = [0x88; 32];
        let now = 1000.0;

        table.handle_tunnel(tunnel_id, InterfaceId(1), now);

        let dest = [0xAA; 16];
        table.store_tunnel_path(
            &tunnel_id,
            dest,
            TunnelPath {
                timestamp: now,
                received_from: [0; 16],
                hops: 1,
                expires: now + constants::DESTINATION_TIMEOUT,
                random_blobs: Vec::new(),
                packet_hash: [0; 32],
            },
            now,
        );

        table.void_tunnel_interface(&tunnel_id);

        let entry = table.get(&tunnel_id).unwrap();
        assert_eq!(entry.interface, None);
        assert_eq!(entry.paths.len(), 1); // paths preserved
    }

    #[test]
    fn test_tunnel_table_store_nonexistent() {
        let mut table = TunnelTable::new();
        // Store to non-existent tunnel should be a no-op
        table.store_tunnel_path(
            &[0xFF; 32],
            [0xAA; 16],
            TunnelPath {
                timestamp: 1000.0,
                received_from: [0; 16],
                hops: 1,
                expires: 2000.0,
                random_blobs: Vec::new(),
                packet_hash: [0; 32],
            },
            1000.0,
        );
        assert!(table.is_empty());
    }
}
