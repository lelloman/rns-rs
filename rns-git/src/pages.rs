use rns_core::types::IdentityHash;
use rns_crypto::identity::Identity;
use rns_net::link_manager::ResourceStrategy;
use rns_net::{Destination, RnsNode};

use crate::{Error, Result};

pub const APP_NAME: &str = "nomadnetwork";
pub const ASPECT_NODE: &str = "node";

pub fn destination_for_identity(identity: &Identity) -> Destination {
    Destination::single_in(APP_NAME, &[ASPECT_NODE], IdentityHash(*identity.hash()))
}

pub fn register_nomadnet_destination(node: &RnsNode, identity: &Identity) -> Result<Destination> {
    let destination = destination_for_identity(identity);
    let public_key = identity
        .get_public_key()
        .ok_or_else(|| Error::msg("repository identity has no public key"))?;
    let private_key = identity
        .get_private_key()
        .ok_or_else(|| Error::msg("repository identity has no private key"))?;
    let sig_prv: [u8; 32] = private_key[32..64].try_into().unwrap();
    let sig_pub: [u8; 32] = public_key[32..64].try_into().unwrap();

    node.register_link_destination(
        destination.hash.0,
        sig_prv,
        sig_pub,
        ResourceStrategy::AcceptAll as u8,
    )
    .map_err(|_| Error::msg("failed to register Nomad Network page destination"))?;

    Ok(destination)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rns_crypto::OsRng;

    #[test]
    fn nomadnet_destination_uses_upstream_name() {
        let identity = Identity::new(&mut OsRng);
        let destination = destination_for_identity(&identity);
        let expected =
            Destination::single_in("nomadnetwork", &["node"], IdentityHash(*identity.hash()));
        assert_eq!(destination.hash, expected.hash);
    }
}
