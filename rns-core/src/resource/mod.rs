#![cfg_attr(not(test), deny(clippy::indexing_slicing))]

/// Resource advertisement encoding and decoding.
pub mod advertisement;
pub mod assembly;
/// Part splitting, part map hashes, hashmaps and metadata framing.
pub mod parts;
/// Resource hash and proof computation and validation.
pub mod proof;
/// Receiving side of a resource transfer.
pub mod receiver;
/// Sending side of a resource transfer.
pub mod sender;
/// Resource statuses, advertisement flags, actions and errors.
pub mod types;
/// Transfer window adaptation.
pub mod window;

pub use advertisement::ResourceAdvertisement;
pub use assembly::{AssemblyId, AssemblyResult, ResourceAssembly};
pub use proof::{compute_expected_proof, compute_resource_hash};
pub use receiver::{PartsDecryptFn, ResourceReceiver};
pub use sender::{ResourceEncrypt, ResourceSender};
pub use types::{AdvFlags, ResourceAction, ResourceError, ResourceStatus};
pub use window::WindowState;
