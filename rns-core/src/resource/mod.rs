pub(crate) mod advertisement;
pub(crate) mod assembly;
/// Part splitting, part map hashes, hashmaps and metadata framing.
pub mod parts;
pub(crate) mod proof;
pub(crate) mod receiver;
pub(crate) mod sender;
pub(crate) mod types;
pub(crate) mod window;

pub use advertisement::ResourceAdvertisement;
pub use assembly::{AssemblyId, AssemblyResult, ResourceAssembly};
pub use proof::{compute_expected_proof, compute_resource_hash};
pub use receiver::{PartsDecryptFn, ResourceReceiver};
pub use sender::{ResourceEncrypt, ResourceSender};
pub use types::{AdvFlags, ResourceAction, ResourceError, ResourceStatus};
pub use window::WindowState;
