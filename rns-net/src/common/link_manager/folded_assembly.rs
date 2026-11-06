//! Assembly of incoming compressed resources on the compact engine's driver
//! loop, in slices, when CPU work is folded (`compact-threads-work` keeps the
//! receive worker thread instead).

use super::*;
use crate::common::compressor::BoundedDecompression;
use rns_core::buffer::types::DecompressError;
use rns_core::resource::{AssemblyId, AssemblyResult, ResourceAssembly};
use rns_crypto::sha256::Sha256;
use std::sync::Arc;

/// Output decoded per slice. bzip2 decodes a whole block (up to 900 kB, as
/// large as the sender chose) the first time any of its output is read, so a
/// slice that reaches a new block also pays for that block's decoding; that
/// is the smallest piece decompression can be cut into.
const FOLDED_ASSEMBLY_OUTPUT: usize = 256 * 1024;

/// Folded assemblies queued at most, as the receive worker admits; past it a
/// resource is assembled at once.
pub(super) const MAX_FOLDED_ASSEMBLIES: usize = 4;

pub(super) struct FoldedAssembly {
    pub(super) link: LinkId,
    generation: Arc<()>,
    id: AssemblyId,
    assembly: Option<ResourceAssembly>,
    decoder: BoundedDecompression<std::io::Cursor<Vec<u8>>>,
    hash: Sha256,
    hashed: usize,
}

impl FoldedAssembly {
    pub(super) fn new(link: LinkId, generation: Arc<()>, mut assembly: ResourceAssembly) -> Self {
        let input = assembly.take_compressed_data();
        let limit = assembly.max_output_size();
        FoldedAssembly {
            link,
            generation,
            id: assembly.id().clone(),
            assembly: Some(assembly),
            decoder: BoundedDecompression::new(std::io::Cursor::new(input), limit),
            hash: Sha256::new(),
            hashed: 0,
        }
    }

    /// Decompress and hash the next piece. Returns the result once the
    /// data is complete, or the decompression failed.
    fn step(&mut self) -> Option<AssemblyResult> {
        let done = self.decoder.step(FOLDED_ASSEMBLY_OUTPUT);
        match done {
            None => {
                let output = self.decoder.output();
                self.hash.update(&output[self.hashed..]);
                self.hashed = output.len();
                None
            }
            Some(Ok(data)) => {
                self.hash.update(&data[self.hashed..]);
                let hash = core::mem::take(&mut self.hash);
                let assembly = self.assembly.take()?;
                Some(assembly.finish_decompressed(data, Some(hash)))
            }
            Some(Err(error)) => {
                let assembly = self.assembly.take()?;
                Some(assembly.decompression_failed(matches!(error, DecompressError::TooLarge)))
            }
        }
    }
}

impl LinkManager {
    /// Queue an authenticated assembly for the driver loop. Returns it back
    /// when the queue is full, for the caller to assemble at once.
    pub(super) fn queue_folded_assembly(
        &mut self,
        link: LinkId,
        generation: Arc<()>,
        assembly: ResourceAssembly,
    ) -> Result<(), ResourceAssembly> {
        if self.folded_assemblies.len() >= MAX_FOLDED_ASSEMBLIES {
            return Err(assembly);
        }
        self.folded_assemblies
            .push_back(FoldedAssembly::new(link, generation, assembly));
        Ok(())
    }

    pub(crate) fn has_folded_assembly(&self) -> bool {
        !self.folded_assemblies.is_empty()
    }

    /// Run one slice of the oldest folded assembly, completing it on the
    /// resource's receiver once done, as the receive worker's result would.
    pub(crate) fn step_folded_assembly(&mut self, rng: &mut dyn Rng) -> Vec<LinkManagerAction> {
        let Some(job) = self.folded_assemblies.front_mut() else {
            return Vec::new();
        };
        let Some(result) = job.step() else {
            return Vec::new();
        };
        let Some(job) = self.folded_assemblies.pop_front() else {
            return Vec::new();
        };
        let Some(receiver) = self
            .links
            .get_mut(&job.link)
            .filter(|link| {
                link.engine.state() == LinkState::Active
                    && Arc::ptr_eq(&link.resource_generation, &job.generation)
            })
            .and_then(|link| {
                link.incoming_resources
                    .iter_mut()
                    .find(|r| r.assembly_id() == Some(&job.id))
            })
        else {
            return Vec::new();
        };
        let actions = receiver.complete_assembly(result);
        let out = self.process_resource_actions(&job.link, actions, rng);
        self.prune_concluded_incoming(&job.link);
        out
    }

    /// Complete every folded assembly up to the last one of `link`, so that
    /// work after them on that link keeps its order.
    pub(super) fn finish_folded_assemblies_for(
        &mut self,
        link: &LinkId,
        rng: &mut dyn Rng,
    ) -> Vec<LinkManagerAction> {
        let mut actions = Vec::new();
        while self.folded_assemblies.iter().any(|job| &job.link == link) {
            actions.extend(self.step_folded_assembly(rng));
        }
        actions
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rns_core::resource::{ResourceAction, ResourceError, ResourceReceiver, ResourceSender};

    /// A receiver holding an assembly of `data`, compressed, fully received
    /// and authenticated, and the assembly.
    fn assembly(data: &[u8], limit: usize) -> (ResourceReceiver, ResourceAssembly) {
        // Fixed, so that two calls build the same resource.
        let mut rng = rns_crypto::FixedRng::new(&[0x5C; 64]);
        let mut sender = ResourceSender::new(
            data,
            Some(b"metadata"),
            constants::RESOURCE_SDU,
            &|x: &[u8]| x.to_vec(),
            &Bzip2Compressor,
            &mut rng,
            1000.,
            true,
            false,
            None,
            1,
            1,
            None,
            0.5,
            6.,
        )
        .unwrap();
        let mut receiver = ResourceReceiver::from_advertisement(
            &sender.get_advertisement(0),
            constants::RESOURCE_SDU,
            0.5,
            1000.,
            None,
            None,
        )
        .unwrap();
        receiver.max_decompressed_size = limit;
        let mut actions = receiver.accept(1001.);
        while let Some(action) = actions.pop() {
            if let ResourceAction::SendRequest(request) = action {
                for action in sender.handle_request(&request, 1002.) {
                    if let ResourceAction::SendPart(part) = action {
                        actions.extend(receiver.receive_part(&part, 1003.));
                    }
                }
            }
        }
        let assembly = receiver
            .prepare_assembly(&|parts, skip| Ok(parts.concat()[skip..].to_vec()))
            .unwrap();
        (receiver, assembly)
    }

    /// The receiver's actions once the assembly is run at once and in
    /// folded slices, and the number of slices.
    fn both_ways(data: &[u8], limit: usize) -> (Vec<ResourceAction>, Vec<ResourceAction>, usize) {
        let (mut receiver, at_once) = assembly(data, limit);
        let expected = receiver.complete_assembly(at_once.run(&Bzip2Compressor));
        let (mut receiver, folded) = assembly(data, limit);
        let mut job = FoldedAssembly::new([7; 16], Arc::new(()), folded);
        let mut slices = 0;
        let result = loop {
            slices += 1;
            if let Some(result) = job.step() {
                break result;
            }
        };
        (expected, receiver.complete_assembly(result), slices)
    }

    #[test]
    fn folded_assembly_in_slices_matches_assembly_at_once() {
        let data: Vec<u8> = (0..900_000)
            .map(|i| (i % 251) as u8 ^ (i / 4099) as u8)
            .collect();
        let (expected, folded, slices) =
            both_ways(&data, constants::RESOURCE_AUTO_COMPRESS_MAX_SIZE);
        assert!(slices >= 4, "{slices} slices");
        assert_eq!(folded, expected);
        assert!(folded
            .iter()
            .any(|a| matches!(a, ResourceAction::DataReceived { data: d, .. } if d == &data)));

        // The output bound applies as it does at once.
        let (expected, folded, _) = both_ways(&data, 100_000);
        assert_eq!(folded, expected);
        assert!(folded.contains(&ResourceAction::Failed(ResourceError::TooLarge)));
    }
}
