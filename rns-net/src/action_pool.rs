//! Reusable action buffers.
//!
//! The engine and the link manager report what to do next as action lists.
//! A fresh `Vec` per call cost an allocation and a free for every packet at
//! every layer. Callers instead take a cleared buffer from a pool, have the
//! producer append to it, drain it, and give it back, so its capacity is
//! reused. Dispatch nests (a link action sends a packet whose transport
//! actions are dispatched in turn), so a pool holds several buffers.

/// Buffers kept for reuse; deeper nesting allocates as before.
const KEEP: usize = 8;
/// A buffer that grew past this many entries is dropped instead of kept, so
/// one burst does not pin its memory.
const KEEP_CAPACITY: usize = 256;

pub(crate) struct ActionPool<T> {
    free: Vec<Vec<T>>,
}

impl<T> ActionPool<T> {
    pub(crate) const fn new() -> Self {
        Self { free: Vec::new() }
    }

    /// An empty buffer, reused when one is free.
    pub(crate) fn take(&mut self) -> Vec<T> {
        self.free.pop().unwrap_or_default()
    }

    /// Return a buffer for reuse. Entries still in it are dropped.
    pub(crate) fn give(&mut self, mut buffer: Vec<T>) {
        if buffer.capacity() == 0 || buffer.capacity() > KEEP_CAPACITY || self.free.len() >= KEEP {
            return;
        }
        buffer.clear();
        self.free.push(buffer);
    }
}

impl<T> Default for ActionPool<T> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_returned_buffer_is_reused_empty() {
        let mut pool = ActionPool::new();
        let mut buffer = pool.take();
        buffer.extend([1u32, 2, 3]);
        let address = buffer.as_ptr();
        pool.give(buffer);
        let again = pool.take();
        assert!(again.is_empty());
        assert_eq!(again.as_ptr(), address);
    }

    #[test]
    fn oversized_and_surplus_buffers_are_dropped() {
        let mut pool = ActionPool::new();
        pool.give(Vec::<u8>::with_capacity(KEEP_CAPACITY + 1));
        assert!(pool.take().capacity() == 0);
        for _ in 0..KEEP + 2 {
            pool.give(vec![0u8; 1]);
        }
        assert_eq!(pool.free.len(), KEEP);
    }
}
