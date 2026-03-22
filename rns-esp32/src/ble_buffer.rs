use std::collections::VecDeque;

pub const DEFAULT_CAPACITY: usize = 4096;

pub struct BleRxBuffer {
    queue: VecDeque<u8>,
    capacity: usize,
}

impl BleRxBuffer {
    pub fn new(capacity: usize) -> Self {
        Self {
            queue: VecDeque::with_capacity(capacity),
            capacity,
        }
    }

    pub fn try_extend(&mut self, data: &[u8]) -> bool {
        if self.queue.len() + data.len() > self.capacity {
            return false;
        }

        self.queue.extend(data.iter().copied());
        true
    }

    pub fn pop_into(&mut self, buf: &mut [u8]) -> usize {
        let n = buf.len().min(self.queue.len());
        for b in buf.iter_mut().take(n) {
            *b = self.queue.pop_front().expect("buffer length checked");
        }
        n
    }

    pub fn clear(&mut self) {
        self.queue.clear();
    }

    pub fn len(&self) -> usize {
        self.queue.len()
    }
}

impl Default for BleRxBuffer {
    fn default() -> Self {
        Self::new(DEFAULT_CAPACITY)
    }
}

#[cfg(test)]
mod tests {
    use super::BleRxBuffer;

    #[test]
    fn accepts_write_under_capacity() {
        let mut buf = BleRxBuffer::new(8);
        assert!(buf.try_extend(b"ping"));
        assert_eq!(buf.len(), 4);
    }

    #[test]
    fn rejects_write_that_exceeds_capacity() {
        let mut buf = BleRxBuffer::new(8);
        assert!(buf.try_extend(b"ping"));
        assert!(!buf.try_extend(b"pong!"));
        assert_eq!(buf.len(), 4);
    }

    #[test]
    fn pop_preserves_fifo_order() {
        let mut buf = BleRxBuffer::new(8);
        assert!(buf.try_extend(b"abcdef"));

        let mut out = [0u8; 4];
        let n = buf.pop_into(&mut out);

        assert_eq!(n, 4);
        assert_eq!(&out, b"abcd");
        assert_eq!(buf.len(), 2);
    }
}
