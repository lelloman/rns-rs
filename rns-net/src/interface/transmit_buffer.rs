//! Coalescing buffer for complete, on-wire interface frames.

use std::collections::VecDeque;
use std::io::{self, Write};

pub(crate) const COALESCE_TARGET: usize = 65_536;

struct Chunk {
    data: Vec<u8>,
    frames: usize,
}

/// Single-owner transmit buffer with bounded coalescing chunks.
///
/// The producer appends finalized frames. The consumer drains immutable
/// chunks, resuming at `head_offset` after a partial write.
pub(crate) struct TransmitBuffer {
    chunks: VecDeque<Chunk>,
    tail: Vec<u8>,
    tail_frames: usize,
    head_offset: usize,
    total_bytes: usize,
    visible_bytes: usize,
    total_frames: usize,
    sent_bytes: usize,
    sent_frames: usize,
}

impl TransmitBuffer {
    pub(crate) fn new() -> Self {
        Self {
            chunks: VecDeque::new(),
            tail: Vec::new(),
            tail_frames: 0,
            head_offset: 0,
            total_bytes: 0,
            visible_bytes: 0,
            total_frames: 0,
            sent_bytes: 0,
            sent_frames: 0,
        }
    }

    /// Append one finalized on-wire frame.
    pub(crate) fn append(&mut self, frame: Vec<u8>) {
        let frame_len = frame.len();
        self.total_bytes = self.total_bytes.saturating_add(frame_len);
        self.total_frames = self.total_frames.saturating_add(1);

        if frame_len >= COALESCE_TARGET {
            self.flush_tail();
            self.visible_bytes = self.visible_bytes.saturating_add(frame_len);
            self.chunks.push_back(Chunk {
                data: frame,
                frames: 1,
            });
            return;
        }

        if !self.tail.is_empty() && self.tail.len() + frame_len > COALESCE_TARGET {
            self.flush_tail();
        }
        self.tail.extend_from_slice(&frame);
        self.tail_frames = self.tail_frames.saturating_add(1);

        // Sparse traffic must become visible immediately.
        if self.chunks.is_empty() {
            self.flush_tail();
        }
    }

    /// Make the current coalescing tail visible to the consumer.
    pub(crate) fn flush(&mut self) {
        self.flush_tail();
    }

    fn flush_tail(&mut self) {
        if self.tail.is_empty() {
            return;
        }
        let data = std::mem::take(&mut self.tail);
        let frames = std::mem::take(&mut self.tail_frames);
        self.visible_bytes = self.visible_bytes.saturating_add(data.len());
        self.chunks.push_back(Chunk { data, frames });
    }

    /// Drain all currently writable chunks, stopping cleanly on backpressure.
    pub(crate) fn drain_to(&mut self, writer: &mut impl Write) -> io::Result<usize> {
        let mut total_written = 0;
        loop {
            if self.chunks.is_empty() {
                self.flush_tail();
                if self.chunks.is_empty() {
                    break;
                }
            }

            let write_result = {
                let chunk = &self.chunks.front().expect("chunk queue is non-empty").data;
                if self.head_offset >= chunk.len() {
                    self.pop_head();
                    continue;
                }
                writer.write(&chunk[self.head_offset..])
            };

            match write_result {
                Ok(0) => break,
                Ok(written) => {
                    total_written += written;
                    self.sent_bytes = self.sent_bytes.saturating_add(written);
                    self.head_offset += written;
                    let chunk_len = self
                        .chunks
                        .front()
                        .expect("chunk remains queued")
                        .data
                        .len();
                    if self.head_offset >= chunk_len {
                        self.pop_head();
                    } else {
                        break;
                    }
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(error),
            }
        }
        Ok(total_written)
    }

    fn pop_head(&mut self) {
        if let Some(chunk) = self.chunks.pop_front() {
            self.sent_frames = self.sent_frames.saturating_add(chunk.frames);
        }
        self.head_offset = 0;
    }

    pub(crate) fn buffered_bytes(&self) -> usize {
        self.total_bytes.saturating_sub(self.sent_bytes)
    }

    pub(crate) fn sendable_bytes(&self) -> usize {
        self.visible_bytes.saturating_sub(self.sent_bytes)
    }

    #[allow(dead_code)]
    pub(crate) fn buffered_frames(&self) -> usize {
        self.total_frames.saturating_sub(self.sent_frames)
    }

    #[allow(dead_code)]
    pub(crate) fn buffered_chunks(&self) -> usize {
        self.chunks.len()
    }
}

impl Default for TransmitBuffer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct StepWriter {
        output: Vec<u8>,
        max_write: usize,
        block_next: bool,
    }

    impl Write for StepWriter {
        fn write(&mut self, data: &[u8]) -> io::Result<usize> {
            if self.block_next {
                self.block_next = false;
                return Err(io::Error::from(io::ErrorKind::WouldBlock));
            }
            let written = data.len().min(self.max_write.max(1));
            self.output.extend_from_slice(&data[..written]);
            Ok(written)
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn empty_and_sparse_state_is_immediately_sendable() {
        let mut buffer = TransmitBuffer::new();
        assert_eq!(buffer.buffered_bytes(), 0);
        assert_eq!(buffer.sendable_bytes(), 0);
        assert_eq!(buffer.buffered_frames(), 0);
        assert_eq!(buffer.buffered_chunks(), 0);

        buffer.append(vec![0x42; 200]);
        assert_eq!(buffer.buffered_bytes(), 200);
        assert_eq!(buffer.sendable_bytes(), 200);
        assert_eq!(buffer.buffered_frames(), 1);
        assert_eq!(buffer.buffered_chunks(), 1);
    }

    #[test]
    fn small_frames_coalesce_into_target_bounded_chunks() {
        let mut buffer = TransmitBuffer::new();
        for _ in 0..2_000 {
            buffer.append(vec![0x31; 200]);
        }

        assert_eq!(buffer.buffered_bytes(), 400_000);
        assert_eq!(buffer.buffered_frames(), 2_000);
        assert!(buffer.chunks.iter().all(|chunk| {
            !chunk.data.is_empty() && chunk.data.len() <= COALESCE_TARGET && chunk.frames > 0
        }));
        assert_eq!(
            buffer.sendable_bytes() + buffer.tail.len(),
            buffer.buffered_bytes()
        );
    }

    #[test]
    fn target_sized_and_larger_frames_get_dedicated_chunks() {
        let mut buffer = TransmitBuffer::new();
        let below = vec![0x31; COALESCE_TARGET - 1];
        let at = vec![0x32; COALESCE_TARGET];
        let above = vec![0x33; COALESCE_TARGET + 1];

        buffer.append(below.clone());
        buffer.append(at.clone());
        buffer.append(above.clone());

        let chunks: Vec<_> = buffer.chunks.iter().collect();
        assert_eq!(chunks.len(), 3);
        assert_eq!(chunks[0].data, below);
        assert_eq!(chunks[1].data, at);
        assert_eq!(chunks[2].data, above);
        assert!(chunks.iter().all(|chunk| chunk.frames == 1));
    }

    #[test]
    fn partial_head_resumes_and_would_block_is_not_an_error() {
        let expected = vec![0x55; COALESCE_TARGET * 2];
        let mut buffer = TransmitBuffer::new();
        buffer.append(expected.clone());
        let mut writer = StepWriter {
            max_write: 4_096,
            block_next: false,
            ..StepWriter::default()
        };

        assert_eq!(buffer.drain_to(&mut writer).unwrap(), 4_096);
        assert_eq!(buffer.head_offset, 4_096);
        writer.block_next = true;
        assert_eq!(buffer.drain_to(&mut writer).unwrap(), 0);
        while buffer.sendable_bytes() > 0 {
            buffer.drain_to(&mut writer).unwrap();
        }

        assert_eq!(writer.output, expected);
        assert_eq!(buffer.buffered_bytes(), 0);
        assert_eq!(buffer.buffered_frames(), 0);
    }

    #[test]
    fn explicit_and_automatic_flush_release_the_tail() {
        let mut buffer = TransmitBuffer::new();
        buffer.append(vec![1; 200]);
        buffer.append(vec![2; 200]);
        buffer.append(vec![3; 200]);
        assert_eq!(buffer.sendable_bytes(), 200);
        assert_eq!(buffer.buffered_bytes(), 600);

        buffer.flush();
        assert_eq!(buffer.sendable_bytes(), 600);
        assert_eq!(buffer.buffered_chunks(), 2);

        let mut second = TransmitBuffer::new();
        second.append(vec![1; 200]);
        second.append(vec![2; 200]);
        second.append(vec![3; 200]);
        let mut writer = StepWriter {
            max_write: usize::MAX,
            ..StepWriter::default()
        };
        assert_eq!(second.drain_to(&mut writer).unwrap(), 600);
        assert_eq!(
            writer.output,
            [vec![1; 200], vec![2; 200], vec![3; 200]].concat()
        );
    }

    #[test]
    fn fifty_thousand_frame_burst_preserves_order_and_accounting() {
        const FRAME_COUNT: usize = 50_000;
        let mut buffer = TransmitBuffer::new();
        let mut expected = Vec::with_capacity(FRAME_COUNT * 8);
        for index in 0..FRAME_COUNT {
            let frame = (index as u64).to_be_bytes().to_vec();
            expected.extend_from_slice(&frame);
            buffer.append(frame);
        }
        buffer.flush();

        let mut writer = StepWriter {
            max_write: usize::MAX,
            ..StepWriter::default()
        };
        assert_eq!(buffer.drain_to(&mut writer).unwrap(), expected.len());
        assert_eq!(writer.output, expected);
        assert_eq!(buffer.buffered_bytes(), 0);
        assert_eq!(buffer.sendable_bytes(), 0);
        assert_eq!(buffer.buffered_frames(), 0);
        assert_eq!(buffer.buffered_chunks(), 0);
    }

    #[test]
    fn fully_drained_accounting_reopens_capacity_for_the_next_burst() {
        let mut buffer = TransmitBuffer::new();
        let mut writer = StepWriter {
            max_write: usize::MAX,
            ..StepWriter::default()
        };

        for _ in 0..10 {
            buffer.append(vec![0x41; 202]);
        }
        buffer.flush();
        assert_eq!(buffer.buffered_bytes(), 2_020);
        assert_eq!(buffer.drain_to(&mut writer).unwrap(), 2_020);
        assert_eq!(buffer.buffered_bytes(), 0);
        assert_eq!(buffer.buffered_frames(), 0);

        for _ in 0..10 {
            buffer.append(vec![0x42; 202]);
        }
        assert_eq!(buffer.buffered_bytes(), 2_020);
        assert_eq!(buffer.buffered_frames(), 10);
    }
}
