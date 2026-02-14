pub mod types;
pub mod envelope;

use alloc::collections::VecDeque;
use alloc::vec::Vec;

use crate::constants::{
    CHANNEL_ENVELOPE_OVERHEAD, CHANNEL_FAST_RATE_THRESHOLD, CHANNEL_MAX_TRIES,
    CHANNEL_RTT_FAST, CHANNEL_RTT_MEDIUM, CHANNEL_RTT_SLOW,
    CHANNEL_SEQ_MODULUS, CHANNEL_WINDOW, CHANNEL_WINDOW_FLEXIBILITY, CHANNEL_WINDOW_MAX_FAST,
    CHANNEL_WINDOW_MAX_MEDIUM, CHANNEL_WINDOW_MAX_SLOW, CHANNEL_WINDOW_MIN,
    CHANNEL_WINDOW_MIN_LIMIT_FAST, CHANNEL_WINDOW_MIN_LIMIT_MEDIUM,
};
#[cfg(test)]
use crate::constants::CHANNEL_SEQ_MAX;

pub use types::{ChannelAction, ChannelError, MessageType, Sequence};

use envelope::{pack_envelope, unpack_envelope};

/// Internal envelope tracking state.
struct Envelope {
    sequence: Sequence,
    raw: Vec<u8>,
    tries: u8,
    sent_at: f64,
    delivered: bool,
}

/// Window-based reliable messaging channel.
///
/// Follows the action-queue model: `send`/`receive`/`tick` return
/// `Vec<ChannelAction>`. The caller dispatches actions.
pub struct Channel {
    tx_ring: VecDeque<Envelope>,
    rx_ring: VecDeque<Envelope>,
    next_sequence: u16,
    next_rx_sequence: u16,
    window: u16,
    window_max: u16,
    window_min: u16,
    window_flexibility: u16,
    fast_rate_rounds: u16,
    medium_rate_rounds: u16,
    max_tries: u8,
    rtt: f64,
}

impl Channel {
    /// Create a new Channel with initial RTT.
    pub fn new(initial_rtt: f64) -> Self {
        let (window, window_max, window_min, window_flexibility) = if initial_rtt > CHANNEL_RTT_SLOW {
            (1, 1, 1, 1)
        } else {
            (
                CHANNEL_WINDOW,
                CHANNEL_WINDOW_MAX_SLOW,
                CHANNEL_WINDOW_MIN,
                CHANNEL_WINDOW_FLEXIBILITY,
            )
        };

        Channel {
            tx_ring: VecDeque::new(),
            rx_ring: VecDeque::new(),
            next_sequence: 0,
            next_rx_sequence: 0,
            window,
            window_max,
            window_min,
            window_flexibility,
            fast_rate_rounds: 0,
            medium_rate_rounds: 0,
            max_tries: CHANNEL_MAX_TRIES,
            rtt: initial_rtt,
        }
    }

    /// Update the RTT value.
    pub fn set_rtt(&mut self, rtt: f64) {
        self.rtt = rtt;
    }

    /// Maximum data unit available for message payload.
    pub fn mdu(&self, link_mdu: usize) -> usize {
        let mdu = link_mdu.saturating_sub(CHANNEL_ENVELOPE_OVERHEAD);
        mdu.min(0xFFFF)
    }

    /// Check if channel is ready to send (has window capacity).
    pub fn is_ready_to_send(&self) -> bool {
        let outstanding = self.tx_ring.iter()
            .filter(|e| !e.delivered)
            .count() as u16;
        outstanding < self.window
    }

    /// Send a message. Returns `SendOnLink` action with packed envelope.
    pub fn send(
        &mut self,
        msgtype: u16,
        payload: &[u8],
        now: f64,
        link_mdu: usize,
    ) -> Result<Vec<ChannelAction>, ChannelError> {
        if !self.is_ready_to_send() {
            return Err(ChannelError::NotReady);
        }

        let sequence = self.next_sequence;
        self.next_sequence = ((self.next_sequence as u32 + 1) % CHANNEL_SEQ_MODULUS) as u16;

        let raw = pack_envelope(msgtype, sequence, payload);
        if raw.len() > link_mdu {
            return Err(ChannelError::MessageTooBig);
        }

        self.tx_ring.push_back(Envelope {
            sequence,
            raw: raw.clone(),
            tries: 1,
            sent_at: now,
            delivered: false,
        });

        Ok(alloc::vec![ChannelAction::SendOnLink { raw }])
    }

    /// Receive decrypted envelope bytes.
    ///
    /// Returns `MessageReceived` for contiguous sequences starting from
    /// `next_rx_sequence`.
    pub fn receive(&mut self, raw: &[u8], _now: f64) -> Vec<ChannelAction> {
        let (_msgtype, sequence, _payload) = match unpack_envelope(raw) {
            Ok(r) => r,
            Err(_) => return Vec::new(),
        };

        // Reject sequences behind our window
        if self.is_behind_rx_window(sequence) {
            return Vec::new();
        }

        // Reject duplicates
        if self.rx_ring.iter().any(|e| e.sequence == sequence) {
            return Vec::new();
        }

        // Emplace in sorted order
        let envelope = Envelope {
            sequence,
            raw: raw.to_vec(),
            tries: 0,
            sent_at: 0.0,
            delivered: false,
        };
        self.emplace_rx(envelope);

        // Collect contiguous messages
        self.collect_contiguous()
    }

    /// Clear all outstanding TX entries, restoring the window to full capacity.
    /// Used after holepunch completion where signaling messages are fire-and-forget.
    pub fn flush_tx(&mut self) {
        self.tx_ring.clear();
    }

    /// Notify that a packet with given sequence was delivered (acknowledged).
    pub fn packet_delivered(&mut self, sequence: Sequence) -> Vec<ChannelAction> {
        if let Some(pos) = self.tx_ring.iter().position(|e| e.sequence == sequence) {
            self.tx_ring.remove(pos);

            if self.window < self.window_max {
                self.window += 1;
            }

            // Adapt window based on RTT
            self.adapt_window_on_delivery();
        }
        Vec::new()
    }

    /// Notify that a packet with given sequence timed out.
    pub fn packet_timeout(&mut self, sequence: Sequence, now: f64) -> Vec<ChannelAction> {
        let pos = match self.tx_ring.iter().position(|e| e.sequence == sequence) {
            Some(p) => p,
            None => return Vec::new(),
        };

        let envelope = &self.tx_ring[pos];
        if envelope.tries >= self.max_tries {
            self.tx_ring.clear();
            self.rx_ring.clear();
            return alloc::vec![ChannelAction::TeardownLink];
        }

        // Retry
        let envelope = &mut self.tx_ring[pos];
        envelope.tries += 1;
        envelope.sent_at = now;
        let raw = envelope.raw.clone();

        // Shrink window (Python nests window_max shrink inside window shrink)
        if self.window > self.window_min {
            self.window -= 1;
            if self.window_max > self.window_min + self.window_flexibility {
                self.window_max -= 1;
            }
        }

        alloc::vec![ChannelAction::SendOnLink { raw }]
    }

    /// Compute timeout duration for the given try count.
    ///
    /// Formula: `1.5^(tries-1) * max(rtt*2.5, 0.025) * (tx_ring.len() + 1.5)`
    pub fn get_packet_timeout(&self, tries: u8) -> f64 {
        let base = 1.5_f64.powi((tries as i32) - 1);
        let rtt_factor = (self.rtt * 2.5).max(0.025);
        let ring_factor = (self.tx_ring.len() as f64) + 1.5;
        base * rtt_factor * ring_factor
    }

    /// Get the current try count for a given sequence.
    pub fn get_tries(&self, sequence: Sequence) -> Option<u8> {
        self.tx_ring.iter()
            .find(|e| e.sequence == sequence)
            .map(|e| e.tries)
    }

    /// Shut down the channel, clearing all rings.
    pub fn shutdown(&mut self) {
        self.tx_ring.clear();
        self.rx_ring.clear();
    }

    /// Current window size.
    pub fn window(&self) -> u16 {
        self.window
    }

    /// Current maximum window size.
    pub fn window_max(&self) -> u16 {
        self.window_max
    }

    /// Number of outstanding (undelivered) envelopes in TX ring.
    pub fn outstanding(&self) -> usize {
        self.tx_ring.iter().filter(|e| !e.delivered).count()
    }

    // --- Internal ---

    fn is_behind_rx_window(&self, sequence: Sequence) -> bool {
        if sequence < self.next_rx_sequence {
            let window_overflow = (self.next_rx_sequence as u32 + CHANNEL_WINDOW_MAX_FAST as u32) % CHANNEL_SEQ_MODULUS;
            let overflow = window_overflow as u16;
            if overflow < self.next_rx_sequence {
                // Wrapped around — sequence is valid if > overflow
                if sequence > overflow {
                    return true; // actually behind
                }
                return false; // valid wrap-around sequence
            }
            return true;
        }
        false
    }

    fn emplace_rx(&mut self, envelope: Envelope) {
        // Use modular distance from next_rx_sequence for correct wrap-boundary ordering.
        // wrapping_sub gives the unsigned distance in sequence space.
        let env_dist = envelope.sequence.wrapping_sub(self.next_rx_sequence);
        let mut i = 0;
        for existing in self.rx_ring.iter() {
            if envelope.sequence == existing.sequence {
                return; // duplicate
            }
            let exist_dist = existing.sequence.wrapping_sub(self.next_rx_sequence);
            if env_dist < exist_dist {
                self.rx_ring.insert(i, envelope);
                return;
            }
            i += 1;
        }
        self.rx_ring.push_back(envelope);
    }

    fn collect_contiguous(&mut self) -> Vec<ChannelAction> {
        let mut actions = Vec::new();

        loop {
            let front_match = self.rx_ring.front()
                .map(|e| e.sequence == self.next_rx_sequence)
                .unwrap_or(false);

            if !front_match {
                break;
            }

            let envelope = self.rx_ring.pop_front().unwrap();

            // Re-parse the envelope to get payload
            if let Ok((msgtype, _seq, payload)) = unpack_envelope(&envelope.raw) {
                actions.push(ChannelAction::MessageReceived {
                    msgtype,
                    payload: payload.to_vec(),
                    sequence: envelope.sequence,
                });
            }

            self.next_rx_sequence = ((self.next_rx_sequence as u32 + 1) % CHANNEL_SEQ_MODULUS) as u16;

            // After wrapping to 0, check if 0 is also in the ring
            if self.next_rx_sequence == 0 {
                // Continue the loop — it will check front again
            }
        }

        actions
    }

    fn adapt_window_on_delivery(&mut self) {
        if self.rtt == 0.0 {
            return;
        }

        if self.rtt > CHANNEL_RTT_FAST {
            self.fast_rate_rounds = 0;

            if self.rtt > CHANNEL_RTT_MEDIUM {
                self.medium_rate_rounds = 0;
            } else {
                self.medium_rate_rounds += 1;
                if self.window_max < CHANNEL_WINDOW_MAX_MEDIUM
                    && self.medium_rate_rounds == CHANNEL_FAST_RATE_THRESHOLD
                {
                    self.window_max = CHANNEL_WINDOW_MAX_MEDIUM;
                    self.window_min = CHANNEL_WINDOW_MIN_LIMIT_MEDIUM;
                }
            }
        } else {
            self.fast_rate_rounds += 1;
            if self.window_max < CHANNEL_WINDOW_MAX_FAST
                && self.fast_rate_rounds == CHANNEL_FAST_RATE_THRESHOLD
            {
                self.window_max = CHANNEL_WINDOW_MAX_FAST;
                self.window_min = CHANNEL_WINDOW_MIN_LIMIT_FAST;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_default() {
        let ch = Channel::new(0.5);
        assert_eq!(ch.window, CHANNEL_WINDOW);
        assert_eq!(ch.window_max, CHANNEL_WINDOW_MAX_SLOW);
        assert!(ch.is_ready_to_send());
    }

    #[test]
    fn test_new_very_slow() {
        let ch = Channel::new(2.0);
        assert_eq!(ch.window, 1);
        assert_eq!(ch.window_max, 1);
    }

    #[test]
    fn test_send_receive() {
        let mut ch = Channel::new(0.1);
        let actions = ch.send(0x01, b"hello", 1.0, 500).unwrap();
        assert_eq!(actions.len(), 1);
        match &actions[0] {
            ChannelAction::SendOnLink { raw } => {
                // Simulate receive on the other side
                let mut ch2 = Channel::new(0.1);
                let recv_actions = ch2.receive(raw, 1.1);
                assert_eq!(recv_actions.len(), 1);
                match &recv_actions[0] {
                    ChannelAction::MessageReceived { msgtype, payload, sequence } => {
                        assert_eq!(*msgtype, 0x01);
                        assert_eq!(payload, b"hello");
                        assert_eq!(*sequence, 0);
                    }
                    _ => panic!("Expected MessageReceived"),
                }
            }
            _ => panic!("Expected SendOnLink"),
        }
    }

    #[test]
    fn test_send_not_ready() {
        let mut ch = Channel::new(0.1);
        // Fill the window
        ch.send(0x01, b"a", 1.0, 500).unwrap();
        ch.send(0x01, b"b", 1.0, 500).unwrap();
        // Window = 2, both outstanding
        assert!(!ch.is_ready_to_send());
        assert_eq!(ch.send(0x01, b"c", 1.0, 500), Err(ChannelError::NotReady));
    }

    #[test]
    fn test_packet_delivered_grows_window() {
        let mut ch = Channel::new(0.1);
        ch.send(0x01, b"a", 1.0, 500).unwrap();
        ch.send(0x01, b"b", 1.0, 500).unwrap();

        assert_eq!(ch.window, 2);
        ch.packet_delivered(0);
        assert_eq!(ch.window, 3);
    }

    #[test]
    fn test_packet_timeout_shrinks_window() {
        let mut ch = Channel::new(0.1);
        ch.send(0x01, b"a", 1.0, 500).unwrap();
        ch.send(0x01, b"b", 1.0, 500).unwrap();

        // Deliver one to grow window
        ch.packet_delivered(0);
        assert_eq!(ch.window, 3);

        // Timeout on seq 1
        let actions = ch.packet_timeout(1, 2.0);
        assert_eq!(actions.len(), 1); // resend
        assert_eq!(ch.window, 2);
    }

    #[test]
    fn test_max_retries_teardown() {
        let mut ch = Channel::new(0.1);
        ch.send(0x01, b"a", 1.0, 500).unwrap();

        // Time out until max_tries exceeded
        for i in 0..4 {
            let actions = ch.packet_timeout(0, 2.0 + i as f64);
            assert_eq!(actions.len(), 1);
            match &actions[0] {
                ChannelAction::SendOnLink { .. } => {}
                _ => panic!("Expected SendOnLink"),
            }
        }

        // One more timeout → teardown
        let actions = ch.packet_timeout(0, 10.0);
        assert_eq!(actions.len(), 1);
        match &actions[0] {
            ChannelAction::TeardownLink => {}
            _ => panic!("Expected TeardownLink"),
        }
    }

    #[test]
    fn test_sequence_wrapping() {
        let mut ch = Channel::new(0.1);
        ch.next_sequence = CHANNEL_SEQ_MAX;

        ch.send(0x01, b"wrap", 1.0, 500).unwrap();
        assert_eq!(ch.next_sequence, 0);

        ch.send(0x01, b"after", 1.0, 500).unwrap();
        assert_eq!(ch.next_sequence, 1);
    }

    #[test]
    fn test_out_of_order_buffering() {
        let mut ch = Channel::new(0.1);

        // Send messages out of order (simulate): sequence 1 arrives before 0
        let raw0 = pack_envelope(0x01, 0, b"first");
        let raw1 = pack_envelope(0x01, 1, b"second");

        // Receive seq 1 first
        let actions = ch.receive(&raw1, 1.0);
        assert!(actions.is_empty()); // buffered, waiting for 0

        // Receive seq 0
        let actions = ch.receive(&raw0, 1.1);
        assert_eq!(actions.len(), 2); // both delivered in order
        match &actions[0] {
            ChannelAction::MessageReceived { sequence, .. } => assert_eq!(*sequence, 0),
            _ => panic!("Expected MessageReceived"),
        }
        match &actions[1] {
            ChannelAction::MessageReceived { sequence, .. } => assert_eq!(*sequence, 1),
            _ => panic!("Expected MessageReceived"),
        }
    }

    #[test]
    fn test_duplicate_rejection() {
        let mut ch = Channel::new(0.1);
        let raw = pack_envelope(0x01, 0, b"hello");

        let actions = ch.receive(&raw, 1.0);
        assert_eq!(actions.len(), 1);

        // Duplicate
        let actions = ch.receive(&raw, 1.1);
        assert!(actions.is_empty());
    }

    #[test]
    fn test_get_packet_timeout() {
        let ch = Channel::new(0.1);
        let t1 = ch.get_packet_timeout(1);
        let t2 = ch.get_packet_timeout(2);
        assert!(t2 > t1); // exponential backoff
    }

    #[test]
    fn test_mdu() {
        let ch = Channel::new(0.1);
        assert_eq!(ch.mdu(431), 431 - CHANNEL_ENVELOPE_OVERHEAD);
    }

    #[test]
    fn test_window_upgrade_fast() {
        let mut ch = Channel::new(0.05); // fast RTT
        ch.window_max = CHANNEL_WINDOW_MAX_SLOW;

        // Deliver FAST_RATE_THRESHOLD messages
        for i in 0..CHANNEL_FAST_RATE_THRESHOLD {
            ch.send(0x01, b"x", i as f64, 500).unwrap();
            ch.packet_delivered(i);
        }

        assert_eq!(ch.window_max, CHANNEL_WINDOW_MAX_FAST);
        assert_eq!(ch.window_min, CHANNEL_WINDOW_MIN_LIMIT_FAST);
    }

    #[test]
    fn test_window_upgrade_medium() {
        let mut ch = Channel::new(0.5); // medium RTT
        ch.window_max = CHANNEL_WINDOW_MAX_SLOW;

        for i in 0..CHANNEL_FAST_RATE_THRESHOLD {
            ch.send(0x01, b"x", i as f64, 500).unwrap();
            ch.packet_delivered(i);
        }

        assert_eq!(ch.window_max, CHANNEL_WINDOW_MAX_MEDIUM);
        assert_eq!(ch.window_min, CHANNEL_WINDOW_MIN_LIMIT_MEDIUM);
    }

    #[test]
    fn test_shutdown() {
        let mut ch = Channel::new(0.1);
        ch.send(0x01, b"a", 1.0, 500).unwrap();
        ch.shutdown();
        assert_eq!(ch.outstanding(), 0);
    }

    #[test]
    fn test_message_too_big() {
        let mut ch = Channel::new(0.1);
        let big = vec![0u8; 500];
        // link_mdu = 10, message + header won't fit
        assert_eq!(ch.send(0x01, &big, 1.0, 10), Err(ChannelError::MessageTooBig));
    }

    #[test]
    fn test_receive_sequence_wrap_at_boundary() {
        let mut ch = Channel::new(0.1);
        ch.next_rx_sequence = CHANNEL_SEQ_MAX;

        let raw_max = pack_envelope(0x01, CHANNEL_SEQ_MAX, b"last");
        let raw_zero = pack_envelope(0x01, 0, b"first_after_wrap");

        let actions = ch.receive(&raw_max, 1.0);
        assert_eq!(actions.len(), 1);
        assert_eq!(ch.next_rx_sequence, 0);

        let actions = ch.receive(&raw_zero, 1.1);
        assert_eq!(actions.len(), 1);
        match &actions[0] {
            ChannelAction::MessageReceived { sequence, .. } => assert_eq!(*sequence, 0),
            _ => panic!("Expected MessageReceived"),
        }
    }

    #[test]
    fn test_receive_wrap_boundary_out_of_order() {
        // Test that out-of-order messages at the wrap boundary (0xFFFF→0) are sorted correctly.
        let mut ch = Channel::new(0.1);
        ch.next_rx_sequence = 0xFFFE;

        let raw_fffe = pack_envelope(0x01, 0xFFFE, b"a");
        let raw_ffff = pack_envelope(0x01, 0xFFFF, b"b");
        let raw_0000 = pack_envelope(0x01, 0x0000, b"c");

        // Deliver in reverse order: 0, 0xFFFF, 0xFFFE
        let actions = ch.receive(&raw_0000, 1.0);
        assert!(actions.is_empty()); // waiting for 0xFFFE

        let actions = ch.receive(&raw_ffff, 1.1);
        assert!(actions.is_empty()); // still waiting for 0xFFFE

        let actions = ch.receive(&raw_fffe, 1.2);
        assert_eq!(actions.len(), 3); // all three delivered in order
        match &actions[0] {
            ChannelAction::MessageReceived { sequence, payload, .. } => {
                assert_eq!(*sequence, 0xFFFE);
                assert_eq!(payload, b"a");
            }
            _ => panic!("Expected MessageReceived"),
        }
        match &actions[1] {
            ChannelAction::MessageReceived { sequence, payload, .. } => {
                assert_eq!(*sequence, 0xFFFF);
                assert_eq!(payload, b"b");
            }
            _ => panic!("Expected MessageReceived"),
        }
        match &actions[2] {
            ChannelAction::MessageReceived { sequence, payload, .. } => {
                assert_eq!(*sequence, 0x0000);
                assert_eq!(payload, b"c");
            }
            _ => panic!("Expected MessageReceived"),
        }
    }

    #[test]
    fn test_many_messages_in_order() {
        let mut sender = Channel::new(0.05);
        let mut receiver = Channel::new(0.05);

        for i in 0..20u16 {
            // Deliver previous to make window available
            if i >= 2 {
                sender.packet_delivered(i - 2);
            }

            let actions = sender.send(0x01, &[i as u8], i as f64, 500).unwrap();
            let raw = match &actions[0] {
                ChannelAction::SendOnLink { raw } => raw.clone(),
                _ => panic!("Expected SendOnLink"),
            };

            let recv_actions = receiver.receive(&raw, i as f64 + 0.1);
            assert_eq!(recv_actions.len(), 1);
            match &recv_actions[0] {
                ChannelAction::MessageReceived { payload, sequence, .. } => {
                    assert_eq!(*sequence, i);
                    assert_eq!(payload, &[i as u8]);
                }
                _ => panic!("Expected MessageReceived"),
            }
        }
    }
}
