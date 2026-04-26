use std::collections::HashMap;
use std::time::{Duration, Instant};

use crate::types::RecipientId;

const WINDOW_SIZE: u64 = 64;
const EVICTION_TIMEOUT: Duration = Duration::from_secs(24 * 60 * 60);

struct SenderState {
    max_seq: u64,
    window: u64,
    last_seen: Instant,
}

/// Sliding-window replay filter (RFC 6479).
///
/// Tracks per-sender sequence numbers and rejects duplicates or sequence
/// numbers that fall outside the 64-packet window. Generic over the sender
/// identity type `R`.
pub struct ReplayFilter<R: RecipientId> {
    state: HashMap<R, SenderState>,
}

impl<R: RecipientId> ReplayFilter<R> {
    pub fn new() -> Self {
        Self {
            state: HashMap::new(),
        }
    }

    /// Check whether `seq` is acceptable for the given sender.
    ///
    /// Returns `true` if the sequence number is new (accepted and recorded).
    /// Returns `false` if it is a duplicate or too old (rejected).
    pub fn check(&mut self, sender_id: R, seq: u64) -> bool {
        let now = Instant::now();
        let entry = self.state.entry(sender_id).or_insert(SenderState {
            max_seq: 0,
            window: 0,
            last_seen: now,
        });

        entry.last_seen = now;

        if seq > entry.max_seq {
            let diff = seq - entry.max_seq;
            if diff >= WINDOW_SIZE {
                entry.window = 1;
            } else {
                entry.window = (entry.window << diff) | 1;
            }
            entry.max_seq = seq;
            true
        } else {
            let diff = entry.max_seq - seq;
            if diff >= WINDOW_SIZE {
                false
            } else {
                let bit = 1u64 << diff;
                if entry.window & bit != 0 {
                    false
                } else {
                    entry.window |= bit;
                    true
                }
            }
        }
    }

    /// Evict state for senders not seen in the last 24 hours.
    pub fn cleanup(&mut self) {
        let now = Instant::now();
        self.state
            .retain(|_, s| now.duration_since(s.last_seen) < EVICTION_TIMEOUT);
    }
}

impl<R: RecipientId> Default for ReplayFilter<R> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Recipient;

    fn sender() -> Recipient {
        Recipient::from_bytes_copy(&[1u8; 16])
    }

    #[test]
    fn accepts_new_sequence() {
        let mut rf = ReplayFilter::new();
        let s = sender();
        assert!(rf.check(s.clone(), 1));
        assert!(rf.check(s.clone(), 2));
        assert!(rf.check(s.clone(), 3));
    }

    #[test]
    fn rejects_duplicate() {
        let mut rf = ReplayFilter::new();
        let s = sender();
        assert!(rf.check(s.clone(), 5));
        assert!(!rf.check(s.clone(), 5));
    }

    #[test]
    fn accepts_out_of_order_within_window() {
        let mut rf = ReplayFilter::new();
        let s = sender();
        assert!(rf.check(s.clone(), 10));
        assert!(rf.check(s.clone(), 8));
        assert!(rf.check(s.clone(), 5));
        assert!(!rf.check(s.clone(), 8));
    }

    #[test]
    fn rejects_too_old() {
        let mut rf = ReplayFilter::new();
        let s = sender();
        assert!(rf.check(s.clone(), 100));
        assert!(!rf.check(s.clone(), 36));
        assert!(rf.check(s.clone(), 37));
    }

    #[test]
    fn window_boundary_exact() {
        let mut rf = ReplayFilter::new();
        let s = sender();
        assert!(rf.check(s.clone(), 64));
        assert!(rf.check(s.clone(), 1));
        assert!(!rf.check(s.clone(), 0));
    }

    #[test]
    fn gap_of_exactly_64_clears_window() {
        let mut rf = ReplayFilter::new();
        let s = sender();
        assert!(rf.check(s.clone(), 1));
        assert!(rf.check(s.clone(), 2));
        assert!(rf.check(s.clone(), 66));
        assert!(rf.check(s.clone(), 65));
    }

    #[test]
    fn large_gap_shifts_window() {
        let mut rf = ReplayFilter::new();
        let s = sender();
        assert!(rf.check(s.clone(), 1));
        assert!(rf.check(s.clone(), 200));
        assert!(!rf.check(s.clone(), 1));
        assert!(!rf.check(s.clone(), 200));
        assert!(rf.check(s.clone(), 137));
    }

    #[test]
    fn independent_senders() {
        let mut rf = ReplayFilter::new();
        let s1 = Recipient::from_bytes_copy(&[1u8; 16]);
        let s2 = Recipient::from_bytes_copy(&[2u8; 16]);

        assert!(rf.check(s1.clone(), 5));
        assert!(rf.check(s2.clone(), 5));
        assert!(!rf.check(s1.clone(), 5));
        assert!(!rf.check(s2.clone(), 5));
    }

    #[test]
    fn seq_zero_accepted_first_time() {
        let mut rf = ReplayFilter::new();
        let s = sender();
        assert!(rf.check(s.clone(), 0));
        assert!(!rf.check(s.clone(), 0));
    }
}
