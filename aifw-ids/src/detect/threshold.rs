use std::net::IpAddr;
use std::sync::atomic::{AtomicI64, Ordering};

use dashmap::DashMap;

use crate::rules::{ThresholdConfig, ThresholdType};

/// Per-rule, per-IP rate tracking state.
struct ThresholdState {
    count: u32,
    window_start: AtomicI64,
    alerted: bool,
}

/// Tracks threshold/rate-limiting state for rules across IPs.
/// Lock-free per-entry via DashMap.
pub struct ThresholdTracker {
    state: DashMap<(u32, IpAddr), ThresholdState>,
}

impl ThresholdTracker {
    pub fn new() -> Self {
        Self {
            state: DashMap::new(),
        }
    }

    /// Check if an alert should fire for this SID + IP, applying threshold logic.
    /// Returns `true` if the alert should fire.
    pub fn check(&self, sid: u32, ip: IpAddr, config: &ThresholdConfig) -> bool {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;

        let key = (sid, ip);

        let mut entry = self.state.entry(key).or_insert_with(|| ThresholdState {
            count: 0,
            window_start: AtomicI64::new(now),
            alerted: false,
        });

        let state = entry.value_mut();
        let window_start = state.window_start.load(Ordering::Relaxed);

        // Check if window expired
        if now - window_start >= config.seconds as i64 {
            state.count = 0;
            state.alerted = false;
            state.window_start.store(now, Ordering::Relaxed);
        }

        state.count += 1;

        match config.threshold_type {
            ThresholdType::Limit => {
                // Alert at most `count` times per window
                state.count <= config.count
            }
            ThresholdType::Threshold => {
                // Alert every `count` occurrences
                state.count >= config.count && (state.count - config.count) % config.count == 0
            }
            ThresholdType::Both => {
                // Alert once after `count` hits per window
                if state.count >= config.count && !state.alerted {
                    state.alerted = true;
                    true
                } else {
                    false
                }
            }
        }
    }

    /// Remove expired entries (call periodically).
    pub fn cleanup(&self, max_age_secs: i64) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;

        self.state.retain(|_, state| {
            let start = state.window_start.load(Ordering::Relaxed);
            now - start < max_age_secs
        });
    }

    /// Number of tracked entries.
    pub fn len(&self) -> usize {
        self.state.len()
    }

    pub fn is_empty(&self) -> bool {
        self.state.is_empty()
    }
}

impl Default for ThresholdTracker {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::TrackBy;

    fn config(threshold_type: ThresholdType, count: u32, seconds: u32) -> ThresholdConfig {
        ThresholdConfig {
            threshold_type,
            track: TrackBy::BySrc,
            count,
            seconds,
        }
    }

    #[test]
    fn test_limit() {
        let tracker = ThresholdTracker::new();
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        let cfg = config(ThresholdType::Limit, 3, 60);

        assert!(tracker.check(1, ip, &cfg)); // 1st
        assert!(tracker.check(1, ip, &cfg)); // 2nd
        assert!(tracker.check(1, ip, &cfg)); // 3rd
        assert!(!tracker.check(1, ip, &cfg)); // 4th — suppressed
        assert!(!tracker.check(1, ip, &cfg)); // 5th — suppressed
    }

    #[test]
    fn test_threshold() {
        let tracker = ThresholdTracker::new();
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        let cfg = config(ThresholdType::Threshold, 3, 60);

        assert!(!tracker.check(1, ip, &cfg)); // 1st — below threshold
        assert!(!tracker.check(1, ip, &cfg)); // 2nd — below threshold
        assert!(tracker.check(1, ip, &cfg)); // 3rd — hit threshold
        assert!(!tracker.check(1, ip, &cfg)); // 4th
        assert!(!tracker.check(1, ip, &cfg)); // 5th
        assert!(tracker.check(1, ip, &cfg)); // 6th — hit threshold again
    }

    #[test]
    fn test_both() {
        let tracker = ThresholdTracker::new();
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        let cfg = config(ThresholdType::Both, 3, 60);

        assert!(!tracker.check(1, ip, &cfg)); // 1st
        assert!(!tracker.check(1, ip, &cfg)); // 2nd
        assert!(tracker.check(1, ip, &cfg)); // 3rd — alert once
        assert!(!tracker.check(1, ip, &cfg)); // 4th — already alerted
        assert!(!tracker.check(1, ip, &cfg)); // 5th — already alerted
    }

    #[test]
    fn test_different_ips() {
        let tracker = ThresholdTracker::new();
        let ip1: IpAddr = "10.0.0.1".parse().unwrap();
        let ip2: IpAddr = "10.0.0.2".parse().unwrap();
        let cfg = config(ThresholdType::Limit, 1, 60);

        assert!(tracker.check(1, ip1, &cfg));
        assert!(tracker.check(1, ip2, &cfg)); // Different IP, fresh counter
        assert!(!tracker.check(1, ip1, &cfg)); // ip1 exhausted
    }
}
