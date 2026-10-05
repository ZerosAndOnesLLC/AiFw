//! Duplicate suppression and rate limiting for outgoing notifications.
//! Pure (time is passed in) so it is unit-testable.

use std::collections::HashMap;
use std::time::{Duration, Instant};

/// What to do with a notification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// Deliver it
    Send,
    /// Same event was sent within the dedupe window
    Duplicate,
    /// Over the per-minute budget
    RateLimited,
}

/// Token bucket (burst = per-minute rate) plus a dedupe window.
pub struct Limiter {
    capacity: f64,
    tokens: f64,
    refill_per_sec: f64,
    last_refill: Instant,
    dedupe: Duration,
    seen: HashMap<String, Instant>,
}

impl Limiter {
    /// `per_minute` deliveries per minute; identical keys within `dedupe`
    /// are dropped.
    pub fn new(per_minute: u32, dedupe: Duration, now: Instant) -> Self {
        let capacity = f64::from(per_minute.max(1));
        Self {
            capacity,
            tokens: capacity,
            refill_per_sec: capacity / 60.0,
            last_refill: now,
            dedupe,
            seen: HashMap::new(),
        }
    }

    /// Decide on one notification with dedupe key `key`.
    pub fn check(&mut self, key: &str, now: Instant) -> Verdict {
        if !self.dedupe.is_zero() {
            if let Some(at) = self.seen.get(key)
                && now.duration_since(*at) < self.dedupe
            {
                return Verdict::Duplicate;
            }
            if self.seen.len() > 4096 {
                let window = self.dedupe;
                self.seen.retain(|_, at| now.duration_since(*at) < window);
            }
        }
        let elapsed = now.duration_since(self.last_refill).as_secs_f64();
        self.tokens = (self.tokens + elapsed * self.refill_per_sec).min(self.capacity);
        self.last_refill = now;
        if self.tokens < 1.0 {
            return Verdict::RateLimited;
        }
        self.tokens -= 1.0;
        if !self.dedupe.is_zero() {
            self.seen.insert(key.to_string(), now);
        }
        Verdict::Send
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dedupes_within_window() {
        let t0 = Instant::now();
        let mut l = Limiter::new(100, Duration::from_secs(600), t0);
        assert_eq!(l.check("a", t0), Verdict::Send);
        assert_eq!(
            l.check("a", t0 + Duration::from_secs(60)),
            Verdict::Duplicate
        );
        assert_eq!(l.check("b", t0 + Duration::from_secs(60)), Verdict::Send);
        assert_eq!(l.check("a", t0 + Duration::from_secs(601)), Verdict::Send);
    }

    #[test]
    fn rate_limits_and_refills() {
        let t0 = Instant::now();
        let mut l = Limiter::new(3, Duration::ZERO, t0);
        for _ in 0..3 {
            assert_eq!(l.check("x", t0), Verdict::Send);
        }
        assert_eq!(l.check("x", t0), Verdict::RateLimited);
        // One token back after 20 s at 3/min.
        assert_eq!(l.check("x", t0 + Duration::from_secs(20)), Verdict::Send);
        assert_eq!(
            l.check("x", t0 + Duration::from_secs(20)),
            Verdict::RateLimited
        );
    }

    #[test]
    fn rate_limited_events_are_not_remembered_as_sent() {
        let t0 = Instant::now();
        let mut l = Limiter::new(1, Duration::from_secs(600), t0);
        assert_eq!(l.check("a", t0), Verdict::Send);
        assert_eq!(l.check("b", t0), Verdict::RateLimited);
        // "b" was never delivered, so it is not a duplicate later.
        assert_eq!(l.check("b", t0 + Duration::from_secs(61)), Verdict::Send);
    }
}
