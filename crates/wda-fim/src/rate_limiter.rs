//! Rate limiter for bounding SHA-256 hash dispatches per second.
//!
//! Tracks how many hashes have been dispatched in the current one-second
//! window. When the configured maximum is reached, [`RateLimiter::acquire`]
//! sleeps until the next second boundary before allowing another dispatch.
//! Between hashes the limiter also yields to the tokio scheduler so other
//! async tasks (keepalive, server forwarding) get a chance to run under
//! bursty FIM workloads.

use std::time::Duration;

use tokio::time::Instant;

/// A simple 1-second-window rate limiter.
pub struct RateLimiter {
    max_per_sec: u32,
    window_start: Instant,
    dispatched: u32,
}

impl RateLimiter {
    /// Create a new rate limiter.
    ///
    /// `max_per_sec == 0` disables rate limiting (acquire is a no-op
    /// except for yielding).
    pub fn new(max_per_sec: u32) -> Self {
        Self {
            max_per_sec,
            window_start: Instant::now(),
            dispatched: 0,
        }
    }

    /// Wait until another dispatch is allowed, then record it.
    ///
    /// Always yields to the tokio scheduler before returning so that
    /// async tasks sharing this thread get a chance to run between
    /// hashes.
    pub async fn acquire(&mut self) {
        if self.max_per_sec == 0 {
            tokio::task::yield_now().await;
            return;
        }

        let now = Instant::now();
        if now.duration_since(self.window_start) >= Duration::from_secs(1) {
            self.window_start = now;
            self.dispatched = 0;
        }

        if self.dispatched >= self.max_per_sec {
            let elapsed = now.duration_since(self.window_start);
            let sleep_for = Duration::from_secs(1).saturating_sub(elapsed);
            if !sleep_for.is_zero() {
                tokio::time::sleep(sleep_for).await;
            }
            self.window_start = Instant::now();
            self.dispatched = 0;
        }

        self.dispatched += 1;
        tokio::task::yield_now().await;
    }

    /// Return the number of hashes already dispatched in the current
    /// window. Primarily useful for tests.
    #[cfg(test)]
    pub fn dispatched_in_window(&self) -> u32 {
        self.dispatched
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_acquire_under_limit_does_not_sleep() {
        let mut rl = RateLimiter::new(10);
        let start = Instant::now();
        for _ in 0..5 {
            rl.acquire().await;
        }
        // Five acquires under a 10/sec budget should be near-instant.
        assert!(
            start.elapsed() < Duration::from_millis(500),
            "under-budget acquires should not sleep"
        );
        assert_eq!(rl.dispatched_in_window(), 5);
    }

    #[tokio::test]
    async fn test_acquire_over_limit_sleeps_until_next_window() {
        // 3 hashes/sec budget.
        let mut rl = RateLimiter::new(3);
        let start = Instant::now();

        // Dispatch 4: the 4th must wait for the next window boundary.
        for _ in 0..4 {
            rl.acquire().await;
        }

        let elapsed = start.elapsed();
        // The 4th acquire forces a sleep to the next 1-second boundary.
        assert!(
            elapsed >= Duration::from_millis(700),
            "over-budget 4th acquire should have slept at least ~1s, took {:?}",
            elapsed
        );
        // And the new window should have started: dispatched counter resets.
        assert_eq!(rl.dispatched_in_window(), 1);
    }

    #[tokio::test]
    async fn test_zero_disables_rate_limit() {
        let mut rl = RateLimiter::new(0);
        let start = Instant::now();
        for _ in 0..100 {
            rl.acquire().await;
        }
        // With rate limiting disabled 100 acquires should complete fast.
        assert!(
            start.elapsed() < Duration::from_millis(500),
            "zero max_per_sec should disable rate limiting"
        );
    }

    #[tokio::test]
    async fn test_window_resets_after_one_second() {
        let mut rl = RateLimiter::new(5);
        for _ in 0..5 {
            rl.acquire().await;
        }
        assert_eq!(rl.dispatched_in_window(), 5);

        // Sleep past the window boundary.
        tokio::time::sleep(Duration::from_millis(1_100)).await;

        // Next acquire should start a fresh window without sleeping.
        let start = Instant::now();
        rl.acquire().await;
        assert!(
            start.elapsed() < Duration::from_millis(200),
            "fresh window acquire should not sleep"
        );
        assert_eq!(rl.dispatched_in_window(), 1);
    }
}
