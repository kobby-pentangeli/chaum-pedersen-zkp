use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Instant;

use tokio::sync::Mutex;
use tonic::Status;

/// Upper bound on the number of live per-peer buckets, guarding against a flood of
/// distinct peers between eviction sweeps.
const MAX_RATE_LIMIT_BUCKETS: usize = 100_000;

/// Per-peer token-bucket rate limiter.
#[derive(Clone)]
pub struct RateLimiter {
    buckets: Arc<Mutex<HashMap<IpAddr, RateLimiterState>>>,
    rate: u64,
    burst: u64,
}

struct RateLimiterState {
    tokens: f64,
    last_update: Instant,
}

impl RateLimiterState {
    /// Token count refilled to `now`, capped at `burst`.
    fn refilled(&self, now: Instant, rate: u64, burst: u64) -> f64 {
        let elapsed = now.duration_since(self.last_update).as_secs_f64();
        (self.tokens + elapsed * rate as f64 / 60.0).min(burst as f64)
    }
}

impl RateLimiter {
    pub fn new(requests_per_minute: u64, burst: u64) -> Self {
        Self {
            buckets: Arc::new(Mutex::new(HashMap::new())),
            rate: requests_per_minute,
            burst,
        }
    }

    /// Attempts to consume one token from `peer`'s bucket; `Err` if that peer's rate
    /// limit is exceeded.
    pub async fn check_rate_limit(&self, peer: IpAddr) -> Result<(), Status> {
        let now = Instant::now();
        let mut buckets = self.buckets.lock().await;

        if buckets.len() >= MAX_RATE_LIMIT_BUCKETS && !buckets.contains_key(&peer) {
            buckets.retain(|_, b| b.refilled(now, self.rate, self.burst) < self.burst as f64);
        }

        let bucket = buckets.entry(peer).or_insert(RateLimiterState {
            tokens: self.burst as f64,
            last_update: now,
        });

        bucket.tokens = bucket.refilled(now, self.rate, self.burst);
        bucket.last_update = now;

        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            Ok(())
        } else {
            Err(Status::resource_exhausted("Rate limit exceeded"))
        }
    }

    /// Drops fully-refilled buckets, reclaiming memory for idle peers. Intended to be
    /// called periodically by the server's cleanup task.
    pub async fn evict_idle(&self) {
        let now = Instant::now();
        let mut buckets = self.buckets.lock().await;
        buckets.retain(|_, b| b.refilled(now, self.rate, self.burst) < self.burst as f64);
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;
    use std::time::Duration;

    use super::*;

    const PEER: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));

    #[tokio::test]
    async fn rate_limiter_allows_within_limit() {
        let limiter = RateLimiter::new(60, 10);

        for _ in 0..10 {
            assert!(limiter.check_rate_limit(PEER).await.is_ok());
        }
    }

    #[tokio::test]
    async fn rate_limiter_blocks_over_limit() {
        let limiter = RateLimiter::new(60, 5);

        for _ in 0..5 {
            limiter.check_rate_limit(PEER).await.unwrap();
        }

        assert!(limiter.check_rate_limit(PEER).await.is_err());
    }

    #[tokio::test]
    async fn rate_limiter_refills_tokens() {
        let limiter = RateLimiter::new(120, 2);

        limiter.check_rate_limit(PEER).await.unwrap();
        limiter.check_rate_limit(PEER).await.unwrap();
        assert!(limiter.check_rate_limit(PEER).await.is_err());

        tokio::time::sleep(Duration::from_millis(600)).await;

        assert!(limiter.check_rate_limit(PEER).await.is_ok());
    }

    #[tokio::test]
    async fn rate_limiter_isolates_peers() {
        let limiter = RateLimiter::new(60, 1);
        let other = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2));

        assert!(limiter.check_rate_limit(PEER).await.is_ok());
        assert!(limiter.check_rate_limit(PEER).await.is_err());
        assert!(limiter.check_rate_limit(other).await.is_ok());
    }

    #[tokio::test]
    async fn rate_limiter_evicts_idle_buckets() {
        let limiter = RateLimiter::new(6000, 10);

        limiter.check_rate_limit(PEER).await.unwrap();
        assert_eq!(limiter.buckets.lock().await.len(), 1);

        tokio::time::sleep(Duration::from_millis(200)).await;
        limiter.evict_idle().await;

        assert_eq!(limiter.buckets.lock().await.len(), 0);
    }

    #[test]
    fn rate_limiter_new_sets_rate_and_burst() {
        let limiter = RateLimiter::new(100, 10);
        assert_eq!(limiter.rate, 100);
        assert_eq!(limiter.burst, 10);
    }
}
