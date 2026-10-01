//! Anti brute-force limiters for login attempts.
use governor::clock::{Clock, DefaultClock};
use governor::{DefaultDirectRateLimiter, DefaultKeyedRateLimiter, Quota, RateLimiter};
use std::net::IpAddr;
use std::num::NonZeroU32;
use std::time::Duration;

/// Distributed brute force protection: the route-wide budget is this much larger than the per-IP one.
const GLOBAL_FACTOR: u32 = 20;

pub struct LoginLimiter {
    pub attempts: u32,
    pub window: Duration,
    per_ip: DefaultKeyedRateLimiter<IpAddr>,
    global: DefaultDirectRateLimiter,
}

fn quota(attempts: u32, window: Duration) -> Option<Quota> {
    let burst = NonZeroU32::new(attempts)?;
    Some(Quota::with_period(window.checked_div(attempts)?)?.allow_burst(burst))
}

impl LoginLimiter {
    pub fn new(attempts: u32, window: Duration) -> Option<Self> {
        let global_attempts = attempts.checked_mul(GLOBAL_FACTOR)?;
        Some(Self {
            attempts,
            window,
            per_ip: RateLimiter::keyed(quota(attempts, window)?),
            global: RateLimiter::direct(quota(global_attempts, window)?),
        })
    }

    /// Consumes one attempt. `Err(retry_after_secs)` when refused (per IP first, then global).
    pub fn check(&self, ip: IpAddr) -> Result<(), u64> {
        let clock = DefaultClock::default();
        let wait = |n: governor::NotUntil<_>| n.wait_time_from(clock.now()).as_secs_f64().ceil() as u64;
        self.per_ip.check_key(&ip).map_err(wait)?;
        self.global.check().map_err(wait)
    }

    pub fn purge(&self) {
        self.per_ip.retain_recent();
        self.per_ip.shrink_to_fit();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn burst_then_429_with_retry_after() {
        let l = LoginLimiter::new(5, Duration::from_secs(900)).unwrap();
        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        for _ in 0..5 {
            assert!(l.check(ip).is_ok());
        }
        let retry = l.check(ip).unwrap_err();
        assert!((1..=180).contains(&retry), "retry {retry}");
        assert!(
            l.check("5.6.7.8".parse().unwrap()).is_ok(),
            "other IPs are independent"
        );
    }

    #[test]
    fn global_budget_applies_across_ips() {
        let l = LoginLimiter::new(1, Duration::from_secs(3600)).unwrap();
        let mut refused = 0;
        for i in 0..40u8 {
            if l.check(IpAddr::from([10, 0, 0, i])).is_err() {
                refused += 1;
            }
        }
        assert_eq!(refused, 40 - GLOBAL_FACTOR);
    }

    #[test]
    fn invalid_parameters_are_rejected() {
        assert!(LoginLimiter::new(0, Duration::from_secs(60)).is_none());
        assert!(LoginLimiter::new(5, Duration::ZERO).is_none());
    }
}
