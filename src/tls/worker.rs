//! Certificate renewal loop with exponential backoff.
use super::{CertManagerInner, TlsJob};
use crate::observe::{Incident, trace};
use crate::storage::now_unix;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio_util::sync::CancellationToken;

const RENEW_BEFORE_SECS: i64 = 30 * 86_400;
const MAX_BACKOFF: Duration = Duration::from_secs(24 * 3600);

/// 1 failure: 60 s, 2: 120 s, ... capped at 24 h.
pub fn backoff(failures: u32) -> Duration {
    let exp = failures.saturating_sub(1).min(20);
    Duration::from_secs(60u64.saturating_mul(1u64 << exp)).min(MAX_BACKOFF)
}

/// A job needs (re)issuance when a host has no certificate or the earliest expiry is within 30 days.
pub fn needs_renewal(now: i64, not_after: Option<i64>, missing_hosts: bool) -> bool {
    missing_hosts || not_after.is_none_or(|n| n - now < RENEW_BEFORE_SECS)
}

#[derive(Default)]
struct JobState {
    failures: u32,
    next_attempt: i64,
}

async fn due(inner: &CertManagerInner, job: &TlsJob, now: i64) -> bool {
    let mut earliest: Option<i64> = None;
    let mut missing = false;
    for h in &job.hosts {
        match inner.db.get_cert(h).await {
            Ok(Some(r)) => earliest = Some(earliest.map_or(r.not_after, |e| e.min(r.not_after))),
            Ok(None) => missing = true,
            Err(e) => {
                tracing::warn!(error = %e, "cannot read certificate");
                missing = true;
            }
        }
    }
    needs_renewal(now, earliest, missing)
}

async fn attempt(inner: &CertManagerInner, job: &TlsJob) -> Result<(), super::TlsError> {
    let acct = super::acme::account(&inner.gw, &inner.db, &job.email).await?;
    super::acme::issue(&acct, &job.hosts, &inner.db, &inner.resolver, &inner.challenges).await?;
    if let Some(dc) = inner.default_cert.load_full()
        && job.hosts.contains(&*dc)
    {
        inner.resolver.set_default(inner.resolver.get(&dc));
    }
    Ok(())
}

pub async fn run(inner: Arc<CertManagerInner>, shutdown: CancellationToken) {
    let mut state: HashMap<Arc<str>, JobState> = HashMap::new();
    let mut wanted = inner.wanted.subscribe();
    loop {
        let jobs = wanted.borrow_and_update().clone();
        for job in jobs.iter() {
            let now = now_unix();
            let st = state.entry(job.route_id.clone()).or_default();
            if now < st.next_attempt || !due(&inner, job, now).await {
                continue;
            }
            match attempt(&inner, job).await {
                Ok(()) => *st = JobState::default(),
                Err(e) => {
                    st.failures += 1;
                    st.next_attempt =
                        now + i64::try_from(backoff(st.failures).as_secs()).unwrap_or(i64::MAX / 2);
                    tracing::warn!(route = %job.route_id, error = %e, failures = st.failures, "certificate issuance failed");
                    let mut i =
                        Incident::new(trace::trace_hex(trace::nz128()), "acme").with_detail(&e.to_string());
                    i.route_id = Some(job.route_id.to_string());
                    inner.recorder.record(i);
                }
            }
        }
        // A 60 s tick processes due retries; the expiry check itself is cheap (one SQLite read per host).
        tokio::select! {
            () = shutdown.cancelled() => return,
            _ = wanted.changed() => {}
            () = tokio::time::sleep(Duration::from_secs(60)) => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_schedule() {
        assert_eq!(backoff(1), Duration::from_secs(60));
        assert_eq!(backoff(2), Duration::from_secs(120));
        assert_eq!(backoff(3), Duration::from_secs(240));
        assert_eq!(backoff(40), Duration::from_secs(24 * 3600));
        assert_eq!(backoff(0), Duration::from_secs(60));
    }

    #[test]
    fn needs_renewal_rules() {
        let now = 1_000_000;
        assert!(needs_renewal(now, None, false));
        assert!(needs_renewal(now, Some(now + 100), false));
        assert!(!needs_renewal(now, Some(now + 31 * 86_400), false));
        assert!(needs_renewal(now, Some(now + 90 * 86_400), true));
    }
}
