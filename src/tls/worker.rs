//! Certificate maintenance loop: re-selects certificates on expiry events and issues ACME certificates.
use super::select::needs_issue;
use super::state::TlsRoute;
use super::{CertManagerInner, refresh};
use crate::config::TlsMode;
use crate::storage::now_unix;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio_util::sync::CancellationToken;

const MAX_BACKOFF: Duration = Duration::from_secs(24 * 3600);

/// 1 failure: 60 s, 2: 120 s, ... capped at 24 h.
pub fn backoff(failures: u32) -> Duration {
    let exp = failures.saturating_sub(1).min(20);
    Duration::from_secs(60u64.saturating_mul(1u64 << exp)).min(MAX_BACKOFF)
}

#[derive(Default)]
struct JobState {
    failures: u32,
    next_attempt: i64,
}

struct Job {
    route: TlsRoute,
    email: String,
    directory: String,
    ca_root: Option<std::path::PathBuf>,
}

/// Routes with at least one host that has neither a local nor an ACME certificate lasting 30 more days.
async fn due_jobs(inner: &CertManagerInner, now: i64) -> Vec<Job> {
    let st = inner.state.lock().await;
    let mut out = Vec::new();
    for route in &st.routes {
        let (TlsMode::Auto { acme: Some(a) }, Some(dir)) = (&route.mode, &route.directory) else {
            continue;
        };
        let mut due = false;
        for h in &route.hosts {
            let local = st.index.best_valid(h, now).map(|c| c.not_after);
            let acme = refresh::acme_cert(inner, h, dir).await.map(|c| c.not_after);
            due |= needs_issue(now, local, acme);
        }
        if due {
            out.push(Job {
                route: route.clone(),
                email: a.email.clone(),
                directory: dir.clone(),
                ca_root: st.gw.acme_ca_root.clone(),
            });
        }
    }
    out
}

async fn attempt(inner: &CertManagerInner, job: &Job) -> Result<(), super::TlsError> {
    let acct = super::acme::account(job.ca_root.as_deref(), &job.directory, &inner.db, &job.email).await?;
    super::acme::issue(
        &acct,
        &job.route.hosts,
        &job.directory,
        &inner.db,
        &inner.challenges,
    )
    .await
}

pub async fn run(inner: Arc<CertManagerInner>, shutdown: CancellationToken) {
    let mut state: HashMap<Arc<str>, JobState> = HashMap::new();
    loop {
        {
            // Expiry is a time event: re-select so that an expired local certificate is replaced at once.
            let mut st = inner.state.lock().await;
            refresh::refresh(&inner, &mut st).await;
        }
        for job in due_jobs(&inner, now_unix()).await {
            let now = now_unix();
            let st = state.entry(job.route.id.clone()).or_default();
            if now < st.next_attempt {
                continue;
            }
            match attempt(&inner, &job).await {
                Ok(()) => {
                    *st = JobState::default();
                    let mut s = inner.state.lock().await;
                    refresh::refresh(&inner, &mut s).await;
                }
                Err(e) => {
                    st.failures += 1;
                    st.next_attempt =
                        now + i64::try_from(backoff(st.failures).as_secs()).unwrap_or(i64::MAX / 2);
                    tracing::warn!(route = %job.route.id, error = %e, failures = st.failures, "certificate issuance failed");
                    inner.incident("acme", &job.route.id, &e.to_string());
                }
            }
        }
        tokio::select! {
            () = shutdown.cancelled() => return,
            () = inner.wake.notified() => {}
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
}
