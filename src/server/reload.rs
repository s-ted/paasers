//! Hot reload: SIGHUP and config file change detection.
use super::Shared;
use crate::config::{self, Config};
use crate::routing::{self, Runtime};
use crate::tls::CertManager;
use arc_swap::ArcSwap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tokio_util::sync::CancellationToken;

/// Keeps restart-only settings from the running config, returning the ignored field names.
pub fn apply_restart_only(old: &Config, mut new: Config) -> (Config, Vec<&'static str>) {
    let mut ignored = Vec::new();
    let (o, n) = (&old.gateway, &mut new.gateway);
    macro_rules! keep {
        ($($f:ident),*) => {$(
            if o.$f != n.$f { ignored.push(stringify!($f)); n.$f = o.$f.clone(); }
        )*};
    }
    keep!(listen_http, listen_https, storage_path, worker_threads, log);
    if old.mcp != new.mcp {
        ignored.push("mcp-server");
        new.mcp = old.mcp.clone();
    }
    (new, ignored)
}

/// Loads the file and swaps the runtime. On any error the previous runtime is kept.
pub async fn reload_once(
    path: &Path,
    current: &ArcSwap<Runtime>,
    shared: &Shared,
    certs: Option<&CertManager>,
) -> Result<usize, String> {
    let new = config::load(path).map_err(|e| e.to_string())?;
    let old = current.load_full();
    let (cfg, ignored) = apply_restart_only(&old.config, new);
    ignored
        .iter()
        .for_each(|f| tracing::warn!(field = f, "changed setting requires a restart, ignored"));
    let cfg = Arc::new(cfg);
    let rt = routing::build(&cfg, shared).map_err(|e| e.to_string())?;
    if let Some(c) = certs {
        c.reconcile(&cfg, false).await.map_err(|e| e.to_string())?;
    }
    let routes = cfg.routes.len();
    current.store(Arc::new(rt));
    shared.health.retain(&routing::active_upstreams(&cfg));
    Ok(routes)
}

fn stamp(path: &Path) -> Option<(SystemTime, u64)> {
    std::fs::metadata(path)
        .ok()
        .and_then(|m| Some((m.modified().ok()?, m.len())))
}

/// Runs reloads sequentially in a single task.
pub async fn watch(
    path: PathBuf,
    current: Arc<ArcSwap<Runtime>>,
    shared: Arc<Shared>,
    certs: CertManager,
    shutdown: CancellationToken,
) {
    use tokio::signal::unix::{SignalKind, signal};
    let Ok(mut hup) = signal(SignalKind::hangup()) else {
        return;
    };
    let mut tick = tokio::time::interval(Duration::from_secs(2));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut last = stamp(&path);
    loop {
        tokio::select! {
            () = shutdown.cancelled() => return,
            _ = hup.recv() => {}
            _ = tick.tick() => {
                let now = stamp(&path);
                if now == last { continue; }
                last = now;
            }
        }
        match reload_once(&path, &current, &shared, Some(&certs)).await {
            Ok(routes) => tracing::info!(routes, "config reloaded"),
            Err(err) => {
                tracing::error!(%err, "config reload failed; keeping previous config");
                shared.recorder.record(
                    crate::observe::Incident::new(
                        crate::observe::trace::trace_hex(crate::observe::trace::nz128()),
                        "config",
                    )
                    .with_detail(&err),
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::parse_str;

    fn cfg(s: &str) -> Config {
        parse_str(s, &|_| None).unwrap()
    }

    #[test]
    fn restart_only_fields_are_kept() {
        let old = cfg("gateway { listen \"127.0.0.1:1\" }\nmcp-server");
        let new = cfg("gateway { listen \"127.0.0.1:2\" }\nroute \"a.com\" { upstream \"10.0.0.1:80\" }");
        let (merged, ignored) = apply_restart_only(&old, new);
        assert_eq!(merged.gateway.listen_http.port(), 1);
        assert_eq!(merged.routes.len(), 1);
        assert!(ignored.contains(&"listen_http") && ignored.contains(&"mcp-server"));
    }

    #[tokio::test]
    async fn reload_keeps_old_runtime_on_error() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("c.kdl");
        std::fs::write(&p, "route \"a.com\" { upstream \"10.0.0.1:80\" }").unwrap();
        let shared = Shared::new();
        let first = Arc::new(cfg("route \"a.com\" { upstream \"10.0.0.1:80\" }"));
        let cur = ArcSwap::from_pointee(routing::build(&first, &shared).unwrap());
        std::fs::write(&p, "route {{{").unwrap();
        assert!(reload_once(&p, &cur, &shared, None).await.is_err());
        assert_eq!(cur.load().generation, 1);
        std::fs::write(&p, "route \"a.com\" \"b.com\" { upstream \"10.0.0.1:80\" }").unwrap();
        assert_eq!(reload_once(&p, &cur, &shared, None).await.unwrap(), 1);
        assert!(cur.load().table.lookup("b.com").is_some());
    }
}
