//! Country lookup (MaxMind DB, memory mapped) with block and allow lists.
use super::util::reject;
use crate::config::GeoIpCfg;
use crate::prelude::{BoxFut, ClientIp, CountryCode, Req, Resp, RouteSvc};
use http::{HeaderValue, StatusCode};
use std::collections::HashMap;
use std::convert::Infallible;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError};
use std::task::{Context, Poll};
use std::time::SystemTime;
use tower::Service;

pub struct GeoDb(Box<dyn Fn(IpAddr) -> Option<[u8; 2]> + Send + Sync>);

impl GeoDb {
    pub fn country(&self, ip: IpAddr) -> Option<[u8; 2]> {
        (self.0)(ip)
    }
}

#[allow(unsafe_code)]
pub fn open(path: &Path) -> Result<GeoDb, maxminddb::MaxMindDbError> {
    // SAFETY: the file is only replaced by atomic rename and never modified in place.
    let r = unsafe { maxminddb::Reader::open_mmap(path) }?;
    Ok(GeoDb(Box::new(move |ip| {
        let res = r.lookup(ip).ok()?;
        let c: Option<String> = res.decode_path(&maxminddb::path!["country", "iso_code"]).ok()?;
        c.and_then(|s| <[u8; 2]>::try_from(s.as_bytes()).ok())
    })))
}

/// File modification time at open, and the reader.
type GeoEntry = (Option<SystemTime>, Arc<GeoDb>);

/// One reader per database path, reloaded only when the file's mtime changes.
#[derive(Default)]
pub struct GeoRegistry {
    inner: Mutex<HashMap<PathBuf, GeoEntry>>,
}

impl GeoRegistry {
    pub fn get_or_open(&self, path: &Path) -> Result<Arc<GeoDb>, maxminddb::MaxMindDbError> {
        let mtime = std::fs::metadata(path).and_then(|m| m.modified()).ok();
        let mut m = self.inner.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some((t, db)) = m.get(path)
            && *t == mtime
        {
            return Ok(db.clone());
        }
        let db = Arc::new(open(path)?);
        m.insert(path.to_path_buf(), (mtime, db.clone()));
        Ok(db)
    }
}

#[derive(Clone)]
pub struct GeoIpLayer {
    db: Arc<GeoDb>,
    block: Arc<Vec<[u8; 2]>>,
    allow: Arc<Vec<[u8; 2]>>,
    inject: bool,
}

fn codes(v: &[String]) -> Vec<[u8; 2]> {
    v.iter()
        .filter_map(|s| <[u8; 2]>::try_from(s.as_bytes()).ok())
        .collect()
}

impl GeoIpLayer {
    pub fn new(cfg: &GeoIpCfg, reg: &GeoRegistry) -> Result<Self, maxminddb::MaxMindDbError> {
        Ok(Self {
            db: reg.get_or_open(&cfg.database)?,
            block: Arc::new(codes(&cfg.block)),
            allow: Arc::new(codes(&cfg.allow)),
            inject: cfg.inject_header,
        })
    }

    /// An IP without result is `XX`: never matched by a block list, always refused by an allow list.
    fn blocked(&self, cc: [u8; 2]) -> bool {
        self.block.contains(&cc) || (!self.allow.is_empty() && !self.allow.contains(&cc))
    }
}

impl tower::Layer<RouteSvc> for GeoIpLayer {
    type Service = GeoIp;
    fn layer(&self, inner: RouteSvc) -> GeoIp {
        GeoIp {
            inner,
            cfg: self.clone(),
        }
    }
}

#[derive(Clone)]
pub struct GeoIp {
    inner: RouteSvc,
    cfg: GeoIpLayer,
}

impl Service<Req> for GeoIp {
    type Response = Resp;
    type Error = Infallible;
    type Future = BoxFut;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Infallible>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut req: Req) -> BoxFut {
        let cc = req
            .extensions()
            .get::<ClientIp>()
            .and_then(|ip| self.cfg.db.country(ip.0))
            .unwrap_or(*b"XX");
        if self.cfg.blocked(cc) {
            return Box::pin(std::future::ready(Ok(reject(
                StatusCode::FORBIDDEN,
                &req,
                "geo_blocked",
            ))));
        }
        req.extensions_mut().insert(CountryCode(cc));
        if self.cfg.inject
            && let Ok(v) = HeaderValue::from_bytes(&cc)
        {
            req.headers_mut().insert("x-country-code", v);
        }
        let clone = self.inner.clone();
        let mut inner = std::mem::replace(&mut self.inner, clone);
        Box::pin(async move { Ok(crate::cache::layer::call_svc(&mut inner, req).await) })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::prelude::empty;
    use tower::Layer;

    const DB: &str = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/GeoIP2-Country-Test.mmdb"
    );
    const GB: &str = "81.2.69.160";

    fn cfg(block: &[&str], allow: &[&str], inject: bool) -> GeoIpCfg {
        GeoIpCfg {
            database: DB.into(),
            block: block.iter().map(|s| s.to_string()).collect(),
            allow: allow.iter().map(|s| s.to_string()).collect(),
            inject_header: inject,
        }
    }

    /// Backend that reports the country header it saw.
    fn svc(c: &GeoIpCfg) -> GeoIp {
        let inner = RouteSvc::new(tower::service_fn(|r: Req| async move {
            let mut resp = http::Response::new(empty());
            if let Some(v) = r.headers().get("x-country-code") {
                resp.headers_mut().insert("x-seen", v.clone());
            }
            Ok::<_, Infallible>(resp)
        }));
        GeoIpLayer::new(c, &GeoRegistry::default()).unwrap().layer(inner)
    }

    async fn hit(s: &mut GeoIp, ip: &str, spoof: Option<&'static str>) -> Resp {
        let mut r = http::Request::new(empty());
        r.extensions_mut().insert(ClientIp(ip.parse().unwrap()));
        if let Some(v) = spoof {
            r.headers_mut()
                .insert("x-country-code", HeaderValue::from_static(v));
        }
        s.call(r).await.unwrap()
    }

    #[test]
    fn gb_ip_resolves_and_private_is_unknown() {
        let db = open(Path::new(DB)).unwrap();
        assert_eq!(db.country(GB.parse().unwrap()), Some(*b"GB"));
        assert_eq!(db.country("10.0.0.1".parse().unwrap()), None);
        assert!(open(Path::new("/nonexistent.mmdb")).is_err());
    }

    #[tokio::test]
    async fn block_gb_403() {
        let mut s = svc(&cfg(&["GB"], &[], true));
        let r = hit(&mut s, GB, None).await;
        assert_eq!(r.status(), 403);
        assert_eq!(
            r.extensions().get::<crate::prelude::IncidentKind>().unwrap().0,
            "geo_blocked"
        );
        assert_eq!(
            hit(&mut s, "10.0.0.1", None).await.status(),
            200,
            "XX is never blocked by a block list"
        );
    }

    #[tokio::test]
    async fn allow_list_blocks_xx() {
        let mut s = svc(&cfg(&[], &["GB"], true));
        assert_eq!(hit(&mut s, GB, None).await.status(), 200);
        assert_eq!(hit(&mut s, "10.0.0.1", None).await.status(), 403);
        let mut s = svc(&cfg(&[], &["FR"], true));
        assert_eq!(hit(&mut s, GB, None).await.status(), 403);
    }

    #[tokio::test]
    async fn header_injected_and_spoof_replaced() {
        let mut s = svc(&cfg(&[], &[], true));
        assert_eq!(hit(&mut s, GB, Some("FR")).await.headers()["x-seen"], "GB");
        assert_eq!(hit(&mut s, "10.0.0.1", None).await.headers()["x-seen"], "XX");
        let mut s = svc(&cfg(&[], &[], false));
        assert!(!hit(&mut s, GB, None).await.headers().contains_key("x-seen"));
    }

    #[test]
    fn registry_shares_reader_per_path() {
        let reg = GeoRegistry::default();
        let a = reg.get_or_open(Path::new(DB)).unwrap();
        assert!(Arc::ptr_eq(&a, &reg.get_or_open(Path::new(DB)).unwrap()));
    }
}
