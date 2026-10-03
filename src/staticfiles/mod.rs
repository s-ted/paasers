//! Static file service: terminal service of a route in place of the reverse proxy.
//!
//! Path resolution and the directory listing are implemented here, file transfer (MIME type, `Range`,
//! conditional requests, `HEAD`) is delegated to tower-http `ServeFile`.
pub mod listing;
pub mod path;

use crate::config::StaticCfg;
use crate::prelude::{Body, Req, Resp, boxed, empty, simple};
use bytes::Bytes;
use http::{HeaderValue, Method, StatusCode, header};
use http_body::Frame;
use http_body_util::BodyExt;
use http_body_util::combinators::UnsyncBoxBody;
use listing::Entry;
use path::{Parsed, PathError};
use std::convert::Infallible;
use std::future::Future;
use std::io;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::{Arc, Mutex, PoisonError};
use std::task::{Context, Poll};
use tower::ServiceExt;
use tower_http::services::ServeFile;

/// `ServeFile` bodies are `Send` only, the gateway body type also needs `Sync`.
/// The mutex is never contended: `poll_frame` has exclusive access (`&mut self`).
struct SyncBody(Mutex<UnsyncBoxBody<Bytes, io::Error>>);

impl http_body::Body for SyncBody {
    type Data = Bytes;
    type Error = io::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, io::Error>>> {
        let inner = self.get_mut().0.get_mut().unwrap_or_else(PoisonError::into_inner);
        Pin::new(inner).poll_frame(cx)
    }

    fn is_end_stream(&self) -> bool {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .is_end_stream()
    }

    fn size_hint(&self) -> http_body::SizeHint {
        self.0.lock().unwrap_or_else(PoisonError::into_inner).size_hint()
    }
}

#[derive(Clone)]
pub struct StaticService {
    cfg: Arc<StaticCfg>,
    root: Arc<PathBuf>,
}

impl StaticService {
    /// The root is canonicalized here (a symlinked root directory is fine).
    pub fn new(cfg: &StaticCfg) -> io::Result<Self> {
        let root = std::fs::canonicalize(&cfg.root)?;
        Ok(Self {
            cfg: Arc::new(cfg.clone()),
            root: Arc::new(root),
        })
    }
}

impl tower::Service<Req> for StaticService {
    type Response = Resp;
    type Error = Infallible;
    type Future = Pin<Box<dyn Future<Output = Result<Resp, Infallible>> + Send>>;

    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Infallible>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: Req) -> Self::Future {
        let (cfg, root) = (self.cfg.clone(), self.root.clone());
        Box::pin(async move {
            let mut resp = handle(&cfg, &root, req).await;
            resp.headers_mut().insert(
                header::X_CONTENT_TYPE_OPTIONS,
                HeaderValue::from_static("nosniff"),
            );
            Ok(resp)
        })
    }
}

fn text(status: StatusCode, msg: &'static str) -> Resp {
    simple(status, "text/plain; charset=utf-8", msg)
}

fn not_found() -> Resp {
    text(StatusCode::NOT_FOUND, "not found")
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    File,
    Dir,
}

/// Metadata of an existing entry, honouring the symlink policy. `None` means "treat as missing".
async fn probe(cfg: &StaticCfg, p: &Path) -> Option<Kind> {
    let lm = tokio::fs::symlink_metadata(p).await.ok()?;
    if lm.file_type().is_symlink() && !cfg.follow_symlinks {
        return None;
    }
    let md = if lm.file_type().is_symlink() {
        tokio::fs::metadata(p).await.ok()?
    } else {
        lm
    };
    if md.is_dir() {
        Some(Kind::Dir)
    } else if md.is_file() {
        Some(Kind::File)
    } else {
        None
    }
}

/// Walks the segments below `root`, refusing symlinks unless allowed. Returns the final path and kind.
async fn resolve(cfg: &StaticCfg, root: &Path, parsed: &Parsed) -> Option<(PathBuf, Kind)> {
    let mut cur = root.to_path_buf();
    let mut kind = Kind::Dir;
    for seg in &parsed.segments {
        if kind != Kind::Dir {
            return None;
        }
        cur.push(seg);
        kind = probe(cfg, &cur).await?;
    }
    Some((cur, kind))
}

async fn handle(cfg: &StaticCfg, root: &Path, req: Req) -> Resp {
    let head = match *req.method() {
        Method::GET => false,
        Method::HEAD => true,
        _ => {
            let mut r = text(StatusCode::METHOD_NOT_ALLOWED, "method not allowed");
            r.headers_mut()
                .insert(header::ALLOW, HeaderValue::from_static("GET, HEAD"));
            return r;
        }
    };
    let parsed = match path::parse(req.uri().path(), cfg.hidden) {
        Ok(p) => p,
        Err(PathError::BadRequest) => return text(StatusCode::BAD_REQUEST, "bad request"),
        Err(PathError::NotFound) => return not_found(),
    };
    let found = resolve(cfg, root, &parsed).await;
    let (file, kind) = match found {
        Some(f) => f,
        None => {
            return spa_fallback(cfg, root, &parsed, &req)
                .await
                .unwrap_or_else(not_found);
        }
    };
    match kind {
        Kind::File if parsed.trailing_slash && !parsed.segments.is_empty() => not_found(),
        Kind::File => serve_file(cfg, &file, &req).await,
        Kind::Dir => serve_dir(cfg, &file, &parsed, &req, head).await,
    }
}

/// Single page application mode: an unknown extensionless path serves the root index.
async fn spa_fallback(cfg: &StaticCfg, root: &Path, parsed: &Parsed, req: &Req) -> Option<Resp> {
    if !cfg.spa || cfg.index.is_empty() {
        return None;
    }
    let last = parsed.segments.last()?;
    if last.contains('.') {
        return None;
    }
    let index = root.join(&cfg.index);
    (probe(cfg, &index).await? == Kind::File).then_some(())?;
    Some(serve_file(cfg, &index, req).await)
}

async fn serve_dir(cfg: &StaticCfg, dir: &Path, parsed: &Parsed, req: &Req, head: bool) -> Resp {
    if !parsed.trailing_slash && !parsed.segments.is_empty() {
        let mut loc = parsed.canonical(true);
        if let Some(q) = req.uri().query() {
            loc.push('?');
            loc.push_str(q);
        }
        return crate::server::request::redirect(&loc);
    }
    if !cfg.index.is_empty() {
        let index = dir.join(&cfg.index);
        if probe(cfg, &index).await == Some(Kind::File) {
            return serve_file(cfg, &index, req).await;
        }
    }
    if !cfg.listing {
        return not_found();
    }
    let Ok((entries, truncated)) = read_entries(cfg, dir).await else {
        return not_found();
    };
    let display = {
        let mut s = String::from("/");
        parsed.segments.iter().for_each(|x| {
            s.push_str(x);
            s.push('/');
        });
        s
    };
    let html = listing::render(&display, !parsed.segments.is_empty(), &entries, truncated);
    let mut r = http::Response::new(if head {
        empty()
    } else {
        crate::prelude::full(html.clone())
    });
    let h = r.headers_mut();
    h.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/html; charset=utf-8"),
    );
    h.insert(header::CONTENT_LENGTH, HeaderValue::from(html.len()));
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-cache"));
    h.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static("default-src 'none'; style-src 'unsafe-inline'"),
    );
    r
}

async fn read_entries(cfg: &StaticCfg, dir: &Path) -> io::Result<(Vec<Entry>, bool)> {
    let mut rd = tokio::fs::read_dir(dir).await?;
    let mut out = Vec::new();
    let mut truncated = false;
    while let Some(de) = rd.next_entry().await? {
        let Ok(name) = de.file_name().into_string() else {
            continue;
        };
        if name.starts_with('.') && !cfg.hidden {
            continue;
        }
        if out.len() >= listing::MAX_ENTRIES {
            truncated = true;
            break;
        }
        let Ok(ft) = de.file_type().await else { continue };
        let md = if ft.is_symlink() {
            if !cfg.follow_symlinks {
                continue;
            }
            tokio::fs::metadata(de.path()).await
        } else {
            de.metadata().await
        };
        let Ok(md) = md else { continue };
        if !(md.is_dir() || md.is_file()) {
            continue;
        }
        out.push(Entry {
            name,
            is_dir: md.is_dir(),
            size: md.len(),
            modified: md.modified().ok(),
        });
    }
    listing::sort(&mut out);
    Ok((out, truncated))
}

async fn serve_file(cfg: &StaticCfg, file: &Path, req: &Req) -> Resp {
    let mut inner = http::Request::new(());
    *inner.method_mut() = req.method().clone();
    *inner.headers_mut() = req.headers().clone();
    let resp = match ServeFile::new(file).oneshot(inner).await {
        Ok(r) => r,
        Err(e) => match e {},
    };
    let (parts, body) = resp.into_parts();
    let body: Body = boxed(SyncBody(Mutex::new(body.boxed_unsync())));
    let mut resp = http::Response::from_parts(parts, body);
    if resp.status() == StatusCode::NOT_FOUND {
        return not_found();
    }
    if let Some(cc) = cfg
        .cache_control
        .as_deref()
        .and_then(|v| HeaderValue::from_str(v).ok())
    {
        resp.headers_mut().insert(header::CACHE_CONTROL, cc);
    }
    resp
}
