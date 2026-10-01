//! Response compression (gzip, brotli, zstd) via tower-http, above the cache.
use crate::config::CompressionCfg;
use crate::prelude::{RouteSvc, map_resp};
use http::{HeaderMap, StatusCode, Version};
use tower::{Layer, ServiceExt};
use tower_http::compression::predicate::{DefaultPredicate, Predicate, SizeAbove};
use tower_http::compression::{CompressionLayer, CompressionLevel};

/// Extra exclusions on top of the default predicate: 1xx, 204, 304 and partial content.
fn extra_ok(status: StatusCode, _v: Version, h: &HeaderMap, _e: &http::Extensions) -> bool {
    !(status.is_informational()
        || status == StatusCode::NO_CONTENT
        || status == StatusCode::NOT_MODIFIED
        || h.contains_key(http::header::CONTENT_RANGE))
}

pub fn wrap(inner: RouteSvc, cfg: &CompressionCfg) -> RouteSvc {
    let pred = DefaultPredicate::new()
        .and(SizeAbove::new(cfg.min_size))
        .and(extra_ok as fn(StatusCode, Version, &HeaderMap, &http::Extensions) -> bool);
    let layer = CompressionLayer::new()
        .gzip(cfg.gzip)
        .br(cfg.brotli)
        .zstd(cfg.zstd)
        .quality(CompressionLevel::Default)
        .compress_when(pred);
    RouteSvc::new(layer.layer(inner).map_response(map_resp))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::prelude::{Req, Resp, empty, full};
    use http::{HeaderValue, header};
    use http_body_util::BodyExt;
    use std::convert::Infallible;
    use tower::Service;

    fn cfg() -> CompressionCfg {
        CompressionCfg {
            zstd: true,
            brotli: true,
            gzip: true,
            min_size: 1024,
        }
    }

    fn backend(make: impl Fn() -> Resp + Clone + Send + Sync + 'static) -> RouteSvc {
        RouteSvc::new(tower::service_fn(move |_r: Req| {
            let r = make();
            async move { Ok::<_, Infallible>(r) }
        }))
    }

    fn big() -> Resp {
        let mut r = http::Response::new(full("hello compressible world ".repeat(200)));
        r.headers_mut()
            .insert(header::CONTENT_TYPE, HeaderValue::from_static("text/plain"));
        r
    }

    async fn send(svc: &mut RouteSvc, accept: Option<&str>) -> Resp {
        let mut r = http::Request::new(empty());
        if let Some(a) = accept {
            r.headers_mut()
                .insert(header::ACCEPT_ENCODING, HeaderValue::from_str(a).unwrap());
        }
        svc.call(r).await.unwrap()
    }

    fn enc(r: &Resp) -> Option<&str> {
        r.headers()
            .get(header::CONTENT_ENCODING)
            .and_then(|v| v.to_str().ok())
    }

    #[tokio::test]
    async fn zstd_when_accepted() {
        let mut s = wrap(backend(big), &cfg());
        let r = send(&mut s, Some("zstd")).await;
        assert_eq!(enc(&r), Some("zstd"));
        let body = r.into_body().collect().await.unwrap().to_bytes();
        assert!(
            body.len() < 5000,
            "compressed body is smaller than the 5000 byte original"
        );
    }

    #[tokio::test]
    async fn gzip_fallback_and_brotli() {
        let mut s = wrap(backend(big), &cfg());
        assert_eq!(enc(&send(&mut s, Some("gzip")).await), Some("gzip"));
        assert_eq!(enc(&send(&mut s, Some("br")).await), Some("br"));
        let only_gzip = CompressionCfg {
            zstd: false,
            brotli: false,
            ..cfg()
        };
        let mut s = wrap(backend(big), &only_gzip);
        assert_eq!(enc(&send(&mut s, Some("zstd, br, gzip")).await), Some("gzip"));
    }

    #[tokio::test]
    async fn no_compress_small_or_without_accept() {
        let mut s = wrap(backend(|| http::Response::new(full("tiny"))), &cfg());
        assert_eq!(enc(&send(&mut s, Some("gzip")).await), None);
        let mut s = wrap(backend(big), &cfg());
        assert_eq!(enc(&send(&mut s, None).await), None);
    }

    #[tokio::test]
    async fn no_compress_101_204_304_and_ranges() {
        for (status, extra) in [
            (101u16, None),
            (204, None),
            (304, None),
            (206, Some((header::CONTENT_RANGE, "bytes 0-1/2"))),
        ] {
            let mut s = wrap(
                backend(move || {
                    let mut r = big();
                    *r.status_mut() = StatusCode::from_u16(status).unwrap();
                    if let Some((k, v)) = &extra {
                        r.headers_mut().insert(k.clone(), HeaderValue::from_static(v));
                    }
                    r
                }),
                &cfg(),
            );
            assert_eq!(enc(&send(&mut s, Some("gzip")).await), None, "{status}");
        }
    }

    #[tokio::test]
    async fn no_compress_already_encoded() {
        let mut s = wrap(
            backend(|| {
                let mut r = big();
                r.headers_mut()
                    .insert(header::CONTENT_ENCODING, HeaderValue::from_static("br"));
                r
            }),
            &cfg(),
        );
        assert_eq!(enc(&send(&mut s, Some("gzip")).await), Some("br"));
    }

    #[tokio::test]
    async fn vary_header_added() {
        let mut s = wrap(backend(big), &cfg());
        let r = send(&mut s, Some("gzip")).await;
        assert!(r.headers().get_all(header::VARY).iter().any(|v| {
            v.to_str()
                .unwrap()
                .to_ascii_lowercase()
                .contains("accept-encoding")
        }));
    }

    #[tokio::test]
    async fn images_are_not_compressed() {
        let mut s = wrap(
            backend(|| {
                let mut r = big();
                r.headers_mut()
                    .insert(header::CONTENT_TYPE, HeaderValue::from_static("image/png"));
                r
            }),
            &cfg(),
        );
        assert_eq!(enc(&send(&mut s, Some("gzip")).await), None);
    }
}
