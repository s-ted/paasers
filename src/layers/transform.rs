//! Header and status transformations on requests and responses (no body rewriting: streaming stays intact).
use crate::config::{HeaderOpCfg, OpKind, TransformCfg};
use crate::observe::trace::trace_hex;
use crate::prelude::{BoxFut, ClientIp, CountryCode, Req, Resp, RouteSvc, TraceCtx};
use http::{HeaderMap, HeaderName, HeaderValue, StatusCode};
use std::convert::Infallible;
use std::sync::Arc;
use std::task::{Context, Poll};
use tower::Service;

#[derive(Debug, Clone, PartialEq)]
enum Part {
    Lit(String),
    ClientIp,
    TraceId,
    Host,
    Country,
}

/// Value template with `{client_ip}`, `{trace_id}`, `{host}` and `{country}`; other braces stay literal.
#[derive(Debug, Clone, PartialEq)]
pub struct Template(Vec<Part>);

impl Template {
    pub fn parse(s: &str) -> Self {
        let vars = [
            ("{client_ip}", Part::ClientIp),
            ("{trace_id}", Part::TraceId),
            ("{host}", Part::Host),
            ("{country}", Part::Country),
        ];
        let (mut parts, mut lit, mut rest) = (Vec::new(), String::new(), s);
        'outer: while !rest.is_empty() {
            for (tag, part) in &vars {
                if let Some(r) = rest.strip_prefix(tag) {
                    if !lit.is_empty() {
                        parts.push(Part::Lit(std::mem::take(&mut lit)));
                    }
                    parts.push(part.clone());
                    rest = r;
                    continue 'outer;
                }
            }
            let mut chars = rest.chars();
            lit.extend(chars.next());
            rest = chars.as_str();
        }
        if !lit.is_empty() {
            parts.push(Part::Lit(lit));
        }
        Self(parts)
    }

    fn render(&self, c: &Ctx) -> String {
        self.0
            .iter()
            .map(|p| match p {
                Part::Lit(s) => s.clone(),
                Part::ClientIp => c.client_ip.clone(),
                Part::TraceId => c.trace_id.clone(),
                Part::Host => c.host.clone(),
                Part::Country => c.country.clone(),
            })
            .collect()
    }
}

/// Request facts captured before `inner` runs, so response operations can use them too.
struct Ctx {
    client_ip: String,
    trace_id: String,
    host: String,
    country: String,
}

impl Ctx {
    fn of(req: &Req) -> Self {
        Self {
            client_ip: req
                .extensions()
                .get::<ClientIp>()
                .map(|c| c.0.to_string())
                .unwrap_or_default(),
            trace_id: req
                .extensions()
                .get::<TraceCtx>()
                .map(|t| trace_hex(t.trace_id))
                .unwrap_or_default(),
            host: crate::server::request::request_host(req.uri(), req.headers()).unwrap_or_default(),
            country: req
                .extensions()
                .get::<CountryCode>()
                .map_or_else(|| "XX".into(), |c| String::from_utf8_lossy(&c.0).into_owned()),
        }
    }
}

enum Op {
    Set(HeaderName, Template),
    SetIfAbsent(HeaderName, Template),
    Add(HeaderName, Template),
    Remove(HeaderName),
    Replace(HeaderName, regex::Regex, String),
}

fn compile(ops: &[HeaderOpCfg]) -> Vec<Op> {
    ops.iter()
        .filter_map(|o| {
            let name = HeaderName::from_bytes(o.header.as_bytes()).ok()?;
            Some(match &o.op {
                OpKind::Set(v) => Op::Set(name, Template::parse(v)),
                OpKind::SetIfAbsent(v) => Op::SetIfAbsent(name, Template::parse(v)),
                OpKind::Add(v) => Op::Add(name, Template::parse(v)),
                OpKind::Remove => Op::Remove(name),
                OpKind::Replace(re, r) => Op::Replace(name, re.clone(), r.clone()),
            })
        })
        .collect()
}

fn apply(ops: &[Op], h: &mut HeaderMap, ctx: &Ctx) {
    for op in ops {
        match op {
            Op::Set(n, t) => match HeaderValue::from_str(&t.render(ctx)) {
                Ok(v) => {
                    h.insert(n.clone(), v);
                }
                Err(_) => {
                    tracing::debug!(header = %n, "transform: rendered value is not a valid header, skipped")
                }
            },
            Op::SetIfAbsent(n, t) => {
                if !h.contains_key(n)
                    && let Ok(v) = HeaderValue::from_str(&t.render(ctx))
                {
                    h.insert(n.clone(), v);
                }
            }
            Op::Add(n, t) => match HeaderValue::from_str(&t.render(ctx)) {
                Ok(v) => {
                    h.append(n.clone(), v);
                }
                Err(_) => {
                    tracing::debug!(header = %n, "transform: rendered value is not a valid header, skipped")
                }
            },
            Op::Remove(n) => {
                h.remove(n);
            }
            Op::Replace(n, re, repl) => {
                let values: Vec<HeaderValue> = h.get_all(n).iter().cloned().collect();
                h.remove(n);
                for v in values {
                    let Ok(s) = v.to_str() else {
                        h.append(n.clone(), v);
                        continue;
                    };
                    match HeaderValue::from_str(&re.replace_all(s, repl.as_str())) {
                        Ok(nv) => {
                            h.append(n.clone(), nv);
                        }
                        Err(_) => {
                            tracing::warn!(header = %n, "transform: replacement produced an invalid value, header value removed")
                        }
                    }
                }
            }
        }
    }
}

struct Rt {
    request: Vec<Op>,
    response: Vec<Op>,
    status: Vec<(StatusCode, StatusCode)>,
}

#[derive(Clone)]
pub struct TransformLayer {
    rt: Arc<Rt>,
}

impl TransformLayer {
    pub fn new(cfg: &TransformCfg) -> Self {
        let status = cfg
            .status
            .iter()
            .filter_map(|(f, t)| Some((StatusCode::from_u16(*f).ok()?, StatusCode::from_u16(*t).ok()?)))
            .collect();
        Self {
            rt: Arc::new(Rt {
                request: compile(&cfg.request),
                response: compile(&cfg.response),
                status,
            }),
        }
    }
}

impl tower::Layer<RouteSvc> for TransformLayer {
    type Service = Transform;
    fn layer(&self, inner: RouteSvc) -> Transform {
        Transform {
            inner,
            rt: self.rt.clone(),
        }
    }
}

#[derive(Clone)]
pub struct Transform {
    inner: RouteSvc,
    rt: Arc<Rt>,
}

impl Service<Req> for Transform {
    type Response = Resp;
    type Error = Infallible;
    type Future = BoxFut;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Infallible>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut req: Req) -> BoxFut {
        let rt = self.rt.clone();
        let ctx = Ctx::of(&req);
        apply(&rt.request, req.headers_mut(), &ctx);
        let clone = self.inner.clone();
        let mut inner = std::mem::replace(&mut self.inner, clone);
        Box::pin(async move {
            let mut resp = crate::cache::layer::call_svc(&mut inner, req).await;
            apply(&rt.response, resp.headers_mut(), &ctx);
            if let Some((_, to)) = rt.status.iter().find(|(from, _)| *from == resp.status()) {
                *resp.status_mut() = *to;
            }
            Ok(resp)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::parse_str;
    use crate::prelude::empty;
    use tower::Layer;

    fn cfg_of(body: &str) -> TransformCfg {
        let src = format!("route \"a.com\" {{\n upstream \"10.0.0.1:80\"\n transform {{\n{body}\n }}\n}}");
        parse_str(&src, &|_| None)
            .unwrap()
            .routes
            .remove(0)
            .transform
            .unwrap()
    }

    /// Backend echoing request headers as response headers `x-req-*`, plus a few of its own.
    fn svc(cfg: &TransformCfg) -> Transform {
        let inner = RouteSvc::new(tower::service_fn(|r: Req| async move {
            let mut resp = http::Response::new(empty());
            for (k, v) in r.headers() {
                resp.headers_mut().append(
                    HeaderName::from_bytes(format!("x-req-{k}").as_bytes()).unwrap(),
                    v.clone(),
                );
            }
            resp.headers_mut()
                .insert("server", HeaderValue::from_static("backend/1.0"));
            *resp.status_mut() = StatusCode::NOT_FOUND;
            Ok::<_, Infallible>(resp)
        }));
        TransformLayer::new(cfg).layer(inner)
    }

    async fn run(s: &mut Transform, headers: &[(&'static str, &'static str)]) -> Resp {
        let mut r = http::Request::new(empty());
        r.headers_mut()
            .insert(http::header::HOST, HeaderValue::from_static("A.test"));
        for (k, v) in headers {
            r.headers_mut()
                .append(HeaderName::from_static(k), HeaderValue::from_static(v));
        }
        r.extensions_mut().insert(ClientIp("9.9.9.9".parse().unwrap()));
        r.extensions_mut().insert(TraceCtx {
            trace_id: 0xabc,
            parent_span: None,
            span_id: 1,
            sampled: true,
        });
        s.call(r).await.unwrap()
    }

    #[tokio::test]
    async fn set_add_remove_order() {
        let c = cfg_of(
            "request {\n set \"x-a\" \"1\"\n add \"x-a\" \"2\"\n remove \"x-gone\"\n set \"x-b\" \"first\"\n set \"x-b\" \"second\"\n }",
        );
        let r = run(&mut svc(&c), &[("x-gone", "x"), ("x-a", "orig")]).await;
        let a: Vec<_> = r
            .headers()
            .get_all("x-req-x-a")
            .iter()
            .map(|v| v.to_str().unwrap().to_string())
            .collect();
        assert_eq!(a, vec!["1", "2"], "set replaces every occurrence, add appends");
        assert!(!r.headers().contains_key("x-req-x-gone"));
        assert_eq!(r.headers()["x-req-x-b"], "second");
    }

    #[tokio::test]
    async fn replace_regex_capture() {
        let c = cfg_of("request {\n replace \"x-path\" \"^/old/(.*)$\" \"/new/$1\"\n }");
        let r = run(&mut svc(&c), &[("x-path", "/old/a/b")]).await;
        assert_eq!(r.headers()["x-req-x-path"], "/new/a/b");
        let r = run(&mut svc(&c), &[("x-path", "/other")]).await;
        assert_eq!(r.headers()["x-req-x-path"], "/other");
    }

    #[tokio::test]
    async fn template_variables() {
        let c =
            cfg_of("request {\n set \"x-t\" \"ip={client_ip} id={trace_id} host={host} cc={country}\"\n }");
        let r = run(&mut svc(&c), &[]).await;
        assert_eq!(
            r.headers()["x-req-x-t"],
            "ip=9.9.9.9 id=00000000000000000000000000000abc host=a.test cc=XX"
        );
    }

    #[test]
    fn unknown_braces_literal() {
        let t = Template::parse("a{b}{host}{client_ip");
        assert_eq!(
            t.0,
            vec![
                Part::Lit("a{b}".into()),
                Part::Host,
                Part::Lit("{client_ip".into())
            ]
        );
    }

    #[tokio::test]
    async fn response_ops_and_status_mapping_first_match() {
        let c = cfg_of(
            "response {\n remove \"server\"\n set \"x-from\" \"{host}\"\n status from=404 to=410\n status from=404 to=500\n }",
        );
        let r = run(&mut svc(&c), &[]).await;
        assert_eq!(r.status(), StatusCode::GONE);
        assert!(!r.headers().contains_key("server"));
        assert_eq!(
            r.headers()["x-from"],
            "a.test",
            "context captured from the request"
        );
    }

    #[tokio::test]
    async fn invalid_value_skipped() {
        let c = cfg_of("request {\n set \"x-bad\" \"line\\nbreak\"\n set \"x-ok\" \"fine\"\n }");
        let r = run(&mut svc(&c), &[]).await;
        assert!(!r.headers().contains_key("x-req-x-bad"));
        assert_eq!(r.headers()["x-req-x-ok"], "fine");
    }

    #[tokio::test]
    async fn replace_producing_invalid_value_removes_it() {
        let c = cfg_of("request {\n replace \"x-v\" \"a\" \"\\n\"\n }");
        let r = run(&mut svc(&c), &[("x-v", "abc")]).await;
        assert!(!r.headers().contains_key("x-req-x-v"));
    }
}
