//! `GatekeeperLayer`: serves `/__gate/*` and requires a valid session cookie everywhere else.
use super::http_util::{forbidden, json_401, origin_ok, query_param, read_body};
use super::login::{MAX_FORM_BYTES, clear_cookie, handle_post, login_page, redirect, safe_next};
use super::pages::{Mode, Page, render};
use super::session::{read_cookie, strip_cookie, verify};
use super::{GateRt, GateShared};
use crate::config::GatekeeperCfg;
use crate::prelude::{BoxFut, ClientIp, Req, Resp, RouteSvc, simple};
use crate::storage::now_unix;
use http::{Method, StatusCode, header};
use std::convert::Infallible;
use std::sync::Arc;
use std::task::{Context, Poll};
use tower::Service;

#[derive(Clone)]
pub struct GatekeeperLayer {
    rt: Arc<GateRt>,
}

impl GatekeeperLayer {
    pub fn new(
        route_id: &Arc<str>,
        hosts: &[String],
        cfg: &GatekeeperCfg,
        secure: bool,
        https_port: Option<u16>,
        shared: &Arc<GateShared>,
    ) -> Result<Self, super::GateError> {
        Ok(Self {
            rt: Arc::new(GateRt::build(route_id, hosts, cfg, secure, https_port, shared)?),
        })
    }
}

impl tower::Layer<RouteSvc> for GatekeeperLayer {
    type Service = Gatekeeper;
    fn layer(&self, inner: RouteSvc) -> Gatekeeper {
        Gatekeeper {
            inner,
            rt: self.rt.clone(),
        }
    }
}

#[derive(Clone)]
pub struct Gatekeeper {
    inner: RouteSvc,
    rt: Arc<GateRt>,
}

fn to_login(req: &Req) -> Resp {
    let pq = req.uri().path_and_query().map_or("/", |p| p.as_str());
    let target = format!(
        "/__gate/login?next={}",
        url::form_urlencoded::byte_serialize(pq.as_bytes()).collect::<String>()
    );
    redirect(&target, None)
}

fn wants_html(req: &Req) -> bool {
    matches!(*req.method(), Method::GET | Method::HEAD)
        && req
            .headers()
            .get(header::ACCEPT)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|a| a.contains("text/html"))
}

fn session_method(rt: &GateRt, req: &Req) -> Option<char> {
    read_cookie(req.headers(), &rt.cookie_name)
        .and_then(|c| verify(&rt.shared.hmac_key, &rt.route_id, &rt.fingerprint, c, now_unix()))
}

async fn passkeys_present(rt: &GateRt) -> bool {
    #[cfg(feature = "passkey")]
    if rt.passkey {
        return super::passkey::has_any(rt).await;
    }
    let _ = rt;
    false
}

async fn gate_route(rt: &GateRt, req: Req) -> Resp {
    let path = req.uri().path().to_string();
    let method = req.method().clone();
    match (method.as_str(), path.as_str()) {
        ("GET", "/__gate/login") => {
            let next = safe_next(&query_param(&req, "next"));
            login_page(rt, &next, passkeys_present(rt).await)
        }
        ("POST", "/__gate/login") => {
            if !origin_ok(&req) {
                return forbidden();
            }
            let ip = req.extensions().get::<ClientIp>().copied();
            let has = passkeys_present(rt).await;
            match (ip, read_body(req, MAX_FORM_BYTES).await) {
                (Some(ip), Some(body)) => handle_post(rt, ip, &body, has).await,
                _ => simple(StatusCode::BAD_REQUEST, "text/plain", "bad request"),
            }
        }
        ("POST", "/__gate/logout") => {
            if !origin_ok(&req) {
                return forbidden();
            }
            redirect("/__gate/login", Some(clear_cookie(rt)))
        }
        ("GET", "/__gate/passkey") if rt.passkey => {
            if session_method(rt, &req) != Some('p') {
                return redirect("/__gate/login", None);
            }
            let next = safe_next(&query_param(&req, "next"));
            render(&Page {
                title: &rt.title,
                mode: Mode::Passkey,
                message: None,
                next: &next,
                totp: false,
                passkey_login: false,
                status: StatusCode::OK,
            })
        }
        #[cfg(feature = "passkey")]
        ("POST", p) if rt.passkey && p.starts_with("/__gate/passkey/") => {
            passkey_route(rt, p.to_string(), req).await
        }
        _ => simple(StatusCode::NOT_FOUND, "text/plain", "not found"),
    }
}

#[cfg(feature = "passkey")]
async fn passkey_route(rt: &GateRt, path: String, req: Req) -> Resp {
    use super::passkey::{MAX_JSON_BYTES, login_finish, login_start, register_finish, register_start};
    if !origin_ok(&req) {
        return forbidden();
    }
    let host = crate::server::request::request_host(req.uri(), req.headers()).unwrap_or_default();
    let ip = req.extensions().get::<ClientIp>().map(|c| c.0);
    let is_register = path.contains("/register/");
    if is_register && session_method(rt, &req) != Some('p') {
        return json_401();
    }
    match (path.as_str(), ip) {
        ("/__gate/passkey/register/start", _) => register_start(rt, &host).await,
        ("/__gate/passkey/login/start", Some(ip)) => login_start(rt, &host, ip).await,
        ("/__gate/passkey/register/finish", _) | ("/__gate/passkey/login/finish", _) => {
            let Some(body) = read_body(req, MAX_JSON_BYTES).await else {
                return simple(StatusCode::BAD_REQUEST, "text/plain", "bad request");
            };
            if is_register {
                register_finish(rt, &host, &body).await
            } else {
                login_finish(rt, &host, &body).await
            }
        }
        _ => simple(StatusCode::NOT_FOUND, "text/plain", "not found"),
    }
}

async fn handle(rt: Arc<GateRt>, mut inner: RouteSvc, mut req: Req) -> Resp {
    if req.uri().path().starts_with("/__gate/") {
        return gate_route(&rt, req).await;
    }
    if session_method(&rt, &req).is_some() {
        strip_cookie(req.headers_mut(), &rt.cookie_name);
        return crate::cache::layer::call_svc(&mut inner, req).await;
    }
    if wants_html(&req) {
        to_login(&req)
    } else {
        json_401()
    }
}

impl Service<Req> for Gatekeeper {
    type Response = Resp;
    type Error = Infallible;
    type Future = BoxFut;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Infallible>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Req) -> BoxFut {
        let clone = self.inner.clone();
        let inner = std::mem::replace(&mut self.inner, clone);
        let rt = self.rt.clone();
        Box::pin(async move { Ok(handle(rt, inner, req).await) })
    }
}
