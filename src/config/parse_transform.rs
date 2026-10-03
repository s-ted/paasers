//! Parsing of the `transform` node.
use super::error::ConfigError;
use super::kdl_ext::NodeCtx;
use super::model_auth::*;
use http::HeaderName;
use std::str::FromStr;

const FORBIDDEN_HEADERS: &[&str] = &["host", "content-length", "transfer-encoding", "connection"];

type ParsedOps = (Vec<HeaderOpCfg>, Vec<(u16, u16)>);

fn parse_ops(n: &NodeCtx<'_>, response: bool) -> Result<ParsedOps, ConfigError> {
    n.check_args(0, 0)?;
    n.check_props(&[])?;
    let (mut ops, mut status) = (Vec::new(), Vec::new());
    for c in n.scope().iter() {
        if c.name() == "status" {
            if !response {
                return Err(c.err("`status` is only allowed in `response`"));
            }
            c.check_args(0, 0)?;
            c.check_props(&["from", "to"])?;
            let from: u16 = c
                .prop_num("from")?
                .ok_or_else(|| c.err("status requires `from`"))?;
            let to: u16 = c.prop_num("to")?.ok_or_else(|| c.err("status requires `to`"))?;
            if [from, to].iter().any(|s| !(100..=999).contains(s)) {
                return Err(c.err("invalid status code"));
            }
            status.push((from, to));
            continue;
        }
        c.check_props(&[])?;
        let (min, max) = match c.name() {
            "set" | "add" => (2, 2),
            "remove" => (1, 1),
            "replace" => (3, 3),
            other => return Err(c.err(format!("unknown node `{other}`"))),
        };
        c.check_args(min, max)?;
        let header = c.arg_str(0)?;
        let name =
            HeaderName::from_str(header).map_err(|_| c.err(format!("invalid header name `{header}`")))?;
        if FORBIDDEN_HEADERS.contains(&name.as_str()) {
            return Err(c.err(format!("header `{header}` cannot be modified")));
        }
        let op = match c.name() {
            "set" => OpKind::Set(c.arg_str(1)?.to_string()),
            "add" => OpKind::Add(c.arg_str(1)?.to_string()),
            "remove" => OpKind::Remove,
            _ => {
                let re =
                    regex::Regex::new(c.arg_str(1)?).map_err(|e| c.err(format!("invalid regex: {e}")))?;
                OpKind::Replace(re, c.arg_str(2)?.to_string())
            }
        };
        ops.push(HeaderOpCfg {
            header: name.as_str().to_string(),
            op,
        });
    }
    Ok((ops, status))
}

/// `transform off` disables every transform, including the built-in security headers (None).
pub fn parse_transform(n: &NodeCtx<'_>) -> Result<Option<TransformCfg>, ConfigError> {
    n.check_args(0, 1)?;
    n.check_props(&[])?;
    if n.args().next().is_some() {
        if n.arg_str(0)? != "off" {
            return Err(n.err("transform accepts only the argument `off`"));
        }
        n.scope().check_only(&[])?;
        return Ok(None);
    }
    let s = n.scope();
    s.check_only(&["request", "response"])?;
    let mut t = TransformCfg::default();
    if let Some(r) = s.single("request")? {
        t.request = parse_ops(&r, false)?.0;
    }
    if let Some(r) = s.single("response")? {
        (t.response, t.status) = parse_ops(&r, true)?;
    }
    Ok(Some(t))
}
