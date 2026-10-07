//! Named IP sets (`ip-set`) and the IP list syntax shared by `allow-ips` and `trusted-proxies`.
use super::error::ConfigError;
use super::kdl_ext::{NodeCtx, Scope};
use super::units::parse_net;
use ipnet::IpNet;
use std::collections::HashMap;

/// Set name to its networks (not aggregated: lists aggregate once, after resolution).
pub type IpSets = HashMap<String, Vec<IpNet>>;

fn valid_name(s: &str) -> bool {
    !s.is_empty()
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        && parse_net(s).is_err()
}

/// The `- "<entry>"` children of a list node, one per line.
fn children<'a>(n: &NodeCtx<'a>) -> Result<Vec<(NodeCtx<'a>, &'a str)>, ConfigError> {
    let scope = n.scope();
    scope.check_only(&["-"])?;
    scope
        .iter()
        .map(|c| match c.node.children() {
            Some(_) => Err(c.err("a list entry has no children")),
            None => Ok((c, c.one_str()?)),
        })
        .collect()
}

/// All top-level `ip-set` nodes. Sets contain networks only (no nesting).
pub fn parse_ip_sets(top: &Scope<'_>) -> Result<IpSets, ConfigError> {
    let mut sets = IpSets::new();
    for n in top.all("ip-set") {
        n.check_props(&[])?;
        n.check_args(1, 1)?;
        let name = n.arg_str(0)?;
        if !valid_name(name) {
            return Err(n.err(format!(
                "invalid ip-set name `{name}` (letters, digits, `-`, `_`)"
            )));
        }
        let nets = children(&n)?
            .into_iter()
            .map(|(c, s)| parse_net(s).map_err(|m| c.err(m)))
            .collect::<Result<Vec<_>, _>>()?;
        if nets.is_empty() {
            return Err(n.err(format!("ip-set `{name}` is empty")));
        }
        if sets.insert(name.to_string(), nets).is_some() {
            return Err(n.err(format!("duplicate ip-set `{name}`")));
        }
    }
    Ok(sets)
}

/// Resolves a list node (networks or set names, positional arguments then children) into
/// aggregated networks. May be empty.
pub fn ip_list(n: &NodeCtx<'_>, sets: &IpSets) -> Result<Vec<IpNet>, ConfigError> {
    n.check_props(&[])?;
    let positional = n.args_str()?.into_iter().map(|s| (*n, s));
    let mut nets = Vec::new();
    for (c, s) in positional.chain(children(n)?) {
        match parse_net(s) {
            Ok(net) => nets.push(net),
            Err(_) => nets.extend(
                sets.get(s)
                    .ok_or_else(|| c.err(format!("unknown ip-set `{s}`")))?,
            ),
        }
    }
    Ok(IpNet::aggregate(&nets))
}
