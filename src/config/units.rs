//! Pure parsers for listen addresses, hosts, durations, sizes, countries and networks.
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::str::FromStr;
use std::time::Duration;

/// `":80"` means dual-stack `[::]:80`; anything else must be a literal socket address.
pub fn parse_listen(s: &str) -> Result<SocketAddr, String> {
    if let Some(port) = s.strip_prefix(':') {
        let port: u16 = port
            .parse()
            .map_err(|_| format!("invalid listen address `{s}`"))?;
        return Ok(SocketAddr::from((Ipv6Addr::UNSPECIFIED, port)));
    }
    s.parse().map_err(|_| format!("invalid listen address `{s}`"))
}

fn valid_label(l: &str) -> bool {
    !l.is_empty()
        && l.len() <= 63
        && !l.starts_with('-')
        && !l.ends_with('-')
        && l.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// Lowercases, strips one trailing dot and validates a hostname or `*.` wildcard.
pub fn normalize_host(s: &str) -> Result<String, String> {
    let h = s.to_ascii_lowercase();
    let h = h.strip_suffix('.').unwrap_or(&h).to_string();
    if !h.is_ascii() || h.is_empty() || h.len() > 253 {
        return Err(format!("invalid host `{s}`"));
    }
    let (wild, rest) = match h.strip_prefix("*.") {
        Some(r) => (true, r),
        None => (false, h.as_str()),
    };
    let labels: Vec<&str> = rest.split('.').collect();
    if !labels.iter().all(|l| valid_label(l)) {
        return Err(format!("invalid host `{s}`"));
    }
    if wild && labels.len() < 2 {
        return Err(format!(
            "wildcard host `{s}` needs at least two labels after `*.`"
        ));
    }
    Ok(h)
}

pub fn parse_duration(s: &str) -> Result<Duration, String> {
    humantime::parse_duration(s).map_err(|e| format!("invalid duration `{s}`: {e}"))
}

pub fn parse_size(s: &str) -> Result<u64, String> {
    bytesize::ByteSize::from_str(s)
        .map(|b| b.as_u64())
        .map_err(|e| format!("invalid size `{s}`: {e}"))
}

/// CSV of ISO 3166-1 alpha-2 codes, normalized to uppercase.
pub fn parse_countries(s: &str) -> Result<Vec<String>, String> {
    s.split(',')
        .map(str::trim)
        .filter(|c| !c.is_empty())
        .map(|c| {
            let u = c.to_ascii_uppercase();
            if u.len() == 2 && u.bytes().all(|b| b.is_ascii_uppercase()) {
                Ok(u)
            } else {
                Err(format!("invalid country code `{c}`"))
            }
        })
        .collect()
}

/// CIDR or bare IP address.
pub fn parse_net(s: &str) -> Result<ipnet::IpNet, String> {
    s.parse::<ipnet::IpNet>()
        .or_else(|_| s.parse::<IpAddr>().map(ipnet::IpNet::from))
        .map_err(|_| format!("invalid network `{s}`"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn listen_colon_port_is_dual_stack() {
        assert_eq!(parse_listen(":80").unwrap().to_string(), "[::]:80");
    }

    #[test]
    fn listen_explicit_v4_v6() {
        assert_eq!(parse_listen("0.0.0.0:80").unwrap().to_string(), "0.0.0.0:80");
        assert_eq!(parse_listen("[::1]:8443").unwrap().to_string(), "[::1]:8443");
        assert_eq!(parse_listen(":0").unwrap().port(), 0);
    }

    #[test]
    fn listen_invalid() {
        assert!(parse_listen("nope").is_err());
        assert!(parse_listen(":99999").is_err());
    }

    #[test]
    fn normalize_host_lower_trailing_dot() {
        assert_eq!(normalize_host("WWW.Client.COM.").unwrap(), "www.client.com");
    }

    #[test]
    fn host_rejects_underscore_and_unicode() {
        assert!(normalize_host("a_b.com").is_err());
        assert!(normalize_host("é.com").is_err());
        assert!(normalize_host("-a.com").is_err());
        assert!(normalize_host("").is_err());
    }

    #[test]
    fn wildcard_ok() {
        assert_eq!(normalize_host("*.client.com").unwrap(), "*.client.com");
    }

    #[test]
    fn wildcard_single_label_rejected() {
        assert!(normalize_host("*.com").is_err());
    }

    #[test]
    fn size_mb_vs_mib() {
        assert_eq!(parse_size("256MB").unwrap(), 256_000_000);
        assert_eq!(parse_size("256MiB").unwrap(), 268_435_456);
    }

    #[test]
    fn duration_days_minutes() {
        assert_eq!(parse_duration("14d").unwrap(), Duration::from_secs(14 * 86400));
        assert_eq!(parse_duration("15m").unwrap(), Duration::from_secs(900));
        assert!(parse_duration("abc").is_err());
    }

    #[test]
    fn countries_csv_normalized() {
        assert_eq!(parse_countries("cn, ru").unwrap(), vec!["CN", "RU"]);
    }

    #[test]
    fn country_invalid() {
        assert!(parse_countries("CHN").is_err());
        assert!(parse_countries("C1").is_err());
    }

    #[test]
    fn net_accepts_cidr_and_ip() {
        assert_eq!(parse_net("10.0.0.0/8").unwrap().to_string(), "10.0.0.0/8");
        assert_eq!(parse_net("1.2.3.4").unwrap().to_string(), "1.2.3.4/32");
        assert!(parse_net("x").is_err());
    }
}
