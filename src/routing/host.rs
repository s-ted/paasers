//! Host to radix-tree key conversion.

/// `"www.client.com"` becomes `"/com/client/www"`, `"*.client.com"` becomes `"/com/client/{w}"`.
pub fn host_key(host: &str) -> String {
    host.rsplit('.')
        .fold(String::with_capacity(host.len() + 2), |mut acc, label| {
            acc.push('/');
            if label == "*" {
                acc.push_str("{w}");
            } else {
                acc.push_str(label);
            }
            acc
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_key_exact_and_wildcard() {
        assert_eq!(host_key("www.client.com"), "/com/client/www");
        assert_eq!(host_key("*.client.com"), "/com/client/{w}");
        assert_eq!(host_key("localhost"), "/localhost");
    }
}
