//! Pure request path handling: percent decoding, traversal and dotfile rules.
use percent_encoding::{AsciiSet, NON_ALPHANUMERIC, percent_decode_str, utf8_percent_encode};

/// Everything except the RFC 3986 unreserved characters is escaped.
const ENCODE: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'.')
    .remove(b'_')
    .remove(b'~');

#[derive(Debug, PartialEq, Eq)]
pub enum PathError {
    /// Undecodable or dangerous bytes (invalid UTF-8, NUL, backslash).
    BadRequest,
    /// Traversal attempt or hidden entry: reported as not found so nothing leaks.
    NotFound,
}

#[derive(Debug, PartialEq, Eq)]
pub struct Parsed {
    pub segments: Vec<String>,
    pub trailing_slash: bool,
}

impl Parsed {
    /// Canonical, re-encoded path with a leading slash (and a trailing one when `dir`).
    pub fn canonical(&self, dir: bool) -> String {
        let mut out = String::from("/");
        for (i, s) in self.segments.iter().enumerate() {
            if i > 0 {
                out.push('/');
            }
            out.push_str(&encode_segment(s));
        }
        if dir && !self.segments.is_empty() {
            out.push('/');
        }
        out
    }
}

pub fn encode_segment(s: &str) -> String {
    utf8_percent_encode(s, ENCODE).to_string()
}

/// Decodes the URI path into clean segments.
pub fn parse(raw: &str, allow_hidden: bool) -> Result<Parsed, PathError> {
    let decoded = percent_decode_str(raw)
        .decode_utf8()
        .map_err(|_| PathError::BadRequest)?;
    if decoded.contains('\0') || decoded.contains('\\') {
        return Err(PathError::BadRequest);
    }
    let mut segments = Vec::new();
    for seg in decoded.split('/') {
        match seg {
            "" | "." => {}
            ".." => return Err(PathError::NotFound),
            s if s.starts_with('.') && !allow_hidden => return Err(PathError::NotFound),
            // Each segment must stay one plain name once pushed onto the root: on Windows `C:` or `c:x`
            // is a drive prefix that would replace the root (`PathBuf::push`), so it never reaches the disk.
            s if !is_plain_name(s) => return Err(PathError::NotFound),
            s => segments.push(s.to_string()),
        }
    }
    Ok(Parsed {
        segments,
        trailing_slash: decoded.ends_with('/'),
    })
}

fn is_plain_name(s: &str) -> bool {
    let mut c = std::path::Path::new(s).components();
    matches!(
        (c.next(), c.next()),
        (Some(std::path::Component::Normal(_)), None)
    ) && !s.contains(':')
}

#[cfg(test)]
mod tests {
    use super::*;

    fn segs(p: &str) -> Vec<String> {
        parse(p, false).unwrap().segments
    }

    #[test]
    fn plain_paths() {
        assert_eq!(segs("/"), Vec::<String>::new());
        assert_eq!(segs("/a/b.txt"), ["a", "b.txt"]);
        assert_eq!(segs("//a///b"), ["a", "b"]);
        assert_eq!(segs("/a/./b"), ["a", "b"]);
        assert!(parse("/a/", false).unwrap().trailing_slash);
        assert!(!parse("/a", false).unwrap().trailing_slash);
    }

    #[test]
    fn percent_decoding() {
        assert_eq!(segs("/sp%20ace%231"), ["sp ace#1"]);
        assert_eq!(segs("/caf%C3%A9"), ["café"]);
    }

    #[test]
    fn traversal_is_not_found() {
        for p in [
            "/..",
            "/../x",
            "/a/../b",
            "/%2e%2e/x",
            "/%2E%2E/x",
            "/a/..%2fb",
            "/a%2f..%2f..%2fx",
            "/a/%2e%2e",
        ] {
            assert_eq!(parse(p, false), Err(PathError::NotFound), "{p}");
            assert_eq!(parse(p, true), Err(PathError::NotFound), "{p} (hidden allowed)");
        }
    }

    #[test]
    fn dangerous_bytes_are_bad_requests() {
        for p in ["/a%00b", "/a\\b", "/a%5cb", "/%ff", "/%c3"] {
            assert_eq!(parse(p, false), Err(PathError::BadRequest), "{p}");
        }
    }

    #[test]
    fn drive_prefixes_and_streams_are_never_segments() {
        for p in [
            "/C:",
            "/c:/windows/win.ini",
            "/docs/C:x",
            "/a.txt:stream",
            "/%43%3a",
        ] {
            assert_eq!(parse(p, true), Err(PathError::NotFound), "{p}");
        }
    }

    #[test]
    fn dotfiles_follow_the_hidden_flag() {
        assert_eq!(parse("/.env", false), Err(PathError::NotFound));
        assert_eq!(parse("/a/.git/config", false), Err(PathError::NotFound));
        assert_eq!(parse("/%2eenv", false), Err(PathError::NotFound));
        assert_eq!(parse("/.env", true).unwrap().segments, [".env"]);
        assert_eq!(segs("/a.b/c."), ["a.b", "c."]);
    }

    #[test]
    fn canonical_is_reencoded_and_never_protocol_relative() {
        let p = parse("//evil.com//x%20y", false).unwrap();
        assert_eq!(p.canonical(true), "/evil.com/x%20y/");
        assert_eq!(parse("/", false).unwrap().canonical(true), "/");
        assert_eq!(parse("//", false).unwrap().canonical(true), "/");
    }
}
