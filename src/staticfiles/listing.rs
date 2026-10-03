//! HTML directory listing: escaping, ordering and rendering.
use super::path::encode_segment;
use crate::config::StaticCfg;
use std::fmt::Write;
use std::io;
use std::path::Path;
use std::time::SystemTime;

/// Hard cap on listed entries (memory bound).
pub const MAX_ENTRIES: usize = 10_000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub name: String,
    pub is_dir: bool,
    pub size: u64,
    pub modified: Option<SystemTime>,
}

pub fn escape_html(s: &str) -> String {
    let mut o = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => o.push_str("&amp;"),
            '<' => o.push_str("&lt;"),
            '>' => o.push_str("&gt;"),
            '"' => o.push_str("&quot;"),
            '\'' => o.push_str("&#39;"),
            c => o.push(c),
        }
    }
    o
}

pub fn human_size(n: u64) -> String {
    const UNITS: [&str; 5] = ["KiB", "MiB", "GiB", "TiB", "PiB"];
    if n < 1024 {
        return format!("{n} B");
    }
    let mut v = n as f64 / 1024.0;
    let mut u = 0;
    while v >= 1024.0 && u + 1 < UNITS.len() {
        v /= 1024.0;
        u += 1;
    }
    format!("{v:.1} {}", UNITS.get(u).copied().unwrap_or("PiB"))
}

/// Directories first, then files, case-insensitive by name (ties broken by exact name).
pub fn sort(entries: &mut [Entry]) {
    entries.sort_by(|a, b| {
        b.is_dir
            .cmp(&a.is_dir)
            .then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase()))
            .then_with(|| a.name.cmp(&b.name))
    });
}

/// Reads and sorts the entries of `dir`, honouring `hidden` and `follow-symlinks`. `true` = truncated.
pub async fn read_entries(cfg: &StaticCfg, dir: &Path) -> io::Result<(Vec<Entry>, bool)> {
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
        if out.len() >= MAX_ENTRIES {
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
    sort(&mut out);
    Ok((out, truncated))
}

/// `display` is the decoded directory path shown to the user (starts and ends with `/`).
pub fn render(display: &str, parent: bool, entries: &[Entry], truncated: bool) -> String {
    let title = escape_html(display);
    let mut h = String::with_capacity(1024 + entries.len() * 160);
    let _ = write!(
        h,
        "<!doctype html>\n<html lang=\"en\"><head><meta charset=\"utf-8\">\
<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\
<title>Index of {title}</title>\
<style>body{{font:14px system-ui,sans-serif;margin:2rem auto;max-width:60rem;padding:0 1rem}}\
table{{border-collapse:collapse;width:100%}}td,th{{padding:.25rem .75rem;text-align:left}}\
td.n,th.n{{text-align:right;white-space:nowrap}}tr:hover{{background:#8881}}a{{text-decoration:none}}</style>\
</head><body><h1>Index of {title}</h1><table><thead><tr><th>Name</th><th class=\"n\">Size</th><th>Modified (UTC)</th></tr></thead><tbody>"
    );
    if parent {
        h.push_str("<tr><td><a href=\"../\">../</a></td><td class=\"n\"></td><td></td></tr>");
    }
    for e in entries {
        let href = encode_segment(&e.name);
        let (slash, size) = if e.is_dir {
            ("/", "-".to_string())
        } else {
            ("", human_size(e.size))
        };
        let modified = e.modified.map(httpdate::fmt_http_date).unwrap_or_default();
        let name = escape_html(&e.name);
        let _ = write!(
            h,
            "<tr><td><a href=\"{href}{slash}\">{name}{slash}</a></td><td class=\"n\">{size}</td><td>{modified}</td></tr>"
        );
    }
    h.push_str("</tbody></table>");
    if truncated {
        let _ = write!(h, "<p>Only the first {MAX_ENTRIES} entries are shown.</p>");
    }
    h.push_str("</body></html>\n");
    h
}

#[cfg(test)]
mod tests {
    use super::*;

    fn e(name: &str, is_dir: bool) -> Entry {
        Entry {
            name: name.into(),
            is_dir,
            size: 2048,
            modified: Some(SystemTime::UNIX_EPOCH),
        }
    }

    #[test]
    fn escapes_html_specials() {
        assert_eq!(
            escape_html("<a href=\"x\">&'"),
            "&lt;a href=&quot;x&quot;&gt;&amp;&#39;"
        );
    }

    #[test]
    fn human_sizes() {
        assert_eq!(human_size(0), "0 B");
        assert_eq!(human_size(1023), "1023 B");
        assert_eq!(human_size(1024), "1.0 KiB");
        assert_eq!(human_size(1536), "1.5 KiB");
        assert_eq!(human_size(5 * 1024 * 1024), "5.0 MiB");
    }

    #[test]
    fn sorts_dirs_first_then_case_insensitive() {
        let mut v = vec![e("b.txt", false), e("A.txt", false), e("z", true), e("a", true)];
        sort(&mut v);
        let names: Vec<_> = v.iter().map(|x| x.name.as_str()).collect();
        assert_eq!(names, ["a", "z", "A.txt", "b.txt"]);
    }

    #[test]
    fn renders_escaped_names_and_encoded_hrefs() {
        let html = render(
            "/x<y>/",
            true,
            &[e("<script>.txt", false), e("sp ace#1", true)],
            false,
        );
        assert!(!html.contains("<script>"));
        assert!(html.contains("&lt;script&gt;.txt"));
        assert!(html.contains("href=\"%3Cscript%3E.txt\""));
        assert!(html.contains("href=\"sp%20ace%231/\""));
        assert!(html.contains("Index of /x&lt;y&gt;/"));
        assert!(html.contains("href=\"../\""));
        assert!(html.contains("Thu, 01 Jan 1970 00:00:00 GMT"));
    }

    #[test]
    fn no_parent_link_at_root_and_truncation_notice() {
        let html = render("/", false, &[], true);
        assert!(!html.contains("../"));
        assert!(html.contains("Only the first"));
    }
}
