//! Configuration errors with source positions.
use std::path::PathBuf;

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("{path}: cannot read: {source}")]
    Io { path: PathBuf, source: std::io::Error },
    #[error("KDL syntax error at {line}:{col}: {msg}")]
    Syntax { line: usize, col: usize, msg: String },
    #[error("{line}:{col}: {msg}")]
    Invalid { line: usize, col: usize, msg: String },
    #[error("{0}")]
    Semantic(String),
}

/// Converts a byte offset into a 1-based `(line, column)` pair.
pub fn line_col(src: &str, offset: usize) -> (usize, usize) {
    src.char_indices()
        .take_while(|(i, _)| *i < offset)
        .fold(
            (1, 1),
            |(line, col), (_, c)| {
                if c == '\n' { (line + 1, 1) } else { (line, col + 1) }
            },
        )
}

impl ConfigError {
    pub fn at(src: &str, offset: usize, msg: impl Into<String>) -> Self {
        let (line, col) = line_col(src, offset);
        Self::Invalid {
            line,
            col,
            msg: msg.into(),
        }
    }

    pub fn from_kdl(src: &str, err: &kdl::KdlError) -> Self {
        match err.diagnostics.first() {
            Some(d) => {
                let (line, col) = line_col(src, d.span.offset());
                let msg = d
                    .message
                    .clone()
                    .or_else(|| d.label.clone())
                    .unwrap_or_else(|| "parse error".into());
                Self::Syntax { line, col, msg }
            }
            None => Self::Syntax {
                line: 1,
                col: 1,
                msg: "parse error".into(),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn line_col_counts_lines_and_chars() {
        let s = "ab\ncd\nef";
        assert_eq!(line_col(s, 0), (1, 1));
        assert_eq!(line_col(s, 1), (1, 2));
        assert_eq!(line_col(s, 3), (2, 1));
        assert_eq!(line_col(s, 7), (3, 2));
        assert_eq!(line_col("é\nx", 3), (2, 1));
    }
}
