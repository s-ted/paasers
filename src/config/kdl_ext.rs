//! Typed read helpers on KDL nodes with position-aware errors.
use super::error::ConfigError;
use super::units;
use kdl::{KdlDocument, KdlEntry, KdlNode, KdlValue};
use std::time::Duration;

/// Environment lookup, injected so that validation is testable.
pub type Env<'a> = &'a dyn Fn(&str) -> Option<String>;

pub fn parse_doc(src: &str) -> Result<KdlDocument, ConfigError> {
    KdlDocument::parse(src).map_err(|e| ConfigError::from_kdl(src, &e))
}

/// A list of sibling nodes.
#[derive(Clone, Copy)]
pub struct Scope<'a> {
    pub nodes: &'a [KdlNode],
    pub src: &'a str,
}

impl<'a> Scope<'a> {
    pub fn iter(&self) -> impl Iterator<Item = NodeCtx<'a>> + use<'a> {
        let src = self.src;
        self.nodes.iter().map(move |node| NodeCtx { node, src })
    }

    pub fn all(&self, name: &str) -> Vec<NodeCtx<'a>> {
        self.iter().filter(|n| n.name() == name).collect()
    }

    /// Rejects any node whose name is not in `allowed`.
    pub fn check_only(&self, allowed: &[&str]) -> Result<(), ConfigError> {
        match self.iter().find(|n| !allowed.contains(&n.name())) {
            Some(n) => Err(n.err(format!("unknown node `{}`", n.name()))),
            None => Ok(()),
        }
    }

    /// Optional singleton node: a second occurrence is an error.
    pub fn single(&self, name: &str) -> Result<Option<NodeCtx<'a>>, ConfigError> {
        let mut found = self.all(name).into_iter();
        let first = found.next();
        match found.next() {
            Some(dup) => Err(dup.err(format!("duplicate node `{name}`"))),
            None => Ok(first),
        }
    }
}

#[derive(Clone, Copy)]
pub struct NodeCtx<'a> {
    pub node: &'a KdlNode,
    pub src: &'a str,
}

impl<'a> NodeCtx<'a> {
    pub fn name(&self) -> &'a str {
        self.node.name().value()
    }

    pub fn scope(&self) -> Scope<'a> {
        let nodes = self.node.children().map(|d| d.nodes()).unwrap_or(&[]);
        Scope { nodes, src: self.src }
    }

    pub fn err(&self, msg: impl Into<String>) -> ConfigError {
        ConfigError::at(self.src, self.node.span().offset(), msg)
    }

    pub fn err_entry(&self, e: &KdlEntry, msg: impl Into<String>) -> ConfigError {
        ConfigError::at(self.src, e.span().offset(), msg)
    }

    pub fn args(&self) -> impl Iterator<Item = &'a KdlEntry> + use<'a> {
        self.node.entries().iter().filter(|e| e.name().is_none())
    }

    fn arg(&self, i: usize) -> Result<&'a KdlEntry, ConfigError> {
        self.args()
            .nth(i)
            .ok_or_else(|| self.err(format!("missing argument #{}", i + 1)))
    }

    pub fn arg_str(&self, i: usize) -> Result<&'a str, ConfigError> {
        let e = self.arg(i)?;
        e.value()
            .as_string()
            .ok_or_else(|| self.err_entry(e, format!("expected string argument #{}", i + 1)))
    }

    pub fn arg_bool(&self, i: usize) -> Result<bool, ConfigError> {
        let e = self.arg(i)?;
        e.value()
            .as_bool()
            .ok_or_else(|| self.err_entry(e, format!("expected boolean argument #{}", i + 1)))
    }

    pub fn args_str(&self) -> Result<Vec<&'a str>, ConfigError> {
        (0..self.args().count()).map(|i| self.arg_str(i)).collect()
    }

    /// Node of the form `name "<string>"` without properties.
    pub fn one_str(&self) -> Result<&'a str, ConfigError> {
        self.check_args(1, 1)?;
        self.check_props(&[])?;
        self.arg_str(0)
    }

    pub fn prop(&self, name: &str) -> Option<&'a KdlEntry> {
        self.node
            .entries()
            .iter()
            .find(|e| e.name().is_some_and(|n| n.value() == name))
    }

    pub fn prop_str(&self, name: &str) -> Result<Option<&'a str>, ConfigError> {
        self.prop(name)
            .map(|e| {
                e.value()
                    .as_string()
                    .ok_or_else(|| self.err_entry(e, format!("`{name}` must be a string")))
            })
            .transpose()
    }

    pub fn prop_bool(&self, name: &str) -> Result<Option<bool>, ConfigError> {
        self.prop(name)
            .map(|e| {
                e.value()
                    .as_bool()
                    .ok_or_else(|| self.err_entry(e, format!("`{name}` must be a boolean")))
            })
            .transpose()
    }

    pub fn prop_num<T: TryFrom<i128>>(&self, name: &str) -> Result<Option<T>, ConfigError> {
        let Some(e) = self.prop(name) else { return Ok(None) };
        let KdlValue::Integer(v) = e.value() else {
            return Err(self.err_entry(e, format!("`{name}` must be an integer")));
        };
        T::try_from(*v)
            .map(Some)
            .map_err(|_| self.err_entry(e, format!("`{name}` out of range")))
    }

    /// Duration as a humantime string or an integer number of seconds.
    pub fn prop_dur(&self, name: &str) -> Result<Option<Duration>, ConfigError> {
        let Some(e) = self.prop(name) else { return Ok(None) };
        match e.value() {
            KdlValue::String(s) => units::parse_duration(s)
                .map(Some)
                .map_err(|m| self.err_entry(e, m)),
            KdlValue::Integer(v) => u64::try_from(*v)
                .map(|s| Some(Duration::from_secs(s)))
                .map_err(|_| self.err_entry(e, format!("`{name}` out of range"))),
            _ => Err(self.err_entry(e, format!("`{name}` must be a duration"))),
        }
    }

    /// Size as a bytesize string or an integer number of bytes.
    pub fn prop_size(&self, name: &str) -> Result<Option<u64>, ConfigError> {
        let Some(e) = self.prop(name) else { return Ok(None) };
        match e.value() {
            KdlValue::String(s) => units::parse_size(s).map(Some).map_err(|m| self.err_entry(e, m)),
            KdlValue::Integer(v) => u64::try_from(*v)
                .map(Some)
                .map_err(|_| self.err_entry(e, format!("`{name}` out of range"))),
            _ => Err(self.err_entry(e, format!("`{name}` must be a size"))),
        }
    }

    /// Rejects unknown and duplicated properties.
    pub fn check_props(&self, allowed: &[&str]) -> Result<(), ConfigError> {
        let mut seen: Vec<&str> = Vec::new();
        for e in self.node.entries() {
            let Some(n) = e.name() else { continue };
            let n = n.value();
            if !allowed.contains(&n) {
                return Err(self.err_entry(e, format!("unknown property `{n}` on `{}`", self.name())));
            }
            if seen.contains(&n) {
                return Err(self.err_entry(e, format!("duplicate property `{n}`")));
            }
            seen.push(n);
        }
        Ok(())
    }

    pub fn check_args(&self, min: usize, max: usize) -> Result<(), ConfigError> {
        let n = self.args().count();
        if n < min || n > max {
            return Err(self.err(format!(
                "`{}` expects {min}..={max} arguments, got {n}",
                self.name()
            )));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn doc(s: &str) -> KdlDocument {
        parse_doc(s).unwrap()
    }

    #[test]
    fn props_and_args() {
        let d = doc("n \"a\" \"b\" x=1 y=\"30s\" z=#true");
        let s = Scope {
            nodes: d.nodes(),
            src: "",
        };
        let n = s.iter().next().unwrap();
        assert_eq!(n.args_str().unwrap(), vec!["a", "b"]);
        assert_eq!(n.prop_num::<u32>("x").unwrap(), Some(1));
        assert_eq!(n.prop_dur("y").unwrap(), Some(Duration::from_secs(30)));
        assert_eq!(n.prop_bool("z").unwrap(), Some(true));
        assert_eq!(n.prop_bool("nope").unwrap(), None);
    }

    #[test]
    fn integer_duration_is_seconds() {
        let d = doc("n x=5");
        let s = Scope {
            nodes: d.nodes(),
            src: "",
        };
        assert_eq!(
            s.iter().next().unwrap().prop_dur("x").unwrap(),
            Some(Duration::from_secs(5))
        );
    }

    #[test]
    fn range_and_type_errors() {
        let d = doc("n x=70000 y=\"s\"");
        let s = Scope {
            nodes: d.nodes(),
            src: "",
        };
        let n = s.iter().next().unwrap();
        assert!(n.prop_num::<u16>("x").is_err());
        assert!(n.prop_num::<u16>("y").is_err());
    }

    #[test]
    fn string_is_not_bool() {
        let d = doc("n x=\"true\"");
        let s = Scope {
            nodes: d.nodes(),
            src: "",
        };
        assert!(s.iter().next().unwrap().prop_bool("x").is_err());
    }

    #[test]
    fn duplicate_and_unknown_props() {
        let d = doc("n x=1 x=2");
        let s = Scope {
            nodes: d.nodes(),
            src: "",
        };
        assert!(s.iter().next().unwrap().check_props(&["x"]).is_err());
        let d = doc("n q=1");
        let s = Scope {
            nodes: d.nodes(),
            src: "",
        };
        assert!(s.iter().next().unwrap().check_props(&["x"]).is_err());
    }

    #[test]
    fn singleton_duplicate() {
        let d = doc("a\na");
        let s = Scope {
            nodes: d.nodes(),
            src: "",
        };
        assert!(s.single("a").is_err());
        assert!(s.single("b").unwrap().is_none());
    }
}
