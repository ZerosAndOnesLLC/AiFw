//! Request bodies: built from flags, read from `-f file.json` (or `-f -`
//! for stdin, JSON or YAML), and merged onto the current object for edits.

use serde::Serialize;
use serde_json::{Map, Value};

use super::exit::CliError;
use super::io::Io;
use super::prompt;

/// Read a JSON/YAML body from a path, or stdin when `path` is `-`.
pub fn read(io: &mut Io, path: &str) -> anyhow::Result<Value> {
    let text = if path == "-" {
        prompt::read_all(io)?
    } else {
        std::fs::read_to_string(path)
            .map_err(|e| CliError::Usage(format!("cannot read {path}: {e}")))?
    };
    parse(&text).map_err(|e| CliError::Usage(format!("{path}: {e}")).into())
}

/// Parse JSON, falling back to YAML.
pub fn parse(text: &str) -> Result<Value, String> {
    serde_json::from_str(text).or_else(|je| {
        serde_yaml_ng::from_str::<Value>(text)
            .map_err(|ye| format!("not valid JSON ({je}) or YAML ({ye})"))
    })
}

/// Deep-merge `patch` into `base`: objects merge key by key, anything else
/// replaces.
pub fn merge(base: &mut Value, patch: &Value) {
    match (base, patch) {
        (Value::Object(b), Value::Object(p)) => {
            for (k, v) in p {
                merge(b.entry(k.clone()).or_insert(Value::Null), v);
            }
        }
        (b, p) => *b = p.clone(),
    }
}

/// Builder for a JSON object from optional flags: unset flags are skipped
/// so an edit only touches what the user passed.
#[derive(Debug, Default, Clone)]
pub struct Fields(Map<String, Value>);

impl Fields {
    pub fn new() -> Self {
        Self::default()
    }

    /// Set `key` when `v` is `Some`.
    pub fn opt<T: Serialize>(mut self, key: &str, v: Option<T>) -> Self {
        if let Some(v) = v {
            self.0.insert(
                key.to_string(),
                serde_json::to_value(v).unwrap_or(Value::Null),
            );
        }
        self
    }

    /// Always set `key`.
    pub fn set<T: Serialize>(mut self, key: &str, v: T) -> Self {
        self.0.insert(
            key.to_string(),
            serde_json::to_value(v).unwrap_or(Value::Null),
        );
        self
    }

    /// Set `key` only when `flag` is true.
    pub fn flag<T: Serialize>(self, key: &str, flag: bool, v: T) -> Self {
        if flag { self.set(key, v) } else { self }
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn into_value(self) -> Value {
        Value::Object(self.0)
    }
}

/// The body for a create: `-f` contents (if any) with flag values on top.
pub fn for_create(io: &mut Io, file: Option<&str>, flags: Fields) -> anyhow::Result<Value> {
    let mut v = match file {
        Some(f) => read(io, f)?,
        None => Value::Object(Map::new()),
    };
    merge(&mut v, &flags.into_value());
    Ok(v)
}

/// The body for an update: `current` (already in request shape), then the
/// `-f` contents, then flag values. Errors if nothing would change.
pub fn for_update(
    io: &mut Io,
    mut current: Value,
    file: Option<&str>,
    flags: Fields,
) -> anyhow::Result<Value> {
    if file.is_none() && flags.is_empty() {
        return Err(
            CliError::Usage("nothing to change: pass a field flag or -f <file>".into()).into(),
        );
    }
    if let Some(f) = file {
        let patch = read(io, f)?;
        merge(&mut current, &patch);
    }
    merge(&mut current, &flags.into_value());
    Ok(current)
}

/// Port spec `80` or `8000:8080` → (start, end).
pub fn port_range(s: &str) -> Result<(u16, u16), CliError> {
    let bad = || CliError::Usage(format!("invalid port '{s}' (use 443 or 8000:8080)"));
    let (a, b) = s.split_once([':', '-']).unwrap_or((s, s));
    let a: u16 = a.trim().parse().map_err(|_| bad())?;
    let b: u16 = b.trim().parse().map_err(|_| bad())?;
    if a == 0 || b < a {
        return Err(bad());
    }
    Ok((a, b))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn merges_deeply() {
        let mut a = json!({"x": 1, "o": {"a": 1, "b": 2}});
        merge(&mut a, &json!({"o": {"b": 3, "c": 4}, "y": null}));
        assert_eq!(a, json!({"x": 1, "o": {"a": 1, "b": 3, "c": 4}, "y": null}));
        let mut s = json!([1]);
        merge(&mut s, &json!([2]));
        assert_eq!(s, json!([2]));
    }

    #[test]
    fn fields_skip_unset() {
        let v = Fields::new()
            .opt("a", Some(1))
            .opt::<i32>("b", None)
            .flag("c", true, "yes")
            .flag("d", false, "no")
            .into_value();
        assert_eq!(v, json!({"a": 1, "c": "yes"}));
    }

    #[test]
    fn json_or_yaml() {
        assert_eq!(parse(r#"{"a":1}"#).unwrap(), json!({"a": 1}));
        assert_eq!(parse("a: 1\nb: [x]").unwrap(), json!({"a": 1, "b": ["x"]}));
        assert!(parse("{nope").is_err());
    }

    #[test]
    fn create_and_update_bodies() {
        let mut io = Io::buffered(r#"{"name":"from-stdin","n":1}"#);
        let v = for_create(&mut io, Some("-"), Fields::new().set("n", 2)).unwrap();
        assert_eq!(
            v,
            json!({"name": "from-stdin", "n": 2}),
            "flags win over file"
        );

        let mut io = Io::buffered("");
        let cur = json!({"name": "a", "port": 1});
        assert!(for_update(&mut io, cur.clone(), None, Fields::new()).is_err());
        let v = for_update(&mut io, cur, None, Fields::new().set("port", 2)).unwrap();
        assert_eq!(v, json!({"name": "a", "port": 2}));
    }

    #[test]
    fn ports() {
        assert_eq!(port_range("443").unwrap(), (443, 443));
        assert_eq!(port_range("8000:8080").unwrap(), (8000, 8080));
        assert_eq!(port_range("10-20").unwrap(), (10, 20));
        for bad in ["0", "x", "20:10", "70000"] {
            assert!(port_range(bad).is_err(), "{bad}");
        }
    }
}
