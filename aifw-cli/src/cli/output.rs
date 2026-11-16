//! Rendering API responses: tables (from column specs over JSON pointers),
//! key/value detail views, JSON and YAML.
//!
//! Commands don't define response structs; they name the columns they want
//! as JSON pointers into what the API returned. `-o json` / `-o yaml`
//! print the API's own JSON unchanged, so scripts get a stable contract.

use serde_json::Value;

/// Output format (`-o/--output`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, clap::ValueEnum)]
pub enum Format {
    /// Aligned columns (default)
    #[default]
    Table,
    /// Table with extra columns
    Wide,
    /// The API's JSON, pretty-printed
    Json,
    /// The API's JSON as YAML
    Yaml,
}

impl Format {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "table" => Some(Self::Table),
            "wide" => Some(Self::Wide),
            "json" => Some(Self::Json),
            "yaml" => Some(Self::Yaml),
            _ => None,
        }
    }

    pub fn is_structured(self) -> bool {
        matches!(self, Self::Json | Self::Yaml)
    }
}

/// One table column: header + JSON pointer (RFC 6901) into each row.
#[derive(Debug, Clone, Copy)]
pub struct Col {
    pub header: &'static str,
    pub ptr: &'static str,
    /// Only shown with `-o wide`.
    pub wide: bool,
}

/// Column shown in every table format.
pub const fn col(header: &'static str, ptr: &'static str) -> Col {
    Col {
        header,
        ptr,
        wide: false,
    }
}

/// Column shown only with `-o wide`.
pub const fn wide(header: &'static str, ptr: &'static str) -> Col {
    Col {
        header,
        ptr,
        wide: true,
    }
}

/// Render one JSON value as a table cell.
pub fn cell(v: Option<&Value>) -> String {
    match v {
        None | Some(Value::Null) => "-".to_string(),
        Some(Value::String(s)) if s.is_empty() => "-".to_string(),
        Some(Value::String(s)) => s.clone(),
        Some(Value::Bool(b)) => if *b { "yes" } else { "no" }.to_string(),
        Some(Value::Number(n)) => n.to_string(),
        Some(Value::Array(a)) if a.is_empty() => "-".to_string(),
        Some(Value::Array(a)) => a
            .iter()
            .map(|x| cell(Some(x)))
            .collect::<Vec<_>>()
            .join(","),
        Some(o @ Value::Object(_)) => o.to_string(),
    }
}

/// The list inside a response: a bare array, or the first array found
/// under `data`, `items`, or the only array-valued key of an object.
pub fn rows(v: &Value) -> Vec<&Value> {
    if let Some(a) = v.as_array() {
        return a.iter().collect();
    }
    if let Some(obj) = v.as_object() {
        for key in ["data", "items", "results"] {
            match obj.get(key) {
                Some(Value::Array(a)) => return a.iter().collect(),
                Some(inner @ Value::Object(_)) => return rows(inner),
                _ => {}
            }
        }
        let arrays: Vec<&Vec<Value>> = obj.values().filter_map(Value::as_array).collect();
        if arrays.len() == 1 {
            return arrays[0].iter().collect();
        }
    }
    Vec::new()
}

/// The object inside a single-item response (`{"data": {...}}` or bare).
pub fn item(v: &Value) -> &Value {
    match v.get("data") {
        Some(d @ Value::Object(_)) => d,
        _ => v,
    }
}

/// Render rows as an aligned, borderless table.
pub fn table(rows: &[&Value], cols: &[Col], format: Format) -> String {
    use comfy_table::{ContentArrangement, Table, presets::NOTHING};
    let cols: Vec<&Col> = cols
        .iter()
        .filter(|c| !c.wide || format == Format::Wide)
        .collect();
    let mut t = Table::new();
    t.load_preset(NOTHING)
        .set_content_arrangement(ContentArrangement::Disabled)
        .set_header(cols.iter().map(|c| c.header));
    for r in rows {
        t.add_row(cols.iter().map(|c| cell(r.pointer(c.ptr))));
    }
    // comfy-table pads every line; trim so piping to `grep`/`awk` is clean.
    t.to_string()
        .lines()
        .map(|l| l.trim_end().trim_start_matches(' '))
        .collect::<Vec<_>>()
        .join("\n")
}

/// Key/value detail view (`show` commands): `label:  value` lines.
pub fn detail(v: &Value, fields: &[(&str, &str)]) -> String {
    let width = fields.iter().map(|(l, _)| l.len()).max().unwrap_or(0) + 1;
    fields
        .iter()
        .map(|(label, ptr)| format!("{:<width$} {}", format!("{label}:"), cell(v.pointer(ptr))))
        .collect::<Vec<_>>()
        .join("\n")
}

/// Structured output (json/yaml) of a value.
pub fn structured(v: &Value, format: Format) -> anyhow::Result<String> {
    Ok(match format {
        Format::Yaml => serde_yaml_ng::to_string(v)?.trim_end().to_string(),
        _ => serde_json::to_string_pretty(v)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn cells() {
        assert_eq!(cell(None), "-");
        assert_eq!(cell(Some(&json!(null))), "-");
        assert_eq!(cell(Some(&json!(""))), "-");
        assert_eq!(cell(Some(&json!(true))), "yes");
        assert_eq!(cell(Some(&json!(3))), "3");
        assert_eq!(cell(Some(&json!(["a", 1]))), "a,1");
        assert_eq!(cell(Some(&json!([]))), "-");
        assert_eq!(cell(Some(&json!({"a":1}))), r#"{"a":1}"#);
    }

    #[test]
    fn finds_rows() {
        assert_eq!(rows(&json!([1, 2])).len(), 2);
        assert_eq!(rows(&json!({"data": [1]})).len(), 1);
        assert_eq!(rows(&json!({"data": {"items": [1, 2, 3]}})).len(), 3);
        assert_eq!(rows(&json!({"roles": [1, 2], "total": 2})).len(), 2);
        assert!(rows(&json!({"a": [1], "b": [2]})).is_empty(), "ambiguous");
        assert!(rows(&json!("x")).is_empty());
    }

    #[test]
    fn item_unwraps_data() {
        assert_eq!(item(&json!({"data": {"id": 1}})), &json!({"id": 1}));
        assert_eq!(item(&json!({"id": 1})), &json!({"id": 1}));
    }

    #[test]
    fn table_respects_wide_and_pointers() {
        let data = json!([{"id": "r1", "action": "pass", "src": {"addr": "any"}}]);
        let r = rows(&data);
        let cols = [
            col("ID", "/id"),
            col("ACTION", "/action"),
            wide("SRC", "/src/addr"),
        ];
        let narrow = table(&r, &cols, Format::Table);
        assert!(narrow.contains("ID") && narrow.contains("pass"));
        assert!(!narrow.contains("SRC"));
        let w = table(&r, &cols, Format::Wide);
        assert!(w.contains("SRC") && w.contains("any"));
        assert!(narrow.lines().all(|l| l == l.trim_end()));
    }

    #[test]
    fn detail_aligns() {
        let v = json!({"name": "x", "n": {"deep": 2}});
        let d = detail(&v, &[("Name", "/name"), ("Deep value", "/n/deep")]);
        assert_eq!(d, "Name:       x\nDeep value: 2");
    }

    #[test]
    fn structured_formats() {
        let v = json!({"a": 1});
        assert_eq!(structured(&v, Format::Json).unwrap(), "{\n  \"a\": 1\n}");
        assert_eq!(structured(&v, Format::Yaml).unwrap(), "a: 1");
        assert_eq!(Format::parse("wide"), Some(Format::Wide));
        assert_eq!(Format::parse("xml"), None);
    }
}
