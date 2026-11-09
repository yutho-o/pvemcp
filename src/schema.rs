//! The subset of zod the tools used: builders that give the same JSON Schema (draft-07) and the
//! same checks, with zod's issue format in refusals.
//!
//! ```ignore
//! use crate::schema::z;
//! z::string().min(1).max(64).regex(r"^[a-z]+$", "Expected a name").describe("The name.").optional()
//! ```

use crate::js::{js_len, js_string, num};
use regex::Regex;
use serde_json::{Map, Value, json};
use std::sync::Arc;

pub const SAFE_INTEGER: f64 = 9_007_199_254_740_991.0;

pub type Preprocess = Arc<dyn Fn(Value) -> Value + Send + Sync>;
pub type Check = Arc<dyn Fn(&Value) -> bool + Send + Sync>;
/// For a map: refuses keys, returning the issues found.
pub type KeyCheck = Arc<dyn Fn(&str) -> Option<String> + Send + Sync>;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Integer {
    No,
    /// z.number().int(): safe integer bounds unless given.
    Int,
    /// A number refined to Number.isInteger, shown as type integer without bounds of its own.
    Whole,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Unknown {
    /// z.object(): unknown keys are dropped.
    Strip,
    /// .strict(): unknown keys are an error.
    Strict,
    /// .loose(): unknown keys pass.
    Loose,
}

#[derive(Clone)]
pub struct Pattern {
    pub regex: Regex,
    /// The source text of the JavaScript regex, as JSON Schema shows it.
    pub source: String,
    pub message: Option<String>,
}

#[derive(Clone)]
pub enum Kind {
    String { min: Option<usize>, max: Option<usize>, patterns: Vec<Pattern> },
    Number { integer: Integer, min: Option<f64>, max: Option<f64> },
    Boolean,
    Enum(Vec<String>),
    Array { item: Box<Schema>, min: Option<usize>, max: Option<usize> },
    Object { shape: Vec<(String, Schema)>, unknown: Unknown },
    Map { value: Box<Schema>, keys: Option<KeyCheck> },
    Union(Vec<Schema>),
    Any,
}

#[derive(Clone)]
pub struct Schema {
    pub kind: Kind,
    pub optional: bool,
    pub description: Option<String>,
    pub preprocess: Option<Preprocess>,
    refines: Vec<(Check, String)>,
}

/// One problem, as zod writes it.
pub type Issue = Value;

fn issue(code: &str, path: &[Value], message: String, extra: Value) -> Issue {
    let mut out = Map::new();
    if let Value::Object(extra) = extra {
        for (k, v) in extra {
            if k == "code" {
                continue;
            }
            out.insert(k, v);
        }
    }
    // zod writes "expected" before "code", the rest after.
    let mut ordered = Map::new();
    if let Some(e) = out.remove("expected") {
        ordered.insert("expected".into(), e);
    }
    if let Some(o) = out.remove("origin") {
        ordered.insert("origin".into(), o);
    }
    ordered.insert("code".into(), Value::String(code.into()));
    for (k, v) in out {
        ordered.insert(k, v);
    }
    ordered.insert("path".into(), Value::Array(path.to_vec()));
    ordered.insert("message".into(), Value::String(message));
    Value::Object(ordered)
}

fn received(v: Option<&Value>) -> &'static str {
    match v {
        None => "undefined",
        Some(Value::Null) => "null",
        Some(Value::Bool(_)) => "boolean",
        Some(Value::Number(_)) => "number",
        Some(Value::String(_)) => "string",
        Some(Value::Array(_)) => "array",
        Some(Value::Object(_)) => "object",
    }
}

fn invalid_type(expected: &str, value: Option<&Value>, path: &[Value]) -> Issue {
    issue("invalid_type", path, format!("Invalid input: expected {expected}, received {}", received(value)), json!({ "expected": expected }))
}

/// A regex given as JavaScript source, compiled for Rust: \0 and \/ are the only spellings that differ here.
pub fn js_regex(source: &str) -> Regex {
    let rust = source.replace(r"\0", r"\x00").replace(r"\/", "/");
    Regex::new(&rust).unwrap_or_else(|e| panic!("regex {source}: {e}"))
}

impl Schema {
    fn new(kind: Kind) -> Self {
        Schema { kind, optional: false, description: None, preprocess: None, refines: Vec::new() }
    }

    pub fn optional(mut self) -> Self {
        self.optional = true;
        self
    }

    pub fn describe(mut self, text: impl Into<String>) -> Self {
        self.description = Some(text.into());
        self
    }

    /// Runs before the checks, on a value that is there.
    pub fn preprocess(mut self, f: impl Fn(Value) -> Value + Send + Sync + 'static) -> Self {
        self.preprocess = Some(Arc::new(f));
        self
    }

    pub fn refine(mut self, check: impl Fn(&Value) -> bool + Send + Sync + 'static, message: impl Into<String>) -> Self {
        self.refines.push((Arc::new(check), message.into()));
        self
    }

    pub fn min(mut self, n: impl Into<f64>) -> Self {
        let n = n.into();
        match &mut self.kind {
            Kind::String { min, .. } => *min = Some(n as usize),
            Kind::Number { min, .. } => *min = Some(n),
            Kind::Array { min, .. } => *min = Some(n as usize),
            _ => panic!("min() on a schema without a length or value"),
        }
        self
    }

    pub fn max(mut self, n: impl Into<f64>) -> Self {
        let n = n.into();
        match &mut self.kind {
            Kind::String { max, .. } => *max = Some(n as usize),
            Kind::Number { max, .. } => *max = Some(n),
            Kind::Array { max, .. } => *max = Some(n as usize),
            _ => panic!("max() on a schema without a length or value"),
        }
        self
    }

    pub fn int(mut self) -> Self {
        if let Kind::Number { integer, .. } = &mut self.kind {
            *integer = Integer::Int;
        }
        self
    }

    /// .regex(/source/, message). The source is JavaScript's.
    pub fn regex(mut self, source: &str, message: &str) -> Self {
        if let Kind::String { patterns, .. } = &mut self.kind {
            patterns.push(Pattern { regex: js_regex(source), source: source.to_string(), message: Some(message.to_string()) });
        }
        self
    }

    /// .regex(/source/) without a message of its own.
    pub fn pattern(mut self, source: &str) -> Self {
        if let Kind::String { patterns, .. } = &mut self.kind {
            patterns.push(Pattern { regex: js_regex(source), source: source.to_string(), message: None });
        }
        self
    }

    /// z.object(...).strict()
    pub fn strict(mut self) -> Self {
        if let Kind::Object { unknown, .. } = &mut self.kind {
            *unknown = Unknown::Strict;
        }
        self
    }

    /// z.object(...).loose()
    pub fn loose(mut self) -> Self {
        if let Kind::Object { unknown, .. } = &mut self.kind {
            *unknown = Unknown::Loose;
        }
        self
    }

    pub fn is_optional(&self) -> bool {
        self.optional
    }

    /// The JSON Schema of this value, as zod 4 writes it for draft-07.
    pub fn json_schema(&self) -> Value {
        let mut out = Map::new();
        // zod writes the description of a wrapper (optional, preprocess) before the rest.
        let desc_first = self.optional || self.preprocess.is_some();
        if desc_first {
            if let Some(d) = &self.description {
                out.insert("description".into(), Value::String(d.clone()));
            }
        }
        match &self.kind {
            Kind::String { min, max, patterns } => {
                out.insert("type".into(), "string".into());
                if let Some(n) = min {
                    out.insert("minLength".into(), Value::from(*n));
                }
                if let Some(n) = max {
                    out.insert("maxLength".into(), Value::from(*n));
                }
                match patterns.len() {
                    0 => {}
                    1 => {
                        out.insert("pattern".into(), Value::String(patterns[0].source.clone()));
                    }
                    _ => {
                        out.insert("allOf".into(), Value::Array(patterns.iter().map(|p| json!({ "pattern": p.source })).collect()));
                    }
                }
            }
            Kind::Number { integer, min, max } => {
                out.insert("type".into(), if *integer == Integer::No { "number" } else { "integer" }.into());
                let (min, max) = if *integer == Integer::Int { (Some(min.unwrap_or(-SAFE_INTEGER).max(-SAFE_INTEGER)), Some(max.unwrap_or(SAFE_INTEGER).min(SAFE_INTEGER))) } else { (*min, *max) };
                if let Some(n) = min {
                    out.insert("minimum".into(), num(n));
                }
                if let Some(n) = max {
                    out.insert("maximum".into(), num(n));
                }
            }
            Kind::Boolean => {
                out.insert("type".into(), "boolean".into());
            }
            Kind::Enum(values) => {
                out.insert("type".into(), "string".into());
                out.insert("enum".into(), Value::Array(values.iter().map(|v| Value::String(v.clone())).collect()));
            }
            Kind::Array { item, min, max } => {
                if let Some(n) = min {
                    out.insert("minItems".into(), Value::from(*n));
                }
                if let Some(n) = max {
                    out.insert("maxItems".into(), Value::from(*n));
                }
                out.insert("type".into(), "array".into());
                out.insert("items".into(), item.json_schema());
            }
            Kind::Object { shape, unknown } => {
                let (properties, required) = shape_schema(shape);
                out.insert("type".into(), "object".into());
                out.insert("properties".into(), Value::Object(properties));
                if !required.is_empty() {
                    out.insert("required".into(), Value::Array(required));
                }
                match unknown {
                    Unknown::Strict => {
                        out.insert("additionalProperties".into(), Value::Bool(false));
                    }
                    Unknown::Loose => {
                        out.insert("additionalProperties".into(), Value::Bool(true));
                    }
                    Unknown::Strip => {}
                }
            }
            Kind::Map { value, .. } => {
                out.insert("type".into(), "object".into());
                out.insert("properties".into(), Value::Object(Map::new()));
                out.insert("additionalProperties".into(), value.json_schema());
            }
            Kind::Union(options) => {
                let simple: Option<Vec<Value>> = options.iter().map(|o| match o.json_schema() {
                    Value::Object(m) if m.len() == 1 => m.get("type").cloned(),
                    _ => None,
                }).collect();
                match simple {
                    Some(types) => {
                        out.insert("type".into(), Value::Array(types));
                    }
                    None => {
                        out.insert("anyOf".into(), Value::Array(options.iter().map(Schema::json_schema).collect()));
                    }
                }
            }
            Kind::Any => {}
        }
        if !desc_first {
            if let Some(d) = &self.description {
                out.insert("description".into(), Value::String(d.clone()));
            }
        }
        Value::Object(out)
    }

    /// Checks a value that is there, and gives it back as zod would: preprocessed, unknown keys of
    /// plain objects dropped.
    pub fn parse(&self, value: Option<&Value>, path: &mut Vec<Value>, issues: &mut Vec<Issue>) -> Option<Value> {
        let value = match value {
            None if self.optional => return None,
            None => {
                // A preprocess sees undefined too, and may turn it into something.
                if let Some(pre) = &self.preprocess {
                    let v = pre(Value::Null);
                    if !v.is_null() {
                        return self.check(v, path, issues);
                    }
                }
                issues.push(invalid_type(self.expected(), None, path));
                return None;
            }
            Some(v) => v.clone(),
        };
        let value = match &self.preprocess {
            Some(pre) => pre(value),
            None => value,
        };
        self.check(value, path, issues)
    }

    fn expected(&self) -> &'static str {
        match &self.kind {
            Kind::String { .. } | Kind::Enum(_) => "string",
            Kind::Number { .. } => "number",
            Kind::Boolean => "boolean",
            Kind::Array { .. } => "array",
            Kind::Object { .. } | Kind::Map { .. } => "object",
            Kind::Union(_) | Kind::Any => "unknown",
        }
    }

    fn check(&self, value: Value, path: &mut Vec<Value>, issues: &mut Vec<Issue>) -> Option<Value> {
        let before = issues.len();
        let out = match &self.kind {
            Kind::Any => Some(value),
            Kind::String { min, max, patterns } => {
                let Value::String(s) = &value else {
                    issues.push(invalid_type("string", Some(&value), path));
                    return None;
                };
                let len = js_len(s);
                if let Some(m) = min {
                    if len < *m {
                        issues.push(issue("too_small", path, format!("Too small: expected string to have >={m} characters"), json!({ "origin": "string", "minimum": m, "inclusive": true })));
                    }
                }
                if let Some(m) = max {
                    if len > *m {
                        issues.push(issue("too_big", path, format!("Too big: expected string to have <={m} characters"), json!({ "origin": "string", "maximum": m, "inclusive": true })));
                    }
                }
                for p in patterns {
                    if !p.regex.is_match(s) {
                        let message = p.message.clone().unwrap_or_else(|| format!("Invalid string: must match pattern /{}/", p.source));
                        issues.push(issue("invalid_format", path, message, json!({ "origin": "string", "format": "regex", "pattern": format!("/{}/", p.source) })));
                    }
                }
                Some(value)
            }
            Kind::Number { integer, min, max } => {
                let Some(n) = value.as_f64() else {
                    issues.push(invalid_type("number", Some(&value), path));
                    return None;
                };
                if *integer == Integer::Int && (n.fract() != 0.0 || n.abs() > SAFE_INTEGER) {
                    issues.push(issue("invalid_type", path, "Invalid input: expected int, received number".into(), json!({ "expected": "int", "format": "safeint" })));
                    return None;
                }
                if let Some(m) = min {
                    if n < *m {
                        issues.push(issue("too_small", path, format!("Too small: expected number to be >={}", js_string(&num(*m))), json!({ "origin": "number", "minimum": num(*m), "inclusive": true })));
                    }
                }
                if let Some(m) = max {
                    if n > *m {
                        issues.push(issue("too_big", path, format!("Too big: expected number to be <={}", js_string(&num(*m))), json!({ "origin": "number", "maximum": num(*m), "inclusive": true })));
                    }
                }
                Some(num(n))
            }
            Kind::Boolean => {
                if !value.is_boolean() {
                    issues.push(invalid_type("boolean", Some(&value), path));
                    return None;
                }
                Some(value)
            }
            Kind::Enum(values) => {
                let ok = matches!(&value, Value::String(s) if values.contains(s));
                if !ok {
                    let shown = values.iter().map(|v| format!("\"{v}\"")).collect::<Vec<_>>().join("|");
                    issues.push(issue("invalid_value", path, format!("Invalid option: expected one of {shown}"), json!({ "values": values })));
                    return None;
                }
                Some(value)
            }
            Kind::Array { item, min, max } => {
                let Value::Array(items) = value else {
                    issues.push(invalid_type("array", Some(&value), path));
                    return None;
                };
                if let Some(m) = min {
                    if items.len() < *m {
                        issues.push(issue("too_small", path, format!("Too small: expected array to have >={m} items"), json!({ "origin": "array", "minimum": m, "inclusive": true })));
                    }
                }
                if let Some(m) = max {
                    if items.len() > *m {
                        issues.push(issue("too_big", path, format!("Too big: expected array to have <={m} items"), json!({ "origin": "array", "maximum": m, "inclusive": true })));
                    }
                }
                let mut out = Vec::with_capacity(items.len());
                for (i, v) in items.iter().enumerate() {
                    path.push(Value::from(i));
                    if let Some(parsed) = item.parse(Some(v), path, issues) {
                        out.push(parsed);
                    }
                    path.pop();
                }
                Some(Value::Array(out))
            }
            Kind::Object { shape, unknown } => {
                let Value::Object(map) = value else {
                    issues.push(invalid_type("object", Some(&value), path));
                    return None;
                };
                Some(Value::Object(parse_shape(shape, *unknown, &map, path, issues)))
            }
            Kind::Map { value: inner, keys } => {
                let Value::Object(map) = value else {
                    issues.push(invalid_type("object", Some(&value), path));
                    return None;
                };
                let mut out = Map::new();
                for (k, v) in &map {
                    path.push(Value::String(k.clone()));
                    if let Some(parsed) = inner.parse(Some(v), path, issues) {
                        out.insert(k.clone(), parsed);
                    }
                    path.pop();
                }
                if let Some(check) = keys {
                    for k in map.keys() {
                        if let Some(message) = check(k) {
                            path.push(Value::String(k.clone()));
                            issues.push(issue("custom", path, message, Value::Null));
                            path.pop();
                        }
                    }
                }
                Some(Value::Object(out))
            }
            Kind::Union(options) => {
                let mut all = Vec::new();
                for option in options {
                    let mut own = Vec::new();
                    if let Some(v) = option.parse(Some(&value), path, &mut own) {
                        if own.is_empty() {
                            return Some(v);
                        }
                    }
                    all.push(Value::Array(own));
                }
                issues.push(issue("invalid_union", path, "Invalid input".into(), json!({ "errors": all })));
                return None;
            }
        };
        if issues.len() == before {
            if let Some(v) = &out {
                for (check, message) in &self.refines {
                    if !check(v) {
                        issues.push(issue("custom", path, message.clone(), Value::Null));
                    }
                }
            }
        }
        out
    }
}

fn shape_schema(shape: &[(String, Schema)]) -> (Map<String, Value>, Vec<Value>) {
    let mut properties = Map::new();
    let mut required = Vec::new();
    for (name, schema) in shape {
        properties.insert(name.clone(), schema.json_schema());
        if !schema.optional {
            required.push(Value::String(name.clone()));
        }
    }
    (properties, required)
}

fn parse_shape(shape: &[(String, Schema)], unknown: Unknown, map: &Map<String, Value>, path: &mut Vec<Value>, issues: &mut Vec<Issue>) -> Map<String, Value> {
    let mut out = Map::new();
    for (name, schema) in shape {
        path.push(Value::String(name.clone()));
        if let Some(v) = schema.parse(map.get(name), path, issues) {
            out.insert(name.clone(), v);
        }
        path.pop();
    }
    let extra: Vec<&String> = map.keys().filter(|k| !shape.iter().any(|(n, _)| n == *k)).collect();
    match unknown {
        Unknown::Strip => {}
        Unknown::Loose => {
            for k in extra {
                out.insert(k.clone(), map[k].clone());
            }
        }
        Unknown::Strict => {
            if !extra.is_empty() {
                let quoted = extra.iter().map(|k| format!("\"{k}\"")).collect::<Vec<_>>().join(", ");
                let message = if extra.len() == 1 { format!("Unrecognized key: {quoted}") } else { format!("Unrecognized keys: {quoted}") };
                issues.push(issue("unrecognized_keys", path, message, json!({ "keys": extra })));
            }
        }
    }
    out
}

/// The input of a tool: a top-level object, strict unless the tool takes extra arguments.
pub fn tool_input_schema(shape: &[(String, Schema)], loose: bool) -> Value {
    let (properties, required) = shape_schema(shape);
    let mut out = Map::new();
    out.insert("type".into(), "object".into());
    out.insert("properties".into(), Value::Object(properties));
    if !required.is_empty() {
        out.insert("required".into(), Value::Array(required));
    }
    out.insert("$schema".into(), "http://json-schema.org/draft-07/schema#".into());
    out.insert("additionalProperties".into(), Value::Bool(loose));
    Value::Object(out)
}

/// Checks the arguments of a tool. Err holds zod's issues.
pub fn parse_tool_args(shape: &[(String, Schema)], loose: bool, args: &Value) -> Result<Map<String, Value>, Vec<Issue>> {
    let mut issues = Vec::new();
    let mut path = Vec::new();
    let Value::Object(map) = args else {
        return Err(vec![invalid_type("object", Some(args), &path)]);
    };
    let out = parse_shape(shape, if loose { Unknown::Loose } else { Unknown::Strict }, map, &mut path, &mut issues);
    if issues.is_empty() { Ok(out) } else { Err(issues) }
}

/// zod's builders.
pub mod z {
    use super::*;

    pub fn string() -> Schema {
        Schema::new(Kind::String { min: None, max: None, patterns: Vec::new() })
    }

    pub fn number() -> Schema {
        Schema::new(Kind::Number { integer: Integer::No, min: None, max: None })
    }

    /// z.number().int()
    pub fn int() -> Schema {
        Schema::new(Kind::Number { integer: Integer::Int, min: None, max: None })
    }

    /// A number refined to whole values, shown as type integer: wholeNumber() of the generated tools.
    pub fn whole() -> Schema {
        Schema::new(Kind::Number { integer: Integer::Whole, min: None, max: None }).refine(|v| v.as_f64().is_some_and(|n| n.fract() == 0.0), "Expected a whole number")
    }

    pub fn boolean() -> Schema {
        Schema::new(Kind::Boolean)
    }

    /// z.enum([...]) keeps its values as the keys of an object, so they come out in the order of
    /// JavaScript keys: array indexes ("2", "1024") first and ascending, then the rest as written.
    pub fn enumeration<S: AsRef<str>>(values: &[S]) -> Schema {
        let is_index = |v: &str| v == "0" || (!v.starts_with('0') && !v.is_empty() && v.len() <= 10 && v.bytes().all(|b| b.is_ascii_digit()) && v.parse::<u64>().is_ok_and(|n| n < u32::MAX as u64));
        let mut indexes: Vec<String> = Vec::new();
        let mut others: Vec<String> = Vec::new();
        for v in values.iter().map(|v| v.as_ref()) {
            let list = if is_index(v) { &mut indexes } else { &mut others };
            if !list.iter().any(|x| x == v) {
                list.push(v.to_string());
            }
        }
        indexes.sort_by_key(|v| v.parse::<u64>().unwrap());
        indexes.extend(others);
        Schema::new(Kind::Enum(indexes))
    }

    pub fn array(item: Schema) -> Schema {
        Schema::new(Kind::Array { item: Box::new(item), min: None, max: None })
    }

    /// z.object(shape): unknown keys are dropped.
    pub fn object(shape: Vec<(&str, Schema)>) -> Schema {
        Schema::new(Kind::Object { shape: shape.into_iter().map(|(k, v)| (k.to_string(), v)).collect(), unknown: Unknown::Strip })
    }

    /// looseObject(shape) of the helpers: additionalProperties true, written out.
    pub fn loose_object(shape: Vec<(&str, Schema)>) -> Schema {
        object(shape).loose()
    }

    /// mapOf(value, keys?) of the helpers: free keys, each value checked.
    pub fn map_of(value: Schema, keys: Option<(&str, &str)>) -> Schema {
        let keys: Option<KeyCheck> = keys.map(|(source, message)| {
            let re = js_regex(source);
            let message = message.to_string();
            Arc::new(move |k: &str| if re.is_match(k) { None } else { Some(format!("{message}: \"{k}\"")) }) as KeyCheck
        });
        Schema::new(Kind::Map { value: Box::new(value), keys })
    }

    pub fn union(options: Vec<Schema>) -> Schema {
        Schema::new(Kind::Union(options))
    }

    pub fn unknown() -> Schema {
        Schema::new(Kind::Any)
    }
}

/// A tool's input, in the order the properties are listed.
pub type Shape = Vec<(String, Schema)>;

/// shape!["name" => schema, ...]
#[macro_export]
macro_rules! shape {
    ($($key:expr => $value:expr),* $(,)?) => {{
        #[allow(unused_mut)]
        let mut v: $crate::schema::Shape = Vec::new();
        $( v.push(($key.to_string(), $value)); )*
        v
    }};
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schema_and_checks() {
        let shape: Shape = vec![
            ("node".into(), z::string().max(64).regex(r"^[a-zA-Z0-9][a-zA-Z0-9.-]*$", "Expected a node name").optional().describe("The node.")),
            ("vmid".into(), z::int().min(1).max(999_999_999).describe("The guest id.")),
            ("tags".into(), z::array(z::string()).min(1).optional()),
        ];
        let s = tool_input_schema(&shape, false);
        assert_eq!(s["properties"]["vmid"], json!({"type": "integer", "minimum": 1, "maximum": 999999999, "description": "The guest id."}));
        assert_eq!(s["required"], json!(["vmid"]));
        let ok = parse_tool_args(&shape, false, &json!({"vmid": 100})).unwrap();
        assert_eq!(ok["vmid"], json!(100));
        let err = parse_tool_args(&shape, false, &json!({"vmid": 1.5, "x": 1, "node": "-bad"})).unwrap_err();
        assert_eq!(err.len(), 3);
        assert_eq!(err[0]["message"], "Expected a node name");
        assert_eq!(err[2]["code"], "unrecognized_keys");
        let p = z::int().min(0);
        assert_eq!(p.json_schema(), json!({"type": "integer", "minimum": 0, "maximum": 9007199254740991.0_f64 as i64}));
        let u = z::map_of(z::union(vec![z::string(), z::number()]), None);
        assert_eq!(u.json_schema(), json!({"type": "object", "properties": {}, "additionalProperties": {"type": ["string", "number"]}}));
    }
}
