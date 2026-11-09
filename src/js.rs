//! What the TypeScript version got from JavaScript itself: String(), Number(), truthiness of
//! JSON values, and numbers that print as JavaScript prints them.

use serde_json::{Map, Number, Value};

pub type Row = Map<String, Value>;

/// A number as a JSON value, written the way JSON.stringify writes it: 5, not 5.0.
pub fn num(n: f64) -> Value {
    if n.is_finite() && n.fract() == 0.0 && n.abs() < 9.007_199_254_740_992e15 {
        Value::from(n as i64)
    } else {
        Number::from_f64(n).map(Value::Number).unwrap_or(Value::Null)
    }
}

/// The value of a JSON number as f64.
pub fn as_f64(v: &Value) -> Option<f64> {
    match v {
        Value::Number(n) => n.as_f64(),
        _ => None,
    }
}

/// num() of the TypeScript workflows: a finite number, or a string that holds one.
pub fn number(v: Option<&Value>) -> Option<f64> {
    match v? {
        Value::Number(n) => n.as_f64().filter(|f| f.is_finite()),
        Value::String(s) if !s.trim().is_empty() => js_number_str(s).filter(|f| f.is_finite()),
        _ => None,
    }
}

/// Number(text) for a string: NaN is None.
pub fn js_number_str(s: &str) -> Option<f64> {
    let t = s.trim();
    if t.is_empty() {
        return Some(0.0);
    }
    if let Some(hex) = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
        return u64::from_str_radix(hex, 16).ok().map(|n| n as f64);
    }
    if t == "Infinity" || t == "+Infinity" {
        return Some(f64::INFINITY);
    }
    if t == "-Infinity" {
        return Some(f64::NEG_INFINITY);
    }
    // Rust accepts "inf" and "nan", JavaScript does not.
    if t.chars().any(|c| c.is_ascii_alphabetic() && c != 'e' && c != 'E') {
        return None;
    }
    t.parse::<f64>().ok()
}

/// Number(value) for any JSON value. None is NaN.
pub fn js_number(v: &Value) -> Option<f64> {
    match v {
        Value::Number(n) => n.as_f64(),
        Value::String(s) => js_number_str(s),
        Value::Bool(b) => Some(if *b { 1.0 } else { 0.0 }),
        Value::Null => Some(0.0),
        Value::Array(a) if a.is_empty() => Some(0.0),
        Value::Array(a) if a.len() == 1 => js_number(&a[0]),
        _ => None,
    }
}

/// Whether Number(value) is an integer: Number.isInteger(Number(v)).
pub fn js_integer(v: &Value) -> Option<i64> {
    js_number(v).filter(|f| f.is_finite() && f.fract() == 0.0).map(|f| f as i64)
}

/// The text JavaScript writes for a number.
pub fn number_text(n: f64) -> String {
    if n.is_nan() {
        return "NaN".into();
    }
    if n.is_infinite() {
        return if n > 0.0 { "Infinity".into() } else { "-Infinity".into() };
    }
    if n.fract() == 0.0 && n.abs() < 1e21 {
        return format!("{}", n as i128);
    }
    let text = format!("{n}");
    text
}

/// String(value), as JavaScript would write it.
pub fn js_string(v: &Value) -> String {
    match v {
        Value::Null => "null".into(),
        Value::Bool(b) => b.to_string(),
        Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                i.to_string()
            } else if let Some(u) = n.as_u64() {
                u.to_string()
            } else {
                number_text(n.as_f64().unwrap_or(f64::NAN))
            }
        }
        Value::String(s) => s.clone(),
        Value::Array(items) => items.iter().map(|i| if i.is_null() { String::new() } else { js_string(i) }).collect::<Vec<_>>().join(","),
        Value::Object(_) => "[object Object]".into(),
    }
}

/// String(value) where value may be absent: "undefined".
pub fn js_string_opt(v: Option<&Value>) -> String {
    v.map(js_string).unwrap_or_else(|| "undefined".into())
}

/// A non-empty string, as str() of the workflows.
pub fn nonempty_str(v: Option<&Value>) -> Option<&str> {
    match v {
        Some(Value::String(s)) if !s.is_empty() => Some(s.as_str()),
        _ => None,
    }
}

/// JavaScript truthiness of a JSON value.
pub fn truthy_js(v: Option<&Value>) -> bool {
    match v {
        None | Some(Value::Null) => false,
        Some(Value::Bool(b)) => *b,
        Some(Value::Number(n)) => n.as_f64().map(|f| f != 0.0 && !f.is_nan()).unwrap_or(false),
        Some(Value::String(s)) => !s.is_empty(),
        Some(_) => true,
    }
}

pub fn is_object(v: &Value) -> bool {
    v.is_object()
}

/// Length as JavaScript counts it: UTF-16 code units.
pub fn js_len(s: &str) -> usize {
    s.encode_utf16().count()
}

/// text.slice(0, n) with n in UTF-16 units. A surrogate pair is never split.
pub fn js_slice_start(s: &str, n: usize) -> &str {
    let mut units = 0;
    for (i, c) in s.char_indices() {
        let next = units + c.len_utf16();
        if next > n {
            return &s[..i];
        }
        units = next;
    }
    s
}

/// text.slice(-n): the last n UTF-16 units.
pub fn js_slice_end(s: &str, n: usize) -> &str {
    let total = js_len(s);
    if total <= n {
        return s;
    }
    let skip = total - n;
    let mut units = 0;
    for (i, c) in s.char_indices() {
        if units >= skip {
            return &s[i..];
        }
        units += c.len_utf16();
    }
    ""
}

/// Numbers that came back as 1.0 print as 1, as they did in JavaScript.
pub fn normalize_numbers(v: &mut Value) {
    match v {
        Value::Number(n) => {
            if n.is_f64() {
                if let Some(f) = n.as_f64() {
                    *v = num(f);
                }
            }
        }
        Value::Array(items) => items.iter_mut().for_each(normalize_numbers),
        Value::Object(map) => map.values_mut().for_each(normalize_numbers),
        _ => {}
    }
}

/// encodeURIComponent.
pub fn encode_uri_component(s: &str) -> String {
    const KEEP: &percent_encoding::AsciiSet = &percent_encoding::NON_ALPHANUMERIC.remove(b'-').remove(b'_').remove(b'.').remove(b'!').remove(b'~').remove(b'*').remove(b'\'').remove(b'(').remove(b')');
    percent_encoding::utf8_percent_encode(s, KEEP).to_string()
}

/// The rows of an array value that are objects.
pub fn rows_of(v: Option<&Value>) -> Vec<Row> {
    match v {
        Some(Value::Array(items)) => items.iter().filter_map(|i| i.as_object().cloned()).collect(),
        _ => Vec::new(),
    }
}

/// new Date(ms).toISOString().
pub fn iso_from_millis(ms: i64) -> String {
    match chrono::DateTime::from_timestamp_millis(ms) {
        Some(t) => t.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string(),
        None => "Invalid Date".into(),
    }
}

pub fn now_millis() -> i64 {
    chrono::Utc::now().timestamp_millis()
}

pub fn now_iso() -> String {
    iso_from_millis(now_millis())
}

/// Math.round, which rounds .5 up rather than away from zero.
pub fn js_round(x: f64) -> f64 {
    (x + 0.5).floor()
}

/// A JSON object from pairs, leaving out the None values.
#[macro_export]
macro_rules! obj {
    ($($key:expr => $value:expr),* $(,)?) => {{
        #[allow(unused_mut)]
        let mut map = serde_json::Map::new();
        $( $crate::js::put(&mut map, $key, $value); )*
        map
    }};
}

/// Puts a value in a map, unless it is an absent Option.
pub fn put(map: &mut Row, key: &str, value: impl IntoMaybeValue) {
    if let Some(v) = value.into_maybe_value() {
        map.insert(key.to_string(), v);
    }
}

pub trait IntoMaybeValue {
    fn into_maybe_value(self) -> Option<Value>;
}

impl IntoMaybeValue for Value {
    fn into_maybe_value(self) -> Option<Value> {
        Some(self)
    }
}

impl<T: Into<Value>> IntoMaybeValue for Option<T> {
    fn into_maybe_value(self) -> Option<Value> {
        self.map(Into::into)
    }
}

macro_rules! into_value {
    ($($t:ty),*) => { $( impl IntoMaybeValue for $t { fn into_maybe_value(self) -> Option<Value> { Some(Value::from(self)) } } )* };
}
into_value!(bool, i32, i64, u32, u64, usize, f64, String, &str, Row, Vec<Value>);

impl IntoMaybeValue for &String {
    fn into_maybe_value(self) -> Option<Value> {
        Some(Value::String(self.clone()))
    }
}

impl IntoMaybeValue for Vec<String> {
    fn into_maybe_value(self) -> Option<Value> {
        Some(Value::Array(self.into_iter().map(Value::String).collect()))
    }
}

impl IntoMaybeValue for &Value {
    fn into_maybe_value(self) -> Option<Value> {
        Some(self.clone())
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strings_like_javascript() {
        assert_eq!(js_string(&Value::from(5)), "5");
        assert_eq!(js_string(&num(2.5)), "2.5");
        assert_eq!(js_string(&serde_json::json!([1, "a", null])), "1,a,");
        assert_eq!(js_number_str(" 12 "), Some(12.0));
        assert_eq!(js_number_str("abc"), None);
        assert_eq!(js_number_str(""), Some(0.0));
        assert_eq!(num(5.0).to_string(), "5");
        assert_eq!(js_slice_start("héllo", 2), "hé");
        assert_eq!(js_slice_end("abcdef", 2), "ef");
        assert_eq!(encode_uri_component("a b/c:d"), "a%20b%2Fc%3Ad");
    }
}
