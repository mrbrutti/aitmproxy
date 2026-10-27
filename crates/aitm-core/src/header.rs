//! `HeaderMap`: an ordered, case-insensitive header multimap.
//!
//! HTTP headers are case-insensitive by name but order- and duplicate-sensitive
//! on the wire (`Set-Cookie` may repeat, and some servers care about ordering).
//! This keeps insertion order and every duplicate, matching names ASCII-case
//! insensitively.

/// Ordered, case-insensitive header collection that preserves duplicates and
/// insertion order.
#[derive(Debug, Clone, Default)]
pub struct HeaderMap(Vec<(String, String)>);

impl HeaderMap {
    /// An empty map.
    pub fn new() -> Self {
        Self(Vec::new())
    }

    /// The first value whose name matches `name` case-insensitively.
    pub fn get(&self, name: &str) -> Option<&str> {
        self.0
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    /// Append a header. Preserves order and keeps any existing entries with the
    /// same name (multimap semantics), so repeated headers survive intact.
    pub fn set(&mut self, name: &str, value: &str) {
        self.0.push((name.to_string(), value.to_string()));
    }

    /// Remove every header whose name matches `name` case-insensitively.
    pub fn remove(&mut self, name: &str) {
        self.0.retain(|(k, _)| !k.eq_ignore_ascii_case(name));
    }

    /// Whether any header matches `name` case-insensitively.
    pub fn has(&self, name: &str) -> bool {
        self.0.iter().any(|(k, _)| k.eq_ignore_ascii_case(name))
    }

    /// Iterate over `(name, value)` pairs in insertion order.
    pub fn iter(&self) -> impl Iterator<Item = (&str, &str)> {
        self.0.iter().map(|(k, v)| (k.as_str(), v.as_str()))
    }

    /// Number of header entries (counting duplicates).
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether the map holds no headers.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}
