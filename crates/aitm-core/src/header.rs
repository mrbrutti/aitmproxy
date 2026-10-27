//! `HeaderMap`: an ordered, case-insensitive header multimap.
//!
//! HTTP headers are case-insensitive by name but order- and duplicate-sensitive
//! on the wire (`Set-Cookie` may repeat, and some servers care about ordering).
//! This keeps insertion order and every duplicate, matching names ASCII-case
//! insensitively.
//!
//! Names and values are validated with [`HeaderMap::try_set`] so a value taken
//! from a command caller can never smuggle a line break onto the wire (CRLF
//! injection / request or response splitting). The infallible [`HeaderMap::set`]
//! is for trusted, already-valid internal callers; the wire encoder validates
//! again as a last line of defence.

use std::fmt;

/// Ordered, case-insensitive header collection that preserves duplicates and
/// insertion order.
#[derive(Debug, Clone, Default)]
pub struct HeaderMap(Vec<(String, String)>);

/// A header name or value that cannot go on the wire safely.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HeaderError {
    /// The name is empty or holds a character outside the RFC 7230 token set.
    InvalidName(String),
    /// The value holds a control character (`\r`, `\n`, `\0`, …) or has
    /// surrounding whitespace.
    InvalidValue(String),
}

impl fmt::Display for HeaderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HeaderError::InvalidName(name) => write!(f, "invalid header name {name:?}"),
            HeaderError::InvalidValue(value) => write!(f, "invalid header value {value:?}"),
        }
    }
}

impl std::error::Error for HeaderError {}

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

    /// Append a header from a **trusted** source, preserving order and keeping
    /// any existing entry with the same name (multimap semantics). An invalid
    /// name or value is dropped rather than put on the wire; untrusted input must
    /// go through [`HeaderMap::try_set`], which reports the error.
    pub fn set(&mut self, name: &str, value: &str) {
        let _ = self.try_set(name, value);
    }

    /// Append a header, rejecting a name or value that would be unsafe on the
    /// wire (control characters, surrounding whitespace, a non-token name).
    pub fn try_set(&mut self, name: &str, value: &str) -> Result<(), HeaderError> {
        if !is_valid_name(name) {
            return Err(HeaderError::InvalidName(name.to_string()));
        }
        if !is_valid_value(value) {
            return Err(HeaderError::InvalidValue(value.to_string()));
        }
        self.0.push((name.to_string(), value.to_string()));
        Ok(())
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

/// A valid RFC 7230 header name: non-empty and every byte a `token` char.
pub fn is_valid_name(name: &str) -> bool {
    !name.is_empty() && name.bytes().all(is_tchar)
}

/// A valid header value: no control bytes (notably `\r`, `\n`, `\0`) and no
/// leading/trailing whitespace that a parser might fold.
pub fn is_valid_value(value: &str) -> bool {
    if value.starts_with([' ', '\t']) || value.ends_with([' ', '\t']) {
        return false;
    }
    value
        .bytes()
        .all(|b| b == b'\t' || (b' '..=b'~').contains(&b) || b >= 0x80)
}

/// RFC 7230 `tchar`: the characters allowed in a header field name.
fn is_tchar(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_crlf_injection() {
        let mut h = HeaderMap::new();
        assert!(h.try_set("X-Ok", "value").is_ok());
        assert!(matches!(
            h.try_set("X-Evil", "a\r\nInjected: 1"),
            Err(HeaderError::InvalidValue(_))
        ));
        assert!(matches!(
            h.try_set("X-Evil", "a\nInjected: 1"),
            Err(HeaderError::InvalidValue(_))
        ));
        assert!(matches!(
            h.try_set("Bad Name", "v"),
            Err(HeaderError::InvalidName(_))
        ));
        assert!(matches!(
            h.try_set("X", " leading"),
            Err(HeaderError::InvalidValue(_))
        ));
        // Only the one valid header made it in.
        assert_eq!(h.len(), 1);
        assert_eq!(h.get("x-ok"), Some("value"));
        // The infallible path drops an invalid header instead of corrupting the wire.
        h.set("X-Evil", "a\r\nInjected: 1");
        assert_eq!(h.len(), 1);
    }
}
