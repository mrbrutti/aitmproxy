//! `Authority`: one parsed `host[:port]` shared by every component that keys on
//! a target — the scope guard, the flow store, the protocol modules, the PoC
//! runner and templater — so IPv6 brackets, default ports and case fold the same
//! way everywhere instead of in five divergent `rsplit_once(':')`s.

use std::fmt;
use std::net::IpAddr;
use std::str::FromStr;

/// A target host and port. `host` is lowercase, with no IPv6 brackets.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Authority {
    pub host: String,
    pub port: u16,
}

/// Why an authority string was rejected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthorityError {
    Empty,
    MissingPort(String),
    InvalidPort(String),
    UnterminatedIpv6(String),
    InvalidHost(String),
}

impl fmt::Display for AuthorityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AuthorityError::Empty => write!(f, "empty authority"),
            AuthorityError::MissingPort(a) => write!(f, "authority {a:?} has no port"),
            AuthorityError::InvalidPort(a) => write!(f, "authority {a:?} has an invalid port"),
            AuthorityError::UnterminatedIpv6(a) => {
                write!(f, "authority {a:?} has an unterminated IPv6 literal")
            }
            AuthorityError::InvalidHost(a) => write!(f, "authority {a:?} has an invalid host"),
        }
    }
}

impl std::error::Error for AuthorityError {}

impl Authority {
    /// Build from already-split parts (host is normalised).
    pub fn new(host: &str, port: u16) -> Self {
        Self {
            host: normalise_host(host),
            port,
        }
    }

    /// The conventional port for a URL scheme (`http` → 80, `https`/`wss` → 443).
    pub fn default_port(scheme: &str) -> u16 {
        if scheme.eq_ignore_ascii_case("https") || scheme.eq_ignore_ascii_case("wss") {
            443
        } else {
            80
        }
    }

    /// Parse `host[:port]`, using `default_port` when the port is absent.
    pub fn parse_with_default(s: &str, default_port: u16) -> Result<Self, AuthorityError> {
        let (host, port) = split(s)?;
        let port = match port {
            Some(p) => p
                .parse::<u16>()
                .map_err(|_| AuthorityError::InvalidPort(s.to_string()))?,
            None => default_port,
        };
        // No delimiter, no space and no ASCII control byte (which includes the
        // `\t\r\n\0` family): an authority is echoed into log and error text.
        if host.is_empty()
            || host
                .chars()
                .any(|c| c == '/' || c == ' ' || c.is_ascii_control())
        {
            return Err(AuthorityError::InvalidHost(s.to_string()));
        }
        Ok(Self::new(&host, port))
    }

    /// The host as an IP literal, if it is one.
    pub fn ip(&self) -> Option<IpAddr> {
        self.host.parse().ok()
    }

    /// Whether `entry` (a scope entry: `host`, `host:port`, or `*.wildcard`)
    /// covers this authority. A portless entry covers every port of its host.
    pub fn matches_scope_entry(&self, entry: &str) -> bool {
        let entry = entry.trim().to_ascii_lowercase();
        if let Some(suffix) = entry.strip_prefix("*.") {
            return self.host == suffix || self.host.ends_with(&format!(".{suffix}"));
        }
        match Authority::parse_with_default(&entry, 0) {
            Ok(e) if e.port == 0 => e.host == self.host,
            Ok(e) => e.host == self.host && e.port == self.port,
            Err(_) => false,
        }
    }

    /// Whether `entry` names this authority *exactly* (`host` or `host:port`,
    /// no wildcard) — the deliberate escape hatch the SSRF guard honours.
    pub fn matches_scope_entry_exactly(&self, entry: &str) -> bool {
        !entry.trim_start().starts_with("*.") && self.matches_scope_entry(entry)
    }
}

impl FromStr for Authority {
    type Err = AuthorityError;

    /// Parse `host:port`; the port is required.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (_, port) = split(s)?;
        if port.is_none() {
            return Err(AuthorityError::MissingPort(s.to_string()));
        }
        Self::parse_with_default(s, 0)
    }
}

impl fmt::Display for Authority {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.host.contains(':') {
            write!(f, "[{}]:{}", self.host, self.port)
        } else {
            write!(f, "{}:{}", self.host, self.port)
        }
    }
}

/// Split `host[:port]` / `[v6][:port]` into the host text and the optional port text.
fn split(s: &str) -> Result<(String, Option<String>), AuthorityError> {
    let s = s.trim();
    if s.is_empty() {
        return Err(AuthorityError::Empty);
    }
    if let Some(rest) = s.strip_prefix('[') {
        let (host, after) = rest
            .split_once(']')
            .ok_or_else(|| AuthorityError::UnterminatedIpv6(s.to_string()))?;
        return match after {
            "" => Ok((host.to_string(), None)),
            p if p.starts_with(':') => Ok((host.to_string(), Some(p[1..].to_string()))),
            _ => Err(AuthorityError::InvalidPort(s.to_string())),
        };
    }
    match s.rsplit_once(':') {
        // A bare IPv6 literal without brackets has several colons: no port.
        Some((host, _)) if host.contains(':') => Ok((s.to_string(), None)),
        Some((host, port)) => Ok((host.to_string(), Some(port.to_string()))),
        None => Ok((s.to_string(), None)),
    }
}

fn normalise_host(host: &str) -> String {
    host.trim()
        .trim_start_matches('[')
        .trim_end_matches(']')
        .to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_host_port_and_defaults() {
        assert_eq!(
            Authority::parse_with_default("Example.test:8443", 80).unwrap(),
            Authority::new("example.test", 8443)
        );
        assert_eq!(
            Authority::parse_with_default("example.test", 443).unwrap(),
            Authority::new("example.test", 443)
        );
        assert_eq!(
            Authority::parse_with_default("[::1]:3000", 80).unwrap(),
            Authority::new("::1", 3000)
        );
        assert_eq!(
            Authority::parse_with_default("::1", 80).unwrap(),
            Authority::new("::1", 80)
        );
        assert_eq!(Authority::new("::1", 3000).to_string(), "[::1]:3000");
        assert_eq!(
            "ex.test".parse::<Authority>(),
            Err(AuthorityError::MissingPort("ex.test".into()))
        );
        assert!(Authority::parse_with_default("ex.test:x", 80).is_err());
        assert!(Authority::parse_with_default("", 80).is_err());
    }

    /// Panel S4: a CONNECT authority is echoed into log and error text, so no
    /// ASCII control byte (a terminal escape, a bell, a DEL) may survive parsing —
    /// not only the whitespace family rejected before. Valid shapes are unchanged.
    #[test]
    fn rejects_ascii_control_characters_in_the_host() {
        assert_eq!(
            Authority::parse_with_default("\x1b[2Jevil.example:443", 443),
            Err(AuthorityError::InvalidHost(
                "\x1b[2Jevil.example:443".into()
            ))
        );
        for c in [
            '\x01', '\x07', '\x08', '\x0b', '\x0c', '\x1b', '\x7f', '\0', '\r', '\n', '\t',
        ] {
            let s = format!("evil{c}example.test:443");
            assert_eq!(
                Authority::parse_with_default(&s, 443),
                Err(AuthorityError::InvalidHost(s.clone())),
                "{c:?} inside the host"
            );
            assert_eq!(
                s.parse::<Authority>(),
                Err(AuthorityError::InvalidHost(s.clone())),
                "{c:?} inside the host (FromStr)"
            );
            let bracketed = format!("[::{c}1]:443");
            assert_eq!(
                Authority::parse_with_default(&bracketed, 443),
                Err(AuthorityError::InvalidHost(bracketed.clone())),
                "{c:?} inside an IPv6 literal"
            );
        }
        // The valid shapes are unchanged.
        assert_eq!(
            Authority::parse_with_default("evil.example:443", 443).unwrap(),
            Authority::new("evil.example", 443)
        );
        assert_eq!(
            Authority::parse_with_default("[::1]:8443", 443).unwrap(),
            Authority::new("::1", 8443)
        );
        assert_eq!(
            Authority::parse_with_default("xn--bcher-kva.example", 443).unwrap(),
            Authority::new("xn--bcher-kva.example", 443)
        );
        assert_eq!(
            Authority::parse_with_default("  padded.example:80  ", 443).unwrap(),
            Authority::new("padded.example", 80),
            "surrounding whitespace is still trimmed, not rejected"
        );
    }

    /// Panel S4, the IPv6 and port corners (Tester addition): a control byte
    /// inside a bracketed literal, between the bracket and the port, inside the
    /// port, or inside an unbracketed literal is rejected, each with the error
    /// the shape calls for; and the error text names the raw input Debug-escaped,
    /// so even the message carries no raw control byte.
    #[test]
    fn rejects_control_bytes_in_every_part_of_an_ipv6_authority() {
        for c in ['\x1b', '\x07', '\0', '\x7f', '\r', '\n'] {
            let inside = format!("[2001:db8::{c}1]:8443");
            assert_eq!(
                Authority::parse_with_default(&inside, 443),
                Err(AuthorityError::InvalidHost(inside.clone())),
                "{c:?} inside the literal"
            );
            let between = format!("[::1]{c}:8443");
            assert_eq!(
                Authority::parse_with_default(&between, 443),
                Err(AuthorityError::InvalidPort(between.clone())),
                "{c:?} between the bracket and the port"
            );
            let in_port = format!("[::1]:84{c}43");
            assert_eq!(
                Authority::parse_with_default(&in_port, 443),
                Err(AuthorityError::InvalidPort(in_port.clone())),
                "{c:?} inside the port"
            );
            let bare = format!("2001:db8::{c}1");
            assert_eq!(
                Authority::parse_with_default(&bare, 443),
                Err(AuthorityError::InvalidHost(bare.clone())),
                "{c:?} inside an unbracketed literal"
            );
            for s in [&inside, &between, &in_port, &bare] {
                let text = Authority::parse_with_default(s, 443)
                    .unwrap_err()
                    .to_string();
                assert!(
                    !text.contains(c),
                    "raw {c:?} in the error text for {s:?}: {text:?}"
                );
            }
        }
        // The valid literal beside them is unchanged.
        assert_eq!(
            Authority::parse_with_default("[2001:db8::1]:8443", 443).unwrap(),
            Authority::new("2001:db8::1", 8443)
        );
    }

    #[test]
    fn scope_entry_matching() {
        let a = Authority::new("127.0.0.1", 3000);
        assert!(a.matches_scope_entry("127.0.0.1"));
        assert!(a.matches_scope_entry("127.0.0.1:3000"));
        assert!(!a.matches_scope_entry("127.0.0.1:3001"));
        let b = Authority::new("api.ex.test", 443);
        assert!(b.matches_scope_entry("*.ex.test"));
        assert!(!b.matches_scope_entry_exactly("*.ex.test"));
        assert!(b.matches_scope_entry_exactly("API.ex.test"));
        assert!(!Authority::new("ex.test.evil", 443).matches_scope_entry("*.ex.test"));
    }
}
