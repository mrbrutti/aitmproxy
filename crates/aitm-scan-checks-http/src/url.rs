//! One URL authority parser for the checks that need one.
//!
//! Two checks read an authority out of a URL for two different reasons —
//! `open-redirect` asks "where would a browser go?", the h2 checks ask "where
//! may I dial?" — and both used to carry their own parser. Two parsers are two
//! chances to disagree about a userinfo, a bracketed IPv6 literal or a
//! lower-case host, and the h2 one decides whether a raw socket is opened, so
//! this is the single implementation both call (quality review Q-M3).
//!
//! The parsing rules here are deliberately narrow, because every caller is a
//! security decision and not a URL library:
//!
//! - either `scheme://authority…` with an ASCII scheme, or the scheme-relative
//!   `//authority…`; a relative reference has no authority and yields `None`;
//! - userinfo (everything before the last `@`) is dropped: it is credential
//!   material, and `https://target.example@canary/` goes to the canary;
//! - the host is lower-cased and an IPv6 literal loses its brackets in
//!   [`Authority::host`] and gets them back in [`Authority::host_literal`];
//! - a port that is not a number makes the whole URL unusable, rather than
//!   being quietly ignored;
//! - a host with anything but ASCII letters, digits, `.`, `-`, `_` or (for an
//!   IPv6 literal) `:` is unusable.
//!
//! [`Authority::origin_key`] is the **canonical** form: lower-case host, the
//! scheme's default port filled in, one string. Anything that compares two
//! origins — the h2 checks' profile gate and their once-per-authority guard —
//! compares that, so `https://origin.test` and `https://ORIGIN.test:443` are
//! one origin and are never both probed.

use aitm_core::Authority as CoreAuthority;

/// The authority of a URL, parsed once.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Authority {
    /// The lower-case scheme, or `None` for a scheme-relative URL (`//host/`).
    pub scheme: Option<String>,
    /// The lower-case host, without IPv6 brackets.
    pub host: String,
    /// The port **as written**, or `None` when the URL did not carry one.
    pub port: Option<u16>,
}

impl Authority {
    /// The host as it is written in a URL: an IPv6 literal in brackets, any
    /// other host as it stands.
    pub(crate) fn host_literal(&self) -> String {
        if self.host.contains(':') {
            format!("[{}]", self.host)
        } else {
            self.host.clone()
        }
    }

    /// `host[:port]`, with the port only when the URL carried one — the form a
    /// client puts in a `Host` header or an `:authority` pseudo-header, where
    /// the scheme's default port is conventionally left out.
    pub(crate) fn as_written(&self) -> String {
        match self.port {
            Some(port) => format!("{}:{port}", self.host_literal()),
            None => self.host_literal(),
        }
    }

    /// The canonical origin: `scheme://host:port` with the scheme's default
    /// port filled in, or `None` for a scheme-relative URL (which names no
    /// origin of its own).
    ///
    /// This is the only form two origins are ever compared in.
    pub(crate) fn origin_key(&self) -> Option<String> {
        let scheme = self.scheme.as_ref()?;
        let port = self
            .port
            .unwrap_or_else(|| CoreAuthority::default_port(scheme));
        Some(format!(
            "{scheme}://{}",
            CoreAuthority::new(&self.host, port)
        ))
    }
}

/// The authority of `url`, or `None` when it has none that can be used.
pub(crate) fn authority_of(url: &str) -> Option<Authority> {
    split_url(url).map(|(authority, _)| authority)
}

/// The authority of `url` and whatever followed it (path, query, fragment).
pub(crate) fn split_url(url: &str) -> Option<(Authority, &str)> {
    let url = url.trim();
    let (scheme, after) = match url.find("://") {
        Some(at)
            if at > 0
                && url[..at]
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.')) =>
        {
            (Some(url[..at].to_ascii_lowercase()), &url[at + 3..])
        }
        // No scheme: only the scheme-relative form has an authority. Three or
        // more slashes leave an empty authority, which is rejected below.
        _ => (None, url.strip_prefix("//")?),
    };

    let end = after.find(['/', '?', '#']).unwrap_or(after.len());
    let (authority, rest) = after.split_at(end);
    // Userinfo is credential material; it names no host and never travels.
    let authority = authority.rsplit_once('@').map_or(authority, |(_, h)| h);
    if authority.is_empty() {
        return None;
    }

    // Port 0 is the core parser's "no port was written" sentinel, the same one
    // `Authority::matches_scope_entry` uses; a URL that really writes `:0`
    // names no port a client could dial.
    let parsed = CoreAuthority::parse_with_default(authority, 0).ok()?;
    if !host_is_usable(&parsed.host) {
        return None;
    }
    Some((
        Authority {
            scheme,
            host: parsed.host,
            port: (parsed.port != 0).then_some(parsed.port),
        },
        rest,
    ))
}

/// Whether `host` is something a client could dial: non-empty ASCII letters,
/// digits, `.`, `-`, `_`, or the colons of an IPv6 literal.
fn host_is_usable(host: &str) -> bool {
    !host.is_empty()
        && host
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_' | b':'))
}

#[cfg(test)]
mod tests {
    use super::{authority_of, split_url, Authority};

    fn parts(url: &str) -> Option<(Option<String>, String, Option<u16>)> {
        authority_of(url).map(|a| (a.scheme, a.host, a.port))
    }

    #[test]
    fn an_absolute_url_splits_into_scheme_host_and_port() {
        assert_eq!(
            parts("https://Origin.TEST:8443/a/b?q=1#f"),
            Some((
                Some("https".to_string()),
                "origin.test".to_string(),
                Some(8443)
            ))
        );
        assert_eq!(
            parts("http://origin.test"),
            Some((Some("http".to_string()), "origin.test".to_string(), None))
        );
    }

    #[test]
    fn a_scheme_relative_url_has_an_authority_and_no_scheme() {
        assert_eq!(
            parts("//AITM-Redirect.Invalid/next"),
            Some((None, "aitm-redirect.invalid".to_string(), None))
        );
    }

    #[test]
    fn userinfo_is_dropped_and_ipv6_keeps_its_brackets() {
        assert_eq!(
            parts("http://user:secret@origin.test/p"),
            Some((Some("http".to_string()), "origin.test".to_string(), None))
        );
        let v6 = authority_of("https://[::1]:9443/x").expect("an IPv6 literal parses");
        assert_eq!(v6.host, "::1");
        assert_eq!(v6.host_literal(), "[::1]");
        assert_eq!(v6.as_written(), "[::1]:9443");
        assert_eq!(v6.origin_key().as_deref(), Some("https://[::1]:9443"));
    }

    #[test]
    fn a_url_with_no_usable_authority_is_none() {
        for url in [
            "",
            "/home",
            "home?next=1",
            "https:///x",
            "origin.test/x",
            "///",
            "https://exa mple.test/",
            "https://origin.test:https/x",
        ] {
            assert_eq!(parts(url), None, "{url}");
        }
    }

    /// The canonical form fills in the scheme's default port, so the three
    /// spellings of one origin are one string. This is what the h2 checks'
    /// profile gate and guard key compare.
    #[test]
    fn the_origin_key_normalises_the_default_port_and_the_case() {
        for url in [
            "https://origin.test/x",
            "https://ORIGIN.test:443/y",
            "https://origin.test:443",
        ] {
            assert_eq!(
                authority_of(url).and_then(|a| a.origin_key()).as_deref(),
                Some("https://origin.test:443"),
                "{url}"
            );
        }
        assert_eq!(
            authority_of("http://origin.test/x")
                .and_then(|a| a.origin_key())
                .as_deref(),
            Some("http://origin.test:80")
        );
        // A scheme-relative URL names no origin.
        assert_eq!(
            authority_of("//origin.test/x").and_then(|a| a.origin_key()),
            None
        );
    }

    /// The wire form keeps the port exactly as the URL wrote it, so an
    /// `:authority` pseudo-header stays what a client would send.
    #[test]
    fn the_written_form_keeps_the_port_the_url_carried() {
        assert_eq!(
            authority_of("https://origin.test/x").map(|a| a.as_written()),
            Some("origin.test".to_string())
        );
        assert_eq!(
            authority_of("https://origin.test:8443/x").map(|a| a.as_written()),
            Some("origin.test:8443".to_string())
        );
    }

    #[test]
    fn split_url_hands_back_what_followed_the_authority() {
        let (authority, rest) = split_url("https://origin.test/a/b?q=1#f").expect("parses");
        assert_eq!(authority.host, "origin.test");
        assert_eq!(rest, "/a/b?q=1#f");

        let (_, none) = split_url("https://origin.test").expect("parses");
        assert_eq!(none, "");
    }

    #[test]
    fn the_authority_type_is_comparable() {
        assert_eq!(
            authority_of("https://a.test"),
            authority_of("https://A.test")
        );
        assert_ne!(
            authority_of("https://a.test"),
            authority_of("https://a.test:443")
        );
        let a = Authority {
            scheme: Some("https".to_string()),
            host: "a.test".to_string(),
            port: None,
        };
        assert_eq!(authority_of("https://a.test"), Some(a));
    }
}
