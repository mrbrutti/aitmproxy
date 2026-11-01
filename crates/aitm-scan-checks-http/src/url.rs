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
//! - a port that is not a number, or is `0`, makes the whole URL unusable,
//!   rather than being quietly ignored or read as "no port";
//! - a host with anything but ASCII letters, digits, `.`, `-`, `_` is
//!   unusable, except an IPv6 literal, which must be **bracketed** and must
//!   parse as an address: `::1` without brackets and `host:p:p` (two colons,
//!   not an address) are both unusable;
//! - an authority that is not its own trimmed form (`origin.test\r\n`) is
//!   unusable; only the URL as a whole may be padded.
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
    // The core parser trims what it is given, so `origin.test\r\n` would come
    // back as `origin.test`; an authority with padding inside the URL is not
    // one a client wrote, and it is refused rather than tidied.
    if authority.is_empty() || authority != authority.trim() {
        return None;
    }

    // Port 0 is the core parser's "no port was written" sentinel, the same one
    // `Authority::matches_scope_entry` uses. A URL that really writes `:0`
    // names no port a client could dial, so a written port that parses to the
    // sentinel is refused too.
    let parsed = CoreAuthority::parse_with_default(authority, 0).ok()?;
    if !host_is_usable(authority, &parsed.host) {
        return None;
    }
    if wrote_a_port(authority) && parsed.port == 0 {
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

/// Whether `written` (the authority as the URL spelt it, userinfo dropped)
/// carries a port: `[v6]:port`, or `host:port`. Everything with two or more
/// bare colons was already refused by [`host_is_usable`], so a bare colon
/// here is the port separator.
fn wrote_a_port(written: &str) -> bool {
    match written.strip_prefix('[') {
        Some(rest) => rest
            .split_once(']')
            .is_some_and(|(_, after)| after.starts_with(':')),
        None => written.contains(':'),
    }
}

/// Whether `host` (as the core parser read it out of `written`) is something
/// a client could dial: non-empty ASCII letters, digits, `.`, `-`, `_`; or an
/// IPv6 literal, which must have been **bracketed** in the URL and must parse
/// as an address. Brackets hold nothing else: `[1.2.3.4]` is not a host.
///
/// The core parser reads any multi-colon authority as a bare IPv6 literal
/// (`::1`, but also `origin.test:8443:9443`); here that heuristic buys
/// nothing, because a URL that names a raw-socket target spells an IPv6 host
/// in brackets or not at all (security re-review S2-1, tester T2-1).
fn host_is_usable(written: &str, host: &str) -> bool {
    if written.starts_with('[') || host.contains(':') {
        return written.starts_with('[') && host.parse::<std::net::Ipv6Addr>().is_ok();
    }
    !host.is_empty()
        && host
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'))
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
            "https://origin.test:443:443/x",
            "https://a:b:c/",
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

    // -----------------------------------------------------------------------
    // Tester pass over fix round F3: the shapes a URL parser that gates a raw
    // socket must get right — IPv6 literals, userinfo, odd ports, control
    // bytes and oversized input — none of which may panic or name a host the
    // URL did not.
    // -----------------------------------------------------------------------

    /// An IPv6 literal with no port, userinfo in front of it and upper-case
    /// hex inside it: the host is the lower-cased literal, the port is absent
    /// and the canonical origin fills in the scheme's default port in the
    /// bracketed form `[::1]:443`.
    #[test]
    fn an_ipv6_literal_without_a_port_folds_and_takes_the_default_port() {
        let a = authority_of("https://User:Pw@[2001:DB8::1]/x").expect("parses");
        assert_eq!(a.scheme.as_deref(), Some("https"));
        assert_eq!(a.host, "2001:db8::1");
        assert_eq!(a.port, None);
        assert_eq!(a.host_literal(), "[2001:db8::1]");
        assert_eq!(a.as_written(), "[2001:db8::1]");
        assert_eq!(a.origin_key().as_deref(), Some("https://[2001:db8::1]:443"));

        // The same origin written with the default port is the same key.
        assert_eq!(
            authority_of("https://[2001:db8::1]:443/y").and_then(|a| a.origin_key()),
            a.origin_key()
        );
        // The loopback literal, the form the h2 tests dial.
        assert_eq!(
            authority_of("https://[::1]/")
                .and_then(|a| a.origin_key())
                .as_deref(),
            Some("https://[::1]:443")
        );
    }

    /// An IPv6 literal is a host only in brackets. The core parser would read
    /// a multi-colon authority as a bare literal; here `https://::1/x` names
    /// nothing, and so cannot be mistaken for a port cut from the middle of
    /// an address, while the bracketed spelling of the same address parses.
    /// An unterminated bracket is unusable too.
    #[test]
    fn an_unbracketed_ipv6_literal_is_unusable_and_the_bracketed_one_parses() {
        for (loose, bracketed) in [
            ("https://::1/x", "https://[::1]/x"),
            ("https://2001:db8::1/x", "https://[2001:db8::1]/x"),
        ] {
            assert_eq!(parts(loose), None, "{loose}");
            let a = authority_of(bracketed).expect("the bracketed literal parses");
            assert_eq!(a.port, None, "{bracketed}");
            assert!(a.host_literal().starts_with('['), "{}", a.host_literal());
        }
        assert_eq!(parts("https://[::1/x"), None);
        // Brackets do not make an address of something that is not one.
        assert_eq!(parts("https://[origin.test:8443]/x"), None);
        assert_eq!(parts("https://[1.2.3.4]/x"), None);
    }

    /// A host that is not an IPv6 address but carries two colons
    /// (`origin.test:8443:9443`) names nothing: it is neither a host with a
    /// port nor an address, so no profile origin can authorise it and no
    /// raw socket is ever opened towards it.
    #[test]
    fn a_doubled_port_is_unusable() {
        for url in [
            "https://origin.test:8443:9443/x",
            "https://origin.test:443:443/x",
            "https://origin.test:8443:/x",
        ] {
            assert_eq!(parts(url), None, "{url}");
        }
    }

    /// Tester finding (F3 pass, Minor), fixed in F5: four authorities the
    /// parser used to accept are unusable — an IPv6 literal without brackets,
    /// a non-address host with two colons, an authority whose trailing CR/LF
    /// the core parser would trim away, and `:0`, which the core parser reads
    /// as "no port" and would so have dialled the scheme's default.
    #[test]
    fn lenient_authorities_should_be_unusable() {
        for url in [
            "https://::1/x",
            "https://origin.test:8443:9443/x",
            "https://origin.test\r\n/x",
            "https://origin.test:0/x",
            "https://[::1]:0/x",
            "https://origin.test:00/x",
        ] {
            assert_eq!(parts(url), None, "{url:?}");
        }
    }

    /// Everything before the *last* `@` is userinfo, however many `@` it
    /// carries and whatever it looks like; the port after the host survives.
    #[test]
    fn userinfo_is_everything_before_the_last_at_sign() {
        assert_eq!(
            parts("https://a@b@origin.test:8443/"),
            Some((
                Some("https".to_string()),
                "origin.test".to_string(),
                Some(8443)
            ))
        );
        // A would-be origin smuggled into the userinfo is not the host.
        assert_eq!(
            parts("https://origin.test@other.test/"),
            Some((Some("https".to_string()), "other.test".to_string(), None))
        );
        // The scheme-relative form drops userinfo too (the redirect check
        // reads `//user@canary/` as the canary).
        assert_eq!(
            parts("//user:pw@aitm-redirect.invalid/"),
            Some((None, "aitm-redirect.invalid".to_string(), None))
        );
    }

    /// A port that is empty, out of range or non-numeric makes the URL
    /// unusable rather than being ignored: a gate that quietly dropped a bad
    /// port would compare the wrong origin.
    #[test]
    fn a_malformed_port_makes_the_url_unusable() {
        for url in [
            "https://origin.test:/x",
            "https://origin.test:65536/x",
            "https://origin.test:-1/x",
            "https://origin.test:44 3/x",
            "https://origin.test\r\n:8443/x",
        ] {
            assert_eq!(parts(url), None, "{url}");
        }
        // The last legal port parses.
        assert_eq!(
            authority_of("https://origin.test:65535/").map(|a| a.port),
            Some(Some(65535))
        );
    }

    /// Control bytes and whitespace inside or around the authority are not a
    /// host; only the URL as a whole may be padded with whitespace, which is
    /// trimmed. A CR/LF that *trails* the authority is what the core parser
    /// would quietly trim away, so it is refused here before the parser sees
    /// it.
    #[test]
    fn control_bytes_in_the_authority_are_unusable_and_padding_is_trimmed() {
        for url in [
            "https://origin.test\r\n/x",
            "https://origin.test /x",
            "https:// origin.test/x",
            "https://origin\ttest/x",
            "https://origin.test\u{0}/x",
            "https://origin.test%0d%0a/x",
            "https://orig in.test/x",
        ] {
            assert_eq!(parts(url), None, "{url:?}");
        }
        assert_eq!(
            parts("  https://origin.test/x  \n"),
            Some((Some("https".to_string()), "origin.test".to_string(), None))
        );
    }

    /// Oversized input: a megabyte of host, path or userinfo neither panics
    /// nor becomes a different host.
    #[test]
    fn oversized_urls_parse_in_bounded_time_without_panicking() {
        let long_host = format!("https://{}.test/", "a".repeat(1024 * 1024));
        let a = authority_of(&long_host).expect("a long label is still a host");
        assert!(a.host.ends_with(".test"));
        assert_eq!(a.host.len(), 1024 * 1024 + 5);

        let long_path = format!("https://origin.test/{}", "p".repeat(1024 * 1024));
        let (a, rest) = split_url(&long_path).expect("parses");
        assert_eq!(a.host, "origin.test");
        assert_eq!(rest.len(), 1024 * 1024 + 1);

        let long_userinfo = format!("https://{}@origin.test/", "u".repeat(1024 * 1024));
        assert_eq!(
            authority_of(&long_userinfo).map(|a| a.host),
            Some("origin.test".to_string())
        );

        let long_garbage = "x".repeat(1024 * 1024);
        assert_eq!(parts(&long_garbage), None);
    }

    /// Only `scheme://` introduces a scheme. A `://` later in the text (a URL
    /// carried in a query parameter) is not one, so a relative reference that
    /// mentions an absolute URL still has no authority of its own.
    #[test]
    fn a_colon_slash_slash_inside_the_text_does_not_make_a_scheme() {
        for url in [
            "/login?next=https://aitm-redirect.invalid/",
            "redirect?to=https://aitm-redirect.invalid/",
            "?u=https://aitm-redirect.invalid/",
        ] {
            assert_eq!(parts(url), None, "{url}");
        }
        // Scheme-relative with an absolute URL in its query: the authority is
        // the one before the path.
        assert_eq!(
            parts("//aitm-redirect.invalid/?next=https://origin.test/"),
            Some((None, "aitm-redirect.invalid".to_string(), None))
        );
        // A scheme with a digit, `+`, `-` or `.` is a scheme.
        assert_eq!(
            parts("h2c+tls://origin.test/").map(|(s, _, _)| s),
            Some(Some("h2c+tls".to_string()))
        );
    }
}
