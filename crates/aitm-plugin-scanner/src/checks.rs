//! Payload sets and the per-class `CheckDefinition`: where a class injects,
//! what inert payloads it tries, and how a hit is confirmed.
//!
//! Payload *values* are inert benign canaries, never a live attack:
//! reflected-XSS uses a unique benign marker that carries HTML metacharacters
//! (an unknown `<aitm-canary-...>` element, never an executing `<script>`), so
//! an output encoder rewrites it and a raw match proves *unencoded* reflection
//! — a correctly escaped (patched) response does not confirm — and only in a
//! response typed as HTML, since a JSON echo is not browser-exploitable.
//! Open-redirect uses an off-origin sentinel host under the reserved `.invalid` TLD, matched
//! only in the `Location` header of a 3xx redirect. Confirmation reuses the
//! `aitm_poc` matcher vocabulary — the exact same `Assertion`/`evaluate` a
//! declarative PoC's `success` would use.

use aitm_poc::matcher::{evaluate, MatchContext};
use aitm_poc::{Assertion, MatchPart};

use crate::discover::Location;

/// Class tag for the reflected-XSS check. Used everywhere instead of a bare
/// literal so a typo cannot silently route a class to the wrong assertion.
pub(crate) const CLASS_REFLECTED_XSS: &str = "reflected-xss";
/// Class tag for the open-redirect check.
pub(crate) const CLASS_OPEN_REDIRECT: &str = "open-redirect";

/// How payloads sweep multiple injection points (the nuclei attack-mode
/// vocabulary). Only `BatteringRam` ships this wave.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttackMode {
    BatteringRam,
}

/// One inert payload: the literal value sent, plus the benign marker the
/// confirming assertion looks for (when distinct from the value itself).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Payload {
    pub value: String,
    pub marker: Option<String>,
}

/// What confirmed a hit: the payload that was sent and a non-sensitive
/// description of what matched. Both are scanner constants (a payload literal
/// or a fixed phrase) — never response text, a header value, or a secret.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Evidence {
    pub payload: String,
    pub matched: String,
}

/// The off-origin sentinel host an open-redirect payload points at. It sits
/// under the reserved `.invalid` TLD (RFC 6761), so a resolver must answer
/// NXDOMAIN and a client that follows the injected redirect cannot reach a
/// real host. The `.` is a regex metacharacter, so it is escaped where the
/// confirming assertion matches it.
pub(crate) const OPEN_REDIRECT_SENTINEL: &str = "aitm-scan-sentinel.invalid";

/// The confirming assertion for open-redirect: a redirect whose `Location`
/// points at the sentinel host. Anchored to the `Location` header line and the
/// authority position, so a same-origin bounce that merely echoes the sentinel
/// in a query string — or the sentinel appearing in any other header — never
/// matches. Case-insensitive, because host names are. Paired with a 3xx status
/// clause in [`CheckDefinition::success_assertion`].
const OPEN_REDIRECT_LOCATION_REGEX: &str =
    r"(?im)^location:[ \t]*(?:https?:)?//aitm-scan-sentinel\.invalid(?:[:/?#]|$)";

/// The `Content-Type` clause of the reflected-XSS confirming assertion: the
/// response is a document a browser renders as HTML (`text/html` or
/// `application/xhtml+xml`) — the only context a reflected marker could
/// execute in. A correctly-typed JSON or plain-text API response that echoes
/// the marker is not browser-exploitable, so it is not a confirmed hit.
/// Anchored to the `Content-Type` header line (spaces/tabs only between the
/// name and the value, as with the `Location` regex), so a differently named
/// header that merely carries the media type never matches.
const REFLECTED_XSS_CONTENT_TYPE_REGEX: &str =
    r"(?im)^content-type:[ \t]*.*(text/html|application/xhtml\+xml)";

/// One vulnerability class: where to inject, the inert payloads to try, and
/// how `confirm` judges a response.
pub struct CheckDefinition {
    pub class: &'static str,
    pub locations: &'static [Location],
    pub payloads: Vec<Payload>,
    pub mode: AttackMode,
}

/// Locations `reflected_xss` injects into: a query or body parameter.
const REFLECTED_XSS_LOCATIONS: &[Location] = &[Location::Query, Location::BodyParam];

/// Locations `open_redirect` injects into: a param already classified as a
/// redirect target by `discover::enumerate`.
const OPEN_REDIRECT_LOCATIONS: &[Location] = &[Location::Redirect];

/// Unique benign marker tokens for reflected-XSS. Each is an inert unknown
/// element (`<aitm-canary-NNNN>`) — never an executing `<script>`, event
/// handler, or `javascript:` URL — but it carries the `<`/`>` metacharacters an
/// HTML encoder rewrites, so `confirm` matches only when the marker is
/// reflected *unencoded*. A correctly escaped (patched) response therefore does
/// not confirm.
const REFLECTED_XSS_MARKERS: &[&str] = &[
    "<aitm-canary-0001>",
    "<aitm-canary-0002>",
    "<aitm-canary-0003>",
    "<aitm-canary-0004>",
    "<aitm-canary-0005>",
    "<aitm-canary-0006>",
    "<aitm-canary-0007>",
    "<aitm-canary-0008>",
];

/// Candidate paths appended to the off-origin sentinel host for open-redirect
/// payloads; distinct values just vary the path a little so a deduping proxy
/// does not collapse them.
const OPEN_REDIRECT_PATHS: &[&str] = &["/", "/x", "/a/b", "/?n=1", "/redir", "/go"];

/// Whether `assertion` contains a `Word` matcher with an empty word, which
/// matches every response. Looks through `All`/`Any` only: a `Not` around an
/// empty word can never turn a miss into a hit.
fn has_empty_word(assertion: &Assertion) -> bool {
    match assertion {
        Assertion::Word { word, .. } => word.is_empty(),
        Assertion::All(items) | Assertion::Any(items) => items.iter().any(has_empty_word),
        _ => false,
    }
}

impl CheckDefinition {
    /// Judge one response against this class's confirming assertion for
    /// `payload`. `None` means no hit.
    pub fn confirm(
        &self,
        status: u16,
        body: &str,
        headers: &[(String, String)],
        payload: &Payload,
    ) -> Option<Evidence> {
        let assertion = self.success_assertion(payload);
        // An empty word matches every response; never confirm on one (a
        // hand-built `Payload` with an empty value and no marker would
        // otherwise report every response as a hit). This is the only check
        // `confirm` makes beyond evaluating `success_assertion`.
        if has_empty_word(&assertion) {
            return None;
        }
        let mut ctx = MatchContext::new(status, body.to_string());
        for (name, value) in headers {
            ctx = ctx.with_header(name.clone(), value.clone());
        }
        if !evaluate(&assertion, &ctx) {
            return None;
        }
        Some(Evidence {
            payload: payload.value.clone(),
            matched: self.matched_description(payload),
        })
    }

    /// The `success` assertion this class confirms with, for one payload — the
    /// exact assertion a recorded PoC's `success` reuses (`build_poc`).
    /// Reflected-XSS requires both the payload's own marker in the body (each
    /// payload judged independently) *and* an HTML `Content-Type`; open-redirect
    /// requires both a redirect status a user agent actually follows (not
    /// 300/304/305/306/309+) *and* the sentinel host in the `Location` header
    /// (one assertion covers every payload).
    ///
    /// `confirm` judges a hit by evaluating exactly this assertion — its only
    /// extra check is rejecting an empty word, which the scanner never builds a
    /// payload for — so a recorded PoC's `success` passes on precisely the
    /// responses `confirm` accepts, and the two cannot drift apart.
    pub(crate) fn success_assertion(&self, payload: &Payload) -> Assertion {
        if self.class == CLASS_OPEN_REDIRECT {
            Assertion::All(vec![
                Assertion::Any(vec![
                    Assertion::Status(301),
                    Assertion::Status(302),
                    Assertion::Status(303),
                    Assertion::Status(307),
                    Assertion::Status(308),
                ]),
                Assertion::Regex {
                    regex: OPEN_REDIRECT_LOCATION_REGEX.to_string(),
                    part: MatchPart::Header,
                },
            ])
        } else {
            Assertion::All(vec![
                Assertion::Word {
                    word: payload
                        .marker
                        .clone()
                        .unwrap_or_else(|| payload.value.clone()),
                    part: MatchPart::Body,
                },
                Assertion::Regex {
                    regex: REFLECTED_XSS_CONTENT_TYPE_REGEX.to_string(),
                    part: MatchPart::Header,
                },
            ])
        }
    }

    /// A non-sensitive description of what a hit matched, for `Evidence`. It is
    /// a scanner constant (the marker, or a fixed phrase) — never response
    /// text, a header value, or a secret.
    fn matched_description(&self, payload: &Payload) -> String {
        if self.class == CLASS_OPEN_REDIRECT {
            "Location header redirects to the off-origin scanner sentinel host".to_string()
        } else {
            payload
                .marker
                .clone()
                .unwrap_or_else(|| payload.value.clone())
        }
    }

    /// Reflected-XSS: a unique benign marker reflected verbatim (unencoded) in
    /// the body of an HTML response. Locations: query and body parameters.
    pub fn reflected_xss() -> Self {
        let payloads = REFLECTED_XSS_MARKERS
            .iter()
            .map(|marker| Payload {
                value: marker.to_string(),
                marker: Some(marker.to_string()),
            })
            .collect();
        Self {
            class: CLASS_REFLECTED_XSS,
            locations: REFLECTED_XSS_LOCATIONS,
            payloads,
            mode: AttackMode::BatteringRam,
        }
    }

    /// Open-redirect: an off-origin sentinel host reflected in the response
    /// `Location` header of a redirect.
    pub fn open_redirect() -> Self {
        let payloads = OPEN_REDIRECT_PATHS
            .iter()
            .map(|path| Payload {
                value: format!("https://{OPEN_REDIRECT_SENTINEL}{path}"),
                marker: None,
            })
            .collect();
        Self {
            class: CLASS_OPEN_REDIRECT,
            locations: OPEN_REDIRECT_LOCATIONS,
            payloads,
            mode: AttackMode::BatteringRam,
        }
    }

    /// The registered definition for `class`, or `None` if unknown.
    pub fn for_class(class: &str) -> Option<Self> {
        match class {
            CLASS_REFLECTED_XSS => Some(Self::reflected_xss()),
            CLASS_OPEN_REDIRECT => Some(Self::open_redirect()),
            _ => None,
        }
    }

    /// Every class `for_class` resolves, in a stable order whose first two
    /// entries are the two shipped classes — the class dispatch table
    /// `scan.inject`/`campaign` list, and the vocabulary an "unknown class"
    /// error names.
    pub fn registered_classes() -> &'static [&'static str] {
        &[CLASS_REFLECTED_XSS, CLASS_OPEN_REDIRECT]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reflected_xss_confirms_on_unencoded_reflection() {
        let def = CheckDefinition::reflected_xss();
        let payload = def
            .payloads
            .first()
            .expect("reflected_xss ships at least one payload");
        let marker = payload.marker.clone().expect("a reflection marker");
        let html = vec![("Content-Type".to_string(), "text/html".to_string())];

        // Reflected verbatim (unencoded) in an HTML response: a hit.
        let hit_body = format!("<h1>Results for {marker}</h1>");
        assert!(def.confirm(200, &hit_body, &html, payload).is_some());

        // Not reflected at all: no hit.
        assert!(def.confirm(200, "nothing here", &html, payload).is_none());
    }

    #[test]
    fn reflected_xss_does_not_confirm_on_escaped_reflection() {
        // A patched target HTML-escapes the marker, so its `<`/`>` become
        // entities and the verbatim marker is absent: `confirm` must miss.
        let def = CheckDefinition::reflected_xss();
        let payload = def.payloads.first().expect("a payload");
        let marker = payload.marker.clone().expect("a marker");
        let escaped = marker.replace('<', "&lt;").replace('>', "&gt;");
        assert_ne!(
            escaped, marker,
            "the marker must carry escapable metacharacters"
        );

        let patched_body = format!("<h1>Results for {escaped}</h1>");
        let html = vec![("Content-Type".to_string(), "text/html".to_string())];
        assert!(
            def.confirm(200, &patched_body, &html, payload).is_none(),
            "escaped reflection must not confirm: a patched target is not vulnerable"
        );
    }

    #[test]
    fn reflected_xss_requires_an_html_content_type() {
        // The same raw marker reflected into a correctly-typed JSON (or
        // typeless) API response is not browser-exploitable, so it is not a hit.
        let def = CheckDefinition::reflected_xss();
        let payload = def.payloads.first().expect("a payload");
        let marker = payload.marker.clone().expect("a marker");
        let body = format!("{{\"q\":\"{marker}\"}}");

        let json = vec![("Content-Type".to_string(), "application/json".to_string())];
        assert!(
            def.confirm(200, &body, &json, payload).is_none(),
            "a JSON echo of the marker is not HTML-exploitable"
        );
        assert!(
            def.confirm(200, &body, &[], payload).is_none(),
            "no Content-Type: do not confirm an XSS hit"
        );
        let html = vec![(
            "Content-Type".to_string(),
            "text/html; charset=utf-8".to_string(),
        )];
        assert!(
            def.confirm(200, &body, &html, payload).is_some(),
            "the same reflection in an HTML response is a hit"
        );
    }

    #[test]
    fn open_redirect_confirms_only_on_redirect_to_sentinel_location() {
        let def = CheckDefinition::open_redirect();
        let payload = def.payloads.first().expect("a payload");
        let loc = |v: &str| vec![("Location".to_string(), v.to_string())];

        // True positives: a 3xx whose Location points off-origin at the host.
        assert!(def
            .confirm(
                302,
                "",
                &loc("https://aitm-scan-sentinel.invalid/x"),
                payload
            )
            .is_some());
        // Host comparison is case-insensitive.
        assert!(def
            .confirm(
                302,
                "",
                &loc("https://AITM-SCAN-SENTINEL.INVALID/x"),
                payload
            )
            .is_some());
        // A protocol-relative redirect to the sentinel is still open-redirect.
        assert!(def
            .confirm(302, "", &loc("//aitm-scan-sentinel.invalid/x"), payload)
            .is_some());

        // Clean same-origin redirect: no hit.
        assert!(def
            .confirm(302, "", &loc("https://app.example/"), payload)
            .is_none());
        // A same-origin bounce that only echoes the sentinel in a query string
        // is NOT an open redirect.
        assert!(def
            .confirm(
                302,
                "",
                &loc("/login?next=https%3A%2F%2Faitm-scan-sentinel.invalid%2Fx"),
                payload,
            )
            .is_none());
        // The sentinel in a non-Location header must not confirm.
        assert!(def
            .confirm(
                200,
                "",
                &[(
                    "Set-Cookie".to_string(),
                    "last=https://aitm-scan-sentinel.invalid/x".to_string(),
                )],
                payload,
            )
            .is_none());
        // The sentinel in Location but on a 2xx (not a redirect): no hit.
        assert!(def
            .confirm(
                200,
                "",
                &loc("https://aitm-scan-sentinel.invalid/x"),
                payload
            )
            .is_none());
        // 304 is not a user-agent-followed redirect: no hit even with the host.
        assert!(def
            .confirm(
                304,
                "",
                &loc("https://aitm-scan-sentinel.invalid/x"),
                payload
            )
            .is_none());
    }

    #[test]
    fn for_class_known() {
        assert!(CheckDefinition::for_class("reflected-xss").is_some());
        assert!(CheckDefinition::for_class("open-redirect").is_some());
        assert!(CheckDefinition::for_class("nope").is_none());
    }

    #[test]
    fn confirm_rejects_empty_word() {
        // A hand-built payload with no marker and an empty value yields an
        // empty Word, which would otherwise match every response.
        let def = CheckDefinition::reflected_xss();
        let empty = Payload {
            value: String::new(),
            marker: None,
        };
        // An HTML Content-Type, so the Content-Type clause passes and the
        // empty-word guard is the only thing standing between this payload and a
        // false hit.
        let html = vec![("Content-Type".to_string(), "text/html".to_string())];
        assert!(def.confirm(200, "anything at all", &html, &empty).is_none());
    }

    #[test]
    fn open_redirect_location_value_must_start_on_the_same_line() {
        // The regex allows only spaces/tabs between `Location:` and the URL. A
        // bare `\s*` would let an *empty* Location value run on into the next
        // header line, so a header named `//aitm-scan-sentinel.invalid/x` would
        // read as `Location: //aitm-scan-sentinel.invalid/x`.
        let def = CheckDefinition::open_redirect();
        let payload = def.payloads.first().expect("a payload");
        let headers = vec![
            ("Location".to_string(), String::new()),
            (
                "//aitm-scan-sentinel.invalid/x".to_string(),
                "1".to_string(),
            ),
        ];
        assert!(
            def.confirm(302, "", &headers, payload).is_none(),
            "an empty Location must not borrow the next header line"
        );

        // Control: the same sentinel as the Location *value* does confirm.
        let real = vec![(
            "Location".to_string(),
            "//aitm-scan-sentinel.invalid/x".to_string(),
        )];
        assert!(def.confirm(302, "", &real, payload).is_some());
    }

    #[test]
    fn registered_classes_starts_with_the_shipped_two() {
        let classes = CheckDefinition::registered_classes();
        assert_eq!(classes[0], "reflected-xss");
        assert_eq!(classes[1], "open-redirect");
        assert!(classes.len() >= 2);
    }

    #[test]
    fn every_registered_class_resolves() {
        for class in CheckDefinition::registered_classes() {
            let def = CheckDefinition::for_class(class)
                .unwrap_or_else(|| panic!("`{class}` is registered but does not resolve"));
            assert!(
                def.payloads.len() <= 25,
                "`{class}` exceeds the payload cap: {}",
                def.payloads.len()
            );
        }
    }

    #[test]
    fn open_redirect_success_assertion_requires_a_redirect_status() {
        let def = CheckDefinition::open_redirect();
        let payload = def.payloads.first().expect("a payload");
        match def.success_assertion(payload) {
            Assertion::All(items) => {
                assert_eq!(
                    items[0],
                    Assertion::Any(vec![
                        Assertion::Status(301),
                        Assertion::Status(302),
                        Assertion::Status(303),
                        Assertion::Status(307),
                        Assertion::Status(308),
                    ])
                );
                assert!(
                    matches!(
                        &items[1],
                        Assertion::Regex {
                            part: MatchPart::Header,
                            ..
                        }
                    ),
                    "{:?}",
                    items[1]
                );
            }
            other => panic!("expected Assertion::All: {other:?}"),
        }
    }

    #[test]
    fn reflected_xss_success_assertion_requires_the_marker_and_an_html_content_type() {
        let def = CheckDefinition::reflected_xss();
        let payload = &def.payloads[0];
        assert_eq!(
            def.success_assertion(payload),
            Assertion::All(vec![
                Assertion::Word {
                    word: "<aitm-canary-0001>".to_string(),
                    part: MatchPart::Body,
                },
                Assertion::Regex {
                    regex: r"(?im)^content-type:[ \t]*.*(text/html|application/xhtml\+xml)"
                        .to_string(),
                    part: MatchPart::Header,
                },
            ])
        );
    }

    /// Evaluate `assertion` against a response, the way a PoC runner would.
    fn assertion_holds(
        assertion: &Assertion,
        status: u16,
        body: &str,
        headers: &[(String, String)],
    ) -> bool {
        let mut ctx = MatchContext::new(status, body.to_string());
        for (name, value) in headers {
            ctx = ctx.with_header(name.clone(), value.clone());
        }
        evaluate(assertion, &ctx)
    }

    /// `confirm` and the recorded PoC's `success` assertion must agree on every
    /// response, for both shipped classes: a hit `confirm` accepts must satisfy
    /// the assertion, and a response `confirm` rejects must fail it.
    #[test]
    fn confirm_matches_the_success_assertion() {
        // Open-redirect: the redirect status and the Location clause.
        let def = CheckDefinition::open_redirect();
        let payload = def.payloads.first().expect("a payload");
        let assertion = def.success_assertion(payload);
        let loc = vec![(
            "Location".to_string(),
            "https://aitm-scan-sentinel.invalid/x".to_string(),
        )];

        for status in [301, 302, 303, 307, 308] {
            assert!(
                def.confirm(status, "", &loc, payload).is_some(),
                "status {status} must confirm"
            );
            assert!(
                assertion_holds(&assertion, status, "", &loc),
                "status {status}: confirm hit but the success assertion is false"
            );
        }
        for status in [300, 304, 399, 200] {
            assert!(
                def.confirm(status, "", &loc, payload).is_none(),
                "status {status} must not confirm"
            );
            assert!(
                !assertion_holds(&assertion, status, "", &loc),
                "status {status}: confirm rejects it but the success assertion passes"
            );
        }

        // Reflected-XSS: the marker in the body *and* an HTML Content-Type.
        let def = CheckDefinition::reflected_xss();
        let payload = def.payloads.first().expect("a payload");
        let marker = payload.marker.clone().expect("a marker");
        let assertion = def.success_assertion(payload);
        let body = format!("{{\"q\":\"{marker}\"}}");
        let typed =
            |content_type: &str| vec![("Content-Type".to_string(), content_type.to_string())];

        // An HTML response reflecting the marker: both agree it is a hit.
        for content_type in [
            "text/html",
            "text/html; charset=utf-8",
            "TEXT/HTML",
            "application/xhtml+xml",
        ] {
            let headers = typed(content_type);
            assert!(
                def.confirm(200, &body, &headers, payload).is_some(),
                "`{content_type}` must confirm"
            );
            assert!(
                assertion_holds(&assertion, 200, &body, &headers),
                "`{content_type}`: confirm hit but the success assertion is false"
            );
        }

        // The same marker echoed into JSON, plain text, or an untyped response:
        // `confirm` rejects it, and a recorded PoC's `success` must not pass it.
        for (label, headers) in [
            ("application/json", typed("application/json")),
            ("text/plain", typed("text/plain")),
            ("no Content-Type", Vec::new()),
            // The HTML media type under a different header name is not the
            // response's Content-Type.
            (
                "X-Content-Type: text/html",
                vec![("X-Content-Type".to_string(), "text/html".to_string())],
            ),
        ] {
            assert!(
                def.confirm(200, &body, &headers, payload).is_none(),
                "{label} must not confirm"
            );
            assert!(
                !assertion_holds(&assertion, 200, &body, &headers),
                "{label}: confirm rejects it but the success assertion passes"
            );
        }

        // An HTML response that does not reflect the marker: neither passes.
        let html = typed("text/html");
        assert!(def.confirm(200, "nothing here", &html, payload).is_none());
        assert!(!assertion_holds(&assertion, 200, "nothing here", &html));
    }

    #[test]
    fn payloads_are_wire_safe() {
        for class in CheckDefinition::registered_classes() {
            let def = CheckDefinition::for_class(class).expect("registered");
            for payload in &def.payloads {
                for byte in payload.value.bytes() {
                    assert!(
                        byte > 0x20 && byte != 0x7f,
                        "`{class}` payload {:?} carries a control/space byte",
                        payload.value
                    );
                }
                for forbidden in ['&', '#', '+', '%', '"', '\\', ';'] {
                    assert!(
                        !payload.value.contains(forbidden),
                        "`{class}` payload {:?} carries `{forbidden}`",
                        payload.value
                    );
                }
            }
        }
    }

    #[test]
    fn payloads_within_configured_cap() {
        let cap = crate::ScannerConfig::default().per_class_payload_cap;
        for def in [
            CheckDefinition::reflected_xss(),
            CheckDefinition::open_redirect(),
        ] {
            assert!(
                def.payloads.len() <= cap,
                "{} exceeds the per-class cap {cap}: {}",
                def.class,
                def.payloads.len()
            );
            assert!(!def.payloads.is_empty(), "{} ships no payloads", def.class);
        }
    }
}
