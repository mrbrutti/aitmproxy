//! Payload sets and the per-class `CheckDefinition`: where a class injects,
//! what inert payloads it tries, and how a hit is confirmed.
//!
//! Payload *values* are inert benign canaries, never a live attack:
//! reflected-XSS uses a unique benign marker that carries HTML metacharacters
//! (an unknown `<aitm-canary-...>` element, never an executing `<script>`), so
//! an output encoder rewrites it and a raw match proves *unencoded* reflection
//! — a correctly escaped (patched) response does not confirm. Open-redirect
//! uses an off-origin sentinel host under the reserved `.invalid` TLD, matched
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
/// check in `confirm`.
const OPEN_REDIRECT_LOCATION_REGEX: &str =
    r"(?im)^location:\s*(?:https?:)?//aitm-scan-sentinel\.invalid(?:[:/?#]|$)";

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
        // Open-redirect only fires on a real redirect: a stray off-origin URL
        // echoed into a 2xx response's headers is not a redirect.
        if self.class == CLASS_OPEN_REDIRECT && !(300..=399).contains(&status) {
            return None;
        }
        let assertion = self.success_assertion(payload);
        // An empty word matches every response; never confirm on one (a
        // hand-built `Payload` with an empty value and no marker would
        // otherwise report every response as a hit).
        if let Assertion::Word { word, .. } = &assertion {
            if word.is_empty() {
                return None;
            }
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
    /// exact assertion a recorded PoC's `success` reuses (`build_poc`, Wave 2).
    /// Reflected-XSS looks for the payload's own marker (each payload judged
    /// independently); open-redirect looks for the sentinel host in the
    /// `Location` header of a redirect (one assertion covers every payload).
    pub(crate) fn success_assertion(&self, payload: &Payload) -> Assertion {
        if self.class == CLASS_OPEN_REDIRECT {
            Assertion::Regex {
                regex: OPEN_REDIRECT_LOCATION_REGEX.to_string(),
                part: MatchPart::Header,
            }
        } else {
            Assertion::Word {
                word: payload
                    .marker
                    .clone()
                    .unwrap_or_else(|| payload.value.clone()),
                part: MatchPart::Body,
            }
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
    /// the response body. Locations: query and body parameters.
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

        // Reflected verbatim (unencoded): a hit.
        let hit_body = format!("<h1>Results for {marker}</h1>");
        assert!(def.confirm(200, &hit_body, &[], payload).is_some());

        // Not reflected at all: no hit.
        assert!(def.confirm(200, "nothing here", &[], payload).is_none());
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
        assert!(
            def.confirm(200, &patched_body, &[], payload).is_none(),
            "escaped reflection must not confirm: a patched target is not vulnerable"
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
        assert!(def.confirm(200, "anything at all", &[], &empty).is_none());
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
