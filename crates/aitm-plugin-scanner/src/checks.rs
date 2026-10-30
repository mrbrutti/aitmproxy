//! Payload sets and the per-class `CheckDefinition`: where a class injects,
//! what inert payloads it tries, and how a hit is confirmed.
//!
//! Payload *values* are inert benign canaries, never a live attack:
//! reflected-XSS uses a unique benign marker token (not an executing
//! `<script>`), open-redirect uses an off-origin sentinel host compared
//! against the response `Location` header. Confirmation reuses the
//! `aitm_poc` matcher vocabulary — the exact same `Assertion`/`evaluate` a
//! declarative PoC's `success` would use.

use aitm_poc::matcher::{evaluate, MatchContext};
use aitm_poc::{Assertion, MatchPart};

use crate::discover::Location;

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

/// What confirmed a hit: the payload that was sent and the text matched.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Evidence {
    pub payload: String,
    pub matched: String,
}

/// The off-origin sentinel host an open-redirect payload points at. No
/// hyphen/dot-only string like this needs regex escaping, and it never
/// resolves to a real host, so a same-origin `Location` never matches it.
pub const OPEN_REDIRECT_SENTINEL: &str = "aitm-scan-sentinel-invalid";

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

/// Unique benign marker tokens for reflected-XSS — inert canaries, never an
/// executing `<script>` or any HTML. A hit only proves *unencoded reflection*
/// of the marker, which is the deterministic signal this scanner looks for.
const REFLECTED_XSS_MARKERS: &[&str] = &[
    "aitmscancanary0001",
    "aitmscancanary0002",
    "aitmscancanary0003",
    "aitmscancanary0004",
    "aitmscancanary0005",
    "aitmscancanary0006",
    "aitmscancanary0007",
    "aitmscancanary0008",
];

/// Candidate paths appended to the off-origin sentinel host for
/// open-redirect payloads; distinct values just vary the path a little so a
/// deduping proxy does not collapse them.
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
        let mut ctx = MatchContext::new(status, body.to_string());
        for (name, value) in headers {
            ctx = ctx.with_header(name.clone(), value.clone());
        }
        let assertion = self.success_assertion(payload);
        if !evaluate(&assertion, &ctx) {
            return None;
        }
        let matched = match &assertion {
            Assertion::Word { word, .. } => word.clone(),
            Assertion::Regex { regex, .. } => regex.clone(),
            _ => payload.value.clone(),
        };
        Some(Evidence {
            payload: payload.value.clone(),
            matched,
        })
    }

    /// The `success` assertion this class confirms with, for one payload.
    /// Reflected-XSS looks for the payload's own marker (so each payload is
    /// judged independently); open-redirect looks for the shared sentinel
    /// host in the `Location` header (every open-redirect payload points at
    /// it, so one assertion covers them all).
    fn success_assertion(&self, payload: &Payload) -> Assertion {
        match self.class {
            "open-redirect" => Assertion::Regex {
                regex: OPEN_REDIRECT_SENTINEL.to_string(),
                part: MatchPart::Header,
            },
            _ => Assertion::Word {
                word: payload
                    .marker
                    .clone()
                    .unwrap_or_else(|| payload.value.clone()),
                part: MatchPart::Body,
            },
        }
    }

    /// Reflected-XSS: a unique benign marker reflected verbatim in the
    /// response body. Locations: query and body parameters.
    pub fn reflected_xss() -> Self {
        let payloads = REFLECTED_XSS_MARKERS
            .iter()
            .map(|marker| Payload {
                value: marker.to_string(),
                marker: Some(marker.to_string()),
            })
            .collect();
        Self {
            class: "reflected-xss",
            locations: REFLECTED_XSS_LOCATIONS,
            payloads,
            mode: AttackMode::BatteringRam,
        }
    }

    /// Open-redirect: an off-origin sentinel host reflected in the response
    /// `Location` header.
    pub fn open_redirect() -> Self {
        let payloads = OPEN_REDIRECT_PATHS
            .iter()
            .map(|path| Payload {
                value: format!("https://{OPEN_REDIRECT_SENTINEL}{path}"),
                marker: None,
            })
            .collect();
        Self {
            class: "open-redirect",
            locations: OPEN_REDIRECT_LOCATIONS,
            payloads,
            mode: AttackMode::BatteringRam,
        }
    }

    /// The registered definition for `class`, or `None` if unknown.
    pub fn for_class(class: &str) -> Option<Self> {
        match class {
            "reflected-xss" => Some(Self::reflected_xss()),
            "open-redirect" => Some(Self::open_redirect()),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reflected_xss_confirms_on_reflection() {
        let def = CheckDefinition::reflected_xss();
        let payload = def
            .payloads
            .first()
            .expect("reflected_xss ships at least one payload");
        let marker = payload.marker.clone().expect("a reflection marker");

        let hit_body = format!("echo: {marker}");
        assert!(def.confirm(200, &hit_body, &[], payload).is_some());

        let miss_body = "nothing here".to_string();
        assert!(def.confirm(200, &miss_body, &[], payload).is_none());
    }

    #[test]
    fn open_redirect_confirms_on_location() {
        let def = CheckDefinition::open_redirect();
        let payload = def
            .payloads
            .first()
            .expect("open_redirect ships at least one payload");

        let off_origin = vec![(
            "Location".to_string(),
            format!("https://{}/next", OPEN_REDIRECT_SENTINEL),
        )];
        assert!(def.confirm(302, "", &off_origin, payload).is_some());

        let same_origin = vec![("Location".to_string(), "https://app.example/".to_string())];
        assert!(def.confirm(302, "", &same_origin, payload).is_none());
    }

    #[test]
    fn for_class_known() {
        assert!(CheckDefinition::for_class("reflected-xss").is_some());
        assert!(CheckDefinition::for_class("nope").is_none());
    }

    #[test]
    fn payloads_within_cap() {
        for def in [
            CheckDefinition::reflected_xss(),
            CheckDefinition::open_redirect(),
        ] {
            assert!(
                def.payloads.len() <= 25,
                "{} exceeds the shipped per-class cap: {}",
                def.class,
                def.payloads.len()
            );
            assert!(!def.payloads.is_empty(), "{} ships no payloads", def.class);
        }
    }
}
