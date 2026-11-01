//! The native `open-redirect` check (spec D8.2). Implemented by T3 task 5.
//!
//! An open redirect is a parameter the application will send a visitor to
//! without validating where. The check proves it the only way that is both
//! conclusive and harmless: it asks the target to redirect to a **canary host
//! that does not exist**, and reads the `Location` the target answers with.
//!
//! `REDIRECT_CANARY` is under `.invalid`, the top-level domain RFC 2606
//! reserves for exactly this — it is guaranteed never to resolve, so a browser,
//! a crawler or an automated client that follows the redirect reaches nothing
//! and contacts nobody. **This check never sends a request to the canary.** The
//! canary is a *value placed at the insertion point*; every request still goes
//! to the point's own target, and `tests/native_reflection.rs` pins that.
//!
//! Three forms are tried, because the bug is almost always a filter that only
//! understands one of them: the absolute URL, the scheme-relative `//host/`
//! that inherits the current scheme, and a backslash form that a browser
//! normalises to `//host/` but a naive string check does not. The check stops
//! at the first form that works.
//!
//! The verdict rule is deliberately narrow: a **3xx** status whose `Location`
//! **authority** is the canary host. A `Location` that merely mentions the
//! canary — carried back as a query parameter of a same-origin URL, say — is
//! the application reflecting input, not redirecting to it, and is clean. That
//! is why `location_host` parses the authority instead of searching for a
//! substring.

use std::sync::Arc;

use aitm_poc::{Assertion, MatchPart, Severity};
use aitm_scan_model::{
    Check, CheckCost, CheckMeta, CheckOrigin, Confidence, ControlHint, Evidence, InsertionKind,
    InsertionPoint, Intensity, LaneKind, Outcome, Payload, PayloadMode, PocHint, PointTrait,
    ProbeHost, ProbeResponse, Technique, Verdict,
};
use futures::future::BoxFuture;

use crate::gate::{may_send, point_label, ProbeTally};
use crate::matching::{header, scrub};

/// The absolute canary target. RFC 2606 reserves `.invalid`, so this name
/// resolves nowhere and a client that follows the redirect contacts nothing.
pub(crate) const REDIRECT_CANARY: &str = "https://aitm-redirect.invalid/";

/// The authority a vulnerable `Location` must carry.
const CANARY_HOST: &str = "aitm-redirect.invalid";

/// The `Location` matcher the PoC reproduction asserts.
///
/// `m` is not decoration: the PoC runner joins the response headers into one
/// newline-separated block before matching, so without multi-line mode `^`
/// would anchor at the first header and the assertion would only hold on the
/// rare response whose `Location` comes first.
const LOCATION_CANARY_REGEX: &str = r"(?im)^location:\s*.*aitm-redirect\.invalid";

/// The benign control payload: a same-origin path. A target that redirects to
/// it has not been sent anywhere it did not choose.
const CONTROL_PAYLOAD: &str = "/";

/// The catalogue entry for the open-redirect check (session call S3).
#[must_use]
pub fn check() -> Arc<dyn Check> {
    Arc::new(OpenRedirect::new())
}

/// Unvalidated redirects, proven with a non-resolving canary host.
struct OpenRedirect {
    meta: CheckMeta,
}

impl OpenRedirect {
    fn new() -> Self {
        Self {
            meta: CheckMeta {
                id: "open-redirect".to_string(),
                name: "Open redirect".to_string(),
                class: "open-redirect".to_string(),
                lanes: vec![LaneKind::Http],
                kinds: vec![
                    InsertionKind::Query,
                    InsertionKind::BodyParam,
                    InsertionKind::JsonValue,
                    InsertionKind::Header,
                ],
                intensity: Intensity::Light,
                cost: CheckCost::Light,
                technique: Technique::Reflected,
                severity: Severity::Medium,
                confidence_max: Confidence::Certain,
                needs_baseline: false,
                // Only a point that already looks like a URL can plausibly be a
                // redirect target, so the scheduler aims this check with the
                // `url` trait (spec D4, "skip checks unlikely to be effective").
                wants_traits: Some(vec![PointTrait::Url]),
                targets_session: false,
                cwe: Some(601),
                description: "Sets the point to a non-resolving canary host in three forms \
                              (absolute, scheme-relative and backslash) and reports when the \
                              target answers with a 3xx whose Location authority is the canary."
                    .to_string(),
                remediation: Some(
                    "Do not redirect to a location taken from the request. Accept a key or \
                     a relative path and resolve it server-side against an allow-list of \
                     destinations, rejecting absolute URLs, scheme-relative URLs and \
                     backslash forms alike."
                        .to_string(),
                ),
                origin: CheckOrigin::Native,
            },
        }
    }
}

/// The three canary forms, in the order they are tried.
fn canary_forms() -> [&'static str; 3] {
    [
        // Absolute: the plain case, and the one a correct filter catches.
        REDIRECT_CANARY,
        // Scheme-relative: inherits the page's scheme, and gets past a filter
        // that only looks for "http".
        "//aitm-redirect.invalid/",
        // Backslash: browsers normalise `\` to `/` in the authority, so this
        // behaves as the scheme-relative form while reading as a local path.
        r"/\aitm-redirect.invalid/",
    ]
}

/// The lower-case authority host a `Location` points at, or `None` when it is
/// relative and therefore stays on the origin.
///
/// The parsing is [`crate::url::authority_of`]; this check's one extra rule is
/// the backslash: browsers normalise `\` to `/` inside a URL, so `/\host/` is
/// read as the authority it will actually resolve to rather than as a path.
fn location_host(location: &str) -> Option<String> {
    let loc = location.trim().replace('\\', "/");
    Some(crate::url::authority_of(&loc)?.host_literal())
}

/// Whether `resp` is a redirect to the canary.
fn redirects_to_canary(resp: &ProbeResponse) -> Option<(u16, String)> {
    let status = resp.status?;
    if !(300..400).contains(&status) {
        return None;
    }
    let location = header(resp, "location")?;
    if location_host(location).as_deref() == Some(CANARY_HOST) {
        Some((status, location.to_string()))
    } else {
        None
    }
}

/// The verdict for a target that followed the canary.
fn redirected(
    point: &InsertionPoint,
    probe: &str,
    status: u16,
    location: &str,
    resp: &ProbeResponse,
) -> Verdict {
    let canary_matcher = Assertion::Regex {
        regex: LOCATION_CANARY_REGEX.to_string(),
        part: MatchPart::Header,
    };
    Verdict {
        outcome: Outcome::Vulnerable,
        confidence: Confidence::Certain,
        evidence: Evidence {
            payload: Some(probe.to_string()),
            // The target wrote this `Location`; it can carry a session value
            // in a query parameter, so it is scrubbed before it is quoted
            // (spec D8.1, "Redaction").
            matched: Some(Evidence::excerpt(&scrub(location))),
            probe_flows: resp.flow.into_iter().collect(),
            ..Evidence::default()
        },
        detail: format!(
            "the {kind:?} point \"{name}\" sent a {status} redirect to the off-origin canary \
             host {CANARY_HOST}; the redirect target is taken from the request and not \
             validated",
            kind = point.kind,
            name = point_label(point),
        ),
        poc_hint: Some(PocHint {
            assertions: vec![Assertion::Status(status), canary_matcher.clone()],
            // The control asks for a same-origin path. If the canary regex no
            // longer holds, the redirect followed the parameter rather than
            // always pointing off-origin.
            control: Some(ControlHint {
                payload: CONTROL_PAYLOAD.to_string(),
                expect: vec![Assertion::Not(Box::new(canary_matcher))],
            }),
        }),
    }
}

impl Check for OpenRedirect {
    fn meta(&self) -> &CheckMeta {
        &self.meta
    }

    fn run<'a>(
        &'a self,
        point: &'a InsertionPoint,
        host: &'a dyn ProbeHost,
    ) -> BoxFuture<'a, Verdict> {
        Box::pin(async move {
            let forms = canary_forms();
            let planned = forms.len();
            let mut tally = ProbeTally::new("canary probes", planned);

            for form in forms {
                if !may_send(host, 1) {
                    break;
                }
                let payload = Payload {
                    value: form.to_string(),
                    mode: PayloadMode::Replace,
                    bytes: None,
                };
                tally.attempted();
                let Ok(resp) = host.probe(&payload).await else {
                    tally.refused();
                    continue;
                };
                if let Some((status, location)) = redirects_to_canary(&resp) {
                    return redirected(point, form, status, &location, &resp);
                }
            }

            tally.conclude(format!(
                "the target did not redirect to the canary host in {planned} forms"
            ))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{canary_forms, location_host, CANARY_HOST, LOCATION_CANARY_REGEX, REDIRECT_CANARY};

    /// Every form must name the canary and nothing else; a probe that named a
    /// real host would be a request to a third party.
    #[test]
    fn every_canary_form_resolves_to_the_reserved_host() {
        assert_eq!(REDIRECT_CANARY, "https://aitm-redirect.invalid/");
        assert!(
            CANARY_HOST.ends_with(".invalid"),
            "the canary must stay under the RFC 2606 reserved TLD"
        );
        for form in canary_forms() {
            assert_eq!(
                location_host(form).as_deref(),
                Some(CANARY_HOST),
                "form {form} did not resolve to the canary"
            );
        }
    }

    /// The authority, not a substring: these are the shapes that separate a
    /// real redirect from an echo.
    #[test]
    fn location_host_reads_the_authority() {
        assert_eq!(
            location_host("https://aitm-redirect.invalid/next").as_deref(),
            Some("aitm-redirect.invalid")
        );
        assert_eq!(
            location_host("//AITM-Redirect.Invalid/").as_deref(),
            Some("aitm-redirect.invalid"),
            "hosts are case-insensitive"
        );
        assert_eq!(
            location_host("https://aitm-redirect.invalid:8443/x").as_deref(),
            Some("aitm-redirect.invalid"),
            "the port is not part of the host"
        );
        assert_eq!(
            location_host("https://target.example@aitm-redirect.invalid/").as_deref(),
            Some("aitm-redirect.invalid"),
            "userinfo before the @ is not the host"
        );
        assert_eq!(
            location_host("http://[2001:db8::1]:80/x").as_deref(),
            Some("[2001:db8::1]"),
            "an IPv6 literal keeps its brackets"
        );

        // Relative targets stay on the origin: no authority at all.
        assert_eq!(location_host("/home"), None);
        assert_eq!(location_host("home?next=1"), None);
        assert_eq!(location_host(""), None);
        assert_eq!(location_host("///"), None);

        // An echo is not a redirect.
        assert_eq!(
            location_host("/login?next=https://aitm-redirect.invalid/").as_deref(),
            None
        );
        assert_eq!(
            location_host("https://target.example/?next=https://aitm-redirect.invalid/").as_deref(),
            Some("target.example")
        );
    }

    /// The PoC matcher runs against a newline-joined header block, so it must
    /// be multi-line and case-insensitive and must stay on the Location line.
    #[test]
    fn the_location_matcher_is_multiline_and_line_bounded() {
        let re = regex::Regex::new(LOCATION_CANARY_REGEX).expect("the matcher compiles");

        let block = "Date: Sat, 01 Nov 2026 00:00:00 GMT\nServer: aitm-testtarget\n\
                     Location: https://aitm-redirect.invalid/\nContent-Length: 0";
        assert!(re.is_match(block), "Location is not the first header");

        let lowercased = "date: x\nlocation: //aitm-redirect.invalid/";
        assert!(re.is_match(lowercased), "header names may be lower-case");

        // The canary on another header's line must not satisfy a Location
        // assertion: `.` does not cross the newline.
        let elsewhere = "Location: /home\nX-Echo: https://aitm-redirect.invalid/";
        assert!(!re.is_match(elsewhere));
    }
}
