//! The native `xss-reflected` check (spec D8.2). Implemented by T3 task 5.
//!
//! The shipped `check-xss.rhai` asked one question and this check asks the same
//! one, with the catalogue's vocabulary around it: **did a markup canary come
//! back verbatim, in a response the browser will parse as HTML?** If it did,
//! the parameter is not entity-encoding what it echoes, and markup placed there
//! reaches the parser. That is the whole finding. The check never sends a
//! script, never calls out and never tries to run anything: the canary is an
//! inert, job-unique element name, and detection is by unencoded reflection,
//! not by execution (spec "Shared facts", anti-goals).
//!
//! Three things make the verdict `certain` rather than a guess:
//!
//! 1. **The canary is unique to the job.** `aitm` + the host's marker cannot
//!    appear in a response by coincidence, so a match is this probe's echo and
//!    not a word the page already contained.
//! 2. **The match is verbatim.** The angle brackets and quotes must survive
//!    byte for byte. `&lt;aitmabcd&gt;` is the server doing its job, and is
//!    clean.
//! 3. **The content type must be HTML.** The same bytes inside
//!    `application/json` are data, not markup; a browser will not parse them,
//!    so there is nothing to report (spec D8.2, "HTML content-type rule").
//!
//! Three probes cover the three contexts a reflection usually lands in — the
//! element body, an attribute value, and a JavaScript string literal — and the
//! check stops at the first hit. It takes no baseline (`needs_baseline: false`)
//! because a unique canary needs nothing to be compared against.

use std::sync::Arc;

use aitm_poc::{Assertion, MatchPart, Severity};
use aitm_scan_model::{
    Check, CheckCost, CheckMeta, CheckOrigin, Confidence, ControlHint, Evidence, InsertionKind,
    InsertionPoint, Intensity, LaneKind, Outcome, Payload, PayloadMode, PocHint, ProbeHost,
    ProbeResponse, Technique, Verdict,
};
use futures::future::BoxFuture;

use crate::gate::{may_send, ProbeTally};
use crate::matching::{body_text, excerpt_around, is_html};

/// The prefix every scanner canary carries, so an operator reading a response
/// or a log can tell at a glance that the odd-looking token is ours.
const CANARY_PREFIX: &str = "aitm";

/// The catalogue entry for the reflected-XSS check (session call S3).
#[must_use]
pub fn check() -> Arc<dyn Check> {
    Arc::new(XssReflected::new())
}

/// Reflected cross-site scripting by unencoded canary reflection.
struct XssReflected {
    meta: CheckMeta,
}

impl XssReflected {
    fn new() -> Self {
        Self {
            meta: CheckMeta {
                id: "xss-reflected".to_string(),
                name: "Reflected cross-site scripting".to_string(),
                class: "xss".to_string(),
                lanes: vec![LaneKind::Http],
                kinds: vec![
                    InsertionKind::Query,
                    InsertionKind::BodyParam,
                    InsertionKind::JsonValue,
                    InsertionKind::XmlValue,
                    InsertionKind::MultipartValue,
                    InsertionKind::Header,
                    InsertionKind::PathSegment,
                    InsertionKind::ParamNameQuery,
                ],
                intensity: Intensity::Light,
                cost: CheckCost::Light,
                technique: Technique::Reflected,
                severity: Severity::High,
                confidence_max: Confidence::Certain,
                needs_baseline: false,
                wants_traits: None,
                targets_session: false,
                cwe: Some(79),
                description: "Places a job-unique markup canary at the point in three HTML \
                              contexts and reports when it is reflected verbatim, with its \
                              angle brackets and quotes intact, into an HTML response."
                    .to_string(),
                remediation: Some(
                    "Contextually encode the value where it is written into the page \
                     (HTML-entity encoding in element and attribute contexts, JavaScript \
                     string escaping in script contexts) rather than filtering the input, \
                     and set a Content-Security-Policy that forbids inline script."
                        .to_string(),
                ),
                origin: CheckOrigin::Native,
            },
        }
    }
}

/// The three context break-out canaries, in the order they are tried.
///
/// Each one is markup only: an element with no attributes, an attribute
/// break-out, and a JavaScript string break-out whose tail is a comment. None
/// of them executes anything even if a browser does parse it.
fn context_probes(tag: &str) -> [String; 3] {
    [
        // Element context: `<tag>x</tag>` survives only if `<` and `>` did.
        format!("<{tag}>x</{tag}>"),
        // Attribute context: close the quote and the tag, then open ours.
        format!("\"><{tag}>"),
        // JavaScript string context: close the string, then comment out the rest.
        format!("';{tag}//"),
    ]
}

/// The verdict for a canary that came back intact.
fn reflected(
    point: &InsertionPoint,
    tag: &str,
    probe: &str,
    status: u16,
    resp: &ProbeResponse,
    body: &str,
) -> Verdict {
    Verdict {
        outcome: Outcome::Vulnerable,
        confidence: Confidence::Certain,
        evidence: Evidence {
            payload: Some(probe.to_string()),
            matched: Some(excerpt_around(body, probe)),
            probe_flows: resp.flow.into_iter().collect(),
            ..Evidence::default()
        },
        detail: format!(
            "the {kind:?} point \"{name}\" reflected an unencoded markup canary into an HTML \
             {status} response; its angle brackets and quotes survived, so markup written \
             here reaches the parser",
            kind = point.kind,
            name = point.name,
        ),
        poc_hint: Some(PocHint {
            // The reproduction is exactly what the probe showed: this status,
            // and the canary present verbatim in the body.
            assertions: vec![
                Assertion::Status(status),
                Assertion::Word {
                    word: probe.to_string(),
                    part: MatchPart::Body,
                },
            ],
            // The control sends the bare tag with no markup at all. A response
            // that does not then contain the full canary tells us the markup,
            // and not merely the word, is what came through.
            control: Some(ControlHint {
                payload: tag.to_string(),
                expect: vec![Assertion::Not(Box::new(Assertion::Word {
                    word: probe.to_string(),
                    part: MatchPart::Body,
                }))],
            }),
        }),
    }
}

impl Check for XssReflected {
    fn meta(&self) -> &CheckMeta {
        &self.meta
    }

    fn run<'a>(
        &'a self,
        point: &'a InsertionPoint,
        host: &'a dyn ProbeHost,
    ) -> BoxFuture<'a, Verdict> {
        Box::pin(async move {
            let tag = format!("{CANARY_PREFIX}{}", host.marker());
            let probes = context_probes(&tag);
            let planned = probes.len();
            let mut tally = ProbeTally::new("reflection probes", planned);

            for probe in &probes {
                if !may_send(host, 1) {
                    break;
                }
                let payload = Payload {
                    value: probe.clone(),
                    mode: PayloadMode::Replace,
                    bytes: None,
                };
                tally.attempted();
                let Ok(resp) = host.probe(&payload).await else {
                    // One refused probe is not a verdict; try the next context.
                    tally.refused();
                    continue;
                };
                // Data is not markup: the same bytes in JSON or plain text are
                // never parsed as HTML, so they are not a finding.
                if !is_html(&resp) {
                    continue;
                }
                let Some(status) = resp.status else {
                    continue;
                };
                let body = body_text(&resp);
                if body.contains(probe.as_str()) {
                    return reflected(point, &tag, probe, status, &resp, &body);
                }
            }

            tally.conclude(format!(
                "the canary was not reflected unencoded into an HTML response after \
                 {planned} context probes"
            ))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{context_probes, CANARY_PREFIX};

    /// The canary is the prefix plus the job marker, and every probe carries it
    /// whole — a probe that dropped the tag would match any page.
    #[test]
    fn the_three_context_probes_all_carry_the_whole_tag() {
        let tag = format!("{CANARY_PREFIX}abcd");
        let probes = context_probes(&tag);

        assert_eq!(tag, "aitmabcd");
        assert_eq!(
            probes,
            [
                "<aitmabcd>x</aitmabcd>".to_string(),
                "\"><aitmabcd>".to_string(),
                "';aitmabcd//".to_string(),
            ]
        );
        for probe in &probes {
            assert!(probe.contains(&tag), "{probe}");
        }
    }

    /// No probe may contain anything that executes, calls out or closes a
    /// document; the canary is inert markup and must stay that way.
    #[test]
    fn no_probe_contains_an_executable_construct() {
        let probes = context_probes("aitmabcd");
        for probe in &probes {
            let lowered = probe.to_ascii_lowercase();
            for banned in [
                "script",
                "onerror",
                "onload",
                "javascript:",
                "http://",
                "//evil",
            ] {
                assert!(!lowered.contains(banned), "{probe} contains {banned}");
            }
        }
    }
}
