//! The native `xss-reflected` check (spec D8.2). Implemented by T3 task 5.
//!
//! The shipped `check-xss.rhai` asked one question and this check asks the same
//! one, with the catalogue's vocabulary around it: **did a canary come back
//! verbatim, in a response the browser will parse as HTML, in a context where
//! what survived reaches the parser?** If it did, the parameter is not
//! encoding what it echoes for the context it echoes into. That is the whole
//! finding. The check never sends a script, never calls out and never tries
//! to run anything: the canary is an inert, job-unique element name, and
//! detection is by unencoded reflection, not by execution (spec "Shared
//! facts", anti-goals).
//!
//! Four things make the verdict `certain` rather than a guess:
//!
//! 1. **The canary is unique to the job.** `aitm` + the host's marker cannot
//!    appear in a response by coincidence, so a match is this probe's echo and
//!    not a word the page already contained.
//! 2. **The match is verbatim.** The probe's break-out bytes must survive byte
//!    for byte. `&lt;aitmabcd&gt;` is the server doing its job, and is clean.
//! 3. **The match is in the context the probe is built for.** The element and
//!    attribute probes carry angle brackets, and an unencoded `<` anywhere in
//!    an HTML body is markup the parser will read. The JavaScript-string probe
//!    carries **no** angle bracket — it is a quote, a semicolon and a comment
//!    — so its bytes in a paragraph are text and prove nothing. That probe is
//!    a hit only when its echo sits **inside a `<script>` element**, between
//!    the open tag and the `</script` that ends it, where a closed quote and a
//!    comment reach the interpreter (spec D2, "reflected marker in the right
//!    context"; final quality review FQ-1).
//! 4. **The content type must be HTML.** The same bytes inside
//!    `application/json` are data, not markup; a browser will not parse them,
//!    so there is nothing to report (spec D8.2, "HTML content-type rule").
//!
//! Three probes cover the three contexts a reflection usually lands in — the
//! element body, an attribute value, and a JavaScript string literal — and the
//! check stops at the first hit. Each probe is paired with its context, the
//! way `h2_observe`'s variants pair a label with a header block, so the rule
//! that judges a probe and the sentence that describes it can never drift
//! from the probe they belong to. It takes no baseline
//! (`needs_baseline: false`) because a unique canary needs nothing to be
//! compared against.

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
                // D6's taxonomy token, which the engine's HTTP lane emits for
                // the same class; dedupe groups issues by it, so the two must
                // agree (cross-track vocabulary decision, 2026-11-01).
                class: "reflected-xss".to_string(),
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
                description: "Places a job-unique canary at the point in three HTML contexts \
                              and reports when it is reflected verbatim into an HTML \
                              response in the context it was built for: markup with its \
                              angle brackets intact, or a string break-out inside a script."
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

/// The HTML context a probe is built to break out of, and so the rule that
/// decides whether its verbatim echo is a finding and the sentence that
/// describes what survived.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Context {
    /// An element body: the probe is a whole element.
    Element,
    /// An attribute value: the probe closes the quote and the tag.
    Attribute,
    /// A JavaScript string literal: the probe closes the string and comments
    /// out the rest of the line. It carries no angle bracket.
    JsString,
}

impl Context {
    /// Whether an HTML `body` reflected `probe` in this context.
    ///
    /// The two markup contexts need only the verbatim bytes: an unencoded `<`
    /// is markup wherever in an HTML body it lands. The JavaScript-string
    /// context needs the bytes **and** a `<script>` element around them; any
    /// one occurrence inside a script is enough, however many sit outside.
    fn reflected_in(self, body: &str, probe: &str) -> bool {
        match self {
            Context::Element | Context::Attribute => body.contains(probe),
            Context::JsString => body
                .match_indices(probe)
                .any(|(at, _)| inside_script_element(body, at)),
        }
    }

    /// What this context's probe proves when it survives, for the detail.
    fn survived(self) -> &'static str {
        match self {
            Context::Element => "the tag survived byte for byte",
            Context::Attribute => "the quote and the tag survived",
            Context::JsString => {
                "the quote, semicolon and comment survived inside a <script> block"
            }
        }
    }
}

/// Whether byte offset `at` of `body` lies inside a `<script>` element: after
/// the `>` that closes the nearest preceding `<script ...>` open tag, with no
/// `</script` between that `>` and `at`, and with a `</script` somewhere
/// after `at`.
///
/// The rule follows the HTML tokenizer, not JavaScript: inside a script
/// element the tokenizer ends the element at the first `</script` it sees,
/// quoted or not, so a `</script` inside an earlier string literal ends the
/// element here too. Tag names match ASCII case-insensitively (`<SCRIPT>` is
/// a script), and `<script` counts only when a delimiter follows it, so
/// `<scripty>` is not one. The open tag ends at the first `>` after
/// `<script`; a `>` inside one of its attribute values is not special-cased.
fn inside_script_element(body: &str, at: usize) -> bool {
    // ASCII lower-casing keeps every byte offset, so `at` indexes both.
    let lower = body.to_ascii_lowercase();
    let before = &lower[..at];
    let Some((open, _)) = before.rmatch_indices("<script").find(|(i, found)| {
        before
            .as_bytes()
            .get(i + found.len())
            .is_some_and(|b| b.is_ascii_whitespace() || *b == b'>' || *b == b'/')
    }) else {
        return false;
    };
    let Some(tag_end) = before[open..].find('>') else {
        return false;
    };
    let inner = &before[open + tag_end + 1..];
    !inner.contains("</script") && lower[at..].contains("</script")
}

/// The three context break-out canaries, each paired with the context it is
/// built for, in the order they are tried.
///
/// Each one is markup only: an element with no attributes, an attribute
/// break-out, and a JavaScript string break-out whose tail is a comment. None
/// of them executes anything even if a browser does parse it.
fn context_probes(tag: &str) -> [(Context, String); 3] {
    [
        // Element context: `<tag>x</tag>` survives only if `<` and `>` did.
        (Context::Element, format!("<{tag}>x</{tag}>")),
        // Attribute context: close the quote and the tag, then open ours.
        (Context::Attribute, format!("\"><{tag}>")),
        // JavaScript string context: close the string, then comment out the rest.
        (Context::JsString, format!("';{tag}//")),
    ]
}

/// The verdict for a canary that came back intact in its context.
fn reflected(
    point: &InsertionPoint,
    tag: &str,
    context: Context,
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
            "the {kind:?} point \"{name}\" reflected an unencoded canary into an HTML {status} \
             response: {survived}",
            kind = point.kind,
            name = point.name,
            survived = context.survived(),
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
            // The control sends the bare tag with no break-out at all. A
            // response that does not then contain the full canary tells us the
            // break-out, and not merely the word, is what came through.
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

            for (context, probe) in &probes {
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
                if context.reflected_in(&body, probe) {
                    return reflected(point, &tag, *context, probe, status, &resp, &body);
                }
            }

            tally.conclude(format!(
                "the canary was not reflected unencoded, in its context, into an HTML response \
                 after {planned} context probes"
            ))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{context_probes, inside_script_element, Context, CANARY_PREFIX};

    /// The canary is the prefix plus the job marker, and every probe carries it
    /// whole — a probe that dropped the tag would match any page. Each probe is
    /// paired with the context it breaks out of, in the order tried.
    #[test]
    fn the_three_context_probes_all_carry_the_whole_tag() {
        let tag = format!("{CANARY_PREFIX}abcd");
        let probes = context_probes(&tag);

        assert_eq!(tag, "aitmabcd");
        assert_eq!(
            probes,
            [
                (Context::Element, "<aitmabcd>x</aitmabcd>".to_string()),
                (Context::Attribute, "\"><aitmabcd>".to_string()),
                (Context::JsString, "';aitmabcd//".to_string()),
            ]
        );
        for (_, probe) in &probes {
            assert!(probe.contains(&tag), "{probe}");
        }
    }

    /// No probe may contain anything that executes, calls out or closes a
    /// document; the canary is inert markup and must stay that way.
    #[test]
    fn no_probe_contains_an_executable_construct() {
        let probes = context_probes("aitmabcd");
        for (_, probe) in &probes {
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

    /// Each context has its own sentence, and the markup ones never claim a
    /// quote or a comment, nor the script one an angle bracket (FQ-1).
    #[test]
    fn each_context_describes_what_its_own_probe_proves() {
        assert_eq!(
            Context::Element.survived(),
            "the tag survived byte for byte"
        );
        assert_eq!(
            Context::Attribute.survived(),
            "the quote and the tag survived"
        );
        assert_eq!(
            Context::JsString.survived(),
            "the quote, semicolon and comment survived inside a <script> block"
        );
    }

    /// The markup contexts need only the verbatim bytes; the script context
    /// needs a script element around them.
    #[test]
    fn markup_contexts_hit_on_bytes_and_the_script_context_needs_a_script() {
        let element = "<aitmabcd>x</aitmabcd>";
        assert!(Context::Element.reflected_in("<p><aitmabcd>x</aitmabcd></p>", element));
        assert!(!Context::Element.reflected_in("<p>&lt;aitmabcd&gt;</p>", element));
        assert!(Context::Attribute.reflected_in("<a href=\"\"><aitmabcd>\">", "\"><aitmabcd>"));

        let js = "';aitmabcd//";
        assert!(!Context::JsString.reflected_in("<p>';aitmabcd//</p>", js));
        assert!(Context::JsString.reflected_in("<script>var q='';aitmabcd//';</script>", js));
        // One echo outside and one inside: the inside one is the finding.
        assert!(Context::JsString.reflected_in(
            "<p>';aitmabcd//</p><script>var q='';aitmabcd//';</script>",
            js
        ));
    }

    fn at(body: &str, needle: &str) -> usize {
        body.find(needle).expect("the needle is in the body")
    }

    /// The containment rule and its edges: case, attributes on the open tag,
    /// a `</script` that an earlier string literal "contains", a look-alike
    /// tag name, an unclosed element, and an echo after the element.
    #[test]
    fn inside_script_element_follows_the_html_tokenizer() {
        let js = "';aitmabcd//";

        // Plain, upper-case and attribute-bearing open tags all count.
        for body in [
            "<script>var q='';aitmabcd//';</script>",
            "<SCRIPT>var q='';aitmabcd//';</SCRIPT>",
            "<script type=\"text/javascript\" nonce=\"x\">\nvar q='';aitmabcd//';\n</script>",
            "<script\n>var q='';aitmabcd//';</script >",
            "<html><body><p>hi</p><script>q='';aitmabcd//';</script></body></html>",
        ] {
            assert!(inside_script_element(body, at(body, js)), "{body}");
        }

        for body in [
            // No script at all.
            "<p>';aitmabcd//</p>",
            // After the element closed.
            "<script>var a=1;</script><p>';aitmabcd//</p>",
            // A `</script` inside an earlier string literal ends the element
            // for the HTML tokenizer, so the probe is outside it.
            "<script>var a='</script>';aitmabcd//</script>",
            // The element never closes.
            "<script>var q='';aitmabcd//';",
            // A look-alike tag name is not a script.
            "<scripty>';aitmabcd//</scripty>",
            // Inside the open tag itself, not between the tags.
            "<script data-q=\"';aitmabcd//\">var a=1;</script>",
            // An open tag that never ends.
            "<script ';aitmabcd//</script>",
        ] {
            assert!(!inside_script_element(body, at(body, js)), "{body}");
        }
    }
}
