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

use std::ops::Range;
use std::sync::Arc;

use aitm_poc::{Assertion, MatchPart, Severity};
use aitm_scan_model::{
    Check, CheckCost, CheckMeta, CheckOrigin, Confidence, ControlHint, Evidence, InsertionKind,
    InsertionPoint, Intensity, LaneKind, Outcome, Payload, PayloadMode, PocHint, ProbeHost,
    ProbeResponse, Technique, Verdict,
};
use futures::future::BoxFuture;

use crate::gate::{may_send, point_label, ProbeTally};
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
    ///
    /// The body is target-controlled, so the script rule is linear in it: one
    /// lower-casing, one pass that lists the script contents
    /// ([`script_content_ranges`]), then one pass that places each echo in
    /// them. Nothing here is repeated per echo.
    fn reflected_in(self, body: &str, probe: &str) -> bool {
        match self {
            Context::Element | Context::Attribute => body.contains(probe),
            Context::JsString => {
                // ASCII lower-casing keeps every byte offset, so ranges found
                // in the lowered copy index the original body too.
                let ranges = script_content_ranges(&body.to_ascii_lowercase());
                if ranges.is_empty() {
                    return false;
                }
                body.match_indices(probe)
                    .any(|(at, _)| within_any(&ranges, at))
            }
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

/// The elements whose body the tokenizer reads as raw text up to the matching
/// end tag — RCDATA (`<title>`, `<textarea>`) and RAWTEXT (`<style>`,
/// `<xmp>`, `<iframe>`, `<noembed>`, `<noframes>`, `<noscript>`) — paired
/// with that end tag: a `<script` inside one is text, not a tag, and must not
/// open a script context.
const RAW_BODY_ELEMENTS: [(&str, &str); 8] = [
    ("title", "</title"),
    ("textarea", "</textarea"),
    ("style", "</style"),
    ("xmp", "</xmp"),
    ("iframe", "</iframe"),
    ("noembed", "</noembed"),
    ("noframes", "</noframes"),
    ("noscript", "</noscript"),
];

/// The byte ranges of `lower` — an ASCII-lower-cased HTML body — that are the
/// content of a `<script>` element: from just after the `>` that closes each
/// `<script ...>` open tag to the `</script` that ends it. One forward pass,
/// so the cost is linear in the body however many script tags or echoes it
/// holds; the ranges come out in document order and never overlap.
///
/// The rule follows the HTML tokenizer, not JavaScript:
///
/// - Inside a script element the tokenizer ends the element at the first
///   `</script` it sees, quoted or not, so a `</script` inside an earlier
///   string literal ends it here too. An element that never closes, and an
///   open tag that never ends, contribute nothing.
/// - Tag names match ASCII case-insensitively (`<SCRIPT>` is a script), and
///   a tag name counts only when a delimiter — whitespace, `>` or `/` —
///   follows it (or, for an end tag, the body ends), so `<scripty>` opens no
///   script and `</scripty` closes none.
/// - A `<script` inside an HTML comment (`<!-- ... -->` or `<!-- ... --!>`,
///   including the abruptly closed `<!-->` and `<!--->`) or inside the raw-text body of
///   one of [`RAW_BODY_ELEMENTS`] is text, not a tag, and opens nothing; a
///   `<plaintext>` turns the rest of the document into text. A comment or
///   raw-text body that never closes swallows the rest of the document, as
///   it does for the tokenizer.
/// - Any other tag-like run — `<` and an ASCII letter, `</`, `<!` or `<?` —
///   is read through to its first `>`, so a `<script` inside an attribute
///   value or a bogus comment (`<![CDATA[`, `<!DOCTYPE`, `<?xml`) opens
///   nothing either.
///
/// Not modelled, each a documented divergence that desynchronises the pass
/// from the tokenizer, after which a later `<script` may be read in either
/// direction (a hidden reflection, or, on a page built for it, an invented
/// one): a `>` inside an attribute value ends its tag early, so the rest of
/// that tag is read as content; the double-escaped state a `<!--<script>`
/// inside a script enters, where the tokenizer needs a second `</script>`
/// before the element ends, is read here as ending at the first one; and
/// foreign content (`<svg>`, `<math>`) is read as HTML, although there
/// `<![CDATA[ ... ]]>` is a CDATA section and `<script>`, `<style>` and
/// `<title>` do not change the tokenizer state.
fn script_content_ranges(lower: &str) -> Vec<Range<usize>> {
    let mut ranges = Vec::new();
    let mut i = 0;
    while let Some(lt) = lower[i..].find('<').map(|off| i + off) {
        let rest = &lower[lt..];
        if rest.starts_with("<!--") {
            let Some(next) = comment_end(lower, lt) else {
                break;
            };
            i = next;
            continue;
        }
        if opens_element(rest, "plaintext") {
            break;
        }
        if let Some((_, end_tag)) = RAW_BODY_ELEMENTS
            .iter()
            .find(|(name, _)| opens_element(rest, name))
        {
            let Some(body) = raw_text_body(lower, lt, end_tag) else {
                break;
            };
            i = body.end + end_tag.len();
            continue;
        }
        if opens_element(rest, "script") {
            let Some(body) = raw_text_body(lower, lt, "</script") else {
                break;
            };
            i = body.end + "</script".len();
            ranges.push(body);
            continue;
        }
        if starts_tag_like(rest) {
            let Some(tag_end) = rest.find('>') else {
                break;
            };
            i = lt + tag_end + 1;
            continue;
        }
        i = lt + 1;
    }
    ranges
}

/// The body of the raw-text or script element whose open tag starts at `lt`
/// in `lower`: from one past the first `>` of the open tag to the delimited
/// `end_tag` that closes it. `None` when the open tag never ends or the
/// element never closes; both swallow the rest of the document.
fn raw_text_body(lower: &str, lt: usize, end_tag: &str) -> Option<Range<usize>> {
    let content = lt + lower[lt..].find('>')? + 1;
    let off = find_end_tag(&lower[content..], end_tag)?;
    Some(content..content + off)
}

/// Where the comment that opens at `lt` (`<!--`) in `lower` ends: one past
/// the `>` of its `-->` or `--!>` close. The comment's own dashes may serve
/// as the close, so `<!-->` and `<!--->` are complete comments, but `<!--!>`
/// is not: the `--` of a `--!>` close must come after the opener. One
/// forward pass over the `>`s, so linear in the body.
fn comment_end(lower: &str, lt: usize) -> Option<usize> {
    let bytes = lower.as_bytes();
    let mut p = lt + "<!--".len();
    while let Some(off) = lower[p..].find('>') {
        let g = p + off;
        if &bytes[g - 2..g] == b"--" || (g >= lt + 7 && &bytes[g - 3..g] == b"--!") {
            return Some(g + 1);
        }
        p = g + 1;
    }
    None
}

/// Whether `b` may follow a tag name: whitespace, `>` or `/`.
fn is_tag_name_delimiter(b: u8) -> bool {
    b.is_ascii_whitespace() || b == b'>' || b == b'/'
}

/// Whether `rest`, which starts at a `<`, opens an element named `name`: the
/// name must be followed by a delimiter, so that `<scripty>` does not open a
/// `script`.
fn opens_element(rest: &str, name: &str) -> bool {
    rest.strip_prefix('<')
        .and_then(|r| r.strip_prefix(name))
        .and_then(|r| r.bytes().next())
        .is_some_and(is_tag_name_delimiter)
}

/// Where `end_tag` (`</name`) first ends an element in `hay`: the first
/// occurrence whose name is followed by a delimiter or by the end of the
/// body, so that `</scripty` ends no script.
fn find_end_tag(hay: &str, end_tag: &str) -> Option<usize> {
    hay.match_indices(end_tag).map(|(at, _)| at).find(|&at| {
        hay.as_bytes()
            .get(at + end_tag.len())
            .is_none_or(|b| is_tag_name_delimiter(*b))
    })
}

/// Whether `rest`, which starts at a `<`, begins a run the tokenizer reads
/// through to its first `>` as markup rather than text: a tag (`<` and an
/// ASCII letter), an end tag (`</`), a markup declaration or bogus comment
/// (`<!`) or a processing instruction (`<?`).
fn starts_tag_like(rest: &str) -> bool {
    rest.as_bytes()
        .get(1)
        .is_some_and(|b| b.is_ascii_alphabetic() || matches!(b, b'/' | b'!' | b'?'))
}

/// Whether `at` lies in one of `ranges`, which are in order and disjoint (as
/// [`script_content_ranges`] returns them), by binary search.
fn within_any(ranges: &[Range<usize>], at: usize) -> bool {
    // The first range that ends after `at` is the only one that can hold it.
    let i = ranges.partition_point(|r| r.end <= at);
    ranges.get(i).is_some_and(|r| r.contains(&at))
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
            name = point_label(point),
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
    use std::ops::Range;

    use super::{
        context_probes, script_content_ranges, within_any, Context, CANARY_PREFIX,
        RAW_BODY_ELEMENTS,
    };

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

    /// The containment oracle the check applies, built on the ranges: whether
    /// byte offset `at` of `body` is script content.
    fn inside_script_element(body: &str, at: usize) -> bool {
        within_any(&script_content_ranges(&body.to_ascii_lowercase()), at)
    }

    /// Each raw-text element's end tag is its own name, so a copy-paste row
    /// cannot make one element swallow the document.
    #[test]
    fn every_raw_body_element_closes_with_its_own_end_tag() {
        for (name, end_tag) in RAW_BODY_ELEMENTS {
            assert_eq!(end_tag, format!("</{name}"));
        }
    }

    /// The pass lists exactly the content spans, in order, whatever the case
    /// of the tags, and an echo is placed by the span it falls in.
    #[test]
    fn script_content_ranges_are_the_spans_between_each_open_and_close_tag() {
        let body = "<p>a</p><script>x</script><SCRIPT y>z</SCRIPT>";
        let ranges = script_content_ranges(&body.to_ascii_lowercase());
        assert_eq!(ranges, vec![16..17, 36..37]);
        assert_eq!(&body[16..17], "x");
        assert_eq!(&body[36..37], "z");

        assert!(within_any(&ranges, 16));
        assert!(within_any(&ranges, 36));
        for outside in [0, 15, 17, 35, 37, 45, 1000] {
            assert!(!within_any(&ranges, outside), "{outside}");
        }
        assert!(!within_any(&[], 0));
        assert_eq!(
            script_content_ranges("<p>no script here</p>"),
            Vec::<Range<usize>>::new()
        );
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

    /// A literal `<script>` that the tokenizer never reads as a tag — inside
    /// an HTML comment, or inside the RCDATA body of a `<title>` or
    /// `<textarea>` — opens no script context, so an echo after it in a
    /// paragraph is still text (F7-2), and so is one inside a RAWTEXT body, an
    /// attribute value, a bogus comment or after `<plaintext>` (F7b). The same
    /// echo inside a real script element that follows the decoy is still the
    /// finding.
    #[test]
    fn a_script_tag_in_a_comment_or_rcdata_body_opens_no_script_context() {
        let js = "';aitmabcd//";

        for body in [
            "<title><script></title><p>you searched for ';aitmabcd//</p><script>init()</script>",
            "<textarea><script></textarea><p>';aitmabcd//</p><script>init()</script>",
            "<!-- <script> --><p>';aitmabcd//</p><script>x()</script>",
            // An unterminated comment swallows the rest of the document.
            "<!-- <script><p>';aitmabcd//</p><script>x()</script>",
            // An unterminated RCDATA body does too.
            "<title><script><p>';aitmabcd//</p><script>x()</script>",
            // RAWTEXT bodies, an attribute value and a bogus comment are text
            // or markup the tokenizer never reads as a script tag (F7b).
            "<style>/*<script>*/</style><p>';aitmabcd//</p><script>x()</script>",
            "<noscript><script></noscript><p>';aitmabcd//</p><script>x()</script>",
            "<div title=\"<script>\"><p>';aitmabcd//</p><script>x()</script>",
            "<![CDATA[<script>]]><p>';aitmabcd//</p><script>x()</script>",
            "<?xml <script> ?><p>';aitmabcd//</p><script>x()</script>",
            // `</textareax` ends no textarea, so its `<script>` is still text.
            "<textarea></textareax <script> </textarea><p>';aitmabcd//</p><script>x()</script>",
            // `<plaintext>` turns the rest of the document into text.
            "<plaintext><script><p>';aitmabcd//</p><script>x()</script>",
            // `</scripty>` ends no script, so the element never closes.
            "<script>x</scripty><p>';aitmabcd//</p>",
            // `--!>` closes a comment, so the `-->` is title text and the
            // echo is title text too (F7c).
            "<!--x--!><title>--><script>';aitmabcd//</script></title>",
            // `<!--!>` is not a closed comment; it swallows the rest.
            "<!--!><script>q='';aitmabcd//';</script>",
            // An end tag is read through to its first `>`, attributes and all.
            "</div <script> ><p>';aitmabcd//</p><script>x()</script>",
        ] {
            assert!(!Context::JsString.reflected_in(body, js), "{body}");
        }

        for body in [
            "<!-- <script> --><script>var q='';aitmabcd//';</script>",
            "<title><script></title><script>var q='';aitmabcd//';</script>",
            "<TITLE>x</TITLE><SCRIPT>var q='';aitmabcd//';</SCRIPT>",
            // A decoy before, a real echo inside, a text echo after.
            "<!-- <script> --><p>';aitmabcd//</p><script>q='';aitmabcd//';</script><p>';aitmabcd//</p>",
            "<style>/*<script>*/</style><script>var q='';aitmabcd//';</script>",
            // A `</scripty` inside the script does not end it.
            "<script>var q='';aitmabcd//'; // </scripty\n</script>",
            // The body may end right after the closing tag's name.
            "<script>var q='';aitmabcd//';</script",
            // A comment closed by `--!>` hides nothing after it.
            "<!-- x --!><script>var q='';aitmabcd//';</script>",
            "<!--><script>var q='';aitmabcd//';</script>",
        ] {
            assert!(Context::JsString.reflected_in(body, js), "{body}");
        }
    }

    /// One mebibyte of nothing but the probe, with no script element at all,
    /// resolves clean in well under the bound: the containment rule is one
    /// pass over the body, not one pass per echo (F7-1; the quadratic version
    /// took 16 s on this input, the pass takes milliseconds; the bound is
    /// loose enough for a loaded debug gate and still two orders below the
    /// regression).
    #[test]
    fn a_body_of_repeated_echoes_and_no_script_resolves_clean_in_bounded_time() {
        let js = "';aitmabcd//";
        let body = js.repeat((1 << 20) / js.len() + 1);
        assert!(body.len() >= 1 << 20, "{}", body.len());

        let started = std::time::Instant::now();
        let hit = Context::JsString.reflected_in(&body, js);
        let took = started.elapsed();

        assert!(!hit);
        assert!(took < std::time::Duration::from_secs(2), "took {took:?}");
    }

    /// One mebibyte with ten thousand text echoes and one script element around
    /// the last of them resolves vulnerable in well under the bound (F7-1).
    #[test]
    fn a_body_of_many_echoes_with_one_script_echo_resolves_vulnerable_in_bounded_time() {
        let js = "';aitmabcd//";
        let filler = "x".repeat(85);
        let mut body = String::with_capacity(1 << 20);
        for _ in 0..9_999 {
            body.push_str("<p>';aitmabcd//</p>");
            body.push_str(&filler);
        }
        body.push_str("<script>var q='';aitmabcd//';</script>");
        while body.len() < 1 << 20 {
            body.push_str(&filler);
        }
        assert_eq!(body.matches(js).count(), 10_000);
        assert!(body.len() >= 1 << 20, "{}", body.len());

        let started = std::time::Instant::now();
        let hit = Context::JsString.reflected_in(&body, js);
        let took = started.elapsed();

        assert!(hit);
        assert!(took < std::time::Duration::from_secs(2), "took {took:?}");
    }
}
