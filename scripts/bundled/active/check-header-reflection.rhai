// check-header-reflection.rhai — catalogue check `header-reflection`, class
// `reflected-xss`.
//
// Request headers and cookies are inputs like any other, and the ones a page
// prints back — a forwarded host, a language, a tracking cookie — are easy to
// miss because no form shows them.
//
// A bare marker is not enough to call this. T4's live run found pages that echo
// a header's letters while escaping everything dangerous around them, and a
// check that only looked for the letters called those vulnerable. So the probe
// sends a MARKUP-SIGNIFICANT payload: a quote and an angle bracket in front of
// the marker, the two characters that would break out of an attribute and open
// a tag. Only that payload coming back VERBATIM counts. If the page prints
// `&quot;&gt;&lt;` instead — or strips the punctuation and leaves the bare
// letters — the output was encoded and there is nothing to report; because
// every entity form of a quote or a bracket leaves the marker's letters alone,
// "the letters are there but the payload is not" recognises them all without
// listing each spelling.
//
// The payload still carries no script and no event handler: it cannot execute
// anything by itself, it only proves the page lets markup through.
//
// Two shapes are a finding, and nothing else is:
//   * the payload verbatim in the body of an HTML response — certain, this is
//     where reflected XSS starts;
//   * the payload verbatim in a response header — firm, which is header
//     injection into whatever reads that header next.
// A JSON or plain-text body that echoes it is neither: an API that returns the
// header it was sent is not a browser injection.
//
// OWASP A03 Injection. CWE-79.
const NAME = "check-header-reflection";
const API  = "1";

const META = #{
    id: "header-reflection",
    name: "Request header reflected into HTML",
    class: "reflected-xss",
    lanes: ["http"],
    kinds: ["header", "cookie"],
    intensity: "light",
    cost: "light",
    technique: "reflected",
    severity: "medium",
    confidence_max: "certain",
    needs_baseline: false,
    cwe: 79,
    description: "Puts a markup-significant marker in the header or cookie the point names and reports when it comes back unencoded in an HTML body, or verbatim in a response header.",
    remediation: "Treat headers and cookies as untrusted input and HTML-escape them on output, or stop echoing them at all.",
};

fn load(reg) {
    reg.add_check(META, |point| {
        // The control arm re-sends the value the request already carried, so
        // the reproduction shows the marker appearing only when we put it there.
        let base = if type_of(point.example) == "string" { point.example } else { "aitm" };
        let marker = probe.marker();
        // Header-legal ASCII: a quote and an angle bracket, then the marker.
        // Plain concatenation, not a template: a back-tick string in Rhai is
        // raw, so the quote could not be escaped inside one.
        let payload = "\"><" + marker;

        let reply = probe.send(payload);
        let content_type = reply.headers["content-type"];
        let is_html = type_of(content_type) == "string" && contains_ci(content_type, "html");

        if is_html && reply.body.contains(payload) {
            return #{
                outcome: "vulnerable",
                confidence: "certain",
                evidence: #{ payload: payload, matched: payload },
                detail: `The "${point.name}" ${point.kind} is printed into this page's HTML unencoded: ${payload} came back verbatim, quote and bracket intact. Attacker-controlled markup reaches the browser from here.`,
                poc_hint: #{
                    matchers: [ #{ type: "word", word: payload, part: "body" } ],
                    control: #{
                        payload: base,
                        matchers: [ #{ not: #{ type: "word", word: payload, part: "body" } } ],
                    },
                },
            };
        }

        // Back out in a response header: not an HTML injection, but whatever
        // parses that header next is being handed our punctuation.
        for name in reply.headers.keys() {
            let value = reply.headers[name];
            if type_of(value) == "string" && value.contains(payload) {
                return #{
                    outcome: "vulnerable",
                    confidence: "firm",
                    evidence: #{ payload: payload, matched: value },
                    detail: `The "${point.name}" ${point.kind} came back verbatim in the "${name}" response header.`,
                    poc_hint: #{
                        matchers: [ #{ type: "word", word: payload, part: "header" } ],
                        control: #{
                            payload: base,
                            matchers: [ #{ not: #{ type: "word", word: payload, part: "header" } } ],
                        },
                    },
                };
            }
        }

        if reply.body.contains(payload) {
            return #{
                outcome: "clean",
                confidence: "firm",
                evidence: #{ payload: payload, matched: () },
                detail: "The marker came back, but not in an HTML body: a non-HTML response is not a browser injection.",
            };
        }

        if reply.body.contains(marker) {
            return #{
                outcome: "clean",
                confidence: "firm",
                evidence: #{ payload: payload, matched: () },
                detail: "The marker came back HTML-encoded, which is what a page that escapes its output does.",
            };
        }

        #{
            outcome: "clean",
            confidence: "firm",
            evidence: #{ payload: payload, matched: () },
            detail: "The marker placed in this header did not come back at all.",
        }
    });
}
