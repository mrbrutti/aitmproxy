// check-header-reflection.rhai — catalogue check `header-reflection`, class
// `reflected-xss`.
//
// Request headers and cookies are inputs like any other, and the ones a page
// prints back — a forwarded host, a language, a tracking cookie — are easy to
// miss because no form shows them. The probe puts one unique marker in the
// header or cookie the point names and looks for that marker verbatim in an
// HTML body. A marker that survives into HTML is a value the page did not
// encode, which is where reflected XSS starts.
//
// The marker is random letters: it carries no script and no markup, so the
// probe cannot itself execute anything. A non-HTML body is not a finding —
// an API that echoes the header into JSON is not a browser injection.
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
    description: "Puts a unique marker in the header or cookie the point names and reports when it comes back verbatim in an HTML response body.",
    remediation: "Treat headers and cookies as untrusted input and HTML-escape them on output, or stop echoing them at all.",
};

fn load(reg) {
    reg.add_check(META, |point| {
        let base = if type_of(point.example) == "string" { point.example } else { "aitm" };
        let marker = probe.marker();
        let reply = probe.send(marker);
        let content_type = reply.headers["content-type"];
        let is_html = type_of(content_type) == "string" && contains_ci(content_type, "html");

        if is_html && reply.body.contains(marker) {
            return #{
                outcome: "vulnerable",
                confidence: "certain",
                evidence: #{ payload: marker, matched: marker },
                detail: `The "${point.name}" ${point.kind} is printed into this page's HTML unencoded: the marker ${marker} came back verbatim. Attacker-controlled markup reaches the browser from here.`,
                // The PoC re-sends the marker and must find it in the body; the
                // control sends the value the request already carried and must not.
                poc_hint: #{
                    matchers: [ #{ type: "word", word: marker, part: "body" } ],
                    control: #{
                        payload: base,
                        matchers: [ #{ not: #{ type: "word", word: marker, part: "body" } } ],
                    },
                },
            };
        }

        #{
            outcome: "clean",
            confidence: "firm",
            evidence: #{ payload: marker, matched: () },
            detail: "The marker placed in this header did not come back in an HTML body.",
        }
    });
}
