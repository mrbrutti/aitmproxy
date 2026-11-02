// check-crlf-injection.rhai — catalogue check `crlf`, class `crlf`.
//
// A value that reaches the response's header block with its line breaks intact
// lets a request write a header of its own. The probe appends an encoded line
// break and one inert canary header to the value the point already carries;
// the finding is that canary coming back among the *response headers*, which
// only a front end that decoded the break can produce.
//
// Nothing is poisoned and no session is fixed: the canary is read, never
// acted on. The three encodings are the shipped script's, unchanged.
// OWASP A03 Injection. CWE-113.
const NAME = "check-crlf-injection";
const API  = "1";

// Lower-case: a probe response's `headers` is a map of lower-case name -> value.
const CANARY_HEADER = "x-aitm-crlf";

const META = #{
    id: "crlf",
    name: "CRLF response-header injection",
    class: "crlf",
    lanes: ["http"],
    kinds: ["query", "body_param", "header"],
    intensity: "medium",
    cost: "light",
    technique: "reflected",
    severity: "high",
    confidence_max: "firm",
    needs_baseline: false,
    cwe: 113,
    description: "Appends an encoded line break and an inert canary header to the value and reports when the canary appears among the response headers.",
    remediation: "Reject or strip CR and LF before a request value is written into a response header, and use an API that encodes header values.",
};

fn load(reg) {
    reg.add_check(META, |point| {
        let base = if type_of(point.example) == "string" { point.example } else { "x" };
        // The job's own marker, not random letters: the host mints it fresh on
        // every call, so it is taken once here and reused for the payload, the
        // evidence and the hint, and the canary in a reply
        // can be tied back to the run that put it there — and the PoC below,
        // replayed later, looks for a value that is written down rather than
        // one that was thrown away when the check returned.
        let canary = probe.marker();
        // The control characters themselves, not their percent-encoding: the
        // lane owns the encoding of whatever a check hands `probe.send` (spec
        // D4), so a pre-encoded `%0d%0a` would reach the wire as `%250d%250a`
        // and never fold into a line break. Three forms: CR LF with a space
        // after the colon, the same without, and the overlong unicode pair
        // (U+560D U+560A) some front ends fold down to CR LF.
        let payloads = [
            base + "\r\nX-Aitm-Crlf: " + canary,
            base + "\r\nX-Aitm-Crlf:" + canary,
            base + "嘍嘊X-Aitm-Crlf:" + canary,
        ];

        for payload in payloads {
            let echoed = probe.send(payload).headers[CANARY_HEADER];
            if type_of(echoed) == "string" && contains_ci(echoed, canary) {
                return #{
                    outcome: "vulnerable",
                    confidence: "firm",
                    evidence: #{ payload: payload, matched: CANARY_HEADER + ": " + canary },
                    detail: `"${point.name}" wrote a header of its own into the reply: the canary ${CANARY_HEADER} came back. A value that reaches the header block enables response splitting and cache poisoning.`,
                    // The PoC re-sends the break and must see the canary header;
                    // the control sends the plain value and must not.
                    poc_hint: #{
                        matchers: [ #{ type: "word", word: canary, part: "header" } ],
                        control: #{
                            payload: base,
                            matchers: [ #{ not: #{ type: "word", word: canary, part: "header" } } ],
                        },
                    },
                };
            }
        }

        #{
            outcome: "clean",
            confidence: "firm",
            evidence: #{ payload: payloads[0], matched: () },
            detail: "No encoding of a line break in this value reached the response header block.",
        }
    });
}
