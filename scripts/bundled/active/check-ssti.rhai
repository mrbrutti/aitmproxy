// check-ssti.rhai — catalogue check `ssti`, class `ssti`.
//
// A template engine that renders request data evaluates expressions written in
// its own syntax. The probe asks it to multiply two primes: if `73*79` comes
// back as 5767 next to a marker tag, the value was evaluated, not echoed. The
// product is a detection marker, not a code-execution payload — nothing is
// read, written or executed beyond the arithmetic.
//
// Four syntaxes cover the common engines: Jinja/Twig, FreeMarker/JSP-EL,
// Ruby/Thymeleaf and ERB. OWASP A03 Injection. CWE-1336.
const NAME = "check-ssti";
const API  = "1";

const META = #{
    id: "ssti",
    name: "Server-side template injection",
    class: "ssti",
    lanes: ["http"],
    kinds: ["query", "body_param", "json_value"],
    intensity: "medium",
    cost: "medium",
    technique: "reflected",
    severity: "critical",
    confidence_max: "certain",
    needs_baseline: false,
    cwe: 1336,
    description: "Sends an arithmetic marker in the major template syntaxes and reports when the server returns the evaluated product.",
    remediation: "Never build a template from request data; pass it as a bound variable to a fixed template, and sandbox the engine.",
};

fn load(reg) {
    reg.add_check(META, |point| {
        // Two primes, so the product is unlikely to appear by chance, and the
        // job's own marker as the tag, so the match is this probe's and nobody
        // else's. The marker rather than random letters: the oracle has to
        // recognise the tag coming back, and the marker is the one token the
        // engine, the evidence and a later PoC all agree on.
        let tag = probe.marker();
        let want = tag + `${73 * 79}`;
        // The second payload is assembled rather than interpolated: a literal
        // dollar-brace would be read by Rhai's own string interpolation.
        let payloads = [
            `${tag}{{73*79}}`,
            tag + "${" + "73*79" + "}",
            `${tag}#{73*79}`,
            `${tag}<%= 73*79 %>`,
        ];

        for payload in payloads {
            let reply = probe.send(payload);
            if reply.body.contains(want) {
                return #{
                    outcome: "vulnerable",
                    confidence: "certain",
                    evidence: #{ payload: payload, matched: want },
                    detail: `"${point.name}" evaluated a template expression: 73*79 came back rendered as ${want}. Template injection usually reaches remote code execution.`,
                    // The tag alone is the control: it must come back unchanged
                    // and without the product.
                    poc_hint: #{
                        matchers: [ #{ type: "word", word: want, part: "body" } ],
                        control: #{
                            payload: tag,
                            matchers: [ #{ not: #{ type: "word", word: want, part: "body" } } ],
                        },
                    },
                };
            }
        }

        #{
            outcome: "clean",
            confidence: "firm",
            evidence: #{ payload: payloads[0], matched: () },
            detail: "No template syntax was evaluated: the arithmetic marker never came back as its product.",
        }
    });
}
