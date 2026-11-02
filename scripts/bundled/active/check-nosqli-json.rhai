// check-nosqli-json.rhai — catalogue check `nosqli-json`, class `nosqli`.
//
// The JSON sibling of `nosqli`. Where a request body is JSON, a value slot can
// hold an object as easily as a string, so the operator goes in whole: the
// point's string value is replaced by a one-key operator document. A store
// that compares the document instead of the string answers with a different
// result set, and that size difference against the point's own baseline is the
// finding.
//
// Read-only: both operators only widen a comparison, neither writes. New in
// the v2 catalogue (spec D8.2) — the shipped scripts had no JSON-body check.
//
// OWASP A03 Injection. CWE-943.
const NAME = "check-nosqli-json";
const API  = "1";

const META = #{
    id: "nosqli-json",
    name: "NoSQL operator injection (JSON body)",
    class: "nosqli",
    lanes: ["http"],
    kinds: ["json_value"],
    intensity: "medium",
    cost: "light",
    technique: "boolean",
    severity: "critical",
    confidence_max: "firm",
    needs_baseline: true,
    cwe: 943,
    description: "Replaces a JSON string value with a one-key query-operator document and reports a result set whose size changes materially against the baseline.",
    remediation: "Validate the JSON body against a schema that says the field is a string, and reject objects in value positions before the query is built.",
};

fn load(reg) {
    reg.add_check(META, |point| {
        let baseline = probe.baseline();
        // "not equal to nothing" and "greater than the empty string": both match
        // every document the honest comparison narrowed away.
        let operators = [`{"$ne": null}`, `{"$gt": ""}`];
        let threshold = if baseline.body.len() / 10 > 80 { baseline.body.len() / 10 } else { 80 };

        for operator in operators {
            let widened = probe.send(#{ value: operator, mode: "replace" });
            let delta = widened.body.len() - baseline.body.len();
            if delta < 0 { delta = -delta; }

            if baseline.status == 200 && widened.status == 200 && delta > threshold {
                return #{
                    outcome: "vulnerable",
                    confidence: "firm",
                    evidence: #{
                        payload: operator,
                        matched: `result set ${baseline.body.len()} -> ${widened.body.len()} bytes`,
                    },
                    detail: `"${point.name}" accepted a query operator in place of its JSON string value and the result set changed materially (${baseline.body.len()} -> ${widened.body.len()} bytes).`,
                };
            }
        }

        #{
            outcome: "clean",
            confidence: "firm",
            evidence: #{ payload: operators[0], matched: () },
            detail: "A query operator in this JSON value did not change the result set.",
        }
    });
}
