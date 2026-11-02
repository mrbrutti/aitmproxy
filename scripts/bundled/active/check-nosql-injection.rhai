// check-nosql-injection.rhai — catalogue check `nosqli`, class `nosqli`.
//
// A document store takes a query operator where a web form meant to pass a
// string. Two signals say the value is parsed as a document rather than
// compared as text: the parser's own error, and a result set that changes
// size when the comparison is inverted. Both are read-only queries — the
// shipped script's operators, unchanged, and no write is attempted.
//
// OWASP A03 Injection. CWE-943.
const NAME = "check-nosql-injection";
const API  = "1";

// The shipped script's error signatures, verbatim.
const NOSQL_ERR = "(?i)(MongoError|CastError|BSONError|E11000|unexpected token|\\$where|mongoose)";

const META = #{
    id: "nosqli",
    name: "NoSQL operator injection",
    class: "nosqli",
    lanes: ["http"],
    kinds: ["query", "body_param"],
    intensity: "medium",
    cost: "light",
    technique: "boolean",
    severity: "high",
    confidence_max: "firm",
    needs_baseline: true,
    cwe: 943,
    description: "Sends a query-operator object in place of the value and reports a database error or a result set whose size changes when the comparison is inverted.",
    remediation: "Coerce request values to the type the query expects and reject objects where a scalar is meant; never interpolate a request value into a query document.",
};

fn load(reg) {
    reg.add_check(META, |point| {
        let base = if type_of(point.example) == "string" { point.example } else { "1" };
        let baseline = probe.baseline();

        // 1) An operator object where a scalar belongs often trips the parser.
        let operator = `{"$ne": null}`;
        let errored = probe.send(operator);
        if regex_match(NOSQL_ERR, errored.body) {
            return #{
                outcome: "vulnerable",
                confidence: "firm",
                evidence: #{ payload: operator, matched: "NoSQL database error signature" },
                detail: `A query operator in "${point.name}" produced a database error, so the value is parsed as part of the query document.`,
            };
        }

        // 2) "not equal to a value nothing holds" should widen the result set.
        let inverted = `{"$ne": "${base}aitmX"}`;
        let widened = probe.send(inverted);
        let delta = widened.body.len() - baseline.body.len();
        if delta < 0 { delta = -delta; }
        let threshold = if baseline.body.len() / 10 > 80 { baseline.body.len() / 10 } else { 80 };
        if baseline.status == 200 && widened.status == 200 && delta > threshold {
            return #{
                outcome: "vulnerable",
                confidence: "firm",
                evidence: #{
                    payload: inverted,
                    matched: `result set ${baseline.body.len()} -> ${widened.body.len()} bytes`,
                },
                detail: `Inverting the comparison on "${point.name}" changed the result set materially (${baseline.body.len()} -> ${widened.body.len()} bytes), so the operator reached the query.`,
            };
        }

        #{
            outcome: "clean",
            confidence: "firm",
            evidence: #{ payload: inverted, matched: () },
            detail: "A query operator in this value produced neither a database error nor a different result set.",
        }
    });
}
