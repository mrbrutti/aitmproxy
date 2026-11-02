// check-sqli.rhai — catalogue check `sqli`, class `sqli`, error technique.
//
// A single quote closes a string literal early. Where the point's value reaches
// the database unparameterised, the engine answers with its own syntax error,
// and that error text is the whole finding: the probe reads no row and changes
// no row, it only makes the parser complain about an unbalanced quote.
//
// The shipped script's boolean-differential half is gone. Native `sqli-boolean`
// owns that technique now, so one class has one source per technique and the
// two dedupe into a single issue (spec D6).
//
// OWASP A03 Injection. CWE-89.
const NAME = "check-sqli";
const API  = "1";

// Database error signatures, carried over verbatim from the shipped script.
const SQL_ERR = "(?i)(SQL syntax.*MySQL|SQL syntax error|syntax error at or near|ORA-[0-9]{5}|PostgreSQL.*ERROR|SQLSTATE\\[|SQLiteException|Unclosed quotation mark|SqlException|psycopg2\\.|sqlalchemy\\.exc\\.|Warning.*mysqli?_|quoted string not properly terminated)";

const META = #{
    id: "sqli",
    name: "SQL injection (error-based)",
    class: "sqli",
    lanes: ["http"],
    kinds: ["query", "body_param", "json_value", "cookie"],
    intensity: "medium",
    cost: "light",
    technique: "error",
    severity: "critical",
    confidence_max: "firm",
    needs_baseline: false,
    cwe: 89,
    description: "Appends a single quote to the value and looks for a database error signature in the reply.",
    remediation: "Use parameterised queries or prepared statements; never concatenate request values into SQL.",
};

fn load(reg) {
    reg.add_check(META, |point| {
        // Start from the value the application already accepts here, so the
        // quote lands in the context the query actually parses.
        let base = if type_of(point.example) == "string" { point.example } else { "1" };
        let payload = base + "'";

        let reply = probe.send(payload);
        if regex_match(SQL_ERR, reply.body) {
            return #{
                outcome: "vulnerable",
                confidence: "firm",
                evidence: #{ payload: payload, matched: "database error signature" },
                detail: `A single quote in "${point.name}" provoked a database error, so the value reaches the query unparameterised.`,
                // The PoC re-sends the quote and must see the same error; the
                // control re-sends the untouched value and must not.
                poc_hint: #{
                    matchers: [ #{ type: "regex", regex: SQL_ERR, part: "body" } ],
                    control: #{
                        payload: base,
                        matchers: [ #{ not: #{ type: "regex", regex: SQL_ERR, part: "body" } } ],
                    },
                },
            };
        }

        #{
            outcome: "clean",
            confidence: "firm",
            evidence: #{ payload: payload, matched: () },
            detail: "A quote in this value produced no database error signature.",
        }
    });
}
