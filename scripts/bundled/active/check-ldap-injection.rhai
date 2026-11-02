// check-ldap-injection.rhai — catalogue check `ldapi`, class `ldapi`.
//
// An LDAP search filter is built from parentheses and operators. A value that
// carries those metacharacters into the filter either breaks it — the
// directory says so in its own words — or rewrites it into one that is always
// true, which returns more entries than the honest query did.
//
// Both probes only search: the shipped script's metacharacters, unchanged,
// and no modify or bind is attempted. OWASP A03 Injection. CWE-90.
const NAME = "check-ldap-injection";
const API  = "1";

// The shipped script's error signatures, verbatim.
const LDAP_ERR = "(?i)(LDAP:.*error|javax\\.naming|com\\.sun\\.jndi|invalid DN syntax|bad search filter|Protocol error.*ldap|OpenLDAP)";

const META = #{
    id: "ldapi",
    name: "LDAP filter injection",
    class: "ldapi",
    lanes: ["http"],
    kinds: ["query", "body_param"],
    intensity: "medium",
    cost: "light",
    technique: "boolean",
    severity: "high",
    confidence_max: "firm",
    needs_baseline: true,
    cwe: 90,
    description: "Puts LDAP filter metacharacters in the value and reports a directory error or an always-true filter that returns a materially larger result set.",
    remediation: "Escape the filter metacharacters of RFC 4515 in every request value, or build the filter from a parameterised API instead of string concatenation.",
};

fn load(reg) {
    reg.add_check(META, |point| {
        let base = if type_of(point.example) == "string" { point.example } else { "x" };
        let baseline = probe.baseline();

        // 1) An unbalanced parenthesis leaves the filter unparseable.
        let unbalanced = base + ")(|(cn=*";
        let errored = probe.send(unbalanced);
        if regex_match(LDAP_ERR, errored.body) {
            return #{
                outcome: "vulnerable",
                confidence: "firm",
                evidence: #{ payload: unbalanced, matched: "LDAP directory error signature" },
                detail: `A filter metacharacter in "${point.name}" produced an LDAP error, so the value reaches the search filter unescaped.`,
            };
        }

        // 2) An always-true filter should return more than the honest query.
        let always_true = "*)(cn=*))%00";
        let widened = probe.send(always_true);
        let delta = widened.body.len() - baseline.body.len();
        if delta < 0 { delta = -delta; }
        let threshold = if baseline.body.len() / 10 > 80 { baseline.body.len() / 10 } else { 80 };
        if widened.status == 200 && delta > threshold {
            return #{
                outcome: "vulnerable",
                confidence: "firm",
                evidence: #{
                    payload: always_true,
                    matched: `result set ${baseline.body.len()} -> ${widened.body.len()} bytes`,
                },
                detail: `An always-true filter in "${point.name}" changed the result set materially (${baseline.body.len()} -> ${widened.body.len()} bytes).`,
            };
        }

        #{
            outcome: "clean",
            confidence: "firm",
            evidence: #{ payload: unbalanced, matched: () },
            detail: "Filter metacharacters in this value produced neither a directory error nor a different result set.",
        }
    });
}
