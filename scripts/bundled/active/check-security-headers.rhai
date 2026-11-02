// check-security-headers.rhai — catalogue check `headers`, class
// `missing-security-headers`.
//
// The cheapest audit there is: the point's baseline response has already been
// fetched, so this check sends nothing at all and only reads which of the five
// standard protective headers are absent. That is why it declares
// `intensity: "passive"` and `technique: "passive"` — no probe leaves.
//
// It is an origin-level audit (`scope: "origin"`): the header set belongs to
// the authority, so one verdict covers it however many points it has.
//
// OWASP A05 Security Misconfiguration.
const NAME = "check-security-headers";
const API  = "1";

// The shipped script's list, lower-cased: probe headers are a lower-case map.
const WANTED = ["strict-transport-security", "content-security-policy",
                "x-content-type-options", "x-frame-options", "referrer-policy"];

const META = #{
    id: "headers",
    name: "Missing security headers",
    class: "missing-security-headers",
    lanes: ["http"],
    kinds: ["query"],
    scope: "origin",
    intensity: "passive",
    cost: "light",
    technique: "passive",
    severity: "low",
    confidence_max: "certain",
    needs_baseline: true,
    description: "Reads the point's baseline response and reports which of HSTS, CSP, X-Content-Type-Options, X-Frame-Options and Referrer-Policy are absent.",
    remediation: "Set the missing headers at the edge for every response, starting with Content-Security-Policy and Strict-Transport-Security.",
};

fn load(reg) {
    reg.add_check(META, |point| {
        let reply = probe.baseline();
        let missing = "";
        let count = 0;
        for name in WANTED {
            // An empty value protects nothing, so it counts as missing.
            let value = reply.headers[name];
            if type_of(value) != "string" || value == "" {
                count += 1;
                missing = if missing == "" { name } else { missing + ", " + name };
            }
        }

        if count > 0 {
            return #{
                outcome: "vulnerable",
                confidence: "certain",
                evidence: #{ payload: "GET " + point.url, matched: missing },
                detail: `${point.url} (HTTP ${reply.status}) is missing ${count} security header(s): ${missing}.`,
            };
        }

        #{
            outcome: "clean",
            confidence: "certain",
            evidence: #{ payload: "GET " + point.url, matched: () },
            detail: "All five standard security headers are present on this origin's responses.",
        }
    });
}
