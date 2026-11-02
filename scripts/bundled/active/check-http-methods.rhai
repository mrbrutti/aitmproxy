// check-http-methods.rhai — catalogue check `methods`, class
// `risky-http-methods`.
//
// One OPTIONS request, and the origin itself says which methods it will take.
// Where that list includes a write or a debug method, the operator is told to
// confirm it is intended: the check never sends PUT, DELETE or TRACE, it only
// reads the advertised `Allow`.
//
// An origin-level audit (`scope: "origin"`): the answer belongs to the
// authority. `probe.raw` composes the OPTIONS because no insertion point
// carries a method.
//
// OWASP A05 Security Misconfiguration.
const NAME = "check-http-methods";
const API  = "1";

// The shipped script's list of methods worth a second look.
const RISKY = ["PUT", "DELETE", "TRACE", "CONNECT", "PATCH"];

const META = #{
    id: "methods",
    name: "Risky HTTP methods advertised",
    class: "risky-http-methods",
    lanes: ["http"],
    kinds: ["query"],
    scope: "origin",
    intensity: "light",
    cost: "light",
    technique: "observe",
    severity: "info",
    confidence_max: "certain",
    needs_baseline: false,
    description: "Sends one OPTIONS request and reports when the advertised Allow header offers a write or debug method.",
    remediation: "Serve only the methods a route implements, and disable TRACE and CONNECT at the edge.",
};

fn load(reg) {
    reg.add_check(META, |point| {
        let reply = probe.raw(#{ method: "OPTIONS", url: point.url });
        let allow = reply.headers["allow"];
        if type_of(allow) != "string" || allow == "" {
            return #{
                outcome: "inconclusive",
                confidence: "certain",
                evidence: #{ payload: "OPTIONS " + point.url, matched: () },
                detail: `OPTIONS ${point.url} answered HTTP ${reply.status} with no Allow header, so the origin advertises nothing.`,
            };
        }

        let upper = allow.to_upper();
        let risky = "";
        for method in RISKY {
            if upper.contains(method) {
                risky = if risky == "" { method } else { risky + ", " + method };
            }
        }

        if risky != "" {
            return #{
                outcome: "vulnerable",
                confidence: "certain",
                evidence: #{ payload: "OPTIONS " + point.url, matched: "allow: " + allow },
                detail: `${point.url} advertises ${risky} in its Allow header (${allow}); confirm each is intended.`,
            };
        }

        #{
            outcome: "clean",
            confidence: "certain",
            evidence: #{ payload: "OPTIONS " + point.url, matched: () },
            detail: `${point.url} advertises only safe methods (${allow}).`,
        }
    });
}
