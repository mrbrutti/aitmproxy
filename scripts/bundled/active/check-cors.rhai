// check-cors.rhai — catalogue check `cors`, class `cors`.
//
// A server that echoes whatever `Origin` it is given has no cross-origin
// policy at all; with credentials allowed, any site a victim visits can read
// authenticated responses. The probe asks the point's own URL once with a
// canary Origin nobody owns and reads two response headers back.
//
// This is an origin-level audit (`scope: "origin"`): the answer belongs to the
// authority, not to the value the point carries, so the host runs it once per
// origin however many points that origin has. It composes its own request
// through `probe.raw` because no insertion point carries an `Origin`.
//
// OWASP A05 Misconfiguration. CWE-942.
const NAME = "check-cors";
const API  = "1";

const META = #{
    id: "cors",
    name: "CORS reflects an arbitrary Origin",
    class: "cors",
    lanes: ["http"],
    kinds: ["query"],
    scope: "origin",
    intensity: "light",
    cost: "light",
    technique: "reflected",
    severity: "medium",
    confidence_max: "certain",
    needs_baseline: false,
    cwe: 942,
    description: "Requests the origin once with a canary Origin header and reports when it comes back in Access-Control-Allow-Origin, noting whether credentials are allowed too.",
    remediation: "Echo only origins on an allow-list, and never pair a reflected origin with Access-Control-Allow-Credentials: true.",
};

fn header_value(headers, name) {
    let value = headers[name];
    if type_of(value) == "string" { value } else { "" }
}

fn load(reg) {
    reg.add_check(META, |point| {
        // `point.url` is `()` when the lane recorded no URL for this point, and
        // an origin-scoped audit has no origin to attribute an answer to.
        if type_of(point.url) != "string" {
            return #{
                outcome: "inconclusive",
                confidence: "tentative",
                detail: "This insertion point carries no URL, so there is no origin to audit.",
            };
        }

        // A canary nobody owns, so a reflection cannot be a real allow-list hit.
        let canary = "https://" + probe.marker() + ".aitm-canary.example";
        let reply = probe.raw(#{ method: "GET", url: point.url, headers: #{ "origin": canary } });
        let allowed = header_value(reply.headers, "access-control-allow-origin");
        let credentialed = contains_ci(header_value(reply.headers, "access-control-allow-credentials"), "true");

        if allowed == canary {
            let with_credentials = if credentialed { " with credentials allowed, so authenticated responses are readable cross-origin" } else { "" };
            return #{
                outcome: "vulnerable",
                confidence: "certain",
                evidence: #{ payload: canary, matched: "access-control-allow-origin: " + allowed },
                detail: `${point.url} reflected an Origin nobody owns${with_credentials}.`,
            };
        }

        // `*` is a real policy decision: it cannot carry credentials, so it is
        // reported as clean here and left to the passive headers audit.
        #{
            outcome: "clean",
            confidence: "certain",
            evidence: #{ payload: canary, matched: () },
            detail: `${point.url} did not reflect the canary Origin (Access-Control-Allow-Origin: ${allowed}).`,
        }
    });
}
