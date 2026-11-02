// check-ssrf.rhai — catalogue check `ssrf`, class `ssrf`.
//
// Where a value is a URL the server fetches for us, pointing it at an address
// only the server can reach shows whether the fetch is filtered. Every probe
// still goes to the in-scope target: the internal address rides inside the
// parameter, the scanner never dials it. A reply carrying the well-known
// in-band signature of a metadata service or a loopback web server is the
// finding.
//
// `wants_traits: ["url"]` keeps the check off values that never look like a
// URL (spec D4). No PoC hint: spec D6 does not list `ssrf` among the classes
// that must supply one, and an in-band signature is not reliably reproducible
// from a different network position.
//
// OWASP A10 Server-Side Request Forgery. CWE-918.
const NAME = "check-ssrf";
const API  = "1";

const META = #{
    id: "ssrf",
    name: "Server-side request forgery",
    class: "ssrf",
    lanes: ["http"],
    kinds: ["query", "body_param", "json_value"],
    intensity: "medium",
    cost: "medium",
    technique: "reflected",
    severity: "critical",
    confidence_max: "firm",
    needs_baseline: false,
    wants_traits: ["url"],
    cwe: 918,
    description: "Points a URL value at cloud-metadata and loopback addresses and reports when their in-band response comes back.",
    remediation: "Allow-list the hosts the server may fetch, resolve and re-check the address after redirects, and block link-local ranges.",
};

fn load(reg) {
    reg.add_check(META, |point| {
        // Each target with a signature its own response carries.
        let targets = [
            ["http://169.254.169.254/latest/meta-data/", "(?i)(ami-id|instance-id|iam/|hostname|public-keys)"],
            ["http://metadata.google.internal/computeMetadata/v1/", "(?i)(computeMetadata|project-id|instance/)"],
            ["http://169.254.169.254/metadata/instance?api-version=2021-02-01", "(?i)(compute|azEnvironment|subscriptionId)"],
            ["http://127.0.0.1/", "(?i)(<title>|server:|apache|nginx|it works)"],
        ];

        for target in targets {
            let reply = probe.send(target[0]);
            if regex_match(target[1], reply.body) {
                return #{
                    outcome: "vulnerable",
                    confidence: "firm",
                    evidence: #{ payload: target[0], matched: "internal service response signature" },
                    detail: `"${point.name}" fetched ${target[0]} and returned its response. Cloud-metadata forgery leaks instance credentials.`,
                };
            }
        }

        #{
            outcome: "clean",
            confidence: "firm",
            evidence: #{ payload: targets[0][0], matched: () },
            detail: "No internal or metadata address was fetched on this value.",
        }
    });
}
