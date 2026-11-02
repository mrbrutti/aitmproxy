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
        // Each target with a signature its own response carries. No signature
        // token appears in its own URL, and none is something an ordinary page
        // says anyway: a page that merely echoes the URL we sent (the first
        // live run read `computeMetadata` and every page's `<title>` as a hit)
        // is not a fetch.
        let targets = [
            ["http://169.254.169.254/latest/meta-data/", "(?i)(ami-id|instance-id|iam/security-credentials|public-keys/)"],
            ["http://metadata.google.internal/computeMetadata/v1/", "(?i)(project-id|numeric-project-id|service-accounts/)"],
            ["http://169.254.169.254/metadata/instance?api-version=2021-02-01", "(?i)(azEnvironment|subscriptionId|vmId|resourceGroupName)"],
            ["http://127.0.0.1/", "(?i)(it works!|welcome to nginx|apache2 (debian|ubuntu) default|iis windows server)"],
        ];

        // A signature the page carries before any payload is the page's own
        // text, not a fetched response.
        let baseline = probe.baseline();

        for target in targets {
            let reply = probe.send(target[0]);
            // The echo of the URL itself is cut out before matching, so a
            // reflected parameter can never be read as a fetched page.
            // (`replace` edits the string in place and returns nothing.)
            let body = reply.body;
            body.replace(target[0], "");
            if regex_match(target[1], body) && !regex_match(target[1], baseline.body) {
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
