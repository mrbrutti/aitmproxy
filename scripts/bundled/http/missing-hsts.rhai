// missing-hsts.rhai — flag HTTPS responses that omit HTTP Strict-Transport-Security.
// OWASP A05:2021 Security Misconfiguration / A02 Cryptographic Failures.
//
// Passive: observes responses already in the authorised engagement scope and
// records a finding. It sends no traffic and mutates nothing. For authorised
// security testing only.
const NAME = "missing-hsts";
const API  = "1";

fn on_response(flow) {
    if flow.request.url.starts_with("https://") {
        if !flow.response.headers.has("Strict-Transport-Security") {
            flow.mark("missing-hsts");
            finding(#{
                name: "Missing HSTS header",
                severity: "low",
                flow_id: flow.id,
                detail: `HTTPS response for ${flow.request.path} has no Strict-Transport-Security header; a network attacker can strip TLS on a later visit.`,
                tags: ["headers", "transport-security", "owasp-a05"],
            });
        }
    }
}
