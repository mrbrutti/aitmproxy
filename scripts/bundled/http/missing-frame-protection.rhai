// missing-frame-protection.rhai — flag HTML responses with no clickjacking
// defence: neither X-Frame-Options nor a CSP frame-ancestors directive.
// OWASP A05:2021 Security Misconfiguration.
//
// Passive: observe-only, no traffic, no mutation. Authorised testing only.
const NAME = "missing-frame-protection";
const API  = "1";

fn on_response(flow) {
    let ct = flow.response.headers.get("Content-Type");
    if !contains_ci(ct, "text/html") { return; }
    let xfo = flow.response.headers.has("X-Frame-Options");
    let csp = flow.response.headers.get("Content-Security-Policy");
    if !xfo && !contains_ci(csp, "frame-ancestors") {
        flow.mark("clickjacking-exposed");
        finding(#{
            name: "No clickjacking protection",
            severity: "low",
            flow_id: flow.id,
            detail: `HTML response for ${flow.request.path} sets neither X-Frame-Options nor CSP frame-ancestors; the page can be framed.`,
            tags: ["headers", "clickjacking", "owasp-a05"],
        });
    }
}
