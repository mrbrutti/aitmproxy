// missing-csp.rhai — flag HTML responses with no Content-Security-Policy.
// OWASP A05:2021 Security Misconfiguration (defence-in-depth against XSS).
//
// Passive: observe-only, no traffic, no mutation. Authorised testing only.
const NAME = "missing-csp";
const API  = "1";

fn on_response(flow) {
    let ct = flow.response.headers.get("Content-Type");
    if contains_ci(ct, "text/html") {
        if !flow.response.headers.has("Content-Security-Policy") {
            flow.mark("missing-csp");
            finding(#{
                name: "Missing Content-Security-Policy",
                severity: "low",
                flow_id: flow.id,
                detail: `HTML response for ${flow.request.path} ships no Content-Security-Policy header.`,
                tags: ["headers", "xss-defence", "owasp-a05"],
            });
        }
    }
}
