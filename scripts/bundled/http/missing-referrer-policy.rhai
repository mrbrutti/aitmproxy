// missing-referrer-policy.rhai — flag HTML responses with no Referrer-Policy.
// OWASP A05:2021 Security Misconfiguration (referrer leakage).
// Passive: observe-only, no traffic, no mutation. Authorised testing only.
const NAME = "missing-referrer-policy";
const API  = "1";

fn on_response(flow) {
    let ct = flow.response.headers.get("Content-Type");
    if contains_ci(ct, "text/html") && !flow.response.headers.has("Referrer-Policy") {
        flow.mark("missing-referrer-policy");
        finding(#{
            name: "Missing Referrer-Policy",
            severity: "info",
            flow_id: flow.id,
            detail: `HTML response for ${flow.request.path} sets no Referrer-Policy; full URLs may leak to third parties.`,
            tags: ["headers", "privacy", "owasp-a05"],
        });
    }
}
