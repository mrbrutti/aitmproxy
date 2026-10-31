// missing-permissions-policy.rhai — flag HTML responses with no Permissions-Policy.
// OWASP A05:2021 Security Misconfiguration (unrestricted browser features).
// Passive: observe-only, no traffic, no mutation. Authorised testing only.
const NAME = "missing-permissions-policy";
const API  = "1";

fn on_response(flow) {
    let ct = flow.response.headers.get("Content-Type");
    if contains_ci(ct, "text/html") && !flow.response.headers.has("Permissions-Policy") {
        flow.mark("missing-permissions-policy");
        finding(#{
            name: "Missing Permissions-Policy",
            severity: "info",
            flow_id: flow.id,
            detail: `HTML response for ${flow.request.path} sets no Permissions-Policy; camera, geolocation and other features are unrestricted.`,
            tags: ["headers", "owasp-a05"],
        });
    }
}
